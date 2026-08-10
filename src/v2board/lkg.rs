use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::backend_config::{NodeType, V2BoardNodeConfig};

use super::plugin_api::{OpaqueEtag, PluginConfigCandidate};
use super::types::{ServerConfig, UserInfo};

const SNAPSHOT_SCHEMA_VERSION: u8 = 1;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeLkgSnapshot {
    schema_version: u8,
    node_id: u64,
    node_type: String,
    pub server_etag: Option<String>,
    pub user_etag: Option<String>,
    pub server_config: ServerConfig,
    pub users: Vec<UserInfo>,
    plugin: Option<PluginLkgSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginLkgSnapshot {
    etag: String,
    manifest: Value,
}

impl NodeLkgSnapshot {
    pub fn new(
        node: &V2BoardNodeConfig,
        server_etag: Option<String>,
        user_etag: Option<String>,
        server_config: ServerConfig,
        users: Vec<UserInfo>,
        plugin_candidate: Option<&PluginConfigCandidate>,
    ) -> std::io::Result<Self> {
        let plugin = match plugin_candidate {
            Some(candidate) => Some(PluginLkgSnapshot {
                etag: candidate.etag().as_str().to_string(),
                manifest: candidate.wire_manifest().cloned().ok_or_else(|| {
                    invalid_data("plugin candidate is missing its validated wire manifest")
                })?,
            }),
            None => None,
        };
        Ok(Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            node_id: node.node_id,
            node_type: node.node_type.as_uniproxy().to_string(),
            server_etag,
            user_etag,
            server_config,
            users,
            plugin,
        })
    }

    pub fn validate_for(&self, node: &V2BoardNodeConfig) -> std::io::Result<()> {
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(invalid_data("unsupported last-known-good snapshot schema"));
        }
        if self.node_id != node.node_id || self.node_type != node.node_type.as_uniproxy() {
            return Err(invalid_data(
                "last-known-good snapshot belongs to a different V2Board node",
            ));
        }
        if node.node_type == NodeType::Shadowsocks && self.plugin.is_none() {
            return Err(invalid_data(
                "Shadowsocks last-known-good snapshot has no plugin manifest",
            ));
        }
        if node.node_type != NodeType::Shadowsocks && self.plugin.is_some() {
            return Err(invalid_data(
                "non-Shadowsocks last-known-good snapshot contains plugin state",
            ));
        }
        Ok(())
    }

    pub fn plugin_candidate(
        &self,
        node: &V2BoardNodeConfig,
    ) -> std::io::Result<Option<PluginConfigCandidate>> {
        self.plugin
            .as_ref()
            .map(|plugin| {
                let etag = OpaqueEtag::parse(plugin.etag.clone())
                    .map_err(|error| invalid_data(error.to_string()))?;
                PluginConfigCandidate::from_wire(etag, plugin.manifest.clone(), node.node_id)
                    .map_err(|error| invalid_data(error.to_string()))
            })
            .transpose()
    }
}

pub async fn load(
    data_dir: &Path,
    node: &V2BoardNodeConfig,
) -> std::io::Result<Option<NodeLkgSnapshot>> {
    let path = snapshot_path(data_dir, node);
    let (path, legacy) = match tokio::fs::metadata(&path).await {
        Ok(_) => (path, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Fall back to the pre-MessagePack file so an upgrade does not
            // throw away the recovery point the previous build wrote.
            let legacy = legacy_snapshot_path(data_dir, node);
            match tokio::fs::metadata(&legacy).await {
                Ok(_) => (legacy, true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    let node = node.clone();
    tokio::task::spawn_blocking(move || load_blocking(&path, &node, legacy))
        .await
        .map_err(|error| std::io::Error::other(format!("LKG load task failed: {error}")))?
        .map(Some)
}

pub async fn persist(
    data_dir: &Path,
    node: &V2BoardNodeConfig,
    snapshot: NodeLkgSnapshot,
) -> std::io::Result<()> {
    tokio::fs::create_dir_all(data_dir).await?;
    let path = snapshot_path(data_dir, node);
    // Encode on the blocking pool alongside the write, not before it. On a node
    // with a large user list this is a long stretch of pure CPU, and it used to
    // run on whichever runtime worker was driving this node's sync -- stalling
    // every connection that worker was also driving.
    tokio::task::spawn_blocking(move || {
        // Named MessagePack: markedly smaller and faster to encode than JSON on
        // a payload that scales with the user count, without the brittleness of
        // a positional encoding for a file a later build has to read back.
        let bytes = rmp_serde::to_vec_named(&snapshot)
            .map_err(|error| invalid_data(format!("failed to encode LKG snapshot: {error}")))?;
        persist_blocking(&path, &bytes)
    })
    .await
    .map_err(|error| std::io::Error::other(format!("LKG persist task failed: {error}")))?
}

fn load_blocking(
    path: &Path,
    node: &V2BoardNodeConfig,
    legacy: bool,
) -> std::io::Result<NodeLkgSnapshot> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    // Deliberately unbounded in length. The snapshot is this process's own
    // recovery point, and its size is whatever the panel's user list makes it;
    // a fixed ceiling only ever rejects legitimate data, and rejecting it here
    // rolls the ETags back and puts the node into a permanent full-refetch loop.
    // The file-type check stays: a FIFO or directory at this path is a real
    // problem, and reading one would block rather than fail.
    if !metadata.is_file() {
        return Err(invalid_data(
            "last-known-good snapshot is not a regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    let snapshot = decode_snapshot(&bytes, legacy)?;
    snapshot.validate_for(node)?;
    Ok(snapshot)
}

fn persist_blocking(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("LKG snapshot path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid_data("LKG snapshot path is not valid UTF-8"))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", super::writer_id()));
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let write_result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        File::open(parent)?.sync_all()
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result
}

fn snapshot_path(data_dir: &Path, node: &V2BoardNodeConfig) -> PathBuf {
    data_dir.join(format!(
        "v2board-lkg-{}-{}.mpk",
        node.node_type.as_uniproxy(),
        node.node_id
    ))
}

/// Where snapshots were written before the encoding changed.
///
/// Read-only: a node that restarts onto this build still recovers from the file
/// its previous build left behind, and writes the new one from then on.
fn legacy_snapshot_path(data_dir: &Path, node: &V2BoardNodeConfig) -> PathBuf {
    data_dir.join(format!(
        "v2board-lkg-{}-{}.json",
        node.node_type.as_uniproxy(),
        node.node_id
    ))
}

/// Decode a snapshot, accepting either encoding.
///
/// MessagePack with field names kept (`to_vec_named`), not positional: the
/// snapshot is a recovery point read back by a possibly newer build, and
/// positional encoding would silently misread a struct whose fields moved.
fn decode_snapshot(bytes: &[u8], legacy: bool) -> std::io::Result<NodeLkgSnapshot> {
    if legacy {
        serde_json::from_slice::<NodeLkgSnapshot>(bytes)
            .map_err(|error| invalid_data(format!("failed to decode LKG snapshot: {error}")))
    } else {
        rmp_serde::from_slice::<NodeLkgSnapshot>(bytes)
            .map_err(|error| invalid_data(format!("failed to decode LKG snapshot: {error}")))
    }
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn snapshot_path_does_not_use_the_operator_controlled_tag() {
        let node = V2BoardNodeConfig {
            tag: "../../escape".to_string(),
            node_id: 42,
            node_type: NodeType::Shadowsocks,
            listen: None,
            api_host: None,
            api_key: None,
            pull_interval_secs: None,
            push_interval_secs: None,
            tls: None,
            trojan_fallback: None,
            hysteria2_masquerade: None,
        };
        assert_eq!(
            snapshot_path(Path::new("/state"), &node),
            Path::new("/state/v2board-lkg-shadowsocks-42.mpk")
        );
    }

    #[tokio::test]
    async fn snapshot_round_trip_is_atomic_and_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let node = V2BoardNodeConfig {
            tag: "vless-a".to_string(),
            node_id: 7,
            node_type: NodeType::Vless,
            listen: None,
            api_host: None,
            api_key: None,
            pull_interval_secs: None,
            push_interval_secs: None,
            tls: None,
            trojan_fallback: None,
            hysteria2_masquerade: None,
        };
        let server_config =
            serde_json::from_value::<ServerConfig>(json!({"server_port": 8443})).unwrap();
        let users = vec![
            serde_json::from_value::<UserInfo>(json!({
                "id": 11,
                "uuid": "00000000-0000-0000-0000-000000000011"
            }))
            .unwrap(),
        ];
        let snapshot = NodeLkgSnapshot::new(
            &node,
            Some("server-etag".to_string()),
            Some("user-etag".to_string()),
            server_config,
            users,
            None,
        )
        .unwrap();
        persist(directory.path(), &node, snapshot).await.unwrap();
        let loaded = load(directory.path(), &node).await.unwrap().unwrap();
        assert_eq!(loaded.server_config.server_port, 8443);
        assert_eq!(loaded.users[0].id, 11);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(snapshot_path(directory.path(), &node))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn a_snapshot_written_by_the_previous_encoding_is_still_recovered() {
        let directory = tempfile::tempdir().unwrap();
        let node = V2BoardNodeConfig {
            tag: "legacy".to_string(),
            node_id: 21,
            node_type: NodeType::Vless,
            listen: None,
            api_host: None,
            api_key: None,
            pull_interval_secs: None,
            push_interval_secs: None,
            tls: None,
            trojan_fallback: None,
            hysteria2_masquerade: None,
        };
        let server_config =
            serde_json::from_value::<ServerConfig>(json!({"server_port": 8443})).unwrap();
        let users = vec![
            serde_json::from_value::<UserInfo>(json!({
                "id": 5,
                "uuid": "00000000-0000-0000-0000-000000000005"
            }))
            .unwrap(),
        ];
        let snapshot = NodeLkgSnapshot::new(
            &node,
            Some("etag".to_string()),
            Some("etag".to_string()),
            server_config,
            users,
            None,
        )
        .unwrap();

        // Write only the pre-MessagePack file, as an older build would have.
        std::fs::write(
            legacy_snapshot_path(directory.path(), &node),
            serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();

        let loaded = load(directory.path(), &node)
            .await
            .unwrap()
            .expect("an upgrade must not discard the recovery point on disk");
        assert_eq!(loaded.users[0].id, 5);
        assert_eq!(loaded.server_config.server_port, 8443);
    }

    #[tokio::test]
    async fn snapshot_round_trips_past_the_old_thirty_two_megabyte_ceiling() {
        let directory = tempfile::tempdir().unwrap();
        let node = V2BoardNodeConfig {
            tag: "big".to_string(),
            node_id: 99,
            node_type: NodeType::Vless,
            listen: None,
            api_host: None,
            api_key: None,
            pull_interval_secs: None,
            push_interval_secs: None,
            tls: None,
            trojan_fallback: None,
            hysteria2_masquerade: None,
        };
        let server_config =
            serde_json::from_value::<ServerConfig>(json!({"server_port": 8443})).unwrap();
        // Comfortably past the ceiling this used to carry: at the ~262 bytes a
        // user costs on the wire, a node this size is ordinary, and refusing to
        // write its snapshot rolled the ETags back and put the node into a
        // permanent full-refetch loop rather than merely being slow.
        // Past 32 MiB at the ~59 bytes a user costs once empty fields are
        // skipped. Cloned from one template rather than parsed individually,
        // so the test spends its time on the persist path and not on serde.
        let template = serde_json::from_value::<UserInfo>(json!({
            "id": 0,
            "uuid": "00000000-0000-0000-0000-000000000000",
        }))
        .unwrap();
        let users = (0..700_000_u64)
            .map(|id| UserInfo {
                id,
                uuid: Some(format!("00000000-0000-0000-0000-{id:012}")),
                ..template.clone()
            })
            .collect::<Vec<_>>();
        let snapshot = NodeLkgSnapshot::new(
            &node,
            Some("server-etag".to_string()),
            Some("user-etag".to_string()),
            server_config,
            users,
            None,
        )
        .unwrap();

        persist(directory.path(), &node, snapshot).await.unwrap();
        let written = std::fs::metadata(snapshot_path(directory.path(), &node))
            .unwrap()
            .len();
        assert!(
            written > 32 * 1024 * 1024,
            "test must exercise a snapshot past the old limit, got {written} bytes"
        );

        let loaded = load(directory.path(), &node).await.unwrap().unwrap();
        assert_eq!(loaded.users.len(), 700_000);
        assert_eq!(loaded.users[699_999].id, 699_999);
    }

    #[tokio::test]
    async fn shadowsocks_snapshot_restores_the_exact_validated_plugin_manifest() {
        use crate::v2board::plugin_api::RuntimePlugin;

        let directory = tempfile::tempdir().unwrap();
        let node = V2BoardNodeConfig {
            tag: "ss-a".to_string(),
            node_id: 12,
            node_type: NodeType::Shadowsocks,
            listen: None,
            api_host: None,
            api_key: None,
            pull_interval_secs: None,
            push_interval_secs: None,
            tls: None,
            trojan_fallback: None,
            hysteria2_masquerade: None,
        };
        let manifest = json!({
            "schema_version": 1,
            "node_type": "shadowsocks",
            "node_id": 12,
            "server_port": 8388,
            "cipher": "aes-128-gcm",
            "server_key": null,
            "obfs": null,
            "obfs_settings": null,
            "multiplex": null,
            "plugin": {
                "type": "restls",
                "listen_port": 443,
                "upstream": {"host": "127.0.0.1", "port": 8388},
                "options": {
                    "host": "cover.example.com",
                    "password": "restls-secret",
                    "restls_script": "300?100<1"
                }
            },
            "routes": [],
            "config_revision": concat!(
                "sha256:",
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef"
            ),
            "base_config": {
                "push_interval": 60,
                "pull_interval": 60,
                "node_report_min_traffic": 0,
                "device_online_min_traffic": 0
            }
        });
        let candidate = PluginConfigCandidate::from_wire(
            OpaqueEtag::parse("\"plugin-etag\"").unwrap(),
            manifest,
            node.node_id,
        )
        .unwrap();
        let server_config = serde_json::from_value::<ServerConfig>(json!({
            "server_port": 8388,
            "cipher": "aes-128-gcm",
            "config_revision": concat!(
                "sha256:",
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef"
            )
        }))
        .unwrap();
        let snapshot = NodeLkgSnapshot::new(
            &node,
            Some("server-etag".to_string()),
            Some("user-etag".to_string()),
            server_config,
            Vec::new(),
            Some(&candidate),
        )
        .unwrap();
        persist(directory.path(), &node, snapshot).await.unwrap();

        let restored = load(directory.path(), &node).await.unwrap().unwrap();
        let restored_candidate = restored.plugin_candidate(&node).unwrap().unwrap();
        let RuntimePlugin::Restls { options, .. } =
            restored_candidate.manifest().plugin.as_ref().unwrap()
        else {
            panic!("expected Restls plugin");
        };
        assert_eq!(options.password.expose_secret(), "restls-secret");
        assert_eq!(restored_candidate.etag().as_str(), "\"plugin-etag\"");
    }
}
