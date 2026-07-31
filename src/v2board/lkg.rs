use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::backend_config::{NodeType, V2BoardNodeConfig};

use super::plugin_api::{OpaqueEtag, PluginConfigCandidate};
use super::types::{ServerConfig, UserInfo};

const SNAPSHOT_SCHEMA_VERSION: u8 = 1;
const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024;

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
    match tokio::fs::metadata(&path).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let node = node.clone();
    tokio::task::spawn_blocking(move || load_blocking(&path, &node))
        .await
        .map_err(|error| std::io::Error::other(format!("LKG load task failed: {error}")))?
        .map(Some)
}

pub async fn persist(
    data_dir: &Path,
    node: &V2BoardNodeConfig,
    snapshot: &NodeLkgSnapshot,
) -> std::io::Result<()> {
    tokio::fs::create_dir_all(data_dir).await?;
    let path = snapshot_path(data_dir, node);
    let bytes = serde_json::to_vec(snapshot)
        .map_err(|error| invalid_data(format!("failed to encode LKG snapshot: {error}")))?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(invalid_data("last-known-good snapshot exceeds size limit"));
    }
    tokio::task::spawn_blocking(move || persist_blocking(&path, &bytes))
        .await
        .map_err(|error| std::io::Error::other(format!("LKG persist task failed: {error}")))?
}

fn load_blocking(path: &Path, node: &V2BoardNodeConfig) -> std::io::Result<NodeLkgSnapshot> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(invalid_data(
            "last-known-good snapshot is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    let snapshot = serde_json::from_slice::<NodeLkgSnapshot>(&bytes)
        .map_err(|error| invalid_data(format!("failed to decode LKG snapshot: {error}")))?;
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
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
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
        "v2board-lkg-{}-{}.json",
        node.node_type.as_uniproxy(),
        node.node_id
    ))
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
            Path::new("/state/v2board-lkg-shadowsocks-42.json")
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
        persist(directory.path(), &node, &snapshot).await.unwrap();
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
        persist(directory.path(), &node, &snapshot).await.unwrap();

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
