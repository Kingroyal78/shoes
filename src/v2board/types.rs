use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::plugin_api::ConfigRevision;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ServerConfig {
    pub server_port: u16,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(default)]
    pub listen_ip: Option<String>,
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub server_key: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, alias = "obfs-password")]
    pub obfs_password: Option<String>,
    #[serde(default)]
    pub obfs_settings: Option<Value>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: Option<Value>,
    #[serde(default)]
    pub disable_sni: Option<Value>,
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    #[serde(default)]
    pub zero_rtt_handshake: Option<Value>,
    #[serde(default)]
    pub congestion_control: Option<String>,
    #[serde(default)]
    pub quic_congestion_control: Option<String>,
    #[serde(default)]
    pub up_mbps: Option<u64>,
    #[serde(default)]
    pub down_mbps: Option<u64>,
    #[serde(default)]
    pub ignore_client_bandwidth: Option<bool>,
    #[serde(default)]
    pub padding_scheme: Option<Value>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, alias = "networkSettings")]
    pub network_settings: Option<Value>,
    #[serde(default)]
    pub tls: Option<Value>,
    #[serde(default, alias = "tlsSettings")]
    pub tls_settings: Option<Value>,
    #[serde(default, alias = "realityConfig")]
    pub reality_config: Option<Value>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default, alias = "encryptionSettings")]
    pub encryption_settings: Option<Value>,
    #[serde(default)]
    pub base_config: BaseConfig,
    #[serde(default)]
    pub routes: Vec<Value>,
    #[serde(default)]
    pub config_revision: Option<ConfigRevision>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BaseConfig {
    #[serde(default = "default_push_interval")]
    pub push_interval: u64,
    #[serde(default = "default_pull_interval")]
    pub pull_interval: u64,
    #[serde(default)]
    pub node_report_min_traffic: u64,
    #[serde(default)]
    pub device_online_min_traffic: u64,
}

impl Default for BaseConfig {
    fn default() -> Self {
        Self {
            push_interval: default_push_interval(),
            pull_interval: default_pull_interval(),
            node_report_min_traffic: 0,
            device_online_min_traffic: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
enum UserListWire {
    Users { users: Vec<UserInfo> },
    Data { data: UserListData },
    Direct(Vec<UserInfo>),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
enum UserListData {
    Users { users: Vec<UserInfo> },
    Direct(Vec<UserInfo>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserList {
    pub users: Vec<UserInfo>,
}

impl<'de> Deserialize<'de> for UserList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = UserListWire::deserialize(deserializer)?;
        let users = match wire {
            UserListWire::Users { users } => users,
            UserListWire::Data { data } => match data {
                UserListData::Users { users } => users,
                UserListData::Direct(users) => users,
            },
            UserListWire::Direct(users) => users,
        };
        Ok(Self { users })
    }
}

/// One user as the panel publishes them.
///
/// The optional fields are skipped when empty rather than written as nulls.
/// They are only ever serialized into the last-known-good snapshot, and a
/// typical user sets two of the fifteen -- the nulls were four fifths of a
/// snapshot that gets rewritten on every pull. Deserialization is unaffected:
/// every one of them already defaults when absent.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserInfo {
    #[serde(alias = "uid")]
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(
        default,
        alias = "link_secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ips: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
}

impl UserInfo {
    pub fn credential(&self) -> Option<&str> {
        self.uuid
            .as_deref()
            .or(self.password.as_deref())
            .or(self.username.as_deref())
    }

    pub fn key(&self) -> String {
        self.uuid
            .clone()
            .or_else(|| self.username.clone())
            .or_else(|| self.label.clone())
            .unwrap_or_else(|| format!("user-{}", self.id))
    }

    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref()
    }

    pub fn enabled_flag(&self) -> Option<bool> {
        flexible_bool(self.enabled.as_ref())
    }

    pub fn expires_at_unix(&self) -> Option<i64> {
        flexible_i64(self.expires_at.as_ref())
    }
}

fn flexible_bool(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => value.as_i64().map(|value| value != 0),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" | "" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn flexible_i64(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(value) => value.as_i64(),
        Value::String(value) => value.trim().parse::<i64>().ok(),
        _ => None,
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AliveList {
    #[serde(default)]
    pub alive: HashMap<u64, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushOk {
    pub data: bool,
}

pub type TrafficPayload = HashMap<String, [u64; 2]>;
pub type AlivePayload = HashMap<String, Vec<String>>;

fn default_push_interval() -> u64 {
    60
}

fn default_pull_interval() -> u64 {
    60
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn user_list_accepts_v2board_response_shapes_and_uid_alias() {
        let direct: UserList = serde_json::from_value(json!([
            {"uid": 7, "uuid": "00000000-0000-0000-0000-000000000007"}
        ]))
        .unwrap();
        assert_eq!(direct.users[0].id, 7);

        let wrapped: UserList = serde_json::from_value(json!({
            "data": {
                "users": [
                    {"id": 8, "uuid": "00000000-0000-0000-0000-000000000008"}
                ]
            }
        }))
        .unwrap();
        assert_eq!(wrapped.users[0].id, 8);

        let data_array: UserList = serde_json::from_value(json!({
            "data": [
                {"id": 9, "uuid": "00000000-0000-0000-0000-000000000009"}
            ]
        }))
        .unwrap();
        assert_eq!(data_array.users[0].id, 9);
    }

    #[test]
    fn user_info_parses_flexible_status_fields() {
        let user: UserInfo = serde_json::from_value(json!({
            "id": 10,
            "uuid": "00000000-0000-0000-0000-000000000010",
            "enabled": "0",
            "expires_at": "123"
        }))
        .unwrap();

        assert_eq!(user.enabled_flag(), Some(false));
        assert_eq!(user.expires_at_unix(), Some(123));
    }
    #[test]
    fn server_config_accepts_v2board_camel_case_settings_aliases() {
        let config: ServerConfig = serde_json::from_value(json!({
            "server_port": 443,
            "networkSettings": {"path": "/ws"},
            "tlsSettings": {"serverName": "example.com"},
            "realityConfig": {"MaxTimeDiff": "1m"},
            "encryptionSettings": {"mode": "native"},
            "obfs-password": "secret"
        }))
        .unwrap();

        assert_eq!(config.network_settings.unwrap()["path"], "/ws");
        assert_eq!(config.tls_settings.unwrap()["serverName"], "example.com");
        assert_eq!(config.reality_config.unwrap()["MaxTimeDiff"], "1m");
        assert_eq!(config.encryption_settings.unwrap()["mode"], "native");
        assert_eq!(config.obfs_password.as_deref(), Some("secret"));
    }
}
