use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::net::Ipv6Addr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub const FEATURE_UOT_V1: &str = "shadowsocks-uot-v1";
pub const FEATURE_UOT_V2: &str = "shadowsocks-uot-v2";
pub const FEATURE_SING_MUX_V1: &str = "shadowsocks-sing-mux-v1";
pub const FEATURE_PLUGIN_RUNTIME_V1: &str = "shadowsocks-plugin-runtime-v1";
pub const FEATURE_PLUGIN_OBFS_V1: &str = "shadowsocks-plugin-obfs-v1";
pub const FEATURE_PLUGIN_V2RAY_V1: &str = "shadowsocks-plugin-v2ray-v1";
pub const FEATURE_PLUGIN_GOST_V1: &str = "shadowsocks-plugin-gost-v1";
pub const FEATURE_PLUGIN_SHADOW_TLS_V1: &str = "shadowsocks-plugin-shadow-tls-v1";
pub const FEATURE_PLUGIN_RESTLS_V1: &str = "shadowsocks-plugin-restls-v1";
pub const FEATURE_PLUGIN_KCPTUN_V1: &str = "shadowsocks-plugin-kcptun-v1";

const MAX_FEATURES: usize = 32;
const MAX_VERSION_BYTES: usize = 128;
const MAX_BRUTAL_MBPS: u64 = 18_446_744_073_709;
/// The one multiplex protocol this backend's Shadowsocks mux implements.
pub const MULTIPLEX_PROTOCOL_H2MUX: &str = "h2mux";
const MAX_KCPTUN_INT: u32 = i32::MAX as u32;
const MAX_RESTLS_RECORD_TARGET: u64 = 16_364;
/// How many response records a Restls script may ask a peer for.
///
/// Measured, not taken from the script grammar, which allows 254. The
/// reference client stops carrying traffic somewhere above thirty-one whatever
/// server it talks to: the reference server fails from thirty-two, this
/// backend from thirty-three. Thirty-one is what both were seen to carry, and
/// a manifest asking for more is refused rather than applied into a node that
/// publishes and then stalls.
const MAX_RESTLS_RESPONSES: u64 = 31;

#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigRevision(String);

impl ConfigRevision {
    pub fn parse(value: impl Into<String>) -> Result<Self, PluginManifestError> {
        let value = value.into();
        let digest = value.strip_prefix("sha256:").ok_or_else(|| {
            PluginManifestError::new("config_revision must use the sha256 wire prefix")
        })?;
        if digest.len() != 64
            || !digest
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(PluginManifestError::new(
                "config_revision must contain 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ConfigRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ConfigRevision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpaqueEtag(String);

impl OpaqueEtag {
    pub fn parse(value: impl Into<String>) -> Result<Self, PluginApiError> {
        let value = value.into();
        let header = http::HeaderValue::try_from(value.as_str())
            .map_err(|_| PluginApiError::InvalidResponse("ETag is not valid ASCII"))?;
        Self::from_header(&header)
    }

    pub fn from_header(value: &http::HeaderValue) -> Result<Self, PluginApiError> {
        let value = value
            .to_str()
            .map_err(|_| PluginApiError::InvalidResponse("ETag is not valid ASCII"))?;
        if value.is_empty() {
            return Err(PluginApiError::InvalidResponse("ETag is empty"));
        }
        Ok(Self(value.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn from_static(value: &'static str) -> Self {
        let value = http::HeaderValue::from_static(value);
        Self::from_header(&value).expect("test ETag must be a valid header")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersionV1;

impl<'de> Deserialize<'de> for SchemaVersionV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 1 {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "unsupported Shadowsocks plugin schema_version",
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum PluginNodeType {
    #[serde(rename = "shadowsocks")]
    Shadowsocks,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginRuntimeManifest {
    pub schema_version: SchemaVersionV1,
    pub node_type: PluginNodeType,
    pub node_id: u64,
    pub server_port: u16,
    pub cipher: String,
    #[serde(deserialize_with = "required_nullable")]
    pub server_key: Option<SecretString>,
    pub obfs: (),
    pub obfs_settings: (),
    #[serde(deserialize_with = "required_nullable")]
    pub multiplex: Option<ServerMultiplex>,
    #[serde(deserialize_with = "required_nullable")]
    pub plugin: Option<RuntimePlugin>,
    pub routes: Vec<Value>,
    pub config_revision: ConfigRevision,
    pub base_config: PluginBaseConfig,
}

impl PluginRuntimeManifest {
    pub fn validate(&self, expected_node_id: u64) -> Result<(), PluginManifestError> {
        if self.node_id != expected_node_id {
            return Err(PluginManifestError::new(
                "plugin-config node_id does not match the requested node",
            ));
        }
        if self.server_port == 0 {
            return Err(PluginManifestError::new(
                "plugin-config server_port must be non-zero",
            ));
        }
        if self.cipher.trim().is_empty() {
            return Err(PluginManifestError::new(
                "plugin-config cipher must be non-empty",
            ));
        }
        if let Some(multiplex) = &self.multiplex {
            multiplex.validate()?;
        }
        if self.base_config.push_interval < 5 {
            return Err(PluginManifestError::new(
                "plugin-config push_interval must be at least five seconds",
            ));
        }
        if let Some(plugin) = &self.plugin {
            plugin.validate(self.server_port)?;
        }
        Ok(())
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginBaseConfig {
    pub push_interval: u64,
    pub pull_interval: u64,
    pub node_report_min_traffic: u64,
    pub device_online_min_traffic: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerMultiplex {
    pub enabled: bool,
    pub padding: bool,
    /// Which multiplex protocol the client will speak.
    ///
    /// Absent from manifests written before the panel learned to send it,
    /// where the only protocol in play was H2MUX. It has to be part of the
    /// manifest because both ends must speak the same one: a client told to
    /// use a protocol this backend does not implement produces a node that
    /// applies cleanly, acknowledges its revision, publishes, and then carries
    /// nothing.
    #[serde(default = "default_multiplex_protocol")]
    pub protocol: String,
    pub brutal: ServerBrutal,
}

fn default_multiplex_protocol() -> String {
    MULTIPLEX_PROTOCOL_H2MUX.to_string()
}

impl ServerMultiplex {
    fn validate(&self) -> Result<(), PluginManifestError> {
        if self.enabled && self.protocol != MULTIPLEX_PROTOCOL_H2MUX {
            return Err(PluginManifestError::new(
                "server multiplex protocol is not implemented by this backend; \
                 only h2mux is supported",
            ));
        }
        if !self.enabled && (self.padding || self.brutal.enabled) {
            return Err(PluginManifestError::new(
                "disabled server multiplex cannot enable padding or TCP Brutal",
            ));
        }
        if self.brutal.enabled {
            if self.brutal.up_mbps == 0 || self.brutal.down_mbps == 0 {
                return Err(PluginManifestError::new(
                    "enabled TCP Brutal requires non-zero bandwidth",
                ));
            }
            if self.brutal.up_mbps > MAX_BRUTAL_MBPS || self.brutal.down_mbps > MAX_BRUTAL_MBPS {
                return Err(PluginManifestError::new(
                    "TCP Brutal bandwidth exceeds the V2Board runtime limit",
                ));
            }
        } else if self.brutal.up_mbps != 0 || self.brutal.down_mbps != 0 {
            return Err(PluginManifestError::new(
                "disabled TCP Brutal must use zero bandwidth",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerBrutal {
    pub enabled: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum RuntimePlugin {
    #[serde(rename = "obfs")]
    Obfs {
        listen_port: u16,
        upstream: PluginUpstream,
        options: ObfsOptions,
    },
    #[serde(rename = "v2ray-plugin")]
    V2ray {
        listen_port: u16,
        upstream: PluginUpstream,
        options: V2rayPluginOptions,
    },
    #[serde(rename = "gost-plugin")]
    Gost {
        listen_port: u16,
        upstream: PluginUpstream,
        options: GostPluginOptions,
    },
    #[serde(rename = "shadow-tls")]
    ShadowTls {
        listen_port: u16,
        upstream: PluginUpstream,
        options: ShadowTlsOptions,
    },
    #[serde(rename = "restls")]
    Restls {
        listen_port: u16,
        upstream: PluginUpstream,
        options: RestlsOptions,
    },
    #[serde(rename = "kcptun")]
    Kcptun {
        listen_port: u16,
        upstream: PluginUpstream,
        options: KcptunOptions,
    },
}

impl RuntimePlugin {
    pub fn kind(&self) -> PluginKind {
        match self {
            Self::Obfs { .. } => PluginKind::Obfs,
            Self::V2ray { .. } => PluginKind::V2ray,
            Self::Gost { .. } => PluginKind::Gost,
            Self::ShadowTls { .. } => PluginKind::ShadowTls,
            Self::Restls { .. } => PluginKind::Restls,
            Self::Kcptun { .. } => PluginKind::Kcptun,
        }
    }

    pub fn listen_port(&self) -> u16 {
        match self {
            Self::Obfs { listen_port, .. }
            | Self::V2ray { listen_port, .. }
            | Self::Gost { listen_port, .. }
            | Self::ShadowTls { listen_port, .. }
            | Self::Restls { listen_port, .. }
            | Self::Kcptun { listen_port, .. } => *listen_port,
        }
    }

    pub fn upstream(&self) -> &PluginUpstream {
        match self {
            Self::Obfs { upstream, .. }
            | Self::V2ray { upstream, .. }
            | Self::Gost { upstream, .. }
            | Self::ShadowTls { upstream, .. }
            | Self::Restls { upstream, .. }
            | Self::Kcptun { upstream, .. } => upstream,
        }
    }

    fn validate(&self, raw_server_port: u16) -> Result<(), PluginManifestError> {
        if self.listen_port() == 0 {
            return Err(PluginManifestError::new(
                "plugin listen_port must be non-zero",
            ));
        }
        let upstream = self.upstream();
        if upstream.host != "127.0.0.1" || upstream.port != raw_server_port {
            return Err(PluginManifestError::new(
                "plugin upstream must match the declared raw Shadowsocks loopback endpoint",
            ));
        }
        match self {
            Self::Obfs { options, .. } => options.validate(),
            Self::V2ray { options, .. } => options.validate(),
            Self::Gost { options, .. } => options.validate(),
            Self::ShadowTls { options, .. } => options.validate(),
            Self::Restls { options, .. } => options.validate(),
            Self::Kcptun { options, .. } => options.validate(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginKind {
    Obfs,
    V2ray,
    Gost,
    ShadowTls,
    Restls,
    Kcptun,
}

impl PluginKind {
    pub fn adapter_feature(self) -> AppliedFeature {
        match self {
            Self::Obfs => AppliedFeature::PluginObfsV1,
            Self::V2ray => AppliedFeature::PluginV2rayV1,
            Self::Gost => AppliedFeature::PluginGostV1,
            Self::ShadowTls => AppliedFeature::PluginShadowTlsV1,
            Self::Restls => AppliedFeature::PluginRestlsV1,
            Self::Kcptun => AppliedFeature::PluginKcptunV1,
        }
    }
}

/// Name the reason when the panel asks for a plugin the contract defines but
/// this backend has no adapter for.
///
/// The manifest is decoded strictly, so an adapter we do not implement is
/// indistinguishable from a corrupt payload in the serde error alone, and the
/// serde message itself is never surfaced because the manifest carries plugin
/// secrets. This inspects only `plugin.type`, which is a fixed vocabulary
/// rather than operator data, and returns a static string.
fn unimplemented_plugin_type_reason(wire_manifest: &Value) -> Option<&'static str> {
    let plugin_type = wire_manifest.get("plugin")?.get("type")?.as_str()?;
    match plugin_type {
        // Every type with a RuntimePlugin variant: a decode failure here is
        // about the options or the rest of the manifest, not the adapter.
        "obfs" | "v2ray-plugin" | "gost-plugin" | "shadow-tls" | "restls" | "kcptun" => None,
        "jls" => Some(
            "plugin-config selects the JLS plugin, which this backend does not implement; \
             the last-known-good runtime is kept and the revision is not acknowledged",
        ),
        _ => Some(
            "plugin-config selects a plugin type this backend does not implement; \
             the last-known-good runtime is kept and the revision is not acknowledged",
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginUpstream {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObfsMode {
    Http,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsOptions {
    pub mode: ObfsMode,
    pub host: String,
}

impl ObfsOptions {
    fn validate(&self) -> Result<(), PluginManifestError> {
        validate_plugin_host(&self.host, "obfs host")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebsocketMode {
    Websocket,
}

/// What the panel stores under a WebSocket plugin's `ech_opts`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchOptions {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub config: String,
    #[serde(default)]
    pub query_server_name: String,
}

impl EchOptions {
    fn is_requested(&self) -> bool {
        self.enable || !self.config.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2rayPluginOptions {
    pub mode: WebsocketMode,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub mux: bool,
    pub v2ray_http_upgrade: bool,
    /// PEM certificate chain this plugin edge serves, when the panel holds it.
    ///
    /// Deliberately not the panel's `certificate`/`private_key`, which are the
    /// client certificate for mutual TLS and are published to every
    /// subscriber. What a node serves is its own identity and must never be.
    #[serde(default)]
    pub server_certificate: String,
    /// PEM private key for [`Self::server_certificate`].
    #[serde(default)]
    pub server_private_key: Option<SecretString>,
    /// Encrypted ClientHello, as the panel has it configured.
    ///
    /// This backend does not implement ECH. A node that publishes it to its
    /// clients and serves a plugin edge that cannot answer it is a node whose
    /// clients cannot connect, so the generation is refused rather than
    /// applied -- the same answer the other node types give.
    #[serde(default)]
    pub ech_opts: Option<EchOptions>,
    /// Trust anchor for the client certificates this edge accepts.
    ///
    /// Present means the edge requires one. The panel hands every subscriber a
    /// client certificate, and without this the backend never asks for it, so
    /// that certificate authenticates nothing. Only the public half belongs
    /// here; the key stays with the clients that have to present it.
    #[serde(default)]
    pub client_ca: String,
    /// Serve clients whose `Host` header is not the published one.
    ///
    /// The panel hands different users different hosts for the same node, so
    /// the header is not a node-wide constant there. Defaults to enforcing it,
    /// which is what a panel that does not send the field means.
    #[serde(default)]
    pub allow_unknown_host: bool,
}

impl V2rayPluginOptions {
    fn validate(&self) -> Result<(), PluginManifestError> {
        validate_websocket_options(&self.host, &self.path)?;
        validate_ech(self.ech_opts.as_ref())?;
        validate_client_ca(self.client_ca.as_str(), self.tls)?;
        validate_tls_material(
            self.server_certificate.as_str(),
            self.server_private_key.as_ref(),
        )?;
        if self.v2ray_http_upgrade && self.mux {
            return Err(PluginManifestError::new(
                "V2Ray HTTP Upgrade cannot be combined with plugin mux",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GostPluginOptions {
    pub mode: WebsocketMode,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub mux: bool,
    /// PEM certificate chain this plugin edge serves, when the panel holds it.
    ///
    /// Deliberately not the panel's `certificate`/`private_key`, which are the
    /// client certificate for mutual TLS and are published to every
    /// subscriber. What a node serves is its own identity and must never be.
    #[serde(default)]
    pub server_certificate: String,
    /// PEM private key for [`Self::server_certificate`].
    #[serde(default)]
    pub server_private_key: Option<SecretString>,
    /// Encrypted ClientHello, as the panel has it configured.
    ///
    /// This backend does not implement ECH. A node that publishes it to its
    /// clients and serves a plugin edge that cannot answer it is a node whose
    /// clients cannot connect, so the generation is refused rather than
    /// applied -- the same answer the other node types give.
    #[serde(default)]
    pub ech_opts: Option<EchOptions>,
    /// Trust anchor for the client certificates this edge accepts.
    ///
    /// Present means the edge requires one. The panel hands every subscriber a
    /// client certificate, and without this the backend never asks for it, so
    /// that certificate authenticates nothing. Only the public half belongs
    /// here; the key stays with the clients that have to present it.
    #[serde(default)]
    pub client_ca: String,
    /// See [`V2rayPluginOptions::allow_unknown_host`].
    #[serde(default)]
    pub allow_unknown_host: bool,
}

impl GostPluginOptions {
    fn validate(&self) -> Result<(), PluginManifestError> {
        validate_websocket_options(&self.host, &self.path)?;
        validate_ech(self.ech_opts.as_ref())?;
        validate_client_ca(self.client_ca.as_str(), self.tls)?;
        validate_tls_material(
            self.server_certificate.as_str(),
            self.server_private_key.as_ref(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowTlsOptions {
    pub host: String,
    pub version: u8,
    #[serde(default)]
    pub password: Option<SecretString>,
}

impl ShadowTlsOptions {
    fn validate(&self) -> Result<(), PluginManifestError> {
        validate_plugin_host(&self.host, "ShadowTLS host")?;
        if !matches!(self.version, 1..=3) {
            return Err(PluginManifestError::new(
                "ShadowTLS version must be 1, 2, or 3",
            ));
        }
        if self.version > 1 && self.password.as_ref().is_none_or(SecretString::is_empty) {
            return Err(PluginManifestError::new(
                "ShadowTLS v2/v3 requires a non-empty password",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestlsOptions {
    pub host: String,
    pub password: SecretString,
    pub restls_script: String,
}

impl RestlsOptions {
    fn validate(&self) -> Result<(), PluginManifestError> {
        validate_plugin_host(&self.host, "Restls host")?;
        if self.password.is_empty() {
            return Err(PluginManifestError::new(
                "Restls requires a non-empty password",
            ));
        }
        validate_restls_script(&self.restls_script)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum KcptunCrypt {
    #[serde(rename = "aes")]
    Aes,
    #[serde(rename = "aes-128")]
    Aes128,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-192")]
    Aes192,
    #[serde(rename = "salsa20")]
    Salsa20,
    #[serde(rename = "blowfish")]
    Blowfish,
    #[serde(rename = "twofish")]
    Twofish,
    #[serde(rename = "cast5")]
    Cast5,
    #[serde(rename = "3des")]
    TripleDes,
    #[serde(rename = "tea")]
    Tea,
    #[serde(rename = "xtea")]
    Xtea,
    #[serde(rename = "xor")]
    Xor,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "null")]
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KcptunMode {
    Fast3,
    Fast2,
    Fast,
    Normal,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KcptunOptions {
    pub key: SecretString,
    pub crypt: KcptunCrypt,
    pub mode: KcptunMode,
    pub mtu: u16,
    pub ratelimit: u32,
    pub sndwnd: u32,
    pub rcvwnd: u32,
    pub datashard: u16,
    pub parityshard: u16,
    pub dscp: u8,
    pub nocomp: bool,
    pub acknodelay: bool,
    pub nodelay: u8,
    pub interval: u16,
    pub resend: u32,
    pub nc: u8,
    pub sockbuf: u32,
    pub smuxver: u8,
    pub smuxbuf: u32,
    pub framesize: u32,
    pub streambuf: u32,
    pub keepalive: u32,
}

impl KcptunOptions {
    fn validate(&self) -> Result<(), PluginManifestError> {
        if self.key.is_empty() {
            return Err(PluginManifestError::new("Kcptun requires a non-empty key"));
        }
        let minimum_mtu = match self.crypt {
            KcptunCrypt::Null => 58,
            KcptunCrypt::Aes128Gcm => 86,
            _ => 78,
        };
        if self.mtu < minimum_mtu || self.mtu > 1500 {
            return Err(PluginManifestError::new(
                "Kcptun mtu is outside the safe runtime range",
            ));
        }
        if self.ratelimit > MAX_KCPTUN_INT
            || self.sndwnd == 0
            || self.sndwnd > MAX_KCPTUN_INT
            || self.rcvwnd == 0
            || self.rcvwnd > MAX_KCPTUN_INT
            || self.resend > MAX_KCPTUN_INT
            || self.sockbuf == 0
            || self.sockbuf > MAX_KCPTUN_INT
            || self.smuxbuf == 0
            || self.smuxbuf > MAX_KCPTUN_INT
            || self.keepalive == 0
            || self.keepalive > MAX_KCPTUN_INT
        {
            return Err(PluginManifestError::new(
                "Kcptun numeric option is outside the 32-bit runtime range",
            ));
        }
        if self.datashard == 0
            || self.parityshard == 0
            || u32::from(self.datashard) + u32::from(self.parityshard) > 256
        {
            return Err(PluginManifestError::new(
                "Kcptun shard configuration is invalid",
            ));
        }
        if self.dscp > 63 {
            return Err(PluginManifestError::new(
                "Kcptun dscp must be between 0 and 63",
            ));
        }
        if !matches!(self.nodelay, 0 | 1) || !matches!(self.nc, 0 | 1) {
            return Err(PluginManifestError::new(
                "Kcptun nodelay and nc must be 0 or 1",
            ));
        }
        if !(10..=5000).contains(&self.interval) {
            return Err(PluginManifestError::new(
                "Kcptun interval must be between 10 and 5000",
            ));
        }
        if !matches!(self.smuxver, 1 | 2) {
            return Err(PluginManifestError::new("Kcptun smuxver must be 1 or 2"));
        }
        if self.framesize == 0 || self.framesize > 65_535 {
            return Err(PluginManifestError::new(
                "Kcptun framesize must be between 1 and 65535",
            ));
        }
        if self.streambuf == 0 || self.streambuf > self.smuxbuf {
            return Err(PluginManifestError::new(
                "Kcptun streambuf must be non-zero and no larger than smuxbuf",
            ));
        }
        Ok(())
    }
}

fn validate_plugin_host(host: &str, field: &'static str) -> Result<(), PluginManifestError> {
    if host.is_empty()
        || host.len() > 255
        || host
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || b"/?#[]".contains(&byte))
    {
        return Err(PluginManifestError::new(field));
    }
    if host.contains(':') && host.parse::<Ipv6Addr>().is_err() {
        return Err(PluginManifestError::new(field));
    }
    Ok(())
}

/// A client certificate is presented during the TLS handshake, so asking for
/// one on a plugin that runs in the clear cannot be honoured. Refusing says so
/// instead of quietly accepting everyone.
fn validate_client_ca(client_ca: &str, tls: bool) -> Result<(), PluginManifestError> {
    if !client_ca.trim().is_empty() && !tls {
        return Err(PluginManifestError::new(
            "plugin client_ca requires TLS on the same plugin",
        ));
    }
    Ok(())
}

/// ECH is a client and server agreement: the client hides the name it is
/// really asking for and the server has to be able to decrypt it. Publishing
/// it to clients while the edge knows nothing about it leaves those clients
/// unable to connect, so a node that asks for it is refused here.
fn validate_ech(ech: Option<&EchOptions>) -> Result<(), PluginManifestError> {
    if ech.is_some_and(EchOptions::is_requested) {
        return Err(PluginManifestError::new(
            "plugin ECH is not supported by this backend",
        ));
    }
    Ok(())
}

/// A certificate without its key, or a key without its certificate, cannot
/// serve anything. Applying half of it would start a listener that fails every
/// handshake, so the generation is refused instead.
fn validate_tls_material(
    certificate: &str,
    private_key: Option<&SecretString>,
) -> Result<(), PluginManifestError> {
    let has_certificate = !certificate.trim().is_empty();
    let has_key = private_key.is_some_and(|key| !key.expose_secret().trim().is_empty());
    if has_certificate != has_key {
        return Err(PluginManifestError::new(
            "plugin TLS needs both a certificate and its private key",
        ));
    }
    Ok(())
}

fn validate_websocket_options(host: &str, path: &str) -> Result<(), PluginManifestError> {
    validate_plugin_host(host, "WebSocket host is invalid")?;
    if path.is_empty()
        || !path.starts_with('/')
        || path.len() > 2048
        || path.contains('#')
        || path.bytes().any(|byte| byte <= 0x1f || byte == 0x7f)
        || has_invalid_percent_encoding(path.as_bytes())
    {
        return Err(PluginManifestError::new("WebSocket path is invalid"));
    }
    Ok(())
}

fn has_invalid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%' {
            if index + 2 >= value.len()
                || !value[index + 1].is_ascii_hexdigit()
                || !value[index + 2].is_ascii_hexdigit()
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn validate_restls_script(script: &str) -> Result<(), PluginManifestError> {
    if script.trim().is_empty() {
        return Ok(());
    }
    let compact: String = script
        .chars()
        .filter(|character| *character != ' ')
        .collect();
    for instruction in compact.split(',') {
        if instruction.is_empty() {
            return Err(PluginManifestError::new("Restls script is invalid"));
        }
        let (record_part, responses) = match instruction.split_once('<') {
            Some((record, responses)) if !record.is_empty() && !responses.is_empty() => {
                if responses.contains('<') {
                    return Err(PluginManifestError::new("Restls script is invalid"));
                }
                (record, parse_decimal(responses)?)
            }
            Some(_) => return Err(PluginManifestError::new("Restls script is invalid")),
            None => (instruction, 0),
        };
        let range_separator = record_part
            .char_indices()
            .find(|(_, character)| matches!(character, '~' | '?'));
        let (target, range) = match range_separator {
            Some((index, _)) => {
                let target = &record_part[..index];
                let range = &record_part[index + 1..];
                if target.is_empty()
                    || range.is_empty()
                    || range.contains('~')
                    || range.contains('?')
                {
                    return Err(PluginManifestError::new("Restls script is invalid"));
                }
                (parse_decimal(target)?, parse_decimal(range)?)
            }
            None => (parse_decimal(record_part)?, 0),
        };
        let last_target = target
            .checked_add(range.saturating_sub(1))
            .ok_or_else(|| PluginManifestError::new("Restls script is invalid"))?;
        if last_target > MAX_RESTLS_RECORD_TARGET || responses > MAX_RESTLS_RESPONSES {
            // The panel accepts a wider script range and gates those Profiles on
            // the `shadowsocks-plugin-restls-v2` feature, which this backend does
            // not advertise. Say so instead of reporting a generic limit.
            return Err(PluginManifestError::new(
                "Restls script exceeds the v1-safe range this backend implements \
                 (record target 16364, responses 127); that Profile requires a \
                 shadowsocks-plugin-restls-v2 backend",
            ));
        }
    }
    Ok(())
}

fn parse_decimal(value: &str) -> Result<u64, PluginManifestError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PluginManifestError::new("Restls script is invalid"));
    }
    value
        .parse()
        .map_err(|_| PluginManifestError::new("Restls script is invalid"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AppliedFeature {
    #[serde(rename = "shadowsocks-uot-v1")]
    UotV1,
    #[serde(rename = "shadowsocks-uot-v2")]
    UotV2,
    #[serde(rename = "shadowsocks-sing-mux-v1")]
    SingMuxV1,
    #[serde(rename = "shadowsocks-plugin-runtime-v1")]
    PluginRuntimeV1,
    #[serde(rename = "shadowsocks-plugin-obfs-v1")]
    PluginObfsV1,
    #[serde(rename = "shadowsocks-plugin-v2ray-v1")]
    PluginV2rayV1,
    #[serde(rename = "shadowsocks-plugin-gost-v1")]
    PluginGostV1,
    #[serde(rename = "shadowsocks-plugin-shadow-tls-v1")]
    PluginShadowTlsV1,
    #[serde(rename = "shadowsocks-plugin-restls-v1")]
    PluginRestlsV1,
    #[serde(rename = "shadowsocks-plugin-kcptun-v1")]
    PluginKcptunV1,
}

impl AppliedFeature {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UotV1 => FEATURE_UOT_V1,
            Self::UotV2 => FEATURE_UOT_V2,
            Self::SingMuxV1 => FEATURE_SING_MUX_V1,
            Self::PluginRuntimeV1 => FEATURE_PLUGIN_RUNTIME_V1,
            Self::PluginObfsV1 => FEATURE_PLUGIN_OBFS_V1,
            Self::PluginV2rayV1 => FEATURE_PLUGIN_V2RAY_V1,
            Self::PluginGostV1 => FEATURE_PLUGIN_GOST_V1,
            Self::PluginShadowTlsV1 => FEATURE_PLUGIN_SHADOW_TLS_V1,
            Self::PluginRestlsV1 => FEATURE_PLUGIN_RESTLS_V1,
            Self::PluginKcptunV1 => FEATURE_PLUGIN_KCPTUN_V1,
        }
    }

    fn plugin_kind(self) -> Option<PluginKind> {
        match self {
            Self::PluginObfsV1 => Some(PluginKind::Obfs),
            Self::PluginV2rayV1 => Some(PluginKind::V2ray),
            Self::PluginGostV1 => Some(PluginKind::Gost),
            Self::PluginShadowTlsV1 => Some(PluginKind::ShadowTls),
            Self::PluginRestlsV1 => Some(PluginKind::Restls),
            Self::PluginKcptunV1 => Some(PluginKind::Kcptun),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum PluginConfigObserved {
    NotModified { etag: OpaqueEtag },
    Candidate(PluginConfigCandidate),
}

#[derive(Debug, Clone)]
pub struct PluginConfigCandidate {
    etag: OpaqueEtag,
    manifest: PluginRuntimeManifest,
    wire_manifest: Option<Value>,
}

impl PluginConfigCandidate {
    pub fn new(
        etag: OpaqueEtag,
        manifest: PluginRuntimeManifest,
        expected_node_id: u64,
    ) -> Result<Self, PluginManifestError> {
        manifest.validate(expected_node_id)?;
        Ok(Self {
            etag,
            manifest,
            wire_manifest: None,
        })
    }

    pub fn from_wire(
        etag: OpaqueEtag,
        wire_manifest: Value,
        expected_node_id: u64,
    ) -> Result<Self, PluginApiError> {
        let manifest = serde_json::from_value::<PluginRuntimeManifest>(wire_manifest.clone())
            .map_err(|_| {
                PluginApiError::InvalidResponse(
                    unimplemented_plugin_type_reason(&wire_manifest).unwrap_or(
                        "plugin-config JSON does not match the strict schema v1 manifest",
                    ),
                )
            })?;
        manifest
            .validate(expected_node_id)
            .map_err(PluginApiError::InvalidManifest)?;
        Ok(Self {
            etag,
            manifest,
            wire_manifest: Some(wire_manifest),
        })
    }

    pub fn etag(&self) -> &OpaqueEtag {
        &self.etag
    }

    pub fn manifest(&self) -> &PluginRuntimeManifest {
        &self.manifest
    }

    pub fn wire_manifest(&self) -> Option<&Value> {
        self.wire_manifest.as_ref()
    }

    pub fn revision(&self) -> &ConfigRevision {
        &self.manifest.config_revision
    }

    pub fn mark_applied(
        self,
        features: impl IntoIterator<Item = AppliedFeature>,
    ) -> Result<PluginConfigApplied, PluginManifestError> {
        let mut seen = HashSet::new();
        let mut features = features
            .into_iter()
            .filter(|feature| seen.insert(*feature))
            .collect::<Vec<_>>();
        features.sort_by_key(|feature| feature.as_str());
        if features.len() > MAX_FEATURES {
            return Err(PluginManifestError::new(
                "applied feature list exceeds the V2Board limit",
            ));
        }
        if !features.contains(&AppliedFeature::PluginRuntimeV1) {
            return Err(PluginManifestError::new(
                "an applied plugin runtime must advertise its runtime feature",
            ));
        }

        let active_kind = self.manifest.plugin.as_ref().map(RuntimePlugin::kind);
        if let Some(kind) = active_kind
            && !features.contains(&kind.adapter_feature())
        {
            return Err(PluginManifestError::new(
                "the active plugin adapter feature is missing",
            ));
        }
        if features
            .iter()
            .filter_map(|feature| feature.plugin_kind())
            .any(|kind| Some(kind) != active_kind)
        {
            return Err(PluginManifestError::new(
                "applied features contain an adapter that is not active",
            ));
        }

        Ok(PluginConfigApplied {
            candidate: self,
            features,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PluginConfigApplied {
    candidate: PluginConfigCandidate,
    features: Vec<AppliedFeature>,
}

impl PluginConfigApplied {
    pub fn candidate(&self) -> &PluginConfigCandidate {
        &self.candidate
    }

    pub fn manifest(&self) -> &PluginRuntimeManifest {
        self.candidate.manifest()
    }

    pub fn revision(&self) -> &ConfigRevision {
        self.candidate.revision()
    }

    pub fn features(&self) -> &[AppliedFeature] {
        &self.features
    }

    pub fn status_report(
        &self,
        version: impl Into<String>,
    ) -> Result<PluginStatusReport, PluginManifestError> {
        PluginStatusReport::ready(self.revision().clone(), self.features.clone(), version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginStatusReport {
    ready: bool,
    applied_revision: String,
    applied_features: Vec<AppliedFeature>,
    version: String,
}

impl PluginStatusReport {
    fn ready(
        revision: ConfigRevision,
        features: Vec<AppliedFeature>,
        version: impl Into<String>,
    ) -> Result<Self, PluginManifestError> {
        let version = validate_backend_version(version.into())?;
        Ok(Self {
            ready: true,
            applied_revision: revision.as_str().to_string(),
            applied_features: features,
            version,
        })
    }

    pub fn not_ready(version: impl Into<String>) -> Result<Self, PluginManifestError> {
        let version = validate_backend_version(version.into())?;
        Ok(Self {
            ready: false,
            applied_revision: String::new(),
            applied_features: Vec::new(),
            version,
        })
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn applied_revision(&self) -> &str {
        &self.applied_revision
    }

    pub fn applied_features(&self) -> &[AppliedFeature] {
        &self.applied_features
    }
}

fn validate_backend_version(version: String) -> Result<String, PluginManifestError> {
    if version.len() > MAX_VERSION_BYTES {
        return Err(PluginManifestError::new(
            "backend version exceeds the V2Board limit",
        ));
    }
    Ok(version)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifestError {
    reason: &'static str,
}

impl PluginManifestError {
    const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for PluginManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl Error for PluginManifestError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginTransportErrorKind {
    Timeout,
    Connect,
    Request,
    ResponseBody,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginApiError {
    UnsupportedNodeType,
    Transport(PluginTransportErrorKind),
    ResponseTooLarge {
        endpoint: &'static str,
        limit: usize,
    },
    InvalidResponse(&'static str),
    InvalidManifest(PluginManifestError),
    HttpStatus {
        status: u16,
        code: Option<String>,
    },
    RevisionMismatch {
        desired_revision: Option<ConfigRevision>,
    },
}

impl fmt::Display for PluginApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedNodeType => {
                f.write_str("the V2Board plugin API only supports Shadowsocks nodes")
            }
            Self::Transport(kind) => write!(f, "V2Board plugin API transport failure: {kind:?}"),
            Self::ResponseTooLarge { endpoint, limit } => {
                write!(f, "V2Board {endpoint} response exceeds {limit} bytes")
            }
            Self::InvalidResponse(reason) => {
                write!(f, "invalid V2Board plugin API response: {reason}")
            }
            Self::InvalidManifest(error) => write!(f, "invalid plugin-config manifest: {error}"),
            Self::HttpStatus { status, code } => match code {
                Some(code) => write!(f, "V2Board plugin API returned HTTP {status} ({code})"),
                None => write!(f, "V2Board plugin API returned HTTP {status}"),
            },
            Self::RevisionMismatch { .. } => {
                f.write_str("V2Board rejected a stale applied config revision")
            }
        }
    }
}

impl Error for PluginApiError {}

impl From<PluginManifestError> for PluginApiError {
    fn from(value: PluginManifestError) -> Self {
        Self::InvalidManifest(value)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const REVISION: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn base_manifest(plugin: Value) -> Value {
        json!({
            "schema_version": 1,
            "node_type": "shadowsocks",
            "node_id": 12,
            "server_port": 8388,
            "cipher": "aes-128-gcm",
            "server_key": null,
            "obfs": null,
            "obfs_settings": null,
            "multiplex": {
                "enabled": false,
                "padding": false,
                "brutal": {
                    "enabled": false,
                    "up_mbps": 0,
                    "down_mbps": 0
                }
            },
            "plugin": plugin,
            "routes": [],
            "config_revision": REVISION,
            "base_config": {
                "push_interval": 60,
                "pull_interval": 60,
                "node_report_min_traffic": 0,
                "device_online_min_traffic": 0
            }
        })
    }

    fn plugin(plugin_type: &str, options: Value) -> Value {
        json!({
            "type": plugin_type,
            "listen_port": 443,
            "upstream": {"host": "127.0.0.1", "port": 8388},
            "options": options
        })
    }

    /// A client certificate is presented during the TLS handshake, so asking
    /// for one on a plugin serving cleartext cannot be honoured -- and
    /// accepting it quietly would leave the operator believing the node
    /// authenticates its clients when it cannot.
    #[test]
    fn a_client_ca_without_tls_is_refused() {
        let with_tls = parse(base_manifest(plugin(
            "gost-plugin",
            json!({
                "mode": "websocket", "host": "gost.example", "path": "/gost",
                "tls": true, "mux": true,
                "client_ca": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
            }),
        )))
        .expect("the manifest parses");
        assert!(
            with_tls.validate(12).is_ok(),
            "a client CA belongs on a TLS plugin"
        );

        let error = parse(base_manifest(plugin(
            "gost-plugin",
            json!({
                "mode": "websocket", "host": "gost.example", "path": "/gost",
                "tls": false, "mux": true,
                "client_ca": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
            }),
        )))
        .expect("the manifest parses")
        .validate(12)
        .expect_err("a client CA without TLS must be refused");
        assert!(error.to_string().contains("client_ca"));
    }

    /// ECH needs the server to decrypt what the client hid. Serving a node
    /// that publishes it would hand its clients a handshake this edge cannot
    /// answer, so the generation is refused -- and a node that merely carries
    /// the panel's empty defaults is not asking for anything.
    #[test]
    fn a_node_asking_for_ech_is_refused() {
        let quiet = parse(base_manifest(plugin(
            "gost-plugin",
            json!({
                "mode": "websocket", "host": "gost.example", "path": "/gost",
                "tls": false, "mux": true,
                "ech_opts": {"enable": false, "config": "", "query_server_name": ""}
            }),
        )));
        assert!(
            quiet.is_ok(),
            "an unused ech_opts block must not fail a node"
        );

        for asking in [
            json!({"enable": true, "config": "", "query_server_name": ""}),
            json!({"enable": false, "config": "AEX+DQBB", "query_server_name": ""}),
        ] {
            let manifest = base_manifest(plugin(
                "gost-plugin",
                json!({
                    "mode": "websocket", "host": "gost.example", "path": "/gost",
                    "tls": false, "mux": true, "ech_opts": asking
                }),
            ));
            let error = parse(manifest)
                .expect("the manifest parses")
                .validate(12)
                .expect_err("a node asking for ECH must be refused");
            assert!(error.to_string().contains("ECH"));
        }
    }

    /// A panel that predates the switch means "keep enforcing the host", and
    /// one that sends it means what it says.
    #[test]
    fn the_host_check_is_on_unless_the_panel_turns_it_off() {
        let without = parse(base_manifest(plugin(
            "gost-plugin",
            json!({
                "mode": "websocket",
                "host": "gost.example",
                "path": "/gost",
                "tls": false,
                "mux": true
            }),
        )))
        .unwrap();
        let Some(RuntimePlugin::Gost { options, .. }) = &without.plugin else {
            panic!("expected a gost plugin");
        };
        assert!(!options.allow_unknown_host);

        let with = parse(base_manifest(plugin(
            "gost-plugin",
            json!({
                "mode": "websocket",
                "host": "gost.example",
                "path": "/gost",
                "tls": false,
                "mux": true,
                "allow_unknown_host": true
            }),
        )))
        .unwrap();
        let Some(RuntimePlugin::Gost { options, .. }) = &with.plugin else {
            panic!("expected a gost plugin");
        };
        assert!(options.allow_unknown_host);
    }

    fn parse(value: Value) -> Result<PluginRuntimeManifest, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn from_wire_error(manifest: Value) -> String {
        PluginConfigCandidate::from_wire(OpaqueEtag::from_static("\"candidate\""), manifest, 12)
            .expect_err("manifest must be rejected")
            .to_string()
    }

    #[test]
    fn an_unimplemented_multiplex_protocol_is_refused_rather_than_applied() {
        // The protocol is server-effective: both ends have to speak the same
        // one. Applying a manifest that names one this backend does not
        // implement produces a node that acknowledges its revision, publishes,
        // and then carries nothing.
        let with_protocol = |protocol: Value, enabled: bool| {
            let mut manifest =
                base_manifest(plugin("obfs", json!({"mode": "tls", "host": "c.example"})));
            manifest["multiplex"] = json!({
                "enabled": enabled,
                "padding": false,
                "protocol": protocol,
                "brutal": {"enabled": false, "up_mbps": 0, "down_mbps": 0}
            });
            manifest
        };

        let manifest = parse(with_protocol(json!("h2mux"), true)).expect("h2mux is implemented");
        assert!(manifest.validate(12).is_ok());

        let error = parse(with_protocol(json!("smux"), true))
            .expect("an unknown protocol still decodes")
            .validate(12)
            .expect_err("smux is not implemented here");
        assert!(error.reason().contains("h2mux"), "{}", error.reason());

        // Absent means the panel predates the field, when h2mux was the only
        // protocol in play.
        let mut legacy = base_manifest(plugin("obfs", json!({"mode": "tls", "host": "c.example"})));
        legacy["multiplex"] = json!({
            "enabled": true,
            "padding": false,
            "brutal": {"enabled": false, "up_mbps": 0, "down_mbps": 0}
        });
        let manifest = parse(legacy).expect("a manifest without the field still decodes");
        assert!(manifest.validate(12).is_ok());

        // Nothing is multiplexed when it is off, so the name does not matter.
        let manifest = parse(with_protocol(json!("yamux"), false)).expect("decodes");
        assert!(manifest.validate(12).is_ok());
    }

    #[test]
    fn rejecting_a_plugin_without_an_adapter_names_the_plugin_type() {
        let message = from_wire_error(base_manifest(plugin(
            "jls",
            json!({
                "host": "cover.example",
                "username": "jls-user",
                "password": "jls-password",
                "alpn": ["h2", "http/1.1"]
            }),
        )));
        assert!(message.contains("JLS"), "{message}");
        assert!(message.contains("last-known-good"), "{message}");
        assert!(!message.contains("jls-password"), "{message}");

        let message = from_wire_error(base_manifest(plugin(
            "brand-new-plugin",
            json!({"host": "cover.example"}),
        )));
        assert!(message.contains("does not implement"), "{message}");
    }

    #[test]
    fn rejecting_a_malformed_supported_plugin_keeps_the_schema_reason() {
        // `obfs` has an adapter, so a bad payload is a schema problem and must
        // not be reported as a missing adapter.
        let message = from_wire_error(base_manifest(plugin("obfs", json!({"mode": "tls"}))));
        assert!(message.contains("strict schema v1 manifest"), "{message}");
        assert!(!message.contains("does not implement"), "{message}");
    }

    #[test]
    fn a_restls_script_beyond_the_v1_safe_range_points_at_restls_v2() {
        let message = from_wire_error(base_manifest(plugin(
            "restls",
            json!({
                "host": "cover.example",
                "password": "restls-password",
                "restls_script": "16365"
            }),
        )));
        assert!(
            message.contains("shadowsocks-plugin-restls-v2"),
            "{message}"
        );
        assert!(!message.contains("restls-password"), "{message}");
    }

    #[test]
    fn accepts_all_six_strict_runtime_plugins() {
        let cases = [
            plugin("obfs", json!({"mode": "tls", "host": "cover.example"})),
            plugin(
                "v2ray-plugin",
                json!({
                    "mode": "websocket",
                    "host": "v2ray.example",
                    "path": "/v2ray",
                    "tls": true,
                    "mux": false,
                    "v2ray_http_upgrade": true
                }),
            ),
            plugin(
                "gost-plugin",
                json!({
                    "mode": "websocket",
                    "host": "gost.example",
                    "path": "/gost",
                    "tls": true,
                    "mux": true
                }),
            ),
            plugin(
                "shadow-tls",
                json!({
                    "host": "shadow.example",
                    "version": 3,
                    "password": "shadow-secret"
                }),
            ),
            plugin(
                "restls",
                json!({
                    "host": "restls.example",
                    "password": "restls-secret",
                    "restls_script": "300?100<1"
                }),
            ),
            plugin(
                "kcptun",
                json!({
                    "key": "kcptun-secret",
                    "crypt": "aes",
                    "mode": "fast",
                    "mtu": 1350,
                    "ratelimit": 0,
                    "sndwnd": 128,
                    "rcvwnd": 512,
                    "datashard": 10,
                    "parityshard": 3,
                    "dscp": 0,
                    "nocomp": false,
                    "acknodelay": false,
                    "nodelay": 0,
                    "interval": 50,
                    "resend": 0,
                    "nc": 0,
                    "sockbuf": 4194304,
                    "smuxver": 1,
                    "smuxbuf": 4194304,
                    "framesize": 8192,
                    "streambuf": 2097152,
                    "keepalive": 10
                }),
            ),
        ];

        for plugin in cases {
            let manifest = parse(base_manifest(plugin)).unwrap();
            manifest.validate(12).unwrap();
        }
    }

    #[test]
    fn rejects_unknown_or_missing_fields_in_manifest_and_options() {
        let mut unknown_top = base_manifest(Value::Null);
        unknown_top["unexpected"] = json!(true);
        assert!(parse(unknown_top).is_err());

        let missing_plugin = {
            let mut value = base_manifest(Value::Null);
            value.as_object_mut().unwrap().remove("plugin");
            value
        };
        assert!(parse(missing_plugin).is_err());

        let unknown_option = base_manifest(plugin(
            "obfs",
            json!({"mode": "http", "host": "cover.example", "path": "/forbidden"}),
        ));
        assert!(parse(unknown_option).is_err());

        let unknown_schema = {
            let mut value = base_manifest(Value::Null);
            value["schema_version"] = json!(2);
            value
        };
        assert!(parse(unknown_schema).is_err());
    }

    #[test]
    fn validates_plugin_specific_ranges_and_relationships() {
        let bad_shadow_tls = parse(base_manifest(plugin(
            "shadow-tls",
            json!({"host": "shadow.example", "version": 3}),
        )))
        .unwrap();
        assert!(bad_shadow_tls.validate(12).is_err());

        let bad_upgrade = parse(base_manifest(plugin(
            "v2ray-plugin",
            json!({
                "mode": "websocket",
                "host": "v2ray.example",
                "path": "/v2ray",
                "tls": false,
                "mux": true,
                "v2ray_http_upgrade": true
            }),
        )))
        .unwrap();
        assert!(bad_upgrade.validate(12).is_err());

        let bad_restls = parse(base_manifest(plugin(
            "restls",
            json!({
                "host": "restls.example",
                "password": "secret",
                "restls_script": "16365"
            }),
        )))
        .unwrap();
        assert!(bad_restls.validate(12).is_err());

        let mut bad_upstream = base_manifest(plugin(
            "obfs",
            json!({"mode": "http", "host": "cover.example"}),
        ));
        bad_upstream["plugin"]["upstream"]["host"] = json!("0.0.0.0");
        assert!(parse(bad_upstream).unwrap().validate(12).is_err());
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let manifest = parse(base_manifest(plugin(
            "shadow-tls",
            json!({
                "host": "shadow.example",
                "version": 3,
                "password": "must-not-leak"
            }),
        )))
        .unwrap();
        let output = format!("{manifest:?}");
        assert!(!output.contains("must-not-leak"));
        assert!(output.contains("[REDACTED]"));
    }

    #[test]
    fn candidate_and_applied_types_enforce_exact_adapter_ack() {
        let manifest = parse(base_manifest(plugin(
            "gost-plugin",
            json!({
                "mode": "websocket",
                "host": "gost.example",
                "path": "/gost",
                "tls": true,
                "mux": false
            }),
        )))
        .unwrap();
        let candidate =
            PluginConfigCandidate::new(OpaqueEtag::from_static("\"opaque-etag\""), manifest, 12)
                .unwrap();

        assert!(
            candidate
                .clone()
                .mark_applied([
                    AppliedFeature::PluginRuntimeV1,
                    AppliedFeature::PluginObfsV1
                ])
                .is_err()
        );
        let applied = candidate
            .mark_applied([
                AppliedFeature::PluginRuntimeV1,
                AppliedFeature::PluginGostV1,
                AppliedFeature::UotV2,
            ])
            .unwrap();
        let report = applied.status_report("shoes-test").unwrap();
        let wire = serde_json::to_value(report).unwrap();
        assert_eq!(wire["ready"], true);
        assert_eq!(wire["applied_revision"], REVISION);
        assert_eq!(
            wire["applied_features"],
            json!([
                "shadowsocks-plugin-gost-v1",
                "shadowsocks-plugin-runtime-v1",
                "shadowsocks-uot-v2"
            ])
        );
    }

    #[test]
    fn plugin_null_requires_only_the_runtime_feature() {
        let manifest = parse(base_manifest(Value::Null)).unwrap();
        let candidate =
            PluginConfigCandidate::new(OpaqueEtag::from_static("W/\"opaque-etag\""), manifest, 12)
                .unwrap();
        assert!(
            candidate
                .clone()
                .mark_applied([
                    AppliedFeature::PluginRuntimeV1,
                    AppliedFeature::PluginObfsV1,
                ])
                .is_err()
        );
        candidate
            .mark_applied([AppliedFeature::PluginRuntimeV1])
            .unwrap();
    }

    #[test]
    fn not_ready_report_clears_revision_and_features() {
        let report = PluginStatusReport::not_ready("shoes-test").unwrap();
        let wire = serde_json::to_value(report).unwrap();
        assert_eq!(wire["ready"], false);
        assert_eq!(wire["applied_revision"], "");
        assert_eq!(wire["applied_features"], json!([]));
    }
}
