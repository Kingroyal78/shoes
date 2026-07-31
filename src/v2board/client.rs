use reqwest::StatusCode;
use reqwest::header::{ACCEPT, CONTENT_TYPE, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH};

use crate::backend_config::{AppConfig, NodeType, V2BoardNodeConfig};

use super::plugin_api::{
    ConfigRevision, OpaqueEtag, PluginApiError, PluginConfigCandidate, PluginConfigObserved,
    PluginStatusReport, PluginTransportErrorKind,
};
use super::types::{AliveList, AlivePayload, ServerConfig, TrafficPayload, UserList};

#[derive(Clone)]
pub struct V2BoardClient {
    http: reqwest::Client,
    error_body_limit: usize,
    user_list_body_limit: usize,
}

pub enum FetchResult<T> {
    NotModified,
    Updated { etag: Option<String>, value: T },
}

impl V2BoardClient {
    pub fn new(config: &AppConfig) -> std::io::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.api_timeout())
            .use_rustls_tls()
            .build()
            .map_err(|e| std::io::Error::other(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            http,
            error_body_limit: config.v2board.error_body_limit_bytes,
            user_list_body_limit: config.v2board.user_list_body_limit_bytes,
        })
    }

    pub async fn get_server_config(
        &self,
        app_config: &AppConfig,
        node: &V2BoardNodeConfig,
        etag: Option<&str>,
    ) -> std::io::Result<FetchResult<ServerConfig>> {
        let request = self
            .http
            .get(Self::config_endpoint(app_config, node))
            .query(&Self::config_query(app_config, node));
        let request = add_etag(request, etag);
        let response = request.send().await.map_err(http_error)?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(FetchResult::NotModified);
        }

        let response = self.ensure_success(response).await?;
        let etag = response_etag(response.headers());
        let value = response.json::<ServerConfig>().await.map_err(http_error)?;
        Ok(FetchResult::Updated { etag, value })
    }

    pub async fn get_user_list(
        &self,
        app_config: &AppConfig,
        node: &V2BoardNodeConfig,
        etag: Option<&str>,
    ) -> std::io::Result<FetchResult<UserList>> {
        let request = self
            .http
            .get(Self::endpoint(app_config, node, "user"))
            .query(&Self::query(app_config, node))
            .header("X-Response-Format", "msgpack")
            .header(ACCEPT, "application/x-msgpack, application/json");
        let request = add_etag(request, etag);
        let response = request.send().await.map_err(http_error)?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(FetchResult::NotModified);
        }

        let response = self.ensure_success(response).await?;
        let etag = response_etag(response.headers());
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let bytes = response.bytes().await.map_err(http_error).and_then(|b| {
            if b.len() > self.user_list_body_limit {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "user list response exceeds configured limit: {} > {}",
                        b.len(),
                        self.user_list_body_limit
                    ),
                ))
            } else {
                Ok(b)
            }
        })?;

        let value = if content_type.contains("msgpack") {
            rmp_serde::from_slice::<UserList>(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to decode msgpack user list: {e}"),
                )
            })?
        } else {
            serde_json::from_slice::<UserList>(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to decode JSON user list: {e}"),
                )
            })?
        };

        Ok(FetchResult::Updated { etag, value })
    }

    pub async fn get_alive_list(
        &self,
        app_config: &AppConfig,
        node: &V2BoardNodeConfig,
    ) -> std::io::Result<AliveList> {
        let response = self
            .http
            .get(Self::endpoint(app_config, node, "alivelist"))
            .query(&Self::query(app_config, node))
            .send()
            .await
            .map_err(http_error)?;
        let response = self.ensure_success(response).await?;
        response.json::<AliveList>().await.map_err(http_error)
    }

    pub async fn push_traffic(
        &self,
        app_config: &AppConfig,
        node: &V2BoardNodeConfig,
        payload: &TrafficPayload,
    ) -> std::io::Result<()> {
        let response = self
            .http
            .post(Self::endpoint(app_config, node, "push"))
            .query(&Self::query(app_config, node))
            .json(payload)
            .send()
            .await
            .map_err(http_error)?;
        self.ensure_success(response).await.map(|_| ())
    }

    pub async fn push_alive(
        &self,
        app_config: &AppConfig,
        node: &V2BoardNodeConfig,
        payload: &AlivePayload,
    ) -> std::io::Result<()> {
        let response = self
            .http
            .post(Self::endpoint(app_config, node, "alive"))
            .query(&Self::query(app_config, node))
            .json(payload)
            .send()
            .await
            .map_err(http_error)?;
        self.ensure_success(response).await.map(|_| ())
    }

    pub async fn get_plugin_config(
        &self,
        app_config: &AppConfig,
        node: &V2BoardNodeConfig,
        etag: Option<&OpaqueEtag>,
    ) -> Result<PluginConfigObserved, PluginApiError> {
        ensure_shadowsocks_node(node)?;
        let mut request = self
            .http
            .get(Self::endpoint(app_config, node, "plugin-config"))
            .query(&Self::query(app_config, node));
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, etag.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(classify_plugin_transport_error)?;

        if response.status() == StatusCode::NOT_MODIFIED {
            let response_etag = response
                .headers()
                .get(ETAG)
                .map(OpaqueEtag::from_header)
                .transpose()?;
            let response_etag = match (response_etag, etag) {
                (Some(response_etag), Some(request_etag)) => {
                    if response_etag != *request_etag {
                        return Err(PluginApiError::InvalidResponse(
                            "HTTP 304 returned an ETag different from the request validator",
                        ));
                    }
                    response_etag
                }
                (None, Some(request_etag)) => request_etag.clone(),
                (Some(_), None) | (None, None) => {
                    return Err(PluginApiError::InvalidResponse(
                        "received HTTP 304 without a prior ETag",
                    ));
                }
            };
            return Ok(PluginConfigObserved::NotModified {
                etag: response_etag,
            });
        }

        if !response.status().is_success() {
            return Err(self.plugin_http_error(response).await);
        }
        let etag = response
            .headers()
            .get(ETAG)
            .ok_or(PluginApiError::InvalidResponse(
                "plugin-config response is missing ETag",
            ))
            .and_then(OpaqueEtag::from_header)?;
        let bytes =
            read_plugin_body_limited(response, self.user_list_body_limit, "plugin-config").await?;
        let manifest = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_| {
            PluginApiError::InvalidResponse(
                "plugin-config JSON does not match the strict schema v1 manifest",
            )
        })?;
        let candidate = PluginConfigCandidate::from_wire(etag, manifest, node.node_id)?;
        Ok(PluginConfigObserved::Candidate(candidate))
    }

    pub async fn post_plugin_status(
        &self,
        app_config: &AppConfig,
        node: &V2BoardNodeConfig,
        status: &PluginStatusReport,
    ) -> Result<(), PluginApiError> {
        ensure_shadowsocks_node(node)?;
        let response = self
            .http
            .post(Self::endpoint(app_config, node, "status"))
            .query(&Self::query(app_config, node))
            .json(status)
            .send()
            .await
            .map_err(classify_plugin_transport_error)?;

        if response.status() == StatusCode::CONFLICT {
            let metadata = read_plugin_error_metadata(response, self.error_body_limit).await;
            return Err(PluginApiError::RevisionMismatch {
                desired_revision: metadata.desired_revision,
            });
        }
        if !response.status().is_success() {
            return Err(self.plugin_http_error(response).await);
        }
        Ok(())
    }

    async fn plugin_http_error(&self, response: reqwest::Response) -> PluginApiError {
        let status = response.status().as_u16();
        let metadata = read_plugin_error_metadata(response, self.error_body_limit).await;
        PluginApiError::HttpStatus {
            status,
            code: metadata.code,
        }
    }

    async fn ensure_success(
        &self,
        response: reqwest::Response,
    ) -> std::io::Result<reqwest::Response> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        Err(std::io::Error::other(format!(
            "V2Board API returned HTTP {status}"
        )))
    }

    fn endpoint(app_config: &AppConfig, node: &V2BoardNodeConfig, resource: &str) -> String {
        let api_host = app_config.effective_api_host(node).trim_end_matches('/');
        format!("{api_host}/api/v1/server/UniProxy/{resource}")
    }

    fn config_endpoint(app_config: &AppConfig, node: &V2BoardNodeConfig) -> String {
        let api_host = app_config.effective_api_host(node).trim_end_matches('/');
        if node.node_type.uses_v2_config_api() {
            format!("{api_host}/api/v2/server/config")
        } else {
            format!("{api_host}/api/v1/server/UniProxy/config")
        }
    }

    fn config_query<'a>(
        app_config: &'a AppConfig,
        node: &'a V2BoardNodeConfig,
    ) -> Vec<(&'static str, String)> {
        if node.node_type.uses_v2_config_api() {
            vec![
                ("token", app_config.effective_api_key(node).to_string()),
                ("node_id", node.node_id.to_string()),
            ]
        } else {
            Self::query(app_config, node)
        }
    }

    fn query<'a>(
        app_config: &'a AppConfig,
        node: &'a V2BoardNodeConfig,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("token", app_config.effective_api_key(node).to_string()),
            ("node_id", node.node_id.to_string()),
            ("node_type", node.node_type.as_uniproxy().to_string()),
        ]
    }
}

fn add_etag(request: reqwest::RequestBuilder, etag: Option<&str>) -> reqwest::RequestBuilder {
    match etag.and_then(|v| HeaderValue::from_str(v).ok()) {
        Some(v) => request.header(IF_NONE_MATCH, v),
        None => request,
    }
}

fn response_etag(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(normalize_etag)
        .filter(|v| !v.is_empty())
}

fn normalize_etag(value: &str) -> String {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

fn http_error(err: reqwest::Error) -> std::io::Error {
    // Reqwest attaches the complete request URL to transport and body errors.
    // V2Board authenticates with a query-string token, so displaying that URL
    // would leak the server credential into routine controller logs.
    std::io::Error::other(err.without_url().to_string())
}

fn ensure_shadowsocks_node(node: &V2BoardNodeConfig) -> Result<(), PluginApiError> {
    if node.node_type == NodeType::Shadowsocks {
        Ok(())
    } else {
        Err(PluginApiError::UnsupportedNodeType)
    }
}

fn classify_plugin_transport_error(error: reqwest::Error) -> PluginApiError {
    let kind = if error.is_timeout() {
        PluginTransportErrorKind::Timeout
    } else if error.is_connect() {
        PluginTransportErrorKind::Connect
    } else if error.is_request() {
        PluginTransportErrorKind::Request
    } else if error.is_body() || error.is_decode() {
        PluginTransportErrorKind::ResponseBody
    } else {
        PluginTransportErrorKind::Other
    };
    PluginApiError::Transport(kind)
}

async fn read_plugin_body_limited(
    mut response: reqwest::Response,
    limit: usize,
    endpoint: &'static str,
) -> Result<Vec<u8>, PluginApiError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(PluginApiError::ResponseTooLarge { endpoint, limit });
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(limit),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(classify_plugin_transport_error)?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(PluginApiError::ResponseTooLarge { endpoint, limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Default)]
struct PluginErrorMetadata {
    code: Option<String>,
    desired_revision: Option<ConfigRevision>,
}

async fn read_plugin_error_metadata(
    response: reqwest::Response,
    limit: usize,
) -> PluginErrorMetadata {
    let Ok(body) = read_plugin_body_limited(response, limit, "error").await else {
        return PluginErrorMetadata::default();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return PluginErrorMetadata::default();
    };
    let code = value
        .get("code")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .map(str::to_string);
    let desired_revision = value
        .get("desired_revision")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| ConfigRevision::parse(value.to_string()).ok());
    PluginErrorMetadata {
        code,
        desired_revision,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::backend_config::{
        LogConfig, NodeType, RuntimeConfig, V2BoardConfig, V2BoardNodeConfig,
    };
    use crate::v2board::plugin_api::PluginConfigObserved;

    const REVISION: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn app_and_node(node_type: NodeType) -> (AppConfig, V2BoardNodeConfig) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let node = V2BoardNodeConfig {
            tag: "node-a".to_string(),
            node_id: 42,
            node_type,
            listen: None,
            api_host: None,
            api_key: None,
            pull_interval_secs: None,
            push_interval_secs: None,
            tls: None,
            trojan_fallback: None,
            hysteria2_masquerade: None,
        };
        let app = AppConfig {
            v2board: V2BoardConfig {
                api_host: "https://panel.example.test/".to_string(),
                api_key: "global-token".to_string(),
                api_timeout_secs: 5,
                error_body_limit_bytes: 1024,
                user_list_body_limit_bytes: 2048,
                route_rule_sets: Default::default(),
                nodes: vec![node.clone()],
            },
            runtime: RuntimeConfig::default(),
            tls: None,
            log: LogConfig::default(),
            outbounds: Vec::new(),
            default_out: None,
            route_rules: Vec::new(),
            rule_providers: Vec::new(),
        };
        (app, node)
    }

    #[test]
    fn v2node_config_uses_v2_api_without_node_type_query() {
        let (app, node) = app_and_node(NodeType::V2Node);

        assert_eq!(
            V2BoardClient::config_endpoint(&app, &node),
            "https://panel.example.test/api/v2/server/config"
        );
        assert_eq!(
            V2BoardClient::config_query(&app, &node),
            vec![
                ("token", "global-token".to_string()),
                ("node_id", "42".to_string()),
            ]
        );
    }

    #[test]
    fn v2node_users_traffic_and_alive_stay_on_uniproxy() {
        let (app, node) = app_and_node(NodeType::V2Node);

        assert_eq!(
            V2BoardClient::endpoint(&app, &node, "user"),
            "https://panel.example.test/api/v1/server/UniProxy/user"
        );
        assert_eq!(
            V2BoardClient::query(&app, &node),
            vec![
                ("token", "global-token".to_string()),
                ("node_id", "42".to_string()),
                ("node_type", "v2node".to_string()),
            ]
        );
    }

    #[test]
    fn response_etag_normalizes_quotes_for_v1_and_v2_cache_hits() {
        assert_eq!(
            normalize_etag("\"626edda67fdda7d7d66e50b8d7312939576bd98a\""),
            "626edda67fdda7d7d66e50b8d7312939576bd98a"
        );
        assert_eq!(
            normalize_etag("626edda67fdda7d7d66e50b8d7312939576bd98a"),
            "626edda67fdda7d7d66e50b8d7312939576bd98a"
        );
    }

    #[tokio::test]
    async fn plugin_config_get_preserves_the_opaque_etag_on_304() {
        let (api_host, request) = serve_once(
            "HTTP/1.1 304 Not Modified\r\n\
             ETag: W/\"opaque-etag\"\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n"
                .to_string(),
        )
        .await;
        let (mut app, node) = app_and_node(NodeType::Shadowsocks);
        app.v2board.api_host = api_host;
        let client = V2BoardClient::new(&app).unwrap();
        let etag = OpaqueEtag::from_static("W/\"opaque-etag\"");

        let observed = client
            .get_plugin_config(&app, &node, Some(&etag))
            .await
            .unwrap();
        match observed {
            PluginConfigObserved::NotModified { etag } => {
                assert_eq!(etag.as_str(), "W/\"opaque-etag\"");
            }
            PluginConfigObserved::Candidate(_) => panic!("expected a 304 observation"),
        }

        let request = request.await.unwrap();
        assert!(request.starts_with("GET /api/v1/server/UniProxy/plugin-config?"));
        assert!(request.contains("token=global-token"));
        assert!(request.contains("node_id=42"));
        assert!(request.contains("node_type=shadowsocks"));
        assert!(request.contains("\r\nif-none-match: W/\"opaque-etag\"\r\n"));
    }

    #[tokio::test]
    async fn plugin_config_get_returns_a_strict_validated_candidate() {
        let body = serde_json::json!({
            "schema_version": 1,
            "node_type": "shadowsocks",
            "node_id": 42,
            "server_port": 8388,
            "cipher": "aes-128-gcm",
            "server_key": null,
            "obfs": null,
            "obfs_settings": null,
            "multiplex": null,
            "plugin": null,
            "routes": [],
            "config_revision": REVISION,
            "base_config": {
                "push_interval": 60,
                "pull_interval": 60,
                "node_report_min_traffic": 0,
                "device_online_min_traffic": 0
            }
        })
        .to_string();
        let response = json_response(StatusCode::OK, "\"candidate-etag\"", &body);
        let (api_host, request) = serve_once(response).await;
        let (mut app, node) = app_and_node(NodeType::Shadowsocks);
        app.v2board.api_host = api_host;
        let client = V2BoardClient::new(&app).unwrap();

        let observed = client.get_plugin_config(&app, &node, None).await.unwrap();
        let PluginConfigObserved::Candidate(candidate) = observed else {
            panic!("expected an updated plugin candidate");
        };
        assert_eq!(candidate.etag().as_str(), "\"candidate-etag\"");
        assert_eq!(candidate.revision().as_str(), REVISION);
        assert_eq!(candidate.manifest().node_id, 42);

        let request = request.await.unwrap();
        assert!(request.starts_with("GET /api/v1/server/UniProxy/plugin-config?"));
        assert!(!request.contains("if-none-match:"));
    }

    #[tokio::test]
    async fn plugin_status_maps_409_and_never_exposes_the_error_body() {
        let body = serde_json::json!({
            "error": "must-not-leak",
            "code": "config_revision_mismatch",
            "desired_revision": REVISION
        })
        .to_string();
        let response = json_response(StatusCode::CONFLICT, "\"error-etag\"", &body);
        let (api_host, request) = serve_once(response).await;
        let (mut app, node) = app_and_node(NodeType::Shadowsocks);
        app.v2board.api_host = api_host;
        let client = V2BoardClient::new(&app).unwrap();
        let report = PluginStatusReport::not_ready("shoes-test").unwrap();

        let error = client
            .post_plugin_status(&app, &node, &report)
            .await
            .unwrap_err();
        match &error {
            PluginApiError::RevisionMismatch { desired_revision } => {
                assert_eq!(
                    desired_revision.as_ref().map(ConfigRevision::as_str),
                    Some(REVISION)
                );
            }
            other => panic!("unexpected plugin status error: {other}"),
        }
        assert!(!error.to_string().contains("must-not-leak"));
        assert!(!format!("{error:?}").contains("must-not-leak"));

        let request = request.await.unwrap();
        assert!(request.starts_with("POST /api/v1/server/UniProxy/status?"));
        assert!(request.contains("\"ready\":false"));
        assert!(request.contains("\"applied_revision\":\"\""));
        assert!(request.contains("\"applied_features\":[]"));
    }

    #[tokio::test]
    async fn plugin_api_rejects_non_shadowsocks_nodes_before_network_io() {
        let (app, node) = app_and_node(NodeType::Vmess);
        let client = V2BoardClient::new(&app).unwrap();
        let error = client
            .get_plugin_config(&app, &node, None)
            .await
            .unwrap_err();
        assert_eq!(error, PluginApiError::UnsupportedNodeType);
    }

    #[tokio::test]
    async fn legacy_api_errors_never_expose_query_tokens_or_response_bodies() {
        let secret = "must-not-appear-in-logs";
        let body = format!(r#"{{"error":"{secret}"}}"#);
        let response = json_response(StatusCode::INTERNAL_SERVER_ERROR, "\"error\"", &body);
        let (api_host, request) = serve_once(response).await;
        let (mut app, node) = app_and_node(NodeType::Shadowsocks);
        app.v2board.api_host = api_host;
        app.v2board.api_key = secret.to_string();
        let client = V2BoardClient::new(&app).unwrap();

        let error = match client.get_server_config(&app, &node, None).await {
            Ok(_) => panic!("expected an HTTP status error"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "V2Board API returned HTTP 500 Internal Server Error"
        );
        assert!(!error.to_string().contains(secret));

        let captured = request.await.unwrap();
        assert!(captured.contains(secret));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_address = listener.local_addr().unwrap();
        drop(listener);
        let transport_error = reqwest::Client::new()
            .get(format!("http://{closed_address}/?token={secret}"))
            .send()
            .await
            .unwrap_err();
        let redacted = http_error(transport_error).to_string();
        assert!(!redacted.contains(secret));
        assert!(!redacted.contains("token="));
    }

    fn json_response(status: StatusCode, etag: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: application/json\r\n\
             ETag: {etag}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown"),
            body.len()
        )
    }

    async fn serve_once(response: String) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request_is_complete(&request) {
                    break;
                }
            }
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}"), task)
    }

    fn request_is_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        request.len() >= header_end + 4 + content_length
    }
}
