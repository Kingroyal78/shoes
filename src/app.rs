use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{Interval, interval};

use crate::backend_config::{AppConfig, NodeType, V2BoardNodeConfig};
use crate::resolver::{CachingNativeResolver, Resolver};
use crate::thread_util::set_num_threads;
use crate::v2board::client::{FetchResult, V2BoardClient};
use crate::v2board::lkg::{self, NodeLkgSnapshot};
use crate::v2board::mapper::{map_node, map_shadowsocks_plugin_nodes};
use crate::v2board::plugin_api::{
    AppliedFeature, OpaqueEtag, PluginApiError, PluginConfigApplied, PluginConfigCandidate,
    PluginConfigObserved, PluginStatusReport,
};
use crate::v2board::runtime_graph::{RuntimeGraph, RuntimeGraphSlot};
use crate::v2board::tracker::TrafficTracker;
use crate::v2board::types::{ServerConfig, UserInfo};

pub async fn validate(config_path: &str) -> std::io::Result<()> {
    let config = AppConfig::load(config_path).await?;
    config.validate().await
}

pub async fn sync_once(config_path: &str) -> std::io::Result<()> {
    let app = V2BoardApp::load(config_path).await?;
    let mut ok = 0usize;
    for node in app.config.v2board.nodes.clone() {
        let mut controller = NodeController::new(
            app.config.clone(),
            node,
            app.client.clone(),
            app.tracker.clone(),
            app.resolver.clone(),
        );
        controller.sync().await?;
        ok += 1;
    }
    log::info!("sync-once finished for {ok} node(s)");
    Ok(())
}

pub async fn run(config_path: &str, threads: usize) -> std::io::Result<()> {
    let app = V2BoardApp::load(config_path).await?;
    if threads > 0 {
        set_num_threads(threads);
    }
    app.run().await
}

struct V2BoardApp {
    config: Arc<AppConfig>,
    client: V2BoardClient,
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
}

impl V2BoardApp {
    async fn load(config_path: &str) -> std::io::Result<Self> {
        let config = Arc::new(AppConfig::load(config_path).await?);
        config.validate().await?;
        let client = V2BoardClient::new(&config)?;
        let tracker = Arc::new(TrafficTracker::new(config.runtime.data_dir.clone()).await?);
        let resolver: Arc<dyn Resolver> = Arc::new(CachingNativeResolver::new());
        Ok(Self {
            config,
            client,
            tracker,
            resolver,
        })
    }

    async fn run(self) -> std::io::Result<()> {
        let mut handles = Vec::new();
        let mut initial_success = 0usize;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        for node in self.config.v2board.nodes.clone() {
            let mut controller = NodeController::new(
                self.config.clone(),
                node,
                self.client.clone(),
                self.tracker.clone(),
                self.resolver.clone(),
            );
            let mut ready = match controller.restore_lkg().await {
                Ok(restored) => restored,
                Err(error) => {
                    log::warn!(
                        "node `{}` ignored an invalid last-known-good snapshot: {error}",
                        controller.node.tag
                    );
                    false
                }
            };
            match controller.sync().await {
                Ok(()) => ready = true,
                Err(e) => {
                    log::warn!(
                        "node `{}` initial sync failed; controller will keep retrying: {e}",
                        controller.node.tag
                    );
                }
            }
            if ready {
                initial_success += 1;
            }
            let shutdown = shutdown_rx.clone();
            handles.push(tokio::spawn(
                async move { controller.run_loop(shutdown).await },
            ));
        }

        log::info!(
            "shoes V2Board backend running with {} controller(s), {initial_success} initially ready",
            handles.len()
        );
        wait_for_shutdown_signal().await;
        log::info!("shutdown signal received; stopping V2Board node controllers");
        let _ = shutdown_tx.send(true);
        futures::future::join_all(handles).await;
        self.tracker.persist().await?;
        Ok(())
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(e) => {
                log::warn!("failed to install SIGTERM handler: {e}");
                if let Err(e) = tokio::signal::ctrl_c().await {
                    log::warn!("failed to wait for Ctrl-C: {e}");
                }
                return;
            }
        };

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    log::warn!("failed to wait for Ctrl-C: {e}");
                }
            }
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log::warn!("failed to wait for Ctrl-C: {e}");
        }
    }
}

struct NodeController {
    config: Arc<AppConfig>,
    node: V2BoardNodeConfig,
    client: V2BoardClient,
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
    server_etag: Option<String>,
    user_etag: Option<String>,
    server_config: Option<ServerConfig>,
    users: Option<Vec<UserInfo>>,
    plugin_candidate: Option<PluginConfigCandidate>,
    plugin_applied: Option<PluginConfigApplied>,
    force_plugin_refresh: bool,
    runtime: NodeRuntime,
}

impl NodeController {
    fn new(
        config: Arc<AppConfig>,
        node: V2BoardNodeConfig,
        client: V2BoardClient,
        tracker: Arc<TrafficTracker>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self {
            config,
            node,
            client,
            tracker,
            resolver,
            server_etag: None,
            user_etag: None,
            server_config: None,
            users: None,
            plugin_candidate: None,
            plugin_applied: None,
            force_plugin_refresh: false,
            runtime: NodeRuntime::default(),
        }
    }

    async fn run_loop(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut pull_secs = self.pull_interval_secs();
        let mut push_secs = self.push_interval_secs();
        let mut pull = controller_interval(pull_secs);
        let mut push = controller_interval(push_secs);
        let mut status = controller_interval(push_secs);
        pull.tick().await;
        push.tick().await;
        if let Err(error) = self.push_plugin_status().await {
            log::warn!(
                "node `{}` initial plugin status failed: {error}",
                self.node.tag
            );
        }
        status.tick().await;

        loop {
            tokio::select! {
                _ = pull.tick() => {
                    if let Err(e) = self.sync().await {
                        log::warn!("node `{}` sync failed: {e}", self.node.tag);
                    }
                    let new_pull_secs = self.pull_interval_secs();
                    if new_pull_secs != pull_secs {
                        log::info!(
                            "node `{}` pull interval changed from {}s to {}s",
                            self.node.tag,
                            pull_secs,
                            new_pull_secs
                        );
                        pull_secs = new_pull_secs;
                        pull = controller_interval(pull_secs);
                        pull.tick().await;
                    }
                    let new_push_secs = self.push_interval_secs();
                    if new_push_secs != push_secs {
                        log::info!(
                            "node `{}` push interval changed from {}s to {}s",
                            self.node.tag,
                            push_secs,
                            new_push_secs
                        );
                        push_secs = new_push_secs;
                        push = controller_interval(push_secs);
                        push.tick().await;
                        status = controller_interval(push_secs);
                        status.tick().await;
                    }
                }
                _ = push.tick() => {
                    if let Err(e) = self.push().await {
                        log::warn!("node `{}` push failed: {e}", self.node.tag);
                    }
                }
                _ = status.tick(), if self.node.node_type == NodeType::Shadowsocks => {
                    if let Err(error) = self.push_plugin_status().await {
                        log::warn!(
                            "node `{}` plugin status failed: {error}",
                            self.node.tag
                        );
                    }
                }
                changed = shutdown.changed() => {
                    match changed {
                        Ok(()) if *shutdown.borrow() => break,
                        Ok(()) => {}
                        Err(_) => break,
                    }
                }
            }
        }

        if let Err(e) = self.push().await {
            log::warn!(
                "node `{}` final push failed during shutdown: {e}",
                self.node.tag
            );
        }
        self.runtime.stop().await;
    }

    async fn sync(&mut self) -> std::io::Result<()> {
        let mut changed = false;
        let mut cache_updated = false;
        let mut next_server_etag = self.server_etag.clone();
        let mut next_server_config = self.server_config.clone();
        let mut next_user_etag = self.user_etag.clone();
        let mut next_users = self.users.clone();
        let mut next_plugin_candidate = self.plugin_candidate.clone();

        match self
            .client
            .get_server_config(&self.config, &self.node, self.server_etag.as_deref())
            .await?
        {
            FetchResult::NotModified => {}
            FetchResult::Updated { etag, value } => {
                let config_changed = self.server_config.as_ref() != Some(&value);
                next_server_etag = etag;
                next_server_config = Some(value);
                changed |= config_changed;
                cache_updated = true;
            }
        }

        if self.node.node_type == NodeType::Shadowsocks {
            let current_etag = if self.force_plugin_refresh {
                None
            } else {
                self.plugin_observed_etag()
            };
            match self
                .client
                .get_plugin_config(&self.config, &self.node, current_etag)
                .await
                .map_err(plugin_io_error)?
            {
                PluginConfigObserved::NotModified { .. } => {}
                PluginConfigObserved::Candidate(candidate) => {
                    next_plugin_candidate = Some(candidate);
                    changed = true;
                    cache_updated = true;
                }
            }
            self.force_plugin_refresh = false;
        }

        match self
            .client
            .get_user_list(&self.config, &self.node, self.user_etag.as_deref())
            .await?
        {
            FetchResult::NotModified => {}
            FetchResult::Updated { etag, value } => {
                let users_changed = self.users.as_ref() != Some(&value.users);
                next_user_etag = etag;
                next_users = Some(value.users);
                changed |= users_changed;
                cache_updated = true;
            }
        }

        if next_users
            .as_ref()
            .is_some_and(|users| users.iter().any(|user| user.device_limit.unwrap_or(0) > 0))
        {
            let alive = self.client.get_alive_list(&self.config, &self.node).await?;
            self.tracker
                .replace_panel_alive(&self.node.tag, alive.alive);
        }

        if next_server_config.is_none() || next_users.is_none() {
            return Err(std::io::Error::other(format!(
                "node `{}` has no cached server config/users after sync",
                self.node.tag
            )));
        }

        let applied_generation = changed || self.runtime.is_empty();
        if applied_generation {
            let server = next_server_config.as_ref().unwrap();
            let users = next_users.as_ref().unwrap();
            self.apply_runtime(server, users, next_plugin_candidate.as_ref())
                .await?;
        }

        // The conditional request validators and cached values describe the
        // applied generation, not merely the most recently observed payload.
        // Commit them only after the whole runtime replacement succeeds so a
        // failed candidate is fetched and retried on the next pull.
        self.server_etag = next_server_etag;
        self.server_config = next_server_config;
        self.user_etag = next_user_etag;
        self.users = next_users;
        self.plugin_candidate = next_plugin_candidate;

        if applied_generation || cache_updated {
            self.persist_lkg().await?;
        }

        Ok(())
    }

    async fn apply_runtime(
        &mut self,
        server: &ServerConfig,
        users: &[UserInfo],
        plugin_candidate: Option<&PluginConfigCandidate>,
    ) -> std::io::Result<()> {
        if self.node.node_type == NodeType::Shadowsocks {
            let candidate = plugin_candidate.ok_or_else(|| {
                std::io::Error::other(format!(
                    "node `{}` has no validated plugin-config candidate",
                    self.node.tag
                ))
            })?;
            let nodes = map_shadowsocks_plugin_nodes(
                &self.config,
                &self.node,
                server,
                users,
                candidate.manifest(),
                self.tracker.clone(),
                self.resolver.clone(),
            )?;
            let features = plugin_features(candidate);
            let graph = RuntimeGraph::new(
                self.node.tag.clone(),
                Some(candidate.revision().as_str().to_string()),
                features
                    .iter()
                    .map(|feature| feature.as_str().to_string())
                    .collect(),
                nodes,
            )?;
            let applied = candidate
                .clone()
                .mark_applied(features)
                .map_err(plugin_io_error)?;
            self.runtime.replace(graph, self.resolver.clone()).await?;
            self.plugin_applied = Some(applied);
        } else {
            let runtime_node = map_node(
                &self.config,
                &self.node,
                server,
                users,
                self.tracker.clone(),
                self.resolver.clone(),
            )?;
            self.runtime
                .replace(RuntimeGraph::single(runtime_node), self.resolver.clone())
                .await?;
        }
        Ok(())
    }

    async fn restore_lkg(&mut self) -> std::io::Result<bool> {
        let Some(snapshot) = lkg::load(&self.config.runtime.data_dir, &self.node).await? else {
            return Ok(false);
        };
        let plugin_candidate = snapshot.plugin_candidate(&self.node)?;
        self.apply_runtime(
            &snapshot.server_config,
            &snapshot.users,
            plugin_candidate.as_ref(),
        )
        .await?;
        self.server_etag = snapshot.server_etag;
        self.user_etag = snapshot.user_etag;
        self.server_config = Some(snapshot.server_config);
        self.users = Some(snapshot.users);
        self.plugin_candidate = plugin_candidate;
        log::info!(
            "node `{}` restored its last-known-good runtime before contacting V2Board",
            self.node.tag
        );
        Ok(true)
    }

    async fn persist_lkg(&self) -> std::io::Result<()> {
        let Some(server_config) = self.server_config.clone() else {
            return Ok(());
        };
        let Some(users) = self.users.clone() else {
            return Ok(());
        };
        let snapshot = NodeLkgSnapshot::new(
            &self.node,
            self.server_etag.clone(),
            self.user_etag.clone(),
            server_config,
            users,
            self.plugin_candidate.as_ref(),
        )?;
        lkg::persist(&self.config.runtime.data_dir, &self.node, &snapshot).await
    }

    async fn push(&mut self) -> std::io::Result<()> {
        let min_traffic = self
            .server_config
            .as_ref()
            .map(|c| c.base_config.node_report_min_traffic)
            .unwrap_or(self.config.runtime.node_report_min_traffic);
        let payload = self.tracker.snapshot_traffic(&self.node.tag, min_traffic);
        if !payload.is_empty() {
            if let Err(e) = self
                .client
                .push_traffic(&self.config, &self.node, &payload)
                .await
            {
                self.tracker.restore_traffic(&self.node.tag, &payload);
                self.tracker.persist().await?;
                return Err(e);
            }
            self.tracker.persist().await?;
        }

        let min_alive_traffic = self
            .server_config
            .as_ref()
            .map(|c| c.base_config.device_online_min_traffic)
            .unwrap_or(self.config.runtime.device_online_min_traffic);
        let alive =
            self.tracker
                .snapshot_alive(&self.node.tag, self.node.node_id, min_alive_traffic);
        if !alive.is_empty() {
            self.client
                .push_alive(&self.config, &self.node, alive.payload())
                .await?;
            self.tracker.commit_alive_snapshot(&self.node.tag, &alive);
        }
        self.tracker.persist().await
    }

    async fn push_plugin_status(&mut self) -> std::io::Result<()> {
        if self.node.node_type != NodeType::Shadowsocks {
            return Ok(());
        }
        let version = format!("shoes/{}", env!("CARGO_PKG_VERSION"));
        let report = match self.plugin_applied.as_ref() {
            Some(applied) => applied.status_report(version).map_err(plugin_io_error)?,
            None => PluginStatusReport::not_ready(version).map_err(plugin_io_error)?,
        };
        match self
            .client
            .post_plugin_status(&self.config, &self.node, &report)
            .await
        {
            Ok(()) => Ok(()),
            Err(PluginApiError::RevisionMismatch { .. }) => {
                self.force_plugin_refresh = true;
                Err(std::io::Error::other(
                    "V2Board rejected the applied plugin revision; a full refresh is scheduled",
                ))
            }
            Err(error) => Err(plugin_io_error(error)),
        }
    }

    fn plugin_observed_etag(&self) -> Option<&OpaqueEtag> {
        self.plugin_candidate
            .as_ref()
            .map(PluginConfigCandidate::etag)
            .or_else(|| {
                self.plugin_applied
                    .as_ref()
                    .map(|applied| applied.candidate().etag())
            })
    }

    fn pull_interval_secs(&self) -> u64 {
        self.node
            .pull_interval_secs
            .or_else(|| {
                self.server_config
                    .as_ref()
                    .map(|c| c.base_config.pull_interval)
            })
            .unwrap_or(self.config.runtime.pull_interval_secs)
            .max(1)
    }

    fn push_interval_secs(&self) -> u64 {
        self.node
            .push_interval_secs
            .or_else(|| {
                self.server_config
                    .as_ref()
                    .map(|c| c.base_config.push_interval)
            })
            .unwrap_or(self.config.runtime.push_interval_secs)
            .max(1)
    }
}

fn plugin_features(candidate: &PluginConfigCandidate) -> Vec<AppliedFeature> {
    let mut features = vec![
        AppliedFeature::UotV1,
        AppliedFeature::UotV2,
        AppliedFeature::PluginRuntimeV1,
    ];
    if candidate
        .manifest()
        .multiplex
        .as_ref()
        .is_some_and(|multiplex| multiplex.enabled)
    {
        features.push(AppliedFeature::SingMuxV1);
    }
    if let Some(plugin) = candidate.manifest().plugin.as_ref() {
        features.push(plugin.kind().adapter_feature());
    }
    features
}

fn plugin_io_error(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn controller_interval(secs: u64) -> Interval {
    interval(Duration::from_secs(secs.max(1)))
}

type NodeRuntime = RuntimeGraphSlot;

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::address::NetLocation;
    use crate::backend_config::{
        LogConfig, NodeType, RuntimeConfig, V2BoardConfig, V2BoardNodeConfig,
    };
    use crate::tcp::tcp_handler::TrafficRecorder;

    #[derive(Debug)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
            Box::pin(async {
                Err(std::io::Error::other(
                    "NoopResolver should not be used by push tests",
                ))
            })
        }
    }

    #[tokio::test]
    async fn push_persists_accepted_traffic_before_attempting_alive() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let data_dir = tempfile::tempdir().unwrap();
        let (api_host, server, push_count, alive_count) = spawn_push_ok_alive_error_server().await;
        let node = V2BoardNodeConfig {
            tag: "node-a".to_string(),
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
        let config = Arc::new(AppConfig {
            v2board: V2BoardConfig {
                api_host,
                api_key: "test-token".to_string(),
                api_timeout_secs: 5,
                error_body_limit_bytes: 1024,
                user_list_body_limit_bytes: 2048,
                route_rule_sets: Default::default(),
                nodes: vec![node.clone()],
            },
            runtime: RuntimeConfig {
                data_dir: data_dir.path().to_path_buf(),
                ..Default::default()
            },
            tls: None,
            log: LogConfig::default(),
        });
        let tracker = Arc::new(
            TrafficTracker::new(data_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(tracker.add_alive_ip_and_check_limit("node-a", 1001, ip, None));
        tracker.add_traffic("node-a", 1001, 123, 456);
        tracker.persist().await.unwrap();

        let client = V2BoardClient::new(&config).unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);
        let mut controller = NodeController::new(config, node, client, tracker, resolver);

        let err = controller.push().await.unwrap_err();
        assert!(err.to_string().contains("HTTP 500"));
        assert_eq!(push_count.load(Ordering::SeqCst), 1);
        assert_eq!(alive_count.load(Ordering::SeqCst), 1);

        let reloaded = TrafficTracker::new(data_dir.path().to_path_buf())
            .await
            .unwrap();
        assert!(reloaded.snapshot_traffic("node-a", 0).is_empty());

        server.abort();
    }

    async fn spawn_push_ok_alive_error_server()
    -> (String, JoinHandle<()>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let push_count = Arc::new(AtomicUsize::new(0));
        let alive_count = Arc::new(AtomicUsize::new(0));
        let server_push_count = push_count.clone();
        let server_alive_count = alive_count.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let push_count = server_push_count.clone();
                let alive_count = server_alive_count.clone();
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 8192];
                    let Ok(n) = stream.read(&mut request).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&request[..n]);
                    let response = if request.starts_with("POST /api/v1/server/UniProxy/push") {
                        push_count.fetch_add(1, Ordering::SeqCst);
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{}"
                    } else if request.starts_with("POST /api/v1/server/UniProxy/alive") {
                        alive_count.fetch_add(1, Ordering::SeqCst);
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nalive"
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        (format!("http://{addr}"), handle, push_count, alive_count)
    }
}
