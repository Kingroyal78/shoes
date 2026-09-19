use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rustc_hash::{FxHashMap, FxHashSet};
use tokio::sync::{Semaphore, watch};
use tokio::time::{Interval, MissedTickBehavior, interval};

use crate::backend_config::{AppConfig, NodeType, V2BoardNodeConfig};
use crate::resolver::{CachingNativeResolver, Resolver};
use crate::thread_util::set_num_threads;
use crate::v2board::client::{FetchResult, UserListFetch, V2BoardApi, V2BoardClient};
use crate::v2board::lkg::{self, NodeLkgSnapshot};
use crate::v2board::mapper::{
    prepare_node, prepare_shadowsocks_plugin_nodes, refresh_node_user_delta, refresh_node_users,
};
use crate::v2board::plugin_api::{
    AppliedFeature, OpaqueEtag, PluginApiError, PluginConfigApplied, PluginConfigCandidate,
    PluginConfigObserved, PluginStatusReport,
};
use crate::v2board::runtime_graph::{RuntimeGraph, RuntimeGraphSlot};
use crate::v2board::tracker::TrafficTracker;
use crate::v2board::types::{ServerConfig, UserInfo};
use crate::v2board::user_tables::NodeUserTables;

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
            app.sync_gate.clone(),
        );
        if let Err(error) = controller.restore_lkg().await {
            log::warn!(
                "node `{}` ignored an invalid last-known-good snapshot before sync-once: {error}",
                controller.node.tag
            );
        }
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
    client: Arc<dyn V2BoardApi>,
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
    sync_gate: Arc<Semaphore>,
}

impl V2BoardApp {
    async fn load(config_path: &str) -> std::io::Result<Self> {
        let config = Arc::new(AppConfig::load(config_path).await?);
        config.validate().await?;
        let client: Arc<dyn V2BoardApi> = Arc::new(V2BoardClient::new(&config)?);
        let tracker = Arc::new(TrafficTracker::new(config.runtime.data_dir.clone()).await?);
        let resolver: Arc<dyn Resolver> = Arc::new(CachingNativeResolver::new());
        let sync_gate = Arc::new(Semaphore::new(config.runtime.max_concurrent_v2board_syncs));
        Ok(Self {
            config,
            client,
            tracker,
            resolver,
            sync_gate,
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
                self.sync_gate.clone(),
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
    client: Arc<dyn V2BoardApi>,
    tracker: Arc<TrafficTracker>,
    resolver: Arc<dyn Resolver>,
    server_etag: Option<String>,
    user_etag: Option<String>,
    user_revision: Option<u64>,
    /// Digest of the user-list body last decoded, so an identical one can be
    /// recognised without paying to decode it again.
    user_body_hash: Option<[u8; 32]>,
    server_config: Option<ServerConfig>,
    users: Option<Arc<Vec<UserInfo>>>,
    device_limited_user_count: usize,
    plugin_candidate: Option<PluginConfigCandidate>,
    plugin_applied: Option<PluginConfigApplied>,
    force_plugin_refresh: bool,
    /// Set when the on-disk snapshot is known to be behind the applied state,
    /// so a failed persist is retried even though nothing changed afterwards.
    lkg_persist_pending: bool,
    runtime: NodeRuntime,
    sync_gate: Arc<Semaphore>,
    /// User tables shared with the live listeners. They outlive runtime
    /// generations so a user-list change is published in place instead of
    /// rebuilding listeners that open connections would then pin.
    user_tables: NodeUserTables,
}

#[derive(Debug)]
struct UserDelta {
    updated: Vec<UserInfo>,
    removed: Vec<u64>,
}

impl NodeController {
    fn new(
        config: Arc<AppConfig>,
        node: V2BoardNodeConfig,
        client: Arc<dyn V2BoardApi>,
        tracker: Arc<TrafficTracker>,
        resolver: Arc<dyn Resolver>,
        sync_gate: Arc<Semaphore>,
    ) -> Self {
        Self {
            config,
            node,
            client,
            tracker,
            resolver,
            server_etag: None,
            user_etag: None,
            user_revision: None,
            user_body_hash: None,
            server_config: None,
            users: None,
            device_limited_user_count: 0,
            plugin_candidate: None,
            plugin_applied: None,
            force_plugin_refresh: false,
            lkg_persist_pending: false,
            runtime: NodeRuntime::default(),
            sync_gate,
            user_tables: NodeUserTables::new(),
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
        // Tracked apart from `changed` so a sync that touched only the user
        // list can be published into the running listeners.
        let mut users_changed = false;
        let mut non_user_changed = false;
        let mut next_server_etag = self.server_etag.clone();
        let mut next_server_config = self.server_config.clone();
        let mut next_user_etag = self.user_etag.clone();
        let mut next_user_revision = self.user_revision;
        let mut next_user_body_hash = self.user_body_hash;
        let mut next_users: Option<Arc<Vec<UserInfo>>> = None;
        let mut next_device_limited_user_count = self.device_limited_user_count;
        let mut next_plugin_candidate = self.plugin_candidate.clone();
        let mut user_delta: Option<UserDelta> = None;
        let mut next_alive: Option<HashMap<u64, u64>> = None;
        let mut clear_force_plugin_refresh = false;

        // A successful pull used to produce no output at all, which left the
        // routine case -- nothing moved -- indistinguishable from a panel that
        // had stopped answering, or from a controller that was no longer
        // ticking. These name what each fetch returned for the summary below,
        // which is emitted at info because release builds compile `debug!`
        // away entirely (`log`'s `release_max_level_info`), and a line only
        // present in a debug build cannot answer "is this node still syncing".
        let mut server_outcome = "not modified";
        let mut plugin_outcome = "n/a";
        let mut users_outcome = "not modified";
        let mut alive_fetched = false;

        let _sync_permit = self
            .sync_gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("V2Board sync gate was closed"))?;

        match self
            .client
            .get_server_config(&self.config, &self.node, self.server_etag.as_deref())
            .await?
        {
            FetchResult::NotModified => {}
            FetchResult::Updated { etag, value } => {
                let config_changed = self.server_config.as_ref() != Some(&value);
                server_outcome = if config_changed {
                    "changed"
                } else {
                    "resent unchanged"
                };
                next_server_etag = etag;
                next_server_config = Some(value);
                changed |= config_changed;
                non_user_changed |= config_changed;
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
                PluginConfigObserved::NotModified { .. } => plugin_outcome = "not modified",
                PluginConfigObserved::Candidate(candidate) => {
                    // A panel or proxy may ignore If-None-Match and resend a
                    // 200 body on every pull.  The ETag is useful for the
                    // next request, but it must not by itself force a new
                    // runtime generation: rebuilding the Shadowsocks edge
                    // retains the old listener/user table until its last
                    // connection closes and creates a large RSS sawtooth.
                    let runtime_changed = self
                        .plugin_candidate
                        .as_ref()
                        .map(|previous| !previous.runtime_equivalent(&candidate))
                        .unwrap_or(true);
                    plugin_outcome = if runtime_changed {
                        "changed"
                    } else {
                        "resent unchanged"
                    };
                    next_plugin_candidate = Some(candidate);
                    if runtime_changed {
                        changed = true;
                        non_user_changed = true;
                    }
                }
            }
            // Keep the force-refresh request armed until the complete
            // candidate has been applied. A mapping/readiness failure must
            // retry with an unconditional plugin pull on the next interval.
            clear_force_plugin_refresh = true;
        }

        match self
            .client
            .get_user_list(
                &self.config,
                &self.node,
                self.user_etag.as_deref(),
                self.user_body_hash.as_ref(),
                self.user_revision.or(Some(0)),
            )
            .await?
        {
            UserListFetch::NotModified => {}
            UserListFetch::Unchanged { etag } => {
                users_outcome = "resent unchanged";
                // Same bytes as last time: nothing to decode, nothing to
                // compare, nothing to apply. The validator is still taken, so a
                // panel that does answer conditional requests can graduate to
                // 304 and skip sending the body at all.
                next_user_etag = etag;
                next_users = self.users.clone();
            }
            UserListFetch::Updated {
                etag,
                value,
                body_hash,
            } => {
                next_user_etag = etag;
                next_user_revision = value.revision;
                next_user_body_hash = Some(body_hash);
                // An empty delta means the panel confirmed the revision we
                // already hold: rebuilding the whole set for it would cost a
                // full clone plus a full map per pull, which is exactly the
                // allocation amplification this feature exists to remove.
                if !value.full && value.users.is_empty() && value.removed.is_empty() {
                    if self.users.is_none() {
                        // The panel's empty delta is only meaningful relative
                        // to a local base. Do not advance its validators while
                        // we have no base to apply; the next pull must be a
                        // full response instead of getting stuck on 304s.
                        self.invalidate_user_cache();
                        return Err(std::io::Error::other(
                            "received an empty user delta without a cached snapshot",
                        ));
                    }
                    users_outcome = "not modified";
                    next_users = self.users.clone();
                } else if value.full {
                    // Some panels regenerate the full response (or its
                    // serialization order) without changing any user.  Sort
                    // once, compare against the stable snapshot, and keep the
                    // existing Arc on an exact semantic no-op.  Otherwise the
                    // old code rebuilt every protocol table despite serving
                    // the same credentials.
                    let (users, full_changed) = prepare_full_user_list(
                        self.users.as_deref().map(Vec::as_slice),
                        value.users,
                    );
                    if !full_changed {
                        users_outcome = "resent unchanged";
                        next_users = self.users.clone();
                    } else {
                        users_changed = true;
                        users_outcome = "changed";
                        next_users = Some(Arc::new(users));
                        next_device_limited_user_count = next_users
                            .as_deref()
                            .map(|users| count_device_limited_users(users))
                            .unwrap_or(0);
                        changed = true;
                    }
                } else {
                    next_device_limited_user_count = device_limit_count_after_delta(
                        self.device_limited_user_count,
                        self.users.as_deref().map(Vec::as_slice).unwrap_or_default(),
                        &value.users,
                        &value.removed,
                    );
                    let Some(current_users) = self.users.as_deref() else {
                        self.invalidate_user_cache();
                        return Err(std::io::Error::other(
                            "received a user delta without a cached snapshot",
                        ));
                    };
                    // Keep the currently applied snapshot intact until the
                    // complete candidate has passed mapping and runtime
                    // readiness. A clone is intentional here: taking the
                    // Arc out of `self.users` made a later mapping failure
                    // partially erase the old controller state.
                    let base = current_users.to_vec();
                    let delta_updated = value.users.clone();
                    let delta_removed = value.removed.clone();
                    let (merged_users, delta_changed) =
                        merge_user_delta(base, value.users, value.removed);
                    // A full response is already a new candidate. For a delta,
                    // merge_user_delta reports whether any row really changed.
                    users_changed = delta_changed;
                    users_outcome = if users_changed {
                        "delta changed"
                    } else {
                        "delta unchanged"
                    };
                    if delta_changed {
                        user_delta = Some(UserDelta {
                            updated: delta_updated,
                            removed: delta_removed,
                        });
                    }
                    next_users = Some(Arc::new(merged_users));
                    changed |= users_changed;
                }
            }
        }

        if next_device_limited_user_count > 0 {
            alive_fetched = true;
            let alive = match self.client.get_alive_list(&self.config, &self.node).await {
                Ok(alive) => alive,
                Err(error) => {
                    if next_users.is_some() && self.users.is_none() {
                        self.invalidate_user_cache();
                    }
                    return Err(error);
                }
            };
            next_alive = Some(alive.alive);
        }

        log::info!(
            "node `{}` pull: config {server_outcome}, users {users_outcome}, plugin \
             {plugin_outcome}{}",
            self.node.tag,
            if alive_fetched {
                ", alivelist fetched"
            } else {
                ""
            }
        );

        if next_server_config.is_none() {
            return Err(std::io::Error::other(format!(
                "node `{}` has no cached server config after sync",
                self.node.tag
            )));
        }
        if next_users.is_none() {
            next_users = self.users.clone();
        }
        if next_users.is_none() {
            return Err(std::io::Error::other(format!(
                "node `{}` has no cached users after sync",
                self.node.tag
            )));
        }

        let applied_generation = changed || self.runtime.is_empty();
        if applied_generation {
            let server = next_server_config.as_ref().unwrap();
            let users: &[UserInfo] = next_users.as_deref().unwrap();
            // A sync that only changed the user list can be published into the
            // running listeners. Replacing the generation instead would leave
            // the superseded listener — and its whole user table — resident
            // until the last connection it accepted closes.
            let users_only = users_changed
                && !non_user_changed
                && !self.runtime.is_empty()
                && self.user_tables.is_published();
            let refreshed = if users_only {
                match self.refresh_users_delta(server, users, user_delta.as_ref()) {
                    Ok(refreshed) => refreshed,
                    Err(error) => {
                        if self.users.is_none() {
                            self.invalidate_user_cache();
                        }
                        return Err(error);
                    }
                }
            } else {
                false
            };
            if !refreshed
                && let Err(error) = self
                    .apply_runtime(server, users, next_plugin_candidate.as_ref())
                    .await
            {
                if self.users.is_none() {
                    self.invalidate_user_cache();
                }
                return Err(error);
            }
            // At info, unlike the pull summary: this is the node changing what
            // it serves, and info is what production runs at.
            if refreshed {
                log::info!(
                    "node `{}` published {} user(s) into the running listeners",
                    self.node.tag,
                    users.len()
                );
            } else {
                log::info!(
                    "node `{}` applied a new runtime generation with {} user(s)",
                    self.node.tag,
                    users.len()
                );
            }
        }

        // The conditional request validators and cached values describe the
        // applied generation, not merely the most recently observed payload.
        // Commit them only after the whole runtime replacement succeeds. A
        // failed user candidate has already invalidated the in-memory cache and
        // will be recovered with a full pull on the next interval.
        self.server_etag = next_server_etag;
        self.server_config = next_server_config;
        self.user_etag = next_user_etag;
        self.user_revision = next_user_revision;
        self.user_body_hash = next_user_body_hash;
        self.users = next_users;
        self.device_limited_user_count = next_device_limited_user_count;
        self.plugin_candidate = next_plugin_candidate;
        if clear_force_plugin_refresh {
            self.force_plugin_refresh = false;
        }
        if let Some(alive) = next_alive {
            self.tracker.replace_panel_alive(&self.node.tag, alive);
        }

        // Persist only when the snapshot's *contents* moved, not merely because
        // a fetch came back 200 instead of 304. A panel that does not honour
        // conditional requests re-sends an identical user list every pull, and
        // rewriting the whole snapshot each time to record nothing but a new
        // ETag is the largest source of write amplification on a node -- it
        // scales with the user count and repeats every interval forever.
        //
        // What that costs is one stale validator: after a restart the node
        // offers the older ETag and gets a full body back instead of a 304,
        // once. The snapshot's contents stay correct, because everything that
        // changes them sets `applied_generation`.
        if applied_generation || self.lkg_persist_pending {
            let persist_result = if !self.lkg_persist_pending && !non_user_changed {
                if let (Some(delta), Some(revision)) = (user_delta.as_ref(), self.user_revision) {
                    match lkg::append_user_delta(
                        &self.config.runtime.data_dir,
                        &self.node,
                        self.user_etag.clone(),
                        revision,
                        delta.updated.clone(),
                        delta.removed.clone(),
                    )
                    .await
                    {
                        Ok(false) => Ok(()),
                        Ok(true) => self.persist_lkg().await,
                        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                            // An unusually large delta is better represented by
                            // a compact base. Preserve availability instead of
                            // retrying an unappendable journal record forever.
                            self.persist_lkg().await
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    self.persist_lkg().await
                }
            } else {
                self.persist_lkg().await
            };
            match persist_result {
                Ok(()) => self.lkg_persist_pending = false,
                Err(e) => {
                    // LKG persist failed (e.g. disk full/permissions). The
                    // applied state stays live. The pending bit makes a later
                    // 304 pull retry persistence without rebuilding the whole
                    // runtime or retaining a second user table for rollback.
                    log::error!(
                        "node `{}` LKG persist failed; will retry on next sync: {e}",
                        self.node.tag
                    );
                    self.lkg_persist_pending = true;
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    fn invalidate_user_cache(&mut self) {
        self.user_etag = None;
        self.user_revision = None;
        self.user_body_hash = None;
        self.users = None;
    }

    /// Publish a new user list into the live listeners.
    ///
    /// Returns `false` when this node has no hot-swappable table, so the caller
    /// falls back to replacing the runtime generation.
    fn refresh_users(
        &mut self,
        server: &ServerConfig,
        users: &[UserInfo],
    ) -> std::io::Result<bool> {
        let transaction = self.user_tables.transaction();
        let refreshed = refresh_node_users(
            &self.config,
            &self.node,
            server,
            users,
            self.tracker.clone(),
            &transaction,
        )?;
        if refreshed {
            transaction.commit();
            self.reconcile_active_users(users);
        }
        Ok(refreshed)
    }

    /// Apply a panel delta directly to a protocol table when that table has a
    /// safe indexed update path. Protocols without one fall back to the
    /// established full-table refresh.
    fn refresh_users_delta(
        &mut self,
        server: &ServerConfig,
        users: &[UserInfo],
        delta: Option<&UserDelta>,
    ) -> std::io::Result<bool> {
        if let Some(delta) = delta
            && let Some(removed) = refresh_node_user_delta(
                &self.config,
                &self.node,
                server,
                &delta.updated,
                &delta.removed,
                self.tracker.clone(),
                &self.user_tables,
            )?
        {
            crate::tcp::tcp_server::remove_speed_limiters(&self.node.tag, &removed);
            self.tracker.remove_users(&self.node.tag, &removed);
            return Ok(true);
        }

        let transaction = self.user_tables.transaction();
        let refreshed = refresh_node_users(
            &self.config,
            &self.node,
            server,
            users,
            self.tracker.clone(),
            &transaction,
        )?;
        if refreshed {
            transaction.commit();
            self.reconcile_active_users(users);
        }
        Ok(refreshed)
    }

    fn reconcile_active_users(&self, users: &[UserInfo]) {
        let active_uids: std::collections::HashSet<u64> =
            users.iter().map(|user| user.id).collect();
        crate::tcp::tcp_server::reconcile_speed_limiters(&self.node.tag, &active_uids);
        self.tracker.reconcile_users(&self.node.tag, &active_uids);
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
            let prepared = prepare_shadowsocks_plugin_nodes(
                &self.config,
                &self.node,
                server,
                users,
                candidate.manifest(),
                self.tracker.clone(),
                self.resolver.clone(),
                &self.user_tables,
            )?;
            let (nodes, transaction) = prepared.into_parts();
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
            if let Err(error) = self.runtime.replace(graph, self.resolver.clone()).await {
                transaction.abort();
                return Err(error);
            }
            transaction.commit();
            self.reconcile_active_users(users);
            self.plugin_applied = Some(applied);
        } else {
            let prepared = prepare_node(
                &self.config,
                &self.node,
                server,
                users,
                self.tracker.clone(),
                self.resolver.clone(),
                &self.user_tables,
            )?;
            let (runtime_node, transaction) = prepared.into_parts();
            if let Err(error) = self
                .runtime
                .replace(RuntimeGraph::single(runtime_node), self.resolver.clone())
                .await
            {
                transaction.abort();
                return Err(error);
            }
            transaction.commit();
            self.reconcile_active_users(users);
        }
        Ok(())
    }

    async fn restore_lkg(&mut self) -> std::io::Result<bool> {
        let Some(mut snapshot) = lkg::load(&self.config.runtime.data_dir, &self.node).await? else {
            return Ok(false);
        };
        if snapshot
            .users
            .windows(2)
            .any(|pair| pair[0].id > pair[1].id)
        {
            Arc::make_mut(&mut snapshot.users).sort_unstable_by_key(|user| user.id);
        }
        let plugin_candidate = snapshot.plugin_candidate(&self.node)?;
        self.apply_runtime(
            &snapshot.server_config,
            &snapshot.users,
            plugin_candidate.as_ref(),
        )
        .await?;
        self.server_etag = snapshot.server_etag;
        self.user_etag = snapshot.user_etag;
        self.user_revision = snapshot.user_revision;
        self.server_config = Some(snapshot.server_config);
        self.users = Some(snapshot.users.clone());
        self.device_limited_user_count = count_device_limited_users(&snapshot.users);
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
        )?
        .with_user_revision(self.user_revision);
        lkg::persist(&self.config.runtime.data_dir, &self.node, snapshot).await
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
            // Logged before the persist, not after: by this point the panel
            // has taken the traffic and the restore path is behind us, so a
            // persist failure would drop the only record that billing did
            // happen and leave nothing but a `push failed` line -- which reads
            // as exactly the opposite of what occurred.
            let (upload, download) =
                payload
                    .values()
                    .fold((0u64, 0u64), |(up, down), [user_up, user_down]| {
                        (up.saturating_add(*user_up), down.saturating_add(*user_down))
                    });
            log::info!(
                "node `{}` reported {upload} bytes up / {download} bytes down for {} user(s)",
                self.node.tag,
                payload.len()
            );
            self.tracker.persist().await?;
        } else {
            // Distinguishing "pushed nothing" from "never pushed" is the whole
            // point of logging the quiet case.
            log::info!("node `{}` had no traffic to report", self.node.tag);
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
            log::info!(
                "node `{}` reported {} online user(s)",
                self.node.tag,
                alive.payload().len()
            );
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
            Ok(()) => {
                // Naming what was acknowledged, not merely that something was.
                // A node whose manifest never applied posts `ready: false`
                // every interval and the panel takes it, so a bare "status
                // acknowledged" reads identically on a healthy node and on one
                // serving nothing but its last-known-good since startup --
                // the stall this line exists to surface.
                log::info!(
                    "node `{}` acknowledged its plugin status: ready={}, applied revision `{}`",
                    self.node.tag,
                    report.is_ready(),
                    report.applied_revision()
                );
                Ok(())
            }
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

/// Apply a panel delta to the stable id-sorted user vector without building a
/// full map or cloning unchanged users. The input vector is owned by the
/// controller and is therefore safe to mutate in place.
fn merge_user_delta(
    mut users: Vec<UserInfo>,
    mut updates: Vec<UserInfo>,
    mut removed: Vec<u64>,
) -> (Vec<UserInfo>, bool) {
    // Full responses are sorted before publication, but snapshots created by
    // older builds may preserve panel order. Repair that once, without a map
    // allocation, before relying on binary search.
    if users.windows(2).any(|pair| pair[0].id > pair[1].id) {
        users.sort_unstable_by_key(|user| user.id);
    }
    // A handful of changes are cheaper to apply in place.  Once the delta
    // grows past this bound, repeated insert/remove calls become O(n*k): each
    // call shifts the tail of the user vector.  The batch path below removes
    // all affected rows in one pass and appends updates before one final sort,
    // keeping the memory profile bounded by the existing vector capacity.
    const IN_PLACE_CHANGE_LIMIT: usize = 32;
    let change_count = updates.len().saturating_add(removed.len());
    if change_count <= IN_PLACE_CHANGE_LIMIT {
        users.reserve(updates.len());
        let mut changed = false;
        for user in updates {
            match users.binary_search_by_key(&user.id, |existing| existing.id) {
                Ok(index) => {
                    if users[index] != user {
                        users[index] = user;
                        changed = true;
                    }
                }
                Err(index) => {
                    users.insert(index, user);
                    changed = true;
                }
            }
        }
        for id in removed {
            if let Ok(index) = users.binary_search_by_key(&id, |existing| existing.id) {
                users.remove(index);
                changed = true;
            }
        }
        return (users, changed);
    }

    // Keep the panel's sequential semantics for duplicate update IDs: the
    // last row in the payload wins. `sort_by` is stable, so equal IDs retain
    // their original order. `dedup_by` receives (current, previous); copying
    // the current row into the previous slot keeps the last value while the
    // duplicate is removed. This clone only occurs for duplicate IDs.
    updates.sort_by_key(|user| user.id);
    updates.dedup_by(|current, previous| {
        let duplicate = current.id == previous.id;
        if duplicate {
            *previous = current.clone();
        }
        duplicate
    });
    removed.sort_unstable();
    removed.dedup();

    // Determine whether the resulting table differs before removing rows.
    // This preserves the no-op result for an identical update, while a
    // remove always wins over an update for the same ID (as in the small
    // sequential path above).
    let mut changed = false;
    let mut additions = 0usize;
    for user in &updates {
        let removed_by_delta = removed.binary_search(&user.id).is_ok();
        if let Ok(index) = users.binary_search_by_key(&user.id, |existing| existing.id) {
            if removed_by_delta || users[index] != *user {
                changed = true;
            }
        } else if !removed_by_delta {
            changed = true;
            additions += 1;
        }
    }
    for id in &removed {
        if users
            .binary_search_by_key(id, |existing| existing.id)
            .is_ok()
        {
            changed = true;
        }
    }

    // Both vectors are sorted. Walk each once and discard rows superseded by
    // either an update or a removal. This is O(n+k), with no second full user
    // table allocated.
    let mut update_index = 0usize;
    let mut removed_index = 0usize;
    users.retain(|existing| {
        while update_index < updates.len() && updates[update_index].id < existing.id {
            update_index += 1;
        }
        while removed_index < removed.len() && removed[removed_index] < existing.id {
            removed_index += 1;
        }
        let updated = update_index < updates.len() && updates[update_index].id == existing.id;
        let deleted = removed_index < removed.len() && removed[removed_index] == existing.id;
        !(updated || deleted)
    });

    // Append new/updated rows except IDs that are removed in the same delta;
    // removal is intentionally authoritative. The retained prefix is already
    // sorted, so only deltas that add rows require a final in-place sort.
    let mut removed_index = 0usize;
    let mut appended = false;
    users.reserve(additions);
    for user in updates {
        while removed_index < removed.len() && removed[removed_index] < user.id {
            removed_index += 1;
        }
        if removed_index < removed.len() && removed[removed_index] == user.id {
            continue;
        }
        users.push(user);
        appended = true;
    }
    if appended {
        users.sort_unstable_by_key(|user| user.id);
    }
    (users, changed)
}

fn count_device_limited_users(users: &[UserInfo]) -> usize {
    users
        .iter()
        .filter(|user| user.device_limit.unwrap_or(0) > 0)
        .count()
}

/// Update the cached count from only the UIDs touched by a delta. The panel's
/// remove list wins over updates, matching `merge_user_delta` semantics.
fn device_limit_count_after_delta(
    current_count: usize,
    users: &[UserInfo],
    updates: &[UserInfo],
    removed: &[u64],
) -> usize {
    let removed: FxHashSet<u64> = removed.iter().copied().collect();
    let mut latest = FxHashMap::default();
    for user in updates {
        latest.insert(user.id, user);
    }
    let mut affected = removed.clone();
    affected.extend(latest.keys().copied());

    let mut count = current_count;
    for uid in affected {
        let previous = users
            .binary_search_by_key(&uid, |user| user.id)
            .ok()
            .and_then(|index| users.get(index))
            .is_some_and(|user| user.device_limit.unwrap_or(0) > 0);
        let next = !removed.contains(&uid)
            && latest
                .get(&uid)
                .is_some_and(|user| user.device_limit.unwrap_or(0) > 0);
        match (previous, next) {
            (true, false) => count = count.saturating_sub(1),
            (false, true) => count = count.saturating_add(1),
            _ => {}
        }
    }
    count
}

/// Normalize a full panel response into the stable id order used by delta
/// merging and report whether it differs from the current snapshot.  Keeping
/// this comparison separate makes a semantically unchanged full response a
/// true no-op even when the panel's wire ordering or ETag changes.
fn prepare_full_user_list(
    current: Option<&[UserInfo]>,
    mut users: Vec<UserInfo>,
) -> (Vec<UserInfo>, bool) {
    users.sort_unstable_by_key(|user| user.id);
    let changed = current != Some(users.as_slice());
    (users, changed)
}

fn plugin_io_error(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn controller_interval(secs: u64) -> Interval {
    let mut timer = interval(Duration::from_secs(secs.max(1)));
    // A delayed sync must not run a burst of catch-up iterations.  Each sync
    // can fetch and apply a full panel snapshot, so replaying missed ticks can
    // amplify both allocations and LKG persistence after a short stall.
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    timer
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

    fn test_user(id: u64, secret: &str) -> UserInfo {
        UserInfo {
            id,
            uuid: None,
            secret: Some(secret.to_string()),
            password: None,
            username: None,
            speed_limit: None,
            device_limit: None,
            label: None,
            enabled: None,
            expires_at: None,
            expires_on: None,
            dedicated_ip: None,
        }
    }

    #[test]
    fn merge_user_delta_updates_sorted_vector_without_rebuilding_unchanged_rows() {
        let original = test_user(2, "old");
        let (users, changed) = merge_user_delta(
            vec![test_user(4, "four"), test_user(1, "one"), original.clone()],
            vec![test_user(2, "new"), test_user(3, "three")],
            vec![1],
        );

        assert!(changed);
        assert_eq!(
            users.iter().map(|user| user.id).collect::<Vec<_>>(),
            [2, 3, 4]
        );
        assert_eq!(users[0].secret.as_deref(), Some("new"));
        assert_eq!(users[2].secret.as_deref(), Some("four"));
        assert_ne!(users[0], original);
    }

    #[test]
    fn merge_user_delta_reports_no_change_for_identical_delta() {
        let users = vec![test_user(1, "one"), test_user(2, "two")];
        let (merged, changed) =
            merge_user_delta(users.clone(), vec![test_user(1, "one")], vec![999]);

        assert!(!changed);
        assert_eq!(merged, users);
    }

    #[test]
    fn merge_user_delta_batches_large_unsorted_delta_and_keeps_last_duplicate() {
        let original = (0..128)
            .map(|id| test_user(id, &format!("old-{id}")))
            .collect::<Vec<_>>();
        let mut updates = (0..65)
            .rev()
            .map(|id| test_user(id, &format!("new-{id}")))
            .collect::<Vec<_>>();
        // Stable sorting plus deduplication must preserve the last occurrence
        // from the payload, even when the update order is otherwise arbitrary.
        updates.push(test_user(42, "last-42"));
        updates.push(test_user(100, "new-100"));
        updates.push(test_user(100, "last-100"));
        updates.push(test_user(200, "added-then-removed"));

        let (merged, changed) = merge_user_delta(original, updates, vec![200, 30, 10, 20, 20, 999]);

        assert!(changed);
        assert!(!merged.iter().any(|user| user.id == 200));
        assert!(!merged.iter().any(|user| [10, 20, 30].contains(&user.id)));
        assert_eq!(
            merged
                .iter()
                .find(|user| user.id == 42)
                .and_then(|user| user.secret.as_deref()),
            Some("last-42")
        );
        assert_eq!(
            merged
                .iter()
                .find(|user| user.id == 100)
                .and_then(|user| user.secret.as_deref()),
            Some("last-100")
        );
        assert!(merged.windows(2).all(|pair| pair[0].id < pair[1].id));
    }

    #[test]
    fn merge_user_delta_large_identical_updates_are_a_no_op() {
        let users = (0..96)
            .map(|id| test_user(id, &format!("user-{id}")))
            .collect::<Vec<_>>();
        let updates = (0..64)
            .map(|id| test_user(id, &format!("user-{id}")))
            .collect::<Vec<_>>();

        let (merged, changed) = merge_user_delta(users.clone(), updates, vec![999, 1000]);

        assert!(!changed);
        assert_eq!(merged, users);
    }

    #[test]
    fn device_limit_count_is_updated_from_delta_without_a_full_scan() {
        let mut users = vec![
            test_user(1, "one"),
            test_user(2, "two"),
            test_user(3, "three"),
        ];
        users[0].device_limit = Some(2);
        users[2].device_limit = Some(1);
        let mut update_two = test_user(2, "two");
        update_two.device_limit = Some(3);
        let mut update_three = test_user(3, "three");
        update_three.device_limit = None;

        assert_eq!(
            device_limit_count_after_delta(2, &users, &[update_two, update_three], &[1]),
            1
        );
    }

    #[test]
    fn full_user_list_reuses_semantically_identical_snapshot() {
        let current = vec![test_user(1, "one"), test_user(2, "two")];
        let (candidate, changed) = prepare_full_user_list(
            Some(current.as_slice()),
            vec![test_user(2, "two"), test_user(1, "one")],
        );

        assert!(!changed);
        assert_eq!(candidate, current);
    }

    #[test]
    fn full_user_list_reports_changed_rows_after_sorting() {
        let current = vec![test_user(1, "one")];
        let (candidate, changed) =
            prepare_full_user_list(Some(current.as_slice()), vec![test_user(1, "new")]);

        assert!(changed);
        assert_eq!(candidate[0].secret.as_deref(), Some("new"));
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
            outbounds: Vec::new(),
            default_out: None,
            route_rules: Vec::new(),
            rule_providers: Vec::new(),
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

        let client: Arc<dyn V2BoardApi> = Arc::new(V2BoardClient::new(&config).unwrap());
        let resolver: Arc<dyn Resolver> = Arc::new(NoopResolver);
        let mut controller = NodeController::new(
            config,
            node,
            client,
            tracker,
            resolver,
            Arc::new(Semaphore::new(1)),
        );

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
