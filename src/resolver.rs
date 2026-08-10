use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::{FutureExt, Shared};
use log::debug;
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use tokio::sync::{Mutex as AsyncMutex, RwLock};

use crate::address::{NetLocation, ResolvedLocation};

type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

pub trait Resolver: Send + Sync + Debug {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;
}

/// Resolver wrapper that enforces a timeout on DNS resolution.
/// Wraps any inner Resolver and fails with TimedOut if resolution takes too long.
pub struct TimeoutResolver<T> {
    inner: T,
    timeout: Duration,
}

impl<T: Resolver> TimeoutResolver<T> {
    #[allow(dead_code)]
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    #[allow(dead_code)]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(inner: T, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<T: Resolver> Debug for TimeoutResolver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeoutResolver")
            .field("inner", &self.inner)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<T: Resolver> Resolver for TimeoutResolver<T> {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        // Fast path: if already an IP address, no resolution needed
        if location.to_socket_addr_nonblocking().is_some() {
            let loc = location.clone();
            return Box::pin(async move { Ok(vec![loc.to_socket_addr_nonblocking().unwrap()]) });
        }

        let inner_future = self.inner.resolve_location(location);
        let timeout_duration = self.timeout;
        let location_str = location.to_string();

        Box::pin(async move {
            match tokio::time::timeout(timeout_duration, inner_future).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "DNS resolution for {} timed out after {:?}",
                        location_str, timeout_duration
                    ),
                )),
            }
        })
    }
}

type ResolverFactoryFuture =
    Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn Resolver>>> + Send>>;

pub type ResolverFactory = Arc<dyn Fn() -> ResolverFactoryFuture + Send + Sync>;

/// Policy controlling when a RefreshingResolver rebuilds its inner resolver.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPolicy {
    /// Rebuild the inner resolver if it has been idle longer than this.
    pub max_idle: Duration,
    /// After a refreshable error, rebuild and retry the lookup once.
    pub retry_once_after_refresh: bool,
}

/// Resolver wrapper that rebuilds its inner resolver on idle timeout or
/// connection-related errors. Targets stale pooled connection state in
/// hickory-backed resolvers.
pub struct RefreshingResolver {
    factory: ResolverFactory,
    inner: Arc<RwLock<Arc<dyn Resolver>>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    refresh_state: Arc<Mutex<RefreshState>>,
    policy: RefreshPolicy,
    description: String,
}

struct RefreshState {
    last_activity_at: Option<Instant>,
    generation: u64,
}

impl Debug for RefreshingResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshingResolver")
            .field("description", &self.description)
            .field("max_idle", &self.policy.max_idle)
            .finish()
    }
}

impl RefreshingResolver {
    pub async fn new(
        factory: ResolverFactory,
        policy: RefreshPolicy,
        description: String,
    ) -> std::io::Result<Self> {
        let inner = factory().await?;
        Ok(Self {
            factory,
            inner: Arc::new(RwLock::new(inner)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            refresh_state: Arc::new(Mutex::new(RefreshState {
                last_activity_at: None,
                generation: 0,
            })),
            policy,
            description,
        })
    }

    fn should_refresh_for_error(err: &std::io::Error) -> bool {
        matches!(
            err.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotConnected
        )
    }
}

impl Resolver for RefreshingResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![socket_addr]) });
        }

        let location = location.clone();
        let inner = self.inner.clone();
        let refresh_lock = self.refresh_lock.clone();
        let factory = self.factory.clone();
        let refresh_state = self.refresh_state.clone();
        let policy = self.policy;
        let description = self.description.clone();

        Box::pin(async move {
            // Refreshes if idle too long using double-checked locking.
            if matches!(refresh_state.lock().last_activity_at, Some(last) if last.elapsed() > policy.max_idle)
            {
                let _guard = refresh_lock.lock().await;
                if matches!(refresh_state.lock().last_activity_at, Some(last) if last.elapsed() > policy.max_idle)
                {
                    log::info!(
                        "RefreshingResolver ({}): rebuilding after idle timeout ({:?})",
                        description,
                        policy.max_idle
                    );
                    match factory().await {
                        Ok(fresh) => {
                            *inner.write().await = fresh;
                            let mut state = refresh_state.lock();
                            state.last_activity_at = Some(Instant::now());
                            state.generation = state.generation.wrapping_add(1);
                        }
                        Err(e) => {
                            log::warn!(
                                "RefreshingResolver ({}): idle refresh failed: {}",
                                description,
                                e
                            );
                        }
                    }
                }
            }

            let current_generation = refresh_state.lock().generation;
            let current = inner.read().await.clone();
            match current.resolve_location(&location).await {
                Ok(addrs) => {
                    refresh_state.lock().last_activity_at = Some(Instant::now());
                    Ok(addrs)
                }
                Err(err)
                    if policy.retry_once_after_refresh
                        && RefreshingResolver::should_refresh_for_error(&err) =>
                {
                    let _guard = refresh_lock.lock().await;
                    if refresh_state.lock().generation != current_generation {
                        let current = inner.read().await.clone();
                        let addrs = current.resolve_location(&location).await?;
                        refresh_state.lock().last_activity_at = Some(Instant::now());
                        return Ok(addrs);
                    }
                    log::info!(
                        "RefreshingResolver ({}): refresh-on-error ({}) for {}",
                        description,
                        err.kind(),
                        location
                    );
                    match factory().await {
                        Ok(fresh) => {
                            *inner.write().await = fresh.clone();
                            {
                                let mut state = refresh_state.lock();
                                state.generation = state.generation.wrapping_add(1);
                            }
                            let addrs = fresh.resolve_location(&location).await?;
                            refresh_state.lock().last_activity_at = Some(Instant::now());
                            Ok(addrs)
                        }
                        Err(factory_err) => {
                            log::warn!(
                                "RefreshingResolver ({}): error-refresh factory failed: {}",
                                description,
                                factory_err
                            );
                            Err(err)
                        }
                    }
                }
                Err(err) => Err(err),
            }
        })
    }
}

#[derive(Debug, Default)]
pub struct NativeResolver;

impl NativeResolver {
    pub fn new() -> Self {
        NativeResolver {}
    }
}

impl Resolver for NativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let address = location.address().clone();
        let port = location.port();
        Box::pin(
            tokio::net::lookup_host((address.to_string(), port)).map(move |result| {
                let ret = result.map(|r| {
                    r.filter(|addr| !addr.ip().is_unspecified())
                        .collect::<Vec<_>>()
                });
                debug!("NativeResolver resolved {address}:{port} -> {ret:?}");
                ret
            }),
        )
    }
}

pub async fn resolve_single_address(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<SocketAddr> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(socket_addr);
    }
    let resolve_results = resolver.resolve_location(location).await?;
    if resolve_results.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(resolve_results[0])
}

/// Resolve all addresses for a location. Returns a single-element vec
/// for IP literals, or the full set from the resolver.
pub async fn resolve_addresses(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(vec![socket_addr]);
    }

    let addrs = resolver.resolve_location(location).await?;
    if addrs.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(addrs)
}

/// Resolve a ResolvedLocation lazily. If already resolved, returns the cached
/// address. Otherwise resolves, caches the result in the location, and returns it.
/// This is the key function for the lazy resolution pattern.
pub async fn resolve_location(
    location: &mut ResolvedLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<SocketAddr> {
    if let Some(addr) = location.resolved_addr() {
        return Ok(addr);
    }
    let addr = resolve_single_address(resolver, location.location()).await?;
    location.set_resolved(addr);
    Ok(addr)
}

/// Native resolver with application-level caching.
/// Uses tokio::net::lookup_host (OS resolver) with TTL-based cache.
/// This is used as the default resolver when no DNS config is specified.
/// Number of independent locks the DNS cache is split across.
///
/// Every outbound connection to a hostname consults this, so a single lock puts
/// all of them in a queue -- and the eviction sweep runs while it is held.
const RESOLVER_SHARD_COUNT: usize = 16;

pub struct CachingNativeResolver {
    shards: Arc<[parking_lot::Mutex<FxHashMap<NetLocation, CachedResolveResult>>]>,
    result_timeout_secs: u64,
    /// Per shard, so the total stays what the caller asked for.
    max_entries_per_shard: usize,
}

fn resolver_shard_index(location: &NetLocation) -> usize {
    use std::hash::BuildHasher;
    rustc_hash::FxBuildHasher.hash_one(location) as usize & (RESOLVER_SHARD_COUNT - 1)
}

struct CachedResolveResult {
    timestamp: Instant,
    addr: SocketAddr,
}

impl std::fmt::Debug for CachingNativeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingNativeResolver")
            .field("result_timeout_secs", &self.result_timeout_secs)
            .finish()
    }
}

impl CachingNativeResolver {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60; // 1 hour

    /// Upper bound on cached entries. Keeps the cache bounded even when the
    /// node resolves a large number of distinct destinations.
    pub const DEFAULT_MAX_ENTRIES: usize = 4096;

    pub fn new() -> Self {
        Self::with_timeout(Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn with_timeout(result_timeout_secs: u64) -> Self {
        Self {
            shards: (0..RESOLVER_SHARD_COUNT)
                .map(|_| parking_lot::Mutex::new(FxHashMap::default()))
                .collect(),
            result_timeout_secs,
            max_entries_per_shard: Self::DEFAULT_MAX_ENTRIES.div_ceil(RESOLVER_SHARD_COUNT),
        }
    }
}

/// Drop expired entries and, if the cache is still over capacity, evict the
/// oldest entry. Callers must hold the cache lock. A pure function so the
/// eviction policy is directly unit-testable without DNS.
fn evict_for_insert(
    cache: &mut FxHashMap<NetLocation, CachedResolveResult>,
    now: Instant,
    timeout: Duration,
    max_entries: usize,
) {
    let max_entries = max_entries.max(1);
    cache.retain(|_, result| now.duration_since(result.timestamp) <= timeout);
    while cache.len() >= max_entries {
        let mut oldest_key: Option<NetLocation> = None;
        let mut oldest_timestamp = now;
        for (key, result) in cache.iter() {
            if result.timestamp < oldest_timestamp {
                oldest_timestamp = result.timestamp;
                oldest_key = Some(key.clone());
            }
        }
        match oldest_key {
            Some(key) => cache.remove(&key),
            None => break,
        };
    }
}

impl Default for CachingNativeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for CachingNativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        // Check cache first. Only this name's shard is touched, so concurrent
        // lookups of other names are not held up behind it.
        let shard_index = resolver_shard_index(location);
        {
            let cache = self.shards[shard_index].lock();
            if let Some(cached) = cache.get(location)
                && Instant::now().duration_since(cached.timestamp)
                    <= Duration::from_secs(self.result_timeout_secs)
            {
                let addr = cached.addr;
                return Box::pin(async move { Ok(vec![addr]) });
            }
        }

        let location = location.clone();
        let shards = self.shards.clone();
        let result_timeout_secs = self.result_timeout_secs;
        let max_entries = self.max_entries_per_shard;

        Box::pin(async move {
            let address = location.address().to_string();
            let port = location.port();

            let result = tokio::net::lookup_host((address.clone(), port)).await?;
            let addrs: Vec<SocketAddr> =
                result.filter(|addr| !addr.ip().is_unspecified()).collect();

            if addrs.is_empty() {
                return Err(std::io::Error::other(format!(
                    "DNS lookup returned no addresses for {address}"
                )));
            }

            // Cache the first result
            {
                let mut cache = shards[shard_index].lock();
                evict_for_insert(
                    &mut cache,
                    Instant::now(),
                    Duration::from_secs(result_timeout_secs),
                    max_entries,
                );
                cache.insert(
                    location,
                    CachedResolveResult {
                        timestamp: Instant::now(),
                        addr: addrs[0],
                    },
                );
            }

            debug!("CachingNativeResolver resolved {address}:{port} -> {addrs:?}");
            Ok(addrs)
        })
    }
}

/// Shared future type for concurrent resolution deduplication.
/// Uses Arc<std::io::Error> because Shared requires Clone on the output type.
type SharedResolveFuture =
    Shared<Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, Arc<std::io::Error>>> + Send>>>;

/// Poll-based resolver cache for use in Future/Stream implementations.
/// Wraps any Resolver and provides poll_resolve_location for manual polling.
/// Uses Shared futures to correctly handle concurrent requests for the same target.
pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    /// Completed resolution results with timestamps
    cache: FxHashMap<NetLocation, CachedResolveResult>,
    /// In-flight resolutions using Shared futures for proper waker handling
    pending: FxHashMap<NetLocation, SharedResolveFuture>,
    result_timeout_secs: u64,
}

impl ResolverCache {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60 * 60;

    /// Upper bound on cached entries.
    ///
    /// One of these lives per connection, and an entry is only ever removed by
    /// looking the same name up again after it expired -- so a name resolved
    /// once stays for the life of the connection. A long-lived association that
    /// keeps naming new destinations would otherwise grow without limit, which
    /// is exactly the traffic pattern a UDP relay sees.
    pub const DEFAULT_MAX_ENTRIES: usize = 512;

    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self::new_with_timeout(resolver, Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(resolver: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            resolver,
            cache: FxHashMap::default(),
            pending: FxHashMap::default(),
            result_timeout_secs,
        }
    }

    /// Cache one result, evicting under the same policy the process-wide
    /// resolver uses so a single connection cannot grow this without bound.
    fn insert(&mut self, target: &NetLocation, addr: SocketAddr) {
        let now = Instant::now();
        evict_for_insert(
            &mut self.cache,
            now,
            Duration::from_secs(self.result_timeout_secs),
            Self::DEFAULT_MAX_ENTRIES,
        );
        self.cache.insert(
            target.clone(),
            CachedResolveResult {
                timestamp: now,
                addr,
            },
        );
    }

    /// Async resolve method for convenience.
    pub async fn resolve_location(&mut self, target: &NetLocation) -> std::io::Result<SocketAddr> {
        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Ok(socket_addr);
        }

        // Check cache
        if let Some(cached) = self.cache.get(target) {
            if Instant::now().duration_since(cached.timestamp)
                <= Duration::from_secs(self.result_timeout_secs)
            {
                return Ok(cached.addr);
            }
            self.cache.remove(target);
        }

        // Resolve
        let addrs = self.resolver.resolve_location(target).await?;
        if addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "DNS lookup returned no addresses for {target}"
            )));
        }
        let addr = addrs[0];
        self.insert(target, addr);
        Ok(addr)
    }

    /// Poll-based resolve for use in Future/Stream poll methods.
    /// Uses Shared futures to correctly wake all tasks waiting on the same target.
    pub fn poll_resolve_location(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<SocketAddr>> {
        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Poll::Ready(Ok(socket_addr));
        }

        // Check completed cache
        if let Some(cached) = self.cache.get(target) {
            if Instant::now().duration_since(cached.timestamp)
                <= Duration::from_secs(self.result_timeout_secs)
            {
                return Poll::Ready(Ok(cached.addr));
            }
            self.cache.remove(target);
        }

        // Get or create shared future for this target
        let mut shared_fut = self
            .pending
            .entry(target.clone())
            .or_insert_with(|| {
                let fut = self.resolver.resolve_location(target);
                // Wrap error in Arc for Clone requirement, then make shared
                fut.map(|r| r.map_err(Arc::new)).boxed().shared()
            })
            .clone();

        // Poll the shared future
        match shared_fut.poll_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(addrs)) => {
                self.pending.remove(target);
                if addrs.is_empty() {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "DNS lookup returned no addresses for {target}"
                    ))));
                }
                let addr = addrs[0];
                self.insert(target, addr);
                Poll::Ready(Ok(addr))
            }
            Poll::Ready(Err(e)) => {
                self.pending.remove(target);
                // Convert Arc<Error> back to Error
                Poll::Ready(Err(std::io::Error::new(e.kind(), e.to_string())))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    /// A mock resolver that returns configurable results, tracking call count.
    #[derive(Debug)]
    struct MockResolver {
        addrs: Vec<SocketAddr>,
        call_count: AtomicUsize,
        error_kind: Option<std::io::ErrorKind>,
    }

    impl MockResolver {
        fn with_addrs(addrs: Vec<SocketAddr>) -> Self {
            Self {
                addrs,
                call_count: AtomicUsize::new(0),
                error_kind: None,
            }
        }

        fn with_error(kind: std::io::ErrorKind) -> Self {
            Self {
                addrs: vec![],
                call_count: AtomicUsize::new(0),
                error_kind: Some(kind),
            }
        }

        fn count(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl Resolver for MockResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            let addrs = self.addrs.clone();
            let error_kind = self.error_kind;
            Box::pin(async move {
                if let Some(kind) = error_kind {
                    Err(std::io::Error::new(kind, "mock error"))
                } else {
                    Ok(addrs)
                }
            })
        }
    }

    /// A mock resolver that fails the first N calls then succeeds.
    #[derive(Debug)]
    struct FlakyResolver {
        fail_count: AtomicUsize,
        fails_remaining: AtomicUsize,
        error_kind: std::io::ErrorKind,
        success_addrs: Vec<SocketAddr>,
    }

    impl FlakyResolver {
        fn new(
            fail_first_n: usize,
            error_kind: std::io::ErrorKind,
            success_addrs: Vec<SocketAddr>,
        ) -> Self {
            Self {
                fail_count: AtomicUsize::new(0),
                fails_remaining: AtomicUsize::new(fail_first_n),
                error_kind,
                success_addrs,
            }
        }
    }

    impl Resolver for FlakyResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            let remaining = self.fails_remaining.fetch_sub(1, Ordering::Relaxed);
            if remaining > 0 {
                self.fail_count.fetch_add(1, Ordering::Relaxed);
                let kind = self.error_kind;
                Box::pin(async move { Err(std::io::Error::new(kind, "flaky error")) })
            } else {
                let addrs = self.success_addrs.clone();
                Box::pin(async move { Ok(addrs) })
            }
        }
    }

    fn test_location() -> NetLocation {
        NetLocation::new(Address::Hostname("example.com".to_string()), 80)
    }

    fn test_addrs() -> Vec<SocketAddr> {
        vec!["127.0.0.1:80".parse().unwrap()]
    }

    #[tokio::test]
    async fn test_refreshing_resolver_retries_after_timeout() {
        let success_addrs = test_addrs();
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let addrs = success_addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let n = call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs.clone();
            Box::pin(async move {
                if n == 0 {
                    // First build: return a resolver that times out
                    Ok(
                        Arc::new(MockResolver::with_error(std::io::ErrorKind::TimedOut))
                            as Arc<dyn Resolver>,
                    )
                } else {
                    // Refresh build: return a resolver that succeeds
                    Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
                }
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, success_addrs);
        // Factory called twice: initial build + refresh-on-error
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_no_retry_on_non_refreshable_error() {
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                // Return a resolver that returns a non-refreshable error
                Ok(
                    Arc::new(MockResolver::with_error(std::io::ErrorKind::Other))
                        as Arc<dyn Resolver>,
                )
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await;
        assert!(result.is_err());
        // Factory called only once (initial build, no refresh for non-refreshable errors)
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(
                async move { Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>) },
            )
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(50),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        // First resolve records activity.
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Wait for idle timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second resolve triggers idle refresh
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        // Factory called twice: initial + idle refresh
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_coalesces_concurrent_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(20),
            retry_once_after_refresh: true,
        };

        let resolver = Arc::new(
            RefreshingResolver::new(factory, policy, "test".to_string())
                .await
                .unwrap(),
        );

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let concurrency = 32;
        let barrier = Arc::new(Barrier::new(concurrency));
        let tasks = (0..concurrency).map(|_| {
            let resolver = resolver.clone();
            let barrier = barrier.clone();
            let location = test_location();
            tokio::spawn(async move {
                barrier.wait().await;
                resolver.resolve_location(&location).await
            })
        });

        for result in futures::future::join_all(tasks).await {
            assert_eq!(result.unwrap().unwrap(), addrs);
        }
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_resolve_addresses_returns_all() {
        let addrs: Vec<SocketAddr> = vec![
            "1.1.1.1:80".parse().unwrap(),
            "2.2.2.2:80".parse().unwrap(),
            "3.3.3.3:80".parse().unwrap(),
        ];
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(addrs.clone()));
        let loc = test_location();

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, addrs);
    }

    #[tokio::test]
    async fn test_resolve_addresses_ip_literal() {
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(vec![]));
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 443);

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, vec!["1.2.3.4:443".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn test_timeout_resolver_ip_bypass() {
        let inner = MockResolver::with_addrs(test_addrs());
        let resolver = TimeoutResolver::with_timeout(inner, Duration::from_millis(1));

        // IP literals should return immediately without timeout
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 80);
        let result = resolver.resolve_location(&loc).await.unwrap();
        assert_eq!(result[0], "1.2.3.4:80".parse::<SocketAddr>().unwrap());
    }

    fn cached(_location: &NetLocation, age: Duration) -> CachedResolveResult {
        CachedResolveResult {
            timestamp: Instant::now() - age,
            addr: "127.0.0.1:80".parse().unwrap(),
        }
    }

    #[test]
    fn evict_for_insert_purges_expired_entries() {
        let mut cache = FxHashMap::default();
        let fresh = test_location();
        let stale = NetLocation::new(Address::Hostname("stale.example".to_string()), 80);
        cache.insert(fresh.clone(), cached(&fresh, Duration::from_secs(5)));
        cache.insert(
            stale.clone(),
            cached(&stale, Duration::from_secs(2 * 60 * 60)),
        );

        evict_for_insert(&mut cache, Instant::now(), Duration::from_secs(60), 10);

        assert!(cache.contains_key(&fresh));
        assert!(!cache.contains_key(&stale));
    }

    #[test]
    fn evict_for_insert_bounds_cache_size() {
        let mut cache = FxHashMap::default();
        let now = Instant::now();
        let mut oldest: Option<NetLocation> = None;
        for i in 0..100usize {
            let location = NetLocation::new(Address::Hostname(format!("host-{i}.example")), 80);
            // Larger index => older timestamp (eviction candidate).
            let age = Duration::from_millis((i + 1) as u64 * 10);
            if i == 99 {
                oldest = Some(location.clone());
            }
            cache.insert(
                location,
                CachedResolveResult {
                    timestamp: now - age,
                    addr: "127.0.0.1:80".parse().unwrap(),
                },
            );
        }

        evict_for_insert(&mut cache, now, Duration::from_secs(3600), 64);

        assert!(cache.len() < 64);
        assert_eq!(cache.len() + 1, 64);
        assert!(!cache.contains_key(oldest.as_ref().unwrap()));
        // Newest entry (index 0) survives.
        let newest = NetLocation::new(Address::Hostname("host-0.example".to_string()), 80);
        assert!(cache.contains_key(&newest));
    }

    #[test]
    fn evict_for_insert_does_not_grow_with_continuous_inserts() {
        let mut cache = FxHashMap::default();
        let now = Instant::now();
        for i in 0..5000usize {
            let location = NetLocation::new(Address::Hostname(format!("host-{i}.example")), 80);
            evict_for_insert(&mut cache, now, Duration::from_secs(3600), 256);
            cache.insert(
                location,
                CachedResolveResult {
                    timestamp: now - Duration::from_millis((5000 - i) as u64),
                    addr: "127.0.0.1:80".parse().unwrap(),
                },
            );
        }
        assert_eq!(cache.len(), 256);
    }

    #[test]
    fn default_resolver_cache_is_bounded_across_all_shards() {
        let resolver = CachingNativeResolver::new();
        assert_eq!(resolver.shards.len(), RESOLVER_SHARD_COUNT);
        // The bound is what the caller asked for; sharding must not multiply it.
        assert!(
            resolver.max_entries_per_shard * RESOLVER_SHARD_COUNT
                >= CachingNativeResolver::DEFAULT_MAX_ENTRIES
        );
        assert!(
            resolver.max_entries_per_shard * RESOLVER_SHARD_COUNT
                < CachingNativeResolver::DEFAULT_MAX_ENTRIES + RESOLVER_SHARD_COUNT
        );
    }

    #[test]
    fn names_spread_across_resolver_shards() {
        use std::collections::HashSet;
        let occupied: HashSet<usize> = (0..500)
            .map(|i| {
                resolver_shard_index(&NetLocation::new(
                    Address::Hostname(format!("host{i}.example")),
                    443,
                ))
            })
            .collect();
        assert_eq!(
            occupied.len(),
            RESOLVER_SHARD_COUNT,
            "a single occupied shard would put every lookup back behind one lock"
        );
    }
}
