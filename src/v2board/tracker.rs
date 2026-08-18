use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::tcp::tcp_handler::TrafficRecorder;

use super::types::{AlivePayload, TrafficPayload};

/// Minimum spacing between synchronous per-connection-close persists. Without
/// a throttle, every authenticated connection close writes the whole pending
/// traffic map to disk synchronously, which serializes connection teardown on
/// file IO under high churn. The push loop (`TrafficTracker::persist`) still
/// persists every push interval regardless, so this only bounds the crash-loss
/// window to at most this interval of unreported traffic.
const FLUSH_THROTTLE_MILLIS: u64 = 2000;

/// Number of independent locks the per-user state is split across.
///
/// Every connection open, close and traffic report has to take one of these,
/// so a single lock makes the whole node's accounting a queue. Users are spread
/// across shards by id, which is exactly the axis these operations are
/// independent along. A power of two so the shard is a mask, not a division.
const SHARD_COUNT: usize = 32;

#[derive(Debug)]
pub struct TrafficTracker {
    snapshot_path: PathBuf,
    shards: Box<[Mutex<TrackerState>]>,
    /// Millis (unix) of the last synchronous close-flush, for throttling.
    last_flush: AtomicU64,
    /// Test-only count of synchronous persists.
    #[cfg(test)]
    flush_count: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct AliveSnapshot {
    payload: AlivePayload,
    consumed_traffic: HashMap<u64, u64>,
}

impl AliveSnapshot {
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    pub fn payload(&self) -> &AlivePayload {
        &self.payload
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct TrackerState {
    traffic: HashMap<String, HashMap<u64, TrafficCounter>>,
    #[serde(default, skip)]
    alive: HashMap<String, HashMap<u64, HashMap<IpAddr, u64>>>,
    #[serde(default, skip)]
    alive_traffic: HashMap<String, HashMap<u64, u64>>,
    #[serde(default, skip)]
    panel_alive: HashMap<String, HashMap<u64, u64>>,
}

/// The on-disk shape, which predates sharding and stays independent of it.
#[derive(Serialize)]
struct TrafficSnapshot<'a> {
    traffic: &'a HashMap<&'a str, HashMap<u64, TrafficCounter>>,
}

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
struct TrafficCounter {
    upload: u64,
    download: u64,
}

/// Borrow a node's map, creating it only when the node is genuinely new.
///
/// `entry()` requires an owned key on every call, so the obvious spelling heap
/// allocates and copies the node tag even on the overwhelming majority of calls
/// that find a node already there -- and these run inside the one global lock,
/// on every connection open, every close, and every traffic flush. Two hash
/// lookups on the hit path cost far less than an allocation.
fn node_map<'a, V: Default>(map: &'a mut HashMap<String, V>, node_tag: &str) -> &'a mut V {
    if !map.contains_key(node_tag) {
        map.insert(node_tag.to_string(), V::default());
    }
    map.get_mut(node_tag)
        .expect("inserted above when it was missing")
}

impl TrafficTracker {
    pub async fn new(data_dir: PathBuf) -> std::io::Result<Self> {
        tokio::fs::create_dir_all(&data_dir).await?;
        let snapshot_path = data_dir.join("traffic-pending.json");
        let state: TrackerState = match tokio::fs::read(&snapshot_path).await {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(state) => state,
                Err(error) => {
                    // Starting empty is the only way forward, but doing it
                    // quietly discards however much unreported traffic the file
                    // held, and that is the one loss on this path nothing else
                    // can reconstruct -- the panel was never told about it.
                    log::warn!(
                        "pending V2Board traffic snapshot at {} is unreadable; \
                         starting with none, and whatever it held is not billable: {error}",
                        snapshot_path.display()
                    );
                    TrackerState::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TrackerState::default(),
            Err(e) => return Err(e),
        };
        let tracker = Self::empty(snapshot_path);
        // The file keeps the whole node's pending traffic in one map; spread it
        // back over the shards it will be updated through.
        for (node_tag, users) in state.traffic {
            for (uid, counter) in users {
                let mut shard = tracker.shard(uid).lock();
                node_map(&mut shard.traffic, &node_tag).insert(uid, counter);
            }
        }
        Ok(tracker)
    }

    fn empty(snapshot_path: PathBuf) -> Self {
        Self {
            snapshot_path,
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(TrackerState::default()))
                .collect(),
            last_flush: AtomicU64::new(0),
            #[cfg(test)]
            flush_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[inline]
    fn shard(&self, uid: u64) -> &Mutex<TrackerState> {
        &self.shards[uid as usize & (SHARD_COUNT - 1)]
    }

    pub fn snapshot_traffic(&self, node_tag: &str, min_traffic: u64) -> TrafficPayload {
        let mut payload = TrafficPayload::default();
        for shard in &self.shards {
            let mut state = shard.lock();
            let Some(node) = state.traffic.get_mut(node_tag) else {
                continue;
            };
            let mut remove = Vec::new();
            for (uid, counter) in node.iter_mut() {
                let total = counter.upload.saturating_add(counter.download);
                if total >= min_traffic && total > 0 {
                    payload.insert(uid.to_string(), [counter.upload, counter.download]);
                    *counter = TrafficCounter::default();
                }
                if counter.upload == 0 && counter.download == 0 {
                    remove.push(*uid);
                }
            }
            for uid in remove {
                node.remove(&uid);
            }
            if node.is_empty() {
                state.traffic.remove(node_tag);
            }
        }
        payload
    }

    pub fn restore_traffic(&self, node_tag: &str, payload: &TrafficPayload) {
        for (uid, traffic) in payload {
            let Ok(uid) = uid.parse::<u64>() else {
                continue;
            };
            let mut state = self.shard(uid).lock();
            let counter = node_map(&mut state.traffic, node_tag)
                .entry(uid)
                .or_default();
            counter.upload = counter.upload.saturating_add(traffic[0]);
            counter.download = counter.download.saturating_add(traffic[1]);
        }
    }

    pub fn snapshot_alive(&self, node_tag: &str, node_id: u64, min_traffic: u64) -> AliveSnapshot {
        let mut collected = Vec::new();
        for shard in &self.shards {
            let state = shard.lock();
            let Some(node) = state.alive.get(node_tag) else {
                continue;
            };
            collected.extend(node.iter().filter_map(|(uid, ips)| {
                if ips.is_empty() {
                    return None;
                }
                let traffic = state
                    .alive_traffic
                    .get(node_tag)
                    .and_then(|node| node.get(uid))
                    .copied()
                    .unwrap_or(0);
                if traffic < min_traffic {
                    return None;
                }
                Some((
                    *uid,
                    traffic,
                    ips.keys()
                        .map(|ip| format!("{}_{}", ip, node_id))
                        .collect::<Vec<_>>(),
                ))
            }));
        }
        let payload = collected;

        let consumed_traffic = payload
            .iter()
            .map(|(uid, traffic, _)| (*uid, *traffic))
            .collect::<HashMap<_, _>>();
        let payload = payload
            .into_iter()
            .map(|(uid, _, ips)| (uid.to_string(), ips))
            .collect();

        AliveSnapshot {
            payload,
            consumed_traffic,
        }
    }

    pub fn commit_alive_snapshot(&self, node_tag: &str, snapshot: &AliveSnapshot) {
        if snapshot.consumed_traffic.is_empty() {
            return;
        }
        for (uid, consumed) in &snapshot.consumed_traffic {
            let mut state = self.shard(*uid).lock();
            let Some(node_traffic) = state.alive_traffic.get_mut(node_tag) else {
                continue;
            };
            if let Some(current) = node_traffic.get_mut(uid) {
                *current = current.saturating_sub(*consumed);
                if *current == 0 {
                    node_traffic.remove(uid);
                }
            }
            if node_traffic.is_empty() {
                state.alive_traffic.remove(node_tag);
            }
        }
    }

    pub fn replace_panel_alive(&self, node_tag: &str, alive: HashMap<u64, u64>) {
        // Split the panel's view along the same axis the admission checks read
        // it back on, so a check only ever touches its own user's shard.
        let mut by_shard: Vec<HashMap<u64, u64>> = vec![HashMap::new(); SHARD_COUNT];
        for (uid, count) in alive {
            by_shard[uid as usize & (SHARD_COUNT - 1)].insert(uid, count);
        }
        for (shard, subset) in self.shards.iter().zip(by_shard) {
            let mut state = shard.lock();
            if subset.is_empty() {
                state.panel_alive.remove(node_tag);
            } else {
                state.panel_alive.insert(node_tag.to_string(), subset);
            }
        }
    }

    /// Drop per-user state for users that are no longer in the panel's user
    /// list. Without this, counters for deleted/churned users (whose traffic
    /// never reaches `min_traffic` and is therefore never reported) would
    /// accumulate in memory and in `traffic-pending.json` forever. Users still
    /// in the list are untouched, so pending sub-minimum traffic is preserved.
    pub fn reconcile_users(&self, node_tag: &str, active_uids: &std::collections::HashSet<u64>) {
        for shard in &self.shards {
            let mut state = shard.lock();
            let mut removed_traffic = false;
            if let Some(node) = state.traffic.get_mut(node_tag) {
                node.retain(|uid, _| active_uids.contains(uid));
                removed_traffic = node.is_empty();
            }
            let mut removed_alive = false;
            if let Some(node) = state.alive.get_mut(node_tag) {
                node.retain(|uid, _| active_uids.contains(uid));
                removed_alive = node.is_empty();
            }
            if let Some(node) = state.alive_traffic.get_mut(node_tag) {
                node.retain(|uid, _| active_uids.contains(uid));
                if node.is_empty() {
                    state.alive_traffic.remove(node_tag);
                }
            }
            if removed_traffic {
                state.traffic.remove(node_tag);
            }
            if removed_alive {
                state.alive.remove(node_tag);
            }
        }
    }

    pub async fn persist(&self) -> std::io::Result<()> {
        let bytes = self.snapshot_bytes()?;
        persist_atomic(&self.snapshot_path, &bytes).await
    }

    fn snapshot_bytes(&self) -> std::io::Result<Vec<u8>> {
        // Merged back into one map so the file keeps its shape regardless of
        // how many shards the process runs with.
        let mut traffic: HashMap<&str, HashMap<u64, TrafficCounter>> = HashMap::new();
        let guards = self
            .shards
            .iter()
            .map(|shard| shard.lock())
            .collect::<Vec<_>>();
        for state in &guards {
            for (node_tag, users) in &state.traffic {
                traffic
                    .entry(node_tag.as_str())
                    .or_default()
                    .extend(users.iter().map(|(uid, counter)| (*uid, *counter)));
            }
        }
        // Not `to_vec_pretty`: nothing reads this by eye, and the indentation
        // costs about a third again in bytes and encoding time.
        serde_json::to_vec(&TrafficSnapshot { traffic: &traffic })
            .map_err(|e| std::io::Error::other(format!("encode traffic snapshot: {e}")))
    }
}

/// Atomically writes `bytes` to `path` via a temporary file + rename, so a
/// concurrent reader (or a crash mid-write) never observes a truncated file.
/// Mirrors the LKG persist pattern.
async fn persist_atomic(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = temp_path(path);
    // Cleaned up on either failure: the name is unique per call now, so a
    // temporary left behind is never reused and would accumulate instead.
    if let Err(error) = tokio::fs::write(&temporary, bytes).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    Ok(())
}

fn persist_atomic_blocking(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = temp_path(path);
    if let Err(error) = std::fs::write(&temporary, bytes) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

/// A temporary name unique to this call, not merely to this process.
///
/// Two persists are routinely in flight at once -- the push loop and the
/// connection-close flush -- and a name shared between them defeats the very
/// atomicity this indirection exists for: one can rename the file away while
/// the other is still writing it, publishing a truncated snapshot, and the
/// loser's own rename then fails with ENOENT. The writer id keeps two shoes
/// processes sharing a `data_dir` apart; the sequence keeps one process's own
/// writers apart.
fn temp_path(path: &std::path::Path) -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "traffic-pending.json".to_string());
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        ".{file_name}.tmp-{}-{sequence}",
        super::writer_id()
    ))
}

impl TrafficRecorder for TrafficTracker {
    fn add_traffic(&self, node_tag: &str, uid: u64, upload: u64, download: u64) {
        if upload == 0 && download == 0 {
            return;
        }
        let mut state = self.shard(uid).lock();
        let counter = node_map(&mut state.traffic, node_tag)
            .entry(uid)
            .or_default();
        counter.upload = counter.upload.saturating_add(upload);
        counter.download = counter.download.saturating_add(download);
        let is_alive = state
            .alive
            .get(node_tag)
            .and_then(|node| node.get(&uid))
            .is_some_and(|ips| !ips.is_empty());
        if is_alive {
            let alive_traffic = node_map(&mut state.alive_traffic, node_tag)
                .entry(uid)
                .or_default();
            *alive_traffic = alive_traffic.saturating_add(upload.saturating_add(download));
        }
    }

    fn flush_pending_traffic(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last = self.last_flush.load(Ordering::Relaxed);
        if now.saturating_sub(last) < FLUSH_THROTTLE_MILLIS {
            return;
        }
        if self
            .last_flush
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // A concurrent close already flushed within this window.
            return;
        }
        #[cfg(test)]
        self.flush_count.fetch_add(1, Ordering::SeqCst);

        let bytes = match self.snapshot_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                log::warn!("failed to encode pending V2Board traffic: {e}");
                return;
            }
        };
        let path = self.snapshot_path.clone();
        let write = move || {
            if let Err(e) = persist_atomic_blocking(&path, &bytes) {
                log::warn!("failed to persist pending V2Board traffic after connection flush: {e}");
            }
        };

        // This is reached from a connection's teardown, on a runtime worker. A
        // synchronous write there stalls every other connection that worker is
        // driving for as long as the filesystem takes. Nothing waits on it: the
        // push loop persists unconditionally each cycle, so this copy only
        // narrows the crash-loss window and may land after the connection has
        // finished closing.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(write);
            }
            // No runtime to hand it to (unit tests, shutdown): write inline.
            Err(_) => write(),
        }
    }

    fn add_alive_ip_and_check_limit(
        &self,
        node_tag: &str,
        uid: u64,
        ip: IpAddr,
        device_limit: Option<u64>,
    ) -> bool {
        let mut state = self.shard(uid).lock();
        let already_local = state
            .alive
            .get(node_tag)
            .and_then(|node| node.get(&uid))
            .is_some_and(|ips| ips.contains_key(&ip));
        if !already_local
            && let Some(limit) = device_limit
            && limit > 0
            && state
                .panel_alive
                .get(node_tag)
                .and_then(|node| node.get(&uid))
                .copied()
                .unwrap_or(0)
                >= limit
        {
            return false;
        }
        let ips = node_map(&mut state.alive, node_tag).entry(uid).or_default();

        if !ips.contains_key(&ip)
            && let Some(limit) = device_limit
            && limit > 0
            && ips.len() as u64 >= limit
        {
            return false;
        }

        *ips.entry(ip).or_default() += 1;
        true
    }

    fn remove_alive_ip(&self, node_tag: &str, uid: u64, ip: IpAddr) {
        let mut state = self.shard(uid).lock();
        let mut remove_user = false;
        if let Some(node) = state.alive.get_mut(node_tag)
            && let Some(ips) = node.get_mut(&uid)
        {
            if let Some(count) = ips.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ips.remove(&ip);
                }
            }
            remove_user = ips.is_empty();
            if remove_user {
                node.remove(&uid);
            }
            if node.is_empty() {
                state.alive.remove(node_tag);
            }
        }
        if remove_user && let Some(node_traffic) = state.alive_traffic.get_mut(node_tag) {
            node_traffic.remove(&uid);
            if node_traffic.is_empty() {
                state.alive_traffic.remove(node_tag);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn concurrent_persists_do_not_share_a_temporary() {
        let path = PathBuf::from("/tmp/shoes-test-traffic-pending.json");
        let first = temp_path(&path);
        let second = temp_path(&path);

        assert_ne!(
            first, second,
            "a temporary shared between two in-flight persists lets one rename \
             the file away while the other is still writing it"
        );
        for name in [&first, &second] {
            assert_eq!(name.parent(), path.parent());
        }
    }

    #[tokio::test]
    async fn a_racing_pair_of_persists_both_succeed() {
        let directory = std::env::temp_dir().join(format!(
            "shoes-persist-race-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let path = directory.join("traffic-pending.json");

        // The push loop and the close flush, overlapping the way they do on a
        // busy node. Before the temporary was made unique per call, one of
        // these reliably lost its rename to ENOENT.
        let bulky = vec![b'x'; 256 * 1024];
        let (left, right) =
            tokio::join!(persist_atomic(&path, &bulky), persist_atomic(&path, &bulky));
        left.expect("first persist");
        right.expect("second persist");

        assert_eq!(
            std::fs::read(&path).expect("published snapshot").len(),
            bulky.len()
        );
        let leftovers: Vec<_> = std::fs::read_dir(&directory)
            .expect("scratch directory")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with('.'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporaries left behind: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    fn tracker() -> TrafficTracker {
        TrafficTracker::empty(PathBuf::from("/tmp/shoes-test-traffic-pending.json"))
    }

    #[test]
    fn alive_snapshot_requires_configured_min_traffic() {
        let tracker = tracker();
        assert!(tracker.add_alive_ip_and_check_limit(
            "node-a",
            10,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            None,
        ));

        assert!(tracker.snapshot_alive("node-a", 7, 100).is_empty());

        tracker.add_traffic("node-a", 10, 40, 59);
        assert!(tracker.snapshot_alive("node-a", 7, 100).is_empty());

        tracker.add_traffic("node-a", 10, 1, 0);
        let snapshot = tracker.snapshot_alive("node-a", 7, 100);

        assert_eq!(
            snapshot.payload().get("10").unwrap(),
            &vec!["192.0.2.1_7".to_string()]
        );
        assert!(!tracker.snapshot_alive("node-a", 7, 1).is_empty());
        tracker.commit_alive_snapshot("node-a", &snapshot);
        assert!(tracker.snapshot_alive("node-a", 7, 1).is_empty());
    }

    #[test]
    fn alive_commit_subtracts_only_consumed_traffic() {
        let tracker = tracker();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(tracker.add_alive_ip_and_check_limit("node-a", 10, ip, None));

        tracker.add_traffic("node-a", 10, 100, 0);
        let snapshot = tracker.snapshot_alive("node-a", 7, 100);
        tracker.add_traffic("node-a", 10, 7, 0);
        tracker.commit_alive_snapshot("node-a", &snapshot);

        assert!(tracker.snapshot_alive("node-a", 7, 8).is_empty());
        assert!(!tracker.snapshot_alive("node-a", 7, 7).is_empty());
    }

    #[test]
    fn alive_ip_limit_counts_current_distinct_ips_and_releases() {
        let tracker = tracker();
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        assert!(tracker.add_alive_ip_and_check_limit("node-a", 10, ip1, Some(1)));
        assert!(tracker.add_alive_ip_and_check_limit("node-a", 10, ip1, Some(1)));
        assert!(!tracker.add_alive_ip_and_check_limit("node-a", 10, ip2, Some(1)));

        tracker.remove_alive_ip("node-a", 10, ip1);
        assert!(!tracker.add_alive_ip_and_check_limit("node-a", 10, ip2, Some(1)));

        tracker.remove_alive_ip("node-a", 10, ip1);
        assert!(tracker.add_alive_ip_and_check_limit("node-a", 10, ip2, Some(1)));
    }

    #[test]
    fn alive_ip_limit_rejects_when_panel_alive_reaches_user_limit() {
        let tracker = tracker();
        tracker.replace_panel_alive("node-a", HashMap::from([(10, 1)]));

        assert!(!tracker.add_alive_ip_and_check_limit(
            "node-a",
            10,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            Some(1),
        ));
        assert!(tracker.add_alive_ip_and_check_limit(
            "node-a",
            11,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            Some(1),
        ));
    }

    #[test]
    fn panel_alive_limit_allows_same_local_ip_reuse() {
        let tracker = tracker();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        assert!(tracker.add_alive_ip_and_check_limit("node-a", 10, ip, Some(2)));
        tracker.replace_panel_alive("node-a", HashMap::from([(10, 2)]));

        assert!(tracker.add_alive_ip_and_check_limit("node-a", 10, ip, Some(2)));
    }

    #[test]
    fn panel_alive_limit_is_scoped_by_node_tag() {
        let tracker = tracker();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        tracker.replace_panel_alive("node-a", HashMap::from([(10, 1)]));
        tracker.replace_panel_alive("node-b", HashMap::new());

        assert!(!tracker.add_alive_ip_and_check_limit("node-a", 10, ip, Some(1)));
        assert!(tracker.add_alive_ip_and_check_limit("node-b", 10, ip, Some(1)));

        tracker.replace_panel_alive("node-b", HashMap::from([(10, 1)]));
        assert!(!tracker.add_alive_ip_and_check_limit(
            "node-b",
            10,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            Some(1),
        ));
    }

    #[tokio::test]
    async fn flush_pending_traffic_writes_snapshot_for_drop_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = TrafficTracker::new(dir.path().to_path_buf()).await.unwrap();
        tracker.add_traffic("node-a", 10, 7, 9);

        tracker.flush_pending_traffic();

        // The write is handed to the blocking pool, so wait for it instead of
        // assuming it completed before the call returned.
        let path = dir.path().join("traffic-pending.json");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while tokio::fs::metadata(&path).await.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the close flush must reach disk");

        let reloaded = TrafficTracker::new(dir.path().to_path_buf()).await.unwrap();
        let payload = reloaded.snapshot_traffic("node-a", 0);
        assert_eq!(payload.get("10"), Some(&[7, 9]));
    }

    #[test]
    fn state_spread_over_shards_still_reads_back_as_one_node() {
        let tracker = tracker();
        // Deliberately more users than shards, so every shard holds some and
        // the whole-node operations have to visit all of them.
        let uids: Vec<u64> = (0..(SHARD_COUNT as u64 * 3)).collect();
        for &uid in &uids {
            tracker.add_traffic("node-a", uid, 1, 2);
        }

        // The persisted shape must not depend on how the state is partitioned.
        let bytes = tracker.snapshot_bytes().unwrap();
        let encoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            encoded["traffic"]["node-a"].as_object().unwrap().len(),
            uids.len()
        );

        // Reconcile has to reach across every shard, or deleted users survive
        // in whichever shards the sweep missed.
        let keep: std::collections::HashSet<u64> = uids.iter().copied().take(2).collect();
        tracker.reconcile_users("node-a", &keep);

        let payload = tracker.snapshot_traffic("node-a", 0);
        assert_eq!(payload.len(), 2);
        for uid in keep {
            assert_eq!(payload.get(&uid.to_string()), Some(&[1, 2]));
        }
    }

    #[test]
    fn reconcile_users_drops_deleted_users_keeps_active_ones() {
        let tracker = tracker();
        tracker.add_traffic("node-a", 10, 1, 1);
        tracker.add_traffic("node-a", 11, 1, 1);
        tracker.add_traffic("node-b", 10, 1, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(tracker.add_alive_ip_and_check_limit("node-a", 11, ip, None));

        let active: std::collections::HashSet<u64> = [10u64].into_iter().collect();
        tracker.reconcile_users("node-a", &active);

        // User 11 (deleted from panel) is purged from traffic and alive state;
        // user 10 survives; the other node is untouched.
        assert_eq!(
            tracker.snapshot_traffic("node-a", 0).get("10"),
            Some(&[1, 1])
        );
        assert!(!tracker.snapshot_traffic("node-a", 0).contains_key("11"));
        assert!(tracker.snapshot_alive("node-a", 7, 0).is_empty());
        assert_eq!(
            tracker.snapshot_traffic("node-b", 0).get("10"),
            Some(&[1, 1])
        );
    }

    #[test]
    fn reconcile_users_removes_empty_node_buckets() {
        let tracker = tracker();
        tracker.add_traffic("node-a", 10, 1, 1);

        tracker.reconcile_users("node-a", &std::collections::HashSet::new());

        assert!(tracker.snapshot_traffic("node-a", 0).is_empty());
        assert!(tracker.snapshot_alive("node-a", 7, 0).is_empty());
    }

    #[tokio::test]
    async fn close_flush_is_throttled() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = TrafficTracker::new(dir.path().to_path_buf()).await.unwrap();

        tracker.add_traffic("node-a", 10, 5, 5);
        tracker.flush_pending_traffic();
        assert_eq!(tracker.flush_count.load(Ordering::SeqCst), 1);

        // Second close within the throttle window must not hit disk.
        tracker.flush_pending_traffic();
        assert_eq!(tracker.flush_count.load(Ordering::SeqCst), 1);

        // Once the throttle window has elapsed, the next close persists again.
        tracker.last_flush.store(0, Ordering::Relaxed);
        tracker.flush_pending_traffic();
        assert_eq!(tracker.flush_count.load(Ordering::SeqCst), 2);
    }
}
