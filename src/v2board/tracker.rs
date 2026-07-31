use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::tcp::tcp_handler::TrafficRecorder;

use super::types::{AlivePayload, TrafficPayload};

#[derive(Debug)]
pub struct TrafficTracker {
    snapshot_path: PathBuf,
    state: Mutex<TrackerState>,
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

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
struct TrafficCounter {
    upload: u64,
    download: u64,
}

impl TrafficTracker {
    pub async fn new(data_dir: PathBuf) -> std::io::Result<Self> {
        tokio::fs::create_dir_all(&data_dir).await?;
        let snapshot_path = data_dir.join("traffic-pending.json");
        let state = match tokio::fs::read(&snapshot_path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TrackerState::default(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            snapshot_path,
            state: Mutex::new(state),
        })
    }

    pub fn snapshot_traffic(&self, node_tag: &str, min_traffic: u64) -> TrafficPayload {
        let mut state = self.state.lock();
        let Some(node) = state.traffic.get_mut(node_tag) else {
            return TrafficPayload::default();
        };

        let mut payload = TrafficPayload::default();
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
        payload
    }

    pub fn restore_traffic(&self, node_tag: &str, payload: &TrafficPayload) {
        let mut state = self.state.lock();
        let node = state.traffic.entry(node_tag.to_string()).or_default();
        for (uid, traffic) in payload {
            let Ok(uid) = uid.parse::<u64>() else {
                continue;
            };
            let counter = node.entry(uid).or_default();
            counter.upload = counter.upload.saturating_add(traffic[0]);
            counter.download = counter.download.saturating_add(traffic[1]);
        }
    }

    pub fn snapshot_alive(&self, node_tag: &str, node_id: u64, min_traffic: u64) -> AliveSnapshot {
        let state = self.state.lock();
        let Some(node) = state.alive.get(node_tag) else {
            return AliveSnapshot {
                payload: AlivePayload::default(),
                consumed_traffic: HashMap::new(),
            };
        };

        let payload = node
            .iter()
            .filter_map(|(uid, ips)| {
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
            })
            .collect::<Vec<_>>();

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
        let mut state = self.state.lock();
        let Some(node_traffic) = state.alive_traffic.get_mut(node_tag) else {
            return;
        };

        let mut remove = Vec::new();
        for (uid, consumed) in &snapshot.consumed_traffic {
            if let Some(current) = node_traffic.get_mut(uid) {
                *current = current.saturating_sub(*consumed);
                if *current == 0 {
                    remove.push(*uid);
                }
            }
        }
        for uid in remove {
            node_traffic.remove(&uid);
        }
        if node_traffic.is_empty() {
            state.alive_traffic.remove(node_tag);
        }
    }

    pub fn replace_panel_alive(&self, node_tag: &str, alive: HashMap<u64, u64>) {
        let mut state = self.state.lock();
        if alive.is_empty() {
            state.panel_alive.remove(node_tag);
        } else {
            state.panel_alive.insert(node_tag.to_string(), alive);
        }
    }

    pub async fn persist(&self) -> std::io::Result<()> {
        let bytes = self.snapshot_bytes()?;
        tokio::fs::write(&self.snapshot_path, bytes).await
    }

    fn persist_blocking(&self) -> std::io::Result<()> {
        let bytes = self.snapshot_bytes()?;
        std::fs::write(&self.snapshot_path, bytes)
    }

    fn snapshot_bytes(&self) -> std::io::Result<Vec<u8>> {
        let state = self.state.lock();
        serde_json::to_vec_pretty(&*state)
            .map_err(|e| std::io::Error::other(format!("encode traffic snapshot: {e}")))
    }
}

impl TrafficRecorder for TrafficTracker {
    fn add_traffic(&self, node_tag: &str, uid: u64, upload: u64, download: u64) {
        if upload == 0 && download == 0 {
            return;
        }
        let mut state = self.state.lock();
        let counter = state
            .traffic
            .entry(node_tag.to_string())
            .or_default()
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
            let alive_traffic = state
                .alive_traffic
                .entry(node_tag.to_string())
                .or_default()
                .entry(uid)
                .or_default();
            *alive_traffic = alive_traffic.saturating_add(upload.saturating_add(download));
        }
    }

    fn flush_pending_traffic(&self) {
        if let Err(e) = self.persist_blocking() {
            log::warn!("failed to persist pending V2Board traffic after connection flush: {e}");
        }
    }

    fn add_alive_ip_and_check_limit(
        &self,
        node_tag: &str,
        uid: u64,
        ip: IpAddr,
        device_limit: Option<u64>,
    ) -> bool {
        let mut state = self.state.lock();
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
        let ips = state
            .alive
            .entry(node_tag.to_string())
            .or_default()
            .entry(uid)
            .or_default();

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
        let mut state = self.state.lock();
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

    fn tracker() -> TrafficTracker {
        TrafficTracker {
            snapshot_path: PathBuf::from("/tmp/shoes-test-traffic-pending.json"),
            state: Mutex::new(TrackerState::default()),
        }
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

        let reloaded = TrafficTracker::new(dir.path().to_path_buf()).await.unwrap();
        let payload = reloaded.snapshot_traffic("node-a", 0);
        assert_eq!(payload.get("10"), Some(&[7, 9]));
    }
}
