use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::salt_checker::SaltChecker;

/// Number of independent locks the seen-salt set is split across.
///
/// Every new connection takes one of these before it can be admitted, so a
/// single lock makes connection setup a queue. Salts are uniformly random, so
/// their hash spreads across shards evenly by construction.
const SHARD_COUNT: usize = 16;

/// Remembers recently seen salts for a bounded window.
///
/// Stores a keyed hash of each salt rather than the salt itself. The bytes were
/// previously kept **twice** -- once in the lookup set and once again in the
/// expiry queue -- which is two heap allocations per connection, and at a
/// retention window measured in tens of seconds that is the whole connection
/// rate resident at once. A `u64` in each structure costs no allocation at all.
///
/// The hash is keyed (`RandomState` is SipHash with a per-process key) rather
/// than a prefix of the salt: with an unkeyed function an attacker who can see
/// a victim's salt could craft one that collides with it and get the victim's
/// next connection rejected as a replay.
pub struct TimedSaltChecker {
    hasher: RandomState,
    shards: Box<[Mutex<Shard>]>,
    timeout: Duration,
}

#[derive(Default)]
struct Shard {
    seen: HashSet<u64>,
    order: VecDeque<(Instant, u64)>,
}

impl TimedSaltChecker {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            hasher: RandomState::new(),
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(Shard::default()))
                .collect(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }
}

impl fmt::Debug for TimedSaltChecker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimedSaltChecker")
            .field("timeout", &self.timeout)
            .field("shards", &self.shards.len())
            .finish()
    }
}

impl SaltChecker for TimedSaltChecker {
    fn insert_and_check(&self, salt: &[u8]) -> bool {
        let digest = self.hasher.hash_one(salt);
        let mut shard = self.shards[digest as usize & (SHARD_COUNT - 1)].lock();
        let now = Instant::now();

        while let Some(&(seen_at, key)) = shard.order.front() {
            if now.duration_since(seen_at) < self.timeout {
                break;
            }
            shard.seen.remove(&key);
            shard.order.pop_front();
        }

        if !shard.seen.insert(digest) {
            return false;
        }
        shard.order.push_back((now, digest));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_salt_is_rejected_and_a_fresh_one_is_not() {
        let checker = TimedSaltChecker::new(60);
        assert!(checker.insert_and_check(b"0123456789abcdef"));
        assert!(!checker.insert_and_check(b"0123456789abcdef"));
        assert!(checker.insert_and_check(b"fedcba9876543210"));
    }

    #[test]
    fn salts_are_forgotten_once_the_window_passes() {
        let checker = TimedSaltChecker::new(0);
        assert!(checker.insert_and_check(b"0123456789abcdef"));
        // With a zero-length window the previous entry is already expired, so
        // the same salt is admitted again rather than being remembered forever.
        assert!(checker.insert_and_check(b"0123456789abcdef"));
    }

    #[test]
    fn distinct_salts_land_across_shards() {
        let checker = TimedSaltChecker::new(60);
        for i in 0..2000_u32 {
            assert!(checker.insert_and_check(&i.to_le_bytes()));
        }
        let occupied = checker
            .shards
            .iter()
            .filter(|shard| !shard.lock().seen.is_empty())
            .count();
        assert_eq!(
            occupied, SHARD_COUNT,
            "a single busy shard would put connection setup back behind one lock"
        );
    }
}
