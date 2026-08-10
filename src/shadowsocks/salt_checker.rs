use std::fmt::Debug;
use std::sync::Arc;

pub trait SaltChecker: Send + Sync + Debug {
    /// Takes `&self`: the checker shards internally, so callers no longer
    /// funnel every connection through one outer lock.
    fn insert_and_check(&self, salt: &[u8]) -> bool;
}

/// A salt-replay checker shared by every handler that must reject the same
/// replayed handshake.
pub type SharedSaltChecker = Arc<dyn SaltChecker>;

/// How long a salt is remembered. Must exceed the AEAD-2022 timestamp window
/// (-30s..+2s), or a handshake could be replayed after its salt was forgotten
/// but before its timestamp went stale.
const SALT_REPLAY_WINDOW_SECS: u64 = 60;

/// Build a checker that several handler generations can share.
///
/// Replay protection is only as good as the memory behind it, and that memory
/// must outlive any single listener: a handler built per generation starts with
/// an empty set, so every listener rebuild would reopen the replay window for
/// one full retention period.
pub fn new_shared_salt_checker() -> SharedSaltChecker {
    Arc::new(super::timed_salt_checker::TimedSaltChecker::new(
        SALT_REPLAY_WINDOW_SECS,
    ))
}
