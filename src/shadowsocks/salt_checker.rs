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

/// How long a salt is remembered. Must exceed the AEAD-2022 timestamp window,
/// or a handshake could be replayed after its salt was forgotten but before its
/// timestamp went stale. That window is symmetric (+/-30s, so a 60s span), and
/// retention equal to the span leaves no margin for the delay between a peer
/// stamping a handshake and this side recording its salt -- hence the extra
/// 30s here. Widening the timestamp tolerance means widening this too.
pub(super) const SALT_REPLAY_WINDOW_SECS: u64 = 90;

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

#[cfg(test)]
mod tests {
    use super::super::shadowsocks_stream::TIMESTAMP_SKEW_TOLERANCE_SECS;
    use super::*;

    /// The two constants live in different modules but are one design: a salt
    /// forgotten while its timestamp is still valid is a replay hole, so
    /// widening the timestamp tolerance must not silently outrun retention.
    #[test]
    fn salt_retention_outlives_the_whole_timestamp_window() {
        let window_span_secs = 2 * TIMESTAMP_SKEW_TOLERANCE_SECS;
        assert!(
            SALT_REPLAY_WINDOW_SECS > window_span_secs,
            "salt retention {SALT_REPLAY_WINDOW_SECS}s must exceed the {window_span_secs}s window"
        );
    }
}
