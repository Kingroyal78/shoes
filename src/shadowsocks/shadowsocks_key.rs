use std::fmt::Debug;

pub trait ShadowsocksKey: Send + Sync + Debug {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]>;

    /// Derive the session key for `salt` into `out`, returning how many bytes
    /// were written, or `None` when `out` is too small.
    ///
    /// A legacy-AEAD listener with more than one user has to try the candidate
    /// users in turn, because the protocol carries nothing that identifies
    /// which one sent the handshake. That happens before anything is
    /// authenticated, on every connection attempt, so the per-candidate cost is
    /// what a node with thousands of users pays to refuse one bad packet.
    /// Going through [`Self::create_session_key`] there is one heap allocation
    /// per candidate; this lets the caller derive into a stack buffer instead.
    ///
    /// The default implementation keeps implementors free to ignore it.
    fn write_session_key(&self, salt: &[u8], out: &mut [u8]) -> Option<usize> {
        let session_key = self.create_session_key(salt);
        if out.len() < session_key.len() {
            return None;
        }
        out[..session_key.len()].copy_from_slice(&session_key);
        Some(session_key.len())
    }
}
