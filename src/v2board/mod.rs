pub mod client;
pub mod grpc;
pub mod http;
pub mod httpupgrade;
pub mod lkg;
pub mod mapper;
pub mod outbound;
pub mod plugin_api;
pub mod proxy_protocol;
pub mod route_rule_set;
pub mod runtime_graph;
pub mod runtime_model;
pub mod tracker;
pub mod types;
pub mod user_tables;
pub mod xhttp;

/// A writer-unique suffix for the "write a temp file, then rename" persistence
/// used for the traffic snapshot and the LKG snapshots.
///
/// The obvious choice -- the process id -- is not unique here. Every container
/// built from this image runs `shoes` as pid 1, so several nodes sharing a
/// `data_dir` all derive the same temp file name and clobber each other's
/// in-progress writes, which surfaces as spurious `NotFound` (the other writer
/// already renamed it away) or `AlreadyExists` failures.
///
/// Drawn once per process rather than once per write: a crash between the
/// write and the rename then leaves at most one stale temp file, which the
/// next write of the same file reuses instead of accumulating garbage.
pub fn writer_id() -> &'static str {
    static WRITER_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    WRITER_ID.get_or_init(|| {
        use rand::RngExt;
        format!(
            "{}-{:016x}",
            std::process::id(),
            rand::rng().random::<u64>()
        )
    })
}
