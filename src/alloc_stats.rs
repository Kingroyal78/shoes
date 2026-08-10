//! Optional jemalloc statistics logging for long-running processes.
//!
//! Spawns a background loop that periodically reports jemalloc's
//! `allocated` / `active` / `resident` / `mapped` / `retained` byte
//! counters. This is the tool for distinguishing a true heap leak
//! (`allocated` keeps growing) from allocator retention (`retained`
//! grows while `allocated` plateaus).
//!
//! Controlled by env vars so no config surface is needed:
//! - `SHOES_ALLOCATOR_STATS_INTERVAL_SECS` (> 0): log every N seconds.
//! - `SHOES_ALLOCATOR_STATS_DUMP_AFTER_SECS` (> 0): one full JSON dump
//!   after N seconds (expensive, used to inspect size-class detail).
//! - `SHOES_ALLOCATOR_STATS_DUMP_INTERVAL_SECS` (> 0): a full JSON dump
//!   every N seconds. Two dumps taken while a leak accumulates can be
//!   differenced per size class, which is what actually names the leaking
//!   allocation -- the aggregate counters only prove that one exists.

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
fn dump_stats() {
    let _ = tikv_jemalloc_ctl::epoch::advance();
    let mut output = Vec::new();
    let mut options = tikv_jemalloc_ctl::stats_print::Options::default();
    options.json_format = true;
    options.skip_constants = true;
    options.skip_per_arena = true;
    options.skip_mutex_statistics = true;
    if tikv_jemalloc_ctl::stats_print::stats_print(&mut output, options).is_ok()
        && let Ok(output) = String::from_utf8(output)
    {
        log::info!("jemalloc stats dump: {output}");
    }
}

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
fn env_secs(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
}

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
pub fn start_allocator_stats_logger() {
    if let Some(dump_after_secs) = env_secs("SHOES_ALLOCATOR_STATS_DUMP_AFTER_SECS") {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(dump_after_secs)).await;
            dump_stats();
        });
    }

    if let Some(dump_interval_secs) = env_secs("SHOES_ALLOCATOR_STATS_DUMP_INTERVAL_SECS") {
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(dump_interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                dump_stats();
            }
        });
    }

    let Some(interval_secs) = env_secs("SHOES_ALLOCATOR_STATS_INTERVAL_SECS") else {
        return;
    };

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if tikv_jemalloc_ctl::epoch::advance().is_err() {
                continue;
            }
            let Ok(allocated) = tikv_jemalloc_ctl::stats::allocated::read() else {
                continue;
            };
            let Ok(active) = tikv_jemalloc_ctl::stats::active::read() else {
                continue;
            };
            let Ok(resident) = tikv_jemalloc_ctl::stats::resident::read() else {
                continue;
            };
            let Ok(mapped) = tikv_jemalloc_ctl::stats::mapped::read() else {
                continue;
            };
            let Ok(retained) = tikv_jemalloc_ctl::stats::retained::read() else {
                continue;
            };
            let streams =
                crate::tcp::tcp_server::LIVE_STREAMS.load(std::sync::atomic::Ordering::Relaxed);
            let refused =
                crate::tcp::tcp_server::STREAMS_REFUSED.load(std::sync::atomic::Ordering::Relaxed);
            let backpressure_drops = crate::ss_plugins::transport::STREAMS_DROPPED_BY_BACKPRESSURE
                .load(std::sync::atomic::Ordering::Relaxed);
            let udp_routers =
                crate::routing::LIVE_UDP_ROUTERS.load(std::sync::atomic::Ordering::Relaxed);
            let udp_routers_read_eof = crate::routing::LIVE_UDP_ROUTERS_READ_EOF
                .load(std::sync::atomic::Ordering::Relaxed);
            log::info!(
                "jemalloc bytes: allocated={allocated} active={active} resident={resident} mapped={mapped} retained={retained} streams={streams} refused={refused} backpressure_drops={backpressure_drops} udp_routers={udp_routers} udp_routers_read_eof={udp_routers_read_eof}"
            );
        }
    });
}

#[cfg(any(target_env = "msvc", target_os = "ios", target_os = "android"))]
pub fn start_allocator_stats_logger() {}
