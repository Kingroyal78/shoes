//! UDP routing module for per-destination routing.
//!
//! This module provides the `UdpRouter` which handles multi-destination UDP streams
//! (both `AsyncTargetedMessageStream` and `AsyncSessionMessageStream`) by creating
//! per-destination sessions that each route through the appropriate upstream chain
//! based on routing rules.

mod udp_router;

pub use udp_router::{
    LIVE_UDP_ROUTERS, LIVE_UDP_ROUTERS_READ_EOF, ServerStream, report_udp_io_error, run_udp_routing,
};
