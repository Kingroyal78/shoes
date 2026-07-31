//! Shared server-side transports used by in-process SIP003-compatible plugins.
//!
//! This module intentionally contains no plugin configuration or V2Board
//! knowledge.  It only provides bounded parsers, transport wrappers, and the two
//! multiplexing protocols used by the supported plugins.

mod handler;
mod http;
mod http_upgrade;
mod mux_cool;
mod smux;
mod tls;
mod virtual_stream;
mod websocket;

pub use handler::ArcTcpServerHandler;
pub(crate) use http::host_matches_optional_port;
pub use http::{HttpLimits, HttpRequest, normalize_path};
pub use http_upgrade::{HttpUpgradeConfig, HttpUpgradeServerHandler};
pub use mux_cool::{MuxCoolLimits, MuxCoolServerHandler};
pub use smux::{SmuxLimits, SmuxServerConfig, SmuxServerHandler, SmuxV1ServerHandler};
pub use tls::TlsTerminatingServerHandler;
pub use websocket::{
    StrictWebsocketServerHandler, WebsocketServerConfig, websocket_server_handler,
};
