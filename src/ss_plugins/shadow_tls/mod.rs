//! ShadowTLS v1/v2 server-side protocol support.
//!
//! Version 3 remains implemented by `crate::shadow_tls`.  This module deliberately
//! keeps v1/v2 independent: their handshake and record-layer semantics are not
//! compatible with v3.

mod handler;
mod record;
mod stream;
mod v1;
mod v2;

pub use handler::{
    ClientChainShadowTlsConnector, ShadowTlsCamouflageConnector, ShadowTlsPluginServerHandler,
};
pub use record::{MAX_TLS_RECORD_PAYLOAD, TlsRecord};
pub use stream::ShadowTlsV2Stream;
pub use v1::{ShadowTlsV1Config, accept_v1};
pub use v2::{ShadowTlsFallback, ShadowTlsV2Config, ShadowTlsV2Outcome, accept_v2};
