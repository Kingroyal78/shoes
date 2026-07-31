//! Production-oriented Restls server protocol primitives.
//!
//! The implementation is derived from the original BSD-3-Clause Restls server,
//! not from Mihomo.  See [`attribution`] for the retained notice.

pub mod app;
pub mod attribution;
pub mod auth;
mod handler;
pub mod hello;
pub mod record;
pub mod script;
pub mod server;

pub use app::{DecodedAppRecord, EncodedAppRecord, RestlsAppCodec, RestlsCommand};
pub use auth::RestlsKey;
pub use handler::{
    ClientChainRestlsConnector, RestlsCamouflageConnector, RestlsPluginServerHandler,
    RestlsRuntimeLimits,
};
pub use hello::{ClientHello, ServerHello};
pub use record::{AsyncTlsRecordReader, MAX_TLS_RECORD_PAYLOAD, TlsRecord, TlsRecordDecoder};
pub use script::{RestlsScript, ScriptLine};
pub use server::{RestlsServerAction, RestlsServerCore, RestlsServerStage};
