//! AnyTLS Server Handler
//!
//! Implements TcpServerHandler for AnyTLS protocol.
//! This handler:
//! 1. Authenticates clients via SHA256(password)
//! 2. Creates an AnyTlsSession with all routing dependencies
//! 3. Runs the session which handles streams internally

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::address::NetLocation;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::anytls::anytls_server_session::{AnyTlsServerSessionContext, AnyTlsSession};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::shared_users::SharedUsers;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    AuthenticatedUser, ServerUser, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;
use aws_lc_rs::digest::{SHA256, digest};

/// The user set of an AnyTLS listener.
///
/// Keyed by the full SHA-256 password hash, with the 8-byte prefixes kept
/// alongside so non-AnyTLS traffic can be rejected after 8 bytes instead of
/// blocking for 32.
#[derive(Debug, Default)]
pub struct AnyTlsUsers {
    by_password_hash: HashMap<[u8; 32], AnyTlsAuthenticatedUser>,
    hash_prefixes: HashSet<[u8; 8]>,
}

impl AnyTlsUsers {
    /// Build the table from V2Board users; the panel user key names the user
    /// and the credential is its password.
    pub fn new(users: Vec<ServerUser>) -> Self {
        let mut by_password_hash = HashMap::with_capacity(users.len());
        let mut hash_prefixes = HashSet::with_capacity(users.len());
        for user in users {
            let hash_result = digest(&SHA256, user.credential.as_bytes());
            let mut password_hash = [0u8; 32];
            password_hash.copy_from_slice(hash_result.as_ref());
            hash_prefixes.insert(password_hash[..8].try_into().unwrap());
            by_password_hash.insert(
                password_hash,
                AnyTlsAuthenticatedUser {
                    name: user.authenticated_user.user_key.clone(),
                    authenticated_user: Some(user.authenticated_user),
                },
            );
        }
        Self {
            by_password_hash,
            hash_prefixes,
        }
    }

    fn matches_prefix(&self, prefix: &[u8]) -> bool {
        self.hash_prefixes.contains(prefix)
    }

    fn get(&self, password_hash: &[u8]) -> Option<&AnyTlsAuthenticatedUser> {
        self.by_password_hash.get(password_hash)
    }

    pub fn len(&self) -> usize {
        self.by_password_hash.len()
    }
}

#[derive(Clone, Debug)]
struct AnyTlsAuthenticatedUser {
    name: String,
    authenticated_user: Option<AuthenticatedUser>,
}

/// AnyTLS server handler implementing TcpServerHandler
///
/// This handler receives a post-TLS stream and handles AnyTLS protocol.
/// It authenticates the client, creates a session with routing dependencies,
/// and runs the session which handles all streams internally.
#[derive(Debug)]
pub struct AnyTlsServerHandler {
    /// Authenticated users, replaceable while the listener keeps running.
    users: Arc<SharedUsers<AnyTlsUsers>>,
    /// Padding factory for traffic obfuscation
    padding: Arc<PaddingFactory>,
    /// Resolver for destination addresses
    resolver: Arc<dyn Resolver>,
    /// Proxy provider for routing decisions
    proxy_provider: Arc<ClientProxySelector>,
    /// UDP enabled for UoT support
    udp_enabled: bool,
    /// Fallback destination for failed authentication
    fallback: Option<NetLocation>,
    /// Node-side outbound dispatcher for stream dials.
    outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
}

impl AnyTlsServerHandler {
    /// Create a new AnyTLS server handler.
    ///
    /// # Arguments
    /// * `users` - Vec of (name, password) tuples for authentication
    /// * `padding` - Padding factory for traffic obfuscation
    /// * `resolver` - DNS resolver for destination addresses
    /// * `proxy_provider` - Proxy selector for routing decisions
    /// * `udp_enabled` - Whether UDP-over-TCP is enabled
    /// * `fallback` - Optional fallback destination for failed auth
    pub fn new(
        users: Vec<(String, String)>,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        fallback: Option<NetLocation>,
    ) -> Self {
        let users = users
            .into_iter()
            .map(|(name, password)| (name, password, None))
            .collect();
        Self::from_users(
            users,
            padding,
            resolver,
            proxy_provider,
            udp_enabled,
            fallback,
        )
    }

    pub fn new_authenticated(
        users: Arc<SharedUsers<AnyTlsUsers>>,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        fallback: Option<NetLocation>,
    ) -> Self {
        Self {
            users,
            padding,
            resolver,
            proxy_provider,
            udp_enabled,
            fallback,
            outbound_dispatcher: None,
        }
    }

    /// Attaches the node-side outbound dispatcher used for stream dials.
    /// `None` (the default) keeps the legacy selector direct dial.
    pub fn with_outbound_dispatcher(
        mut self,
        outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
    ) -> Self {
        self.outbound_dispatcher = outbound_dispatcher;
        self
    }

    fn from_users(
        users: Vec<(String, String, Option<AuthenticatedUser>)>,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        fallback: Option<NetLocation>,
    ) -> Self {
        // Build hash -> name map and collect prefixes
        let mut user_map = HashMap::with_capacity(users.len());
        let mut hash_prefixes = HashSet::with_capacity(users.len());

        for (name, password, authenticated_user) in users {
            let hash_result = digest(&SHA256, password.as_bytes());
            let mut password_hash = [0u8; 32];
            password_hash.copy_from_slice(hash_result.as_ref());

            // Extract 8-byte prefix for quick fallback lookup
            let prefix: [u8; 8] = password_hash[..8].try_into().unwrap();
            hash_prefixes.insert(prefix);

            user_map.insert(
                password_hash,
                AnyTlsAuthenticatedUser {
                    name,
                    authenticated_user,
                },
            );
        }

        Self {
            users: SharedUsers::new(AnyTlsUsers {
                by_password_hash: user_map,
                hash_prefixes,
            }),
            padding,
            resolver,
            proxy_provider,
            udp_enabled,
            fallback,
            outbound_dispatcher: None,
        }
    }
}

#[async_trait]
impl TcpServerHandler for AnyTlsServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_anytls_server_stream(server_stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_anytls_server_stream(server_stream, peer_addr)
            .await
    }
}

impl AnyTlsServerHandler {
    async fn setup_anytls_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        // Use StreamReader to peek at auth header without consuming
        let mut reader = StreamReader::new();

        // First, peek at the 8-byte prefix for quick fallback.
        // This allows us to reject non-AnyTLS traffic (e.g., small HTTP requests)
        // without hanging waiting for the full 32-byte hash.
        //
        // Timing side-channel note: This creates a timing difference between prefix
        // match and mismatch, but is not exploitable since enumerating 2^64 prefixes
        // is infeasible, and discovering a valid prefix doesn't help recover the
        // password or the remaining 24 bytes of the SHA256 hash.
        let prefix_data = reader.peek_slice(&mut server_stream, 8).await?;

        // Borrowed across the two peeks of one handshake only; see `SharedUsers`.
        let users = self.users.load();
        if !users.matches_prefix(prefix_data) {
            log::debug!("AnyTLS quick fallback: 8-byte prefix doesn't match any user");
            if let Some(ref fallback) = self.fallback {
                return self.fallback_to_dest(server_stream, reader, fallback).await;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authentication failed (prefix mismatch)",
            ));
        }

        // Prefix matches - now read the full 32-byte hash
        let auth_data = reader.peek_slice(&mut server_stream, 32).await?;

        let user = match users.get(auth_data) {
            Some(user) => {
                log::debug!("AnyTLS user authenticated: {}", user.name);
                // Auth succeeded - consume the header bytes
                reader.consume(32);
                user.clone()
            }
            None => {
                log::debug!("AnyTLS authentication failed: unknown password");
                // If fallback is configured, forward the connection there
                if let Some(ref fallback) = self.fallback {
                    return self.fallback_to_dest(server_stream, reader, fallback).await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authentication failed",
                ));
            }
        };

        let padding_len = reader.read_u16_be(&mut server_stream).await?;

        // Skip padding bytes (consume them from the reader)
        if padding_len > 0 {
            let _ = reader
                .read_slice(&mut *server_stream, padding_len as usize)
                .await?;
        }

        // Get any remaining unparsed data that may have been buffered
        let initial_data = reader.unparsed_data_owned();

        // Create session with all dependencies for internal stream handling
        let session = AnyTlsSession::new_server_with_initial_data(
            server_stream,
            AnyTlsServerSessionContext {
                padding: Arc::clone(&self.padding),
                resolver: Arc::clone(&self.resolver),
                proxy_provider: Arc::clone(&self.proxy_provider),
                outbound_dispatcher: self.outbound_dispatcher.clone(),
                udp_enabled: self.udp_enabled,
                user_name: user.name,
                authenticated_user: user.authenticated_user,
                peer_addr,
                initial_data,
            },
        );

        Ok(TcpServerSetupResult::connection_task(async move {
            if let Err(e) = session.run().await {
                log::debug!("AnyTLS session ended: {}", e);
            }
            Ok(())
        }))
    }

    /// Forward the connection to a fallback destination when authentication fails.
    ///
    /// This makes the server indistinguishable from a legitimate server by transparently
    /// proxying failed auth attempts to the configured fallback destination.
    async fn fallback_to_dest(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        reader: StreamReader,
        fallback: &NetLocation,
    ) -> std::io::Result<TcpServerSetupResult> {
        log::debug!("AnyTLS FALLBACK: Connecting to fallback: {}", fallback);

        // Get the unconsumed data from the reader (includes auth header)
        let unconsumed_data = reader.unparsed_data();

        // Use dispatcher when available, otherwise direct connect
        let mut dest_stream: Box<dyn AsyncStream> =
            if let Some(ref dispatcher) = self.outbound_dispatcher {
                dispatcher
                    .dial_tcp(fallback, None, &self.resolver)
                    .await
                    .map_err(|e| std::io::Error::other(format!("fallback dial failed: {e}")))?
            } else {
                let dest_addr =
                    crate::resolver::resolve_single_address(&self.resolver, fallback).await?;
                Box::new(TcpStream::connect(dest_addr).await?)
            };

        log::debug!(
            "AnyTLS FALLBACK: Connected to fallback, forwarding {} bytes",
            unconsumed_data.len()
        );

        // Forward the unconsumed data (auth header that the client sent)
        if !unconsumed_data.is_empty() {
            write_all(&mut dest_stream, unconsumed_data).await?;
            dest_stream.flush().await?;
        }

        log::debug!("AnyTLS FALLBACK: Returning owned bidirectional copy task");

        Ok(TcpServerSetupResult::connection_task(async move {
            let result = copy_bidirectional(
                &mut *client_stream,
                &mut *dest_stream,
                false, // client doesn't need initial flush
                false, // dest doesn't need initial flush
            )
            .await;

            let _ = client_stream.shutdown().await;
            let _ = dest_stream.shutdown().await;

            if let Err(e) = result {
                log::debug!("AnyTLS FALLBACK: Connection ended: {}", e);
            } else {
                log::debug!("AnyTLS FALLBACK: Connection completed");
            }
            Ok(())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to compute password hash the same way the handler does
    fn compute_password_hash(password: &str) -> [u8; 32] {
        let hash_result = digest(&SHA256, password.as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_result.as_ref());
        hash
    }

    #[test]
    fn test_password_hashing() {
        let hash = compute_password_hash("secret123");

        let expected = digest(&SHA256, b"secret123");
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(expected.as_ref());

        assert_eq!(hash, expected_bytes);
    }

    #[test]
    fn test_different_passwords_different_hashes() {
        let hash1 = compute_password_hash("pass1");
        let hash2 = compute_password_hash("pass2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_map_and_prefix_construction() {
        // Test that the handler correctly builds user map and prefix set
        let users = vec![
            ("alice".to_string(), "password1".to_string()),
            ("bob".to_string(), "password2".to_string()),
        ];

        // Compute expected hashes
        let hash1 = compute_password_hash("password1");
        let hash2 = compute_password_hash("password2");

        // Build the maps the same way the handler does
        let mut user_map = HashMap::with_capacity(users.len());
        let mut hash_prefixes = HashSet::with_capacity(users.len());

        for (name, password) in users {
            let hash = compute_password_hash(&password);
            let prefix: [u8; 8] = hash[..8].try_into().unwrap();
            hash_prefixes.insert(prefix);
            user_map.insert(hash, name);
        }

        assert_eq!(user_map.len(), 2);
        assert_eq!(hash_prefixes.len(), 2);

        // Verify slice lookups work via Borrow<[u8]>
        let prefix1_slice: &[u8] = &hash1[..8];
        let prefix2_slice: &[u8] = &hash2[..8];
        assert!(hash_prefixes.contains(prefix1_slice));
        assert!(hash_prefixes.contains(prefix2_slice));

        // Verify a random prefix is NOT in the set
        let random_prefix: &[u8] = &[0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54]; // "GET / HT"
        assert!(!hash_prefixes.contains(random_prefix));

        // Verify full hash lookup returns correct name
        let hash1_slice: &[u8] = &hash1[..];
        assert!(user_map.contains_key(hash1_slice));
        assert_eq!(user_map.get(hash1_slice).unwrap(), "alice");

        let hash2_slice: &[u8] = &hash2[..];
        assert_eq!(user_map.get(hash2_slice).unwrap(), "bob");
    }
}
