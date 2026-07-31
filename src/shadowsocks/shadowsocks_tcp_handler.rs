use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::cipher::{AES_128, AES_256, DecryptingKey, DecryptionContext, UnboundCipherKey};
#[cfg(test)]
use aws_lc_rs::cipher::{EncryptingKey, EncryptionContext};
use log::debug;
use parking_lot::Mutex;
use rand::{Rng, RngExt};
use tokio::io::AsyncWriteExt;

use super::salt_checker::SaltChecker;
use super::timed_salt_checker::TimedSaltChecker;
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::h2mux::{
    MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, PrependStream, handle_h2mux_session_with_context,
};
use crate::resolver::Resolver;
use crate::socks_handler::{read_location, try_write_location_to_vec, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    AuthenticatedUser, ServerUser, TcpClientHandler, TcpClientSetupResult, TcpServerHandler,
    TcpServerSetupResult,
};
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};
use crate::util::write_all;

use super::blake3_key::{
    AEAD2022_USER_HASH_LEN, Blake3Key, create_shadowsocks_2022_identity_subkey,
    shadowsocks_2022_user_hash,
};
use super::default_key::DefaultKey;
use super::shadowsocks_cipher::ShadowsocksCipher;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_obfs::ShadowsocksHttpObfs;
use super::shadowsocks_stream::{ShadowsocksStream, try_decrypt_aead_length};
use super::shadowsocks_stream_type::ShadowsocksStreamType;

#[derive(Debug)]
pub struct ShadowsocksTcpHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    aead2022: bool,
    salt_checker: Option<Arc<Mutex<dyn SaltChecker>>>,
    udp_enabled: bool,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
    authenticated_user: Option<AuthenticatedUser>,
    multi_user_keys: Option<Vec<ShadowsocksUserKey>>,
    aead2022_identity_psk: Option<Box<[u8]>>,
    http_obfs: Option<ShadowsocksHttpObfs>,
    h2mux_server_enabled: bool,
    h2mux_padding: bool,
    /// Node-side outbound dispatcher for server handler use.
    outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
}

#[derive(Clone, Debug)]
struct ShadowsocksUserKey {
    key: Arc<Box<dyn ShadowsocksKey>>,
    aead2022_user_hash: Option<[u8; AEAD2022_USER_HASH_LEN]>,
    authenticated_user: AuthenticatedUser,
}

impl ShadowsocksTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: false,
            salt_checker: None,
            udp_enabled,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
            authenticated_user: None,
            multi_user_keys: None,
            aead2022_identity_psk: None,
            http_obfs: None,
            h2mux_server_enabled: false,
            h2mux_padding: false,
            outbound_dispatcher: None,
        }
    }

    /// Attaches the node-side outbound dispatcher used for the TCP forward
    /// dial. `None` (the default) keeps the legacy selector direct dial.
    pub fn with_outbound_dispatcher(
        mut self,
        outbound_dispatcher: Option<Arc<crate::v2board::outbound::dispatcher::OutboundDispatcher>>,
    ) -> Self {
        self.outbound_dispatcher = outbound_dispatcher;
        self
    }

    pub fn with_http_obfs(mut self, http_obfs: ShadowsocksHttpObfs) -> Self {
        self.http_obfs = Some(http_obfs);
        self
    }

    /// Enable sing-mux h2mux server handling for the magic destination.
    ///
    /// It is disabled by default so a client cannot turn a regular
    /// Shadowsocks listener into a multiplexed session without server-side
    /// configuration. The padding setting is negotiated strictly: the client
    /// session header must match it.
    pub fn with_h2mux_server(mut self, padding: bool) -> Self {
        self.h2mux_server_enabled = true;
        self.h2mux_padding = padding;
        self
    }

    pub fn new_v2board_server(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        authenticated_user: AuthenticatedUser,
    ) -> Self {
        let mut handler = Self::new_server(cipher, password, udp_enabled, proxy_selector, resolver);
        handler.authenticated_user = Some(authenticated_user);
        handler
    }

    pub fn new_v2board_multi_server(
        cipher: ShadowsocksCipher,
        users: Vec<ServerUser>,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let multi_user_keys = users
            .into_iter()
            .map(|user| ShadowsocksUserKey {
                key: Arc::new(Box::new(DefaultKey::new(
                    &user.credential,
                    cipher.algorithm().key_len(),
                ))),
                aead2022_user_hash: None,
                authenticated_user: user.authenticated_user,
            })
            .collect();
        let mut handler = Self::new_server(cipher, "", udp_enabled, proxy_selector, resolver);
        handler.multi_user_keys = Some(multi_user_keys);
        handler
    }

    pub fn new_v2board_aead2022_multi_server(
        cipher: ShadowsocksCipher,
        server_psk: Vec<u8>,
        users: Vec<(Vec<u8>, AuthenticatedUser)>,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let identity_psk = server_psk.clone().into_boxed_slice();
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            server_psk.into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        let multi_user_keys = users
            .into_iter()
            .map(|(user_psk, authenticated_user)| ShadowsocksUserKey {
                aead2022_user_hash: Some(shadowsocks_2022_user_hash(&user_psk)),
                key: Arc::new(Box::new(Blake3Key::new(
                    user_psk.into_boxed_slice(),
                    cipher.algorithm().key_len(),
                ))),
                authenticated_user,
            })
            .collect();
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
            udp_enabled,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
            authenticated_user: None,
            multi_user_keys: Some(multi_user_keys),
            aead2022_identity_psk: Some(identity_psk),
            http_obfs: None,
            h2mux_server_enabled: false,
            h2mux_padding: false,
            outbound_dispatcher: None,
        }
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(cipher: ShadowsocksCipher, password: &str, udp_enabled: bool) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: false,
            salt_checker: None,
            udp_enabled,
            proxy_selector: None,
            resolver: None,
            authenticated_user: None,
            multi_user_keys: None,
            aead2022_identity_psk: None,
            http_obfs: None,
            h2mux_server_enabled: false,
            h2mux_padding: false,
            outbound_dispatcher: None,
        }
    }

    /// Create a new AEAD2022 handler for server use
    pub fn new_aead2022_server(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
            udp_enabled,
            proxy_selector: Some(proxy_selector),
            resolver: Some(resolver),
            authenticated_user: None,
            multi_user_keys: None,
            aead2022_identity_psk: Some(key_bytes.to_vec().into_boxed_slice()),
            http_obfs: None,
            h2mux_server_enabled: false,
            h2mux_padding: false,
            outbound_dispatcher: None,
        }
    }

    /// Create a new AEAD2022 handler for client use
    pub fn new_aead2022_client(
        cipher: ShadowsocksCipher,
        key_bytes: &[u8],
        udp_enabled: bool,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
            udp_enabled,
            proxy_selector: None,
            resolver: None,
            authenticated_user: None,
            multi_user_keys: None,
            aead2022_identity_psk: None,
            http_obfs: None,
            h2mux_server_enabled: false,
            h2mux_padding: false,
            outbound_dispatcher: None,
        }
    }

    async fn select_server_user(
        &self,
        server_stream: Box<dyn AsyncStream>,
        stream_type: ShadowsocksStreamType,
    ) -> std::io::Result<(
        Box<dyn AsyncStream>,
        Arc<Box<dyn ShadowsocksKey>>,
        Option<AuthenticatedUser>,
        Option<Arc<Mutex<dyn SaltChecker>>>,
    )> {
        let Some(users) = &self.multi_user_keys else {
            return Ok((
                server_stream,
                self.key.clone(),
                self.authenticated_user.clone(),
                self.salt_checker.clone(),
            ));
        };
        if users.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "multi-user Shadowsocks handler has no users",
            ));
        }

        match stream_type {
            ShadowsocksStreamType::Aead => {
                let (stream, key, user) = self
                    .select_legacy_server_user(server_stream, users, stream_type)
                    .await?;
                Ok((stream, key, user, self.salt_checker.clone()))
            }
            ShadowsocksStreamType::AEAD2022Server => {
                self.select_aead2022_server_user(server_stream, users).await
            }
            ShadowsocksStreamType::AEAD2022Client => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "client stream type is invalid for Shadowsocks server user selection",
            )),
        }
    }

    async fn select_legacy_server_user(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        users: &[ShadowsocksUserKey],
        stream_type: ShadowsocksStreamType,
    ) -> std::io::Result<(
        Box<dyn AsyncStream>,
        Arc<Box<dyn ShadowsocksKey>>,
        Option<AuthenticatedUser>,
    )> {
        let salt_len = self.cipher.salt_len();
        let encrypted_length_len = 2 + super::aead_util::TAG_LEN;
        let probe_len = salt_len + encrypted_length_len;
        let mut reader = StreamReader::new_with_buffer_size(probe_len + 1024);
        let probe = reader
            .read_slice(&mut server_stream, probe_len)
            .await?
            .to_vec();
        let salt = &probe[..salt_len];
        let encrypted_length = &probe[salt_len..];

        for user in users {
            if try_decrypt_aead_length(
                self.cipher.algorithm(),
                user.key.as_ref().as_ref(),
                salt,
                encrypted_length,
                stream_type.max_payload_len(),
            )
            .is_ok()
            {
                let stream = prepend_probe(server_stream, reader, probe);
                return Ok((
                    stream,
                    user.key.clone(),
                    Some(user.authenticated_user.clone()),
                ));
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no matching Shadowsocks user",
        ))
    }

    async fn select_aead2022_server_user(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        users: &[ShadowsocksUserKey],
    ) -> std::io::Result<(
        Box<dyn AsyncStream>,
        Arc<Box<dyn ShadowsocksKey>>,
        Option<AuthenticatedUser>,
        Option<Arc<Mutex<dyn SaltChecker>>>,
    )> {
        let salt_len = self.cipher.salt_len();
        let encrypted_identity_len = AEAD2022_USER_HASH_LEN;
        let fixed_header_len = 11 + super::aead_util::TAG_LEN;
        let probe_len = salt_len + encrypted_identity_len + fixed_header_len;
        let mut reader = StreamReader::new_with_buffer_size(probe_len + 1024);
        let probe = reader
            .read_slice(&mut server_stream, probe_len)
            .await?
            .to_vec();
        let request_salt = &probe[..salt_len];

        if let Some(salt_checker) = &self.salt_checker
            && !salt_checker.lock().insert_and_check(request_salt)
        {
            return Err(std::io::Error::other("got duplicate salt"));
        }

        let encrypted_identity_header = &probe[salt_len..salt_len + encrypted_identity_len];
        let Some(identity_psk) = &self.aead2022_identity_psk else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 multi-user handler is missing server identity PSK",
            ));
        };
        let user_hash = decrypt_aead2022_identity_header(
            identity_psk,
            request_salt,
            encrypted_identity_header,
        )?;

        for user in users {
            if user.aead2022_user_hash == Some(user_hash) {
                let mut initial_data = Vec::with_capacity(probe.len() - encrypted_identity_len);
                initial_data.extend_from_slice(request_salt);
                initial_data.extend_from_slice(&probe[salt_len + encrypted_identity_len..]);
                if let Some(unparsed) = reader.unparsed_data_owned() {
                    initial_data.extend_from_slice(&unparsed);
                }
                let stream: Box<dyn AsyncStream> = Box::new(PrependStream::new(
                    server_stream,
                    Some(initial_data.into_boxed_slice()),
                ));
                return Ok((
                    stream,
                    user.key.clone(),
                    Some(user.authenticated_user.clone()),
                    None,
                ));
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no matching Shadowsocks 2022 user",
        ))
    }
}

fn prepend_probe(
    server_stream: Box<dyn AsyncStream>,
    reader: StreamReader,
    mut probe: Vec<u8>,
) -> Box<dyn AsyncStream> {
    if let Some(unparsed) = reader.unparsed_data_owned() {
        probe.extend_from_slice(&unparsed);
    }
    Box::new(PrependStream::new(
        server_stream,
        Some(probe.into_boxed_slice()),
    ))
}

fn decrypt_aead2022_identity_header(
    server_key: &[u8],
    request_salt: &[u8],
    encrypted_identity_header: &[u8],
) -> std::io::Result<[u8; AEAD2022_USER_HASH_LEN]> {
    let identity_subkey = create_shadowsocks_2022_identity_subkey(server_key, request_salt)?;
    decrypt_aes_2022_block(&identity_subkey, encrypted_identity_header)
}

fn decrypt_aes_2022_block(
    key: &[u8],
    encrypted_block: &[u8],
) -> std::io::Result<[u8; AEAD2022_USER_HASH_LEN]> {
    if encrypted_block.len() != AEAD2022_USER_HASH_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid encrypted identity header length {}, expected {}",
                encrypted_block.len(),
                AEAD2022_USER_HASH_LEN
            ),
        ));
    }
    let algorithm = match key.len() {
        16 => &AES_128,
        32 => &AES_256,
        len => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported Shadowsocks 2022 AES key length {len}"),
            ));
        }
    };
    let unbound_key = UnboundCipherKey::new(algorithm, key).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Shadowsocks 2022 AES identity subkey",
        )
    })?;
    let decrypting_key = DecryptingKey::ecb(unbound_key)
        .map_err(|_| std::io::Error::other("failed to initialize AES ECB decryptor"))?;
    let mut block = [0u8; AEAD2022_USER_HASH_LEN];
    block.copy_from_slice(encrypted_block);
    decrypting_key
        .decrypt(&mut block, DecryptionContext::None)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "EIH decrypt failed"))?;
    Ok(block)
}

#[cfg(test)]
fn encrypt_aes_2022_block(
    key: &[u8],
    block: &[u8; AEAD2022_USER_HASH_LEN],
) -> std::io::Result<[u8; AEAD2022_USER_HASH_LEN]> {
    let algorithm = match key.len() {
        16 => &AES_128,
        32 => &AES_256,
        len => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported Shadowsocks 2022 AES key length {len}"),
            ));
        }
    };
    let unbound_key = UnboundCipherKey::new(algorithm, key).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Shadowsocks 2022 AES identity subkey",
        )
    })?;
    let encrypting_key = EncryptingKey::ecb(unbound_key)
        .map_err(|_| std::io::Error::other("failed to initialize AES ECB encryptor"))?;
    let mut encrypted = *block;
    encrypting_key
        .less_safe_encrypt(&mut encrypted, EncryptionContext::None)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "EIH encrypt failed"))?;
    Ok(encrypted)
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(server_stream, None)
            .await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if let Some(http_obfs) = &self.http_obfs {
            server_stream = http_obfs.accept(server_stream).await?;
        }

        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Server
        } else {
            ShadowsocksStreamType::Aead
        };
        let (server_stream, key, authenticated_user, salt_checker) =
            self.select_server_user(server_stream, stream_type).await?;

        let mut server_stream = ShadowsocksStream::new(
            server_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            key,
            salt_checker,
        );

        let mut stream_reader = StreamReader::new_with_buffer_size(1024);

        // Blocks waiting for the location since the client always sends it before expecting a response.
        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        if self.aead2022 {
            let padding_len = stream_reader.read_u16_be(&mut server_stream).await?;

            if padding_len > 0 {
                if padding_len > 900 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid padding length: {padding_len}"),
                    ));
                }
                stream_reader
                    .read_slice(&mut server_stream, padding_len as usize)
                    .await?;
            }
        }

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            if !self.h2mux_server_enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "h2mux is disabled for this Shadowsocks server",
                ));
            }

            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");
            let udp_enabled = self.udp_enabled;
            let expected_padding = self.h2mux_padding;

            let initial_data = stream_reader.unparsed_data_owned();
            let outbound_dispatcher = self.outbound_dispatcher.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_h2mux_session_with_context(
                    server_stream,
                    initial_data,
                    udp_enabled,
                    proxy_selector,
                    resolver,
                    outbound_dispatcher,
                    expected_padding,
                    authenticated_user,
                    peer_addr,
                )
                .await
                {
                    debug!("Shadowsocks h2mux session ended: {}", e);
                }
            });

            return Ok(TcpServerSetupResult::AlreadyHandled);
        }

        // Checks for UDP-over-TCP (UoT) magic addresses
        if let Address::Hostname(host) = remote_location.address() {
            if !self.udp_enabled && (host == UOT_V1_MAGIC_ADDRESS || host == UOT_V2_MAGIC_ADDRESS) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "UDP-over-TCP is disabled for this Shadowsocks server",
                ));
            }
            if host == UOT_V1_MAGIC_ADDRESS {
                // UoT V1: Multi-destination UDP
                // Each packet has: ATYP + address + port + length + data
                let mut uot_stream = UotV1ServerStream::new_uot(server_stream);

                // Feeds unparsed data since first UoT packet might be in same TCP segment
                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    log::debug!(
                        "Shadowsocks UoT V1: feeding {} bytes of initial data",
                        unparsed_data.len()
                    );
                    uot_stream.feed_initial_data(unparsed_data);
                }

                return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                    stream: Box::new(uot_stream),
                    need_initial_flush: false,
                    proxy_selector: self
                        .proxy_selector
                        .clone()
                        .expect("proxy_selector required for server handler"),
                    outbound_dispatcher: self.outbound_dispatcher.clone(),
                    authenticated_user: authenticated_user.clone(),
                });
            } else if host == UOT_V2_MAGIC_ADDRESS {
                // UoT V2: Read request header first
                // Request: isConnect(u8) + ATYP + address + port
                // Note: V2 uses SOCKS address format (0x01=IPv4, 0x03=Domain, 0x04=IPv6),
                // NOT UoT address format!
                let is_connect = stream_reader.read_u8(&mut server_stream).await?;
                log::debug!("Shadowsocks UoT V2: is_connect = {}", is_connect);

                // Reads destination address using SOCKS address format
                let destination = read_location(&mut server_stream, &mut stream_reader).await?;
                log::debug!("Shadowsocks UoT V2: destination = {:?}", destination);

                if is_connect == 1 {
                    // V2 Connect mode: Single destination, length-prefixed packets only
                    // Reuse UotV2Stream which has identical format: length(u16be) + data
                    let unparsed_data = stream_reader.unparsed_data();
                    let mut uot_v2_stream = UotV2Stream::new(server_stream);
                    if !unparsed_data.is_empty() {
                        uot_v2_stream.feed_initial_read_data(unparsed_data)?;
                    }

                    return Ok(TcpServerSetupResult::BidirectionalUdp {
                        remote_location: destination,
                        stream: Box::new(uot_v2_stream),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                        outbound_dispatcher: self.outbound_dispatcher.clone(),
                        authenticated_user: authenticated_user.clone(),
                    });
                } else {
                    // V2 Non-connect mode: Same as V1 (multi-destination)
                    let mut uot_stream = UotV1ServerStream::new_uot(server_stream);
                    let unparsed_data = stream_reader.unparsed_data();
                    if !unparsed_data.is_empty() {
                        log::debug!(
                            "Shadowsocks UoT V2 non-connect: feeding {} bytes of initial data",
                            unparsed_data.len()
                        );
                        uot_stream.feed_initial_data(unparsed_data);
                    }

                    return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                        stream: Box::new(uot_stream),
                        need_initial_flush: false,
                        proxy_selector: self
                            .proxy_selector
                            .clone()
                            .expect("proxy_selector required for server handler"),
                        outbound_dispatcher: self.outbound_dispatcher.clone(),
                        authenticated_user: authenticated_user.clone(),
                    });
                }
            }
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(server_stream),
            // Lets the IV be written when data actually arrives rather than flushing here.
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
            outbound_dispatcher: self.outbound_dispatcher.clone(),
            authenticated_user,
        })
    }
}

#[async_trait]
impl TcpClientHandler for ShadowsocksTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        ));

        let mut location_vec = try_write_location_to_vec(remote_location.location())?;

        if self.aead2022 {
            let location_len = location_vec.len();

            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);

            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);

            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;
        client_stream.flush().await?;

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        use crate::uot::{UOT_V2_MAGIC_ADDRESS, UotV2Stream};

        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        ));

        // UoT V2 connect mode: Single destination. Writes magic address first.
        let magic_location =
            NetLocation::new(Address::Hostname(UOT_V2_MAGIC_ADDRESS.to_string()), 0);
        let mut location_vec = write_location_to_vec(&magic_location);

        if self.aead2022 {
            let location_len = location_vec.len();
            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);
            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);
            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;

        // Writes UoT V2 request header: isConnect(1) + SOCKS address
        let mut uot_header = Vec::with_capacity(64);
        uot_header.push(1u8); // isConnect = 1 (connect mode)
        let target_bytes = try_write_location_to_vec(target.location())?;
        uot_header.extend_from_slice(&target_bytes);
        write_all(&mut client_stream, &uot_header).await?;
        client_stream.flush().await?;

        // Uses UotV2Stream for length-prefixed packets
        let message_stream = UotV2Stream::new(client_stream);

        Ok(Box::new(message_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2mux_server_requires_explicit_enablement() {
        let cipher: ShadowsocksCipher = "aes-128-gcm".try_into().unwrap();
        let handler = ShadowsocksTcpHandler::new_client(cipher, "password", false);
        assert!(!handler.h2mux_server_enabled);

        let handler = handler.with_h2mux_server(true);
        assert!(handler.h2mux_server_enabled);
        assert!(handler.h2mux_padding);
    }

    #[test]
    fn aead2022_identity_header_decodes_user_hash_aes128() {
        assert_identity_header_round_trip(16);
    }

    #[test]
    fn aead2022_identity_header_decodes_user_hash_aes256() {
        assert_identity_header_round_trip(32);
    }

    fn assert_identity_header_round_trip(key_len: usize) {
        let server_psk = vec![1u8; key_len];
        let request_salt = vec![2u8; key_len];
        let user_psk = vec![3u8; key_len];
        let user_hash = shadowsocks_2022_user_hash(&user_psk);
        let identity_subkey =
            create_shadowsocks_2022_identity_subkey(&server_psk, &request_salt).unwrap();
        let encrypted_identity_header =
            encrypt_aes_2022_block(&identity_subkey, &user_hash).unwrap();

        let decoded = decrypt_aead2022_identity_header(
            &server_psk,
            &request_salt,
            &encrypted_identity_header,
        )
        .unwrap();

        assert_eq!(decoded, user_hash);
    }
}
