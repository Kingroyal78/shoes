use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use futures::task::noop_waker_ref;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, CryptoTlsStream, perform_crypto_handshake};
use crate::reality::{
    DEFAULT_CIPHER_SUITES, RealityClientConfig, RealityClientConnection, decode_public_key,
    decode_short_id,
};
use crate::tcp::tcp_handler::TcpClientHandler;
use crate::uuid_util::parse_uuid;
use crate::vmess::VmessTcpClientHandler;

pub trait E2eCryptoStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> E2eCryptoStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub async fn connect_reality_tcp_stream(
    tcp: TcpStream,
    server_name: &str,
    public_key: &str,
    short_id: &str,
) -> io::Result<Box<dyn E2eCryptoStream>> {
    let public_key = decode_public_key(public_key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid REALITY public key: {e}"),
        )
    })?;
    let short_id = decode_short_id(short_id).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid REALITY short_id: {e}"),
        )
    })?;
    let reality_config = RealityClientConfig {
        public_key,
        short_id,
        server_name: server_name.to_string(),
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
    };
    let reality_conn = RealityClientConnection::new(reality_config)?;
    let mut connection = CryptoConnection::new_reality_client(reality_conn);
    let mut stream: Box<dyn AsyncStream> = Box::new(tcp);

    perform_crypto_handshake(&mut connection, &mut stream, 16 * 1024).await?;

    Ok(Box::new(CryptoTlsStream::new(stream, connection)))
}

pub struct VmessE2eSession {
    client_stream: Box<dyn AsyncStream>,
    transport: MemoryTransport,
}

impl VmessE2eSession {
    pub async fn new(
        user_id: &str,
        cipher_name: &str,
        target_host: &str,
        target_port: u16,
    ) -> io::Result<Self> {
        parse_uuid(user_id).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid VMess user id: {e}"),
            )
        })?;
        validate_vmess_cipher(cipher_name)?;

        let handler = VmessTcpClientHandler::new(cipher_name, user_id, false);
        let transport = MemoryTransport::new();
        let target =
            ResolvedLocation::new(NetLocation::new(Address::from(target_host)?, target_port));
        let result = handler
            .setup_client_tcp_stream(Box::new(transport.clone()), target)
            .await?;
        if result
            .early_data
            .as_ref()
            .is_some_and(|data| !data.is_empty())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess setup returned unexpected early data",
            ));
        }

        Ok(Self {
            client_stream: result.client_stream,
            transport,
        })
    }

    pub async fn encode_request(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
        self.client_stream.write_all(request).await?;
        self.client_stream.flush().await?;
        Ok(self.transport.take_outbound())
    }

    pub fn feed_encrypted_response(
        &mut self,
        encrypted: &[u8],
        decrypted: &mut Vec<u8>,
    ) -> io::Result<()> {
        self.transport.push_inbound(encrypted);
        self.drain_decrypted_response(decrypted, true).map(|_| ())
    }

    pub fn finish_response(&mut self, decrypted: &mut Vec<u8>) -> io::Result<()> {
        self.transport.close_inbound();
        self.drain_decrypted_response(decrypted, false).map(|_| ())
    }

    fn drain_decrypted_response(
        &mut self,
        decrypted: &mut Vec<u8>,
        allow_pending: bool,
    ) -> io::Result<bool> {
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        let mut buf = [0u8; 8192];

        loop {
            let mut read_buf = ReadBuf::new(&mut buf);
            match Pin::new(&mut self.client_stream).poll_read(&mut cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        return Ok(true);
                    }
                    decrypted.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending if allow_pending => return Ok(false),
                Poll::Pending => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VMess response decoder is still waiting after encrypted response EOF",
                    ));
                }
            }
        }
    }
}

fn validate_vmess_cipher(cipher_name: &str) -> io::Result<()> {
    match cipher_name {
        ""
        | "any"
        | "auto"
        | "aes-128-gcm"
        | "chacha20-poly1305"
        | "chacha20-ietf-poly1305"
        | "none"
        | "zero" => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported VMess security `{cipher_name}`"),
        )),
    }
}

#[derive(Clone, Debug)]
struct MemoryTransport {
    state: Arc<Mutex<MemoryTransportState>>,
}

#[derive(Debug, Default)]
struct MemoryTransportState {
    inbound: VecDeque<u8>,
    inbound_closed: bool,
    outbound: Vec<u8>,
    read_waker: Option<Waker>,
}

impl MemoryTransport {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryTransportState::default())),
        }
    }

    fn push_inbound(&self, bytes: &[u8]) {
        let waker = {
            let mut state = self.state.lock().expect("memory transport mutex poisoned");
            state.inbound.extend(bytes);
            state.read_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn close_inbound(&self) {
        let waker = {
            let mut state = self.state.lock().expect("memory transport mutex poisoned");
            state.inbound_closed = true;
            state.read_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn take_outbound(&self) -> Vec<u8> {
        let mut state = self.state.lock().expect("memory transport mutex poisoned");
        std::mem::take(&mut state.outbound)
    }
}

impl AsyncRead for MemoryTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut state = self.state.lock().expect("memory transport mutex poisoned");
        if state.inbound.is_empty() {
            if state.inbound_closed {
                return Poll::Ready(Ok(()));
            }
            state.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let copy_len = {
            let contiguous = state.inbound.make_contiguous();
            let copy_len = contiguous.len().min(buf.remaining());
            buf.put_slice(&contiguous[..copy_len]);
            copy_len
        };
        state.inbound.drain(..copy_len);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.lock().expect("memory transport mutex poisoned");
        state.outbound.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncPing for MemoryTransport {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for MemoryTransport {}
