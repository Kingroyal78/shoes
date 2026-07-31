use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const CONTENT_HANDSHAKE: u8 = 0x16;
const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CONTENT_APPLICATION_DATA: u8 = 0x17;
const TLS_1_0: [u8; 2] = [0x03, 0x01];
const TLS_1_2: [u8; 2] = [0x03, 0x03];
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SESSION_TICKET: u16 = 0x0023;
const MAX_TLS_RECORD_PAYLOAD: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct ObfsTlsConfig {
    pub expected_hosts: Vec<String>,
    pub max_client_hello_bytes: usize,
    pub max_initial_payload: usize,
}

impl Default for ObfsTlsConfig {
    fn default() -> Self {
        Self {
            expected_hosts: Vec::new(),
            max_client_hello_bytes: 32 * 1024,
            max_initial_payload: MAX_TLS_RECORD_PAYLOAD,
        }
    }
}

pub struct ObfsTlsServerHandler {
    config: ObfsTlsConfig,
    inner: Arc<dyn TcpServerHandler>,
}

impl fmt::Debug for ObfsTlsServerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsTlsServerHandler")
            .field("config", &self.config)
            .field("inner", &self.inner)
            .finish()
    }
}

impl ObfsTlsServerHandler {
    pub fn new(mut config: ObfsTlsConfig, inner: Arc<dyn TcpServerHandler>) -> Self {
        config.expected_hosts = config
            .expected_hosts
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        Self { config, inner }
    }
}

#[async_trait]
impl TcpServerHandler for ObfsTlsServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        self.setup_server_stream_with_peer_addr(stream, None).await
    }

    async fn setup_server_stream_with_peer_addr(
        &self,
        mut stream: Box<dyn AsyncStream>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> io::Result<TcpServerSetupResult> {
        validate_config(&self.config)?;
        let hello = read_client_hello(&mut stream, self.config.max_client_hello_bytes).await?;
        if hello.initial_payload.len() > self.config.max_initial_payload {
            return invalid("simple-obfs TLS initial payload exceeds configured limit");
        }
        if !self.config.expected_hosts.is_empty() {
            let host = hello
                .server_name
                .as_deref()
                .ok_or_else(|| invalid_error("simple-obfs TLS ClientHello has no SNI"))?;
            if !self
                .config
                .expected_hosts
                .iter()
                .any(|expected| host.eq_ignore_ascii_case(expected))
            {
                return invalid("simple-obfs TLS SNI does not match configuration");
            }
        }

        let obfs_stream = ObfsTlsStream::new(stream, hello.session_id, hello.initial_payload);
        self.inner
            .setup_server_stream_with_peer_addr(Box::new(obfs_stream), peer_addr)
            .await
    }
}

struct ParsedClientHello {
    session_id: [u8; 32],
    server_name: Option<String>,
    initial_payload: Vec<u8>,
}

async fn read_client_hello(
    stream: &mut Box<dyn AsyncStream>,
    max_hello_bytes: usize,
) -> io::Result<ParsedClientHello> {
    let mut record_header = [0u8; 5];
    stream.read_exact(&mut record_header).await?;
    if record_header[0] != CONTENT_HANDSHAKE
        || record_header[1] != 0x03
        || !matches!(record_header[2], 0x01..=0x03)
    {
        return invalid("simple-obfs TLS connection does not start with a TLS ClientHello");
    }
    let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
    if record_len == 0 || record_len + 5 > max_hello_bytes {
        return invalid("simple-obfs TLS ClientHello exceeds configured limit");
    }
    let mut record = vec![0u8; record_len];
    stream.read_exact(&mut record).await?;
    parse_client_hello(&record)
}

fn parse_client_hello(record: &[u8]) -> io::Result<ParsedClientHello> {
    let mut cursor = Cursor::new(record);
    if cursor.u8()? != 0x01 {
        return invalid("simple-obfs TLS handshake is not ClientHello");
    }
    let handshake_len = cursor.u24()?;
    if handshake_len != cursor.remaining() {
        return invalid("simple-obfs TLS ClientHello length is inconsistent");
    }
    if cursor.take(2)? != TLS_1_2 {
        return invalid("simple-obfs TLS ClientHello legacy version is not TLS 1.2");
    }
    cursor.take(32)?;
    let session_id_len = cursor.u8()? as usize;
    if session_id_len != 32 {
        return invalid("simple-obfs TLS ClientHello session ID must be 32 bytes");
    }
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(cursor.take(session_id_len)?);
    let cipher_suites_len = cursor.u16()? as usize;
    if cipher_suites_len < 2 || !cipher_suites_len.is_multiple_of(2) {
        return invalid("simple-obfs TLS cipher-suite vector is malformed");
    }
    cursor.take(cipher_suites_len)?;
    let compression_len = cursor.u8()? as usize;
    if compression_len == 0 {
        return invalid("simple-obfs TLS compression-method vector is empty");
    }
    cursor.take(compression_len)?;
    let extensions_len = cursor.u16()? as usize;
    if extensions_len != cursor.remaining() {
        return invalid("simple-obfs TLS extension length is inconsistent");
    }

    let mut server_name = None;
    let mut initial_payload = None;
    while cursor.remaining() > 0 {
        let extension_type = cursor.u16()?;
        let extension_len = cursor.u16()? as usize;
        let extension = cursor.take(extension_len)?;
        match extension_type {
            EXT_SESSION_TICKET if initial_payload.replace(extension.to_vec()).is_some() => {
                return invalid("simple-obfs TLS has duplicate session-ticket extensions");
            }
            EXT_SERVER_NAME => {
                let name = parse_server_name(extension)?;
                if server_name.replace(name).is_some() {
                    return invalid("simple-obfs TLS has duplicate SNI extensions");
                }
            }
            _ => {}
        }
    }
    let initial_payload = initial_payload
        .filter(|payload| !payload.is_empty())
        .ok_or_else(|| invalid_error("simple-obfs TLS session ticket carries no payload"))?;

    Ok(ParsedClientHello {
        session_id,
        server_name,
        initial_payload,
    })
}

fn parse_server_name(extension: &[u8]) -> io::Result<String> {
    let mut cursor = Cursor::new(extension);
    let list_len = cursor.u16()? as usize;
    if list_len != cursor.remaining() {
        return invalid("simple-obfs TLS SNI list length is inconsistent");
    }
    let name_type = cursor.u8()?;
    if name_type != 0 {
        return invalid("simple-obfs TLS SNI is not a host_name");
    }
    let name_len = cursor.u16()? as usize;
    let name = cursor.take(name_len)?;
    if cursor.remaining() != 0
        || name.is_empty()
        || !name.is_ascii()
        || name.iter().any(|byte| *byte <= 0x20 || *byte == 0x7f)
    {
        return invalid("simple-obfs TLS SNI host is malformed");
    }
    std::str::from_utf8(name)
        .map(str::to_ascii_lowercase)
        .map_err(|_| invalid_error("simple-obfs TLS SNI is not UTF-8"))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_error("simple-obfs TLS length overflow"))?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid_error("simple-obfs TLS structure is truncated"))?;
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> io::Result<usize> {
        let bytes = self.take(3)?;
        Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
    }
}

struct ObfsTlsStream {
    inner: Box<dyn AsyncStream>,
    initial_payload: Vec<u8>,
    initial_offset: usize,
    read_header: [u8; 5],
    read_header_len: usize,
    read_payload_remaining: usize,
    read_eof: bool,
    session_id: [u8; 32],
    first_write: bool,
    pending_write: Vec<u8>,
    pending_write_offset: usize,
}

impl ObfsTlsStream {
    fn new(inner: Box<dyn AsyncStream>, session_id: [u8; 32], initial_payload: Vec<u8>) -> Self {
        Self {
            inner,
            initial_payload,
            initial_offset: 0,
            read_header: [0; 5],
            read_header_len: 0,
            read_payload_remaining: 0,
            read_eof: false,
            session_id,
            first_write: true,
            pending_write: Vec::new(),
            pending_write_offset: 0,
        }
    }

    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_write_offset < self.pending_write.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &self.pending_write[self.pending_write_offset..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "simple-obfs TLS underlying stream wrote zero bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => self.pending_write_offset += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        self.pending_write.clear();
        self.pending_write_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn prepare_server_hello(&mut self, payload: &[u8]) {
        let mut random = [0u8; 32];
        rand::rng().fill_bytes(&mut random);
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        random[..4].copy_from_slice(&unix_time.to_be_bytes());

        // TLS 1.2 ServerHello with session-id echo and three commonplace
        // extensions.  This is a syntactic cover handshake; no TLS keys exist.
        let mut body = Vec::with_capacity(87);
        body.extend_from_slice(&TLS_1_2);
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&0xcca8u16.to_be_bytes());
        body.push(0);
        let extensions: [u8; 15] = [
            0xff, 0x01, 0, 1, 0, // renegotiation_info
            0, 0x17, 0, 0, // extended_master_secret
            0, 0x0b, 0, 2, 1, 0, // ec_point_formats
        ];
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let handshake_len = body.len();
        self.pending_write.push(CONTENT_HANDSHAKE);
        self.pending_write.extend_from_slice(&TLS_1_0);
        self.pending_write
            .extend_from_slice(&((handshake_len + 4) as u16).to_be_bytes());
        self.pending_write.push(0x02);
        self.pending_write
            .push(((handshake_len >> 16) & 0xff) as u8);
        self.pending_write.push(((handshake_len >> 8) & 0xff) as u8);
        self.pending_write.push((handshake_len & 0xff) as u8);
        self.pending_write.extend_from_slice(&body);
        self.pending_write.extend_from_slice(&[
            CONTENT_CHANGE_CIPHER_SPEC,
            TLS_1_2[0],
            TLS_1_2[1],
            0,
            1,
            1,
        ]);
        append_record(&mut self.pending_write, CONTENT_HANDSHAKE, payload);
    }
}

impl AsyncRead for ObfsTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 || self.read_eof {
            return Poll::Ready(Ok(()));
        }
        if self.initial_offset < self.initial_payload.len() {
            let remaining = &self.initial_payload[self.initial_offset..];
            let length = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..length]);
            self.initial_offset += length;
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.read_payload_remaining > 0 {
                let before = buf.filled().len();
                let mut scratch = [0u8; 8192];
                let max = self
                    .read_payload_remaining
                    .min(buf.remaining())
                    .min(scratch.len());
                let mut nested = ReadBuf::new(&mut scratch[..max]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut nested) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = nested.filled().len();
                        if read == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF inside simple-obfs TLS application record",
                            )));
                        }
                        buf.put_slice(&nested.filled()[..read]);
                        self.read_payload_remaining -= read;
                        debug_assert_eq!(buf.filled().len(), before + read);
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            while self.read_header_len < self.read_header.len() {
                let start = self.read_header_len;
                let mut scratch = [0u8; 5];
                let mut nested = ReadBuf::new(&mut scratch[..self.read_header.len() - start]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut nested) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = nested.filled().len();
                        if read == 0 {
                            if self.read_header_len == 0 {
                                self.read_eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "EOF inside simple-obfs TLS record header",
                            )));
                        }
                        self.read_header[start..start + read]
                            .copy_from_slice(&nested.filled()[..read]);
                        self.read_header_len += read;
                    }
                }
            }
            if self.read_header[0] != CONTENT_APPLICATION_DATA || self.read_header[1..3] != TLS_1_2
            {
                return Poll::Ready(invalid(
                    "simple-obfs TLS expected an application-data record",
                ));
            }
            self.read_payload_remaining =
                u16::from_be_bytes([self.read_header[3], self.read_header[4]]) as usize;
            self.read_header_len = 0;
            if self.read_payload_remaining > MAX_TLS_RECORD_PAYLOAD {
                return Poll::Ready(invalid(
                    "simple-obfs TLS application record exceeds 16384 bytes",
                ));
            }
        }
    }
}

impl AsyncWrite for ObfsTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.pending_write.is_empty() {
            match self.poll_drain_write(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = buf.len().min(MAX_TLS_RECORD_PAYLOAD);
        if self.first_write {
            self.prepare_server_hello(&buf[..length]);
            self.first_write = false;
        } else {
            append_record(
                &mut self.pending_write,
                CONTENT_APPLICATION_DATA,
                &buf[..length],
            );
        }
        // The plaintext is now accepted into a bounded internal buffer.  Make a
        // best-effort write without changing the accepted byte count.
        if let Poll::Ready(Err(error)) = self.poll_drain_write(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
        }
    }
}

impl AsyncPing for ObfsTlsStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for ObfsTlsStream {}

fn append_record(output: &mut Vec<u8>, content_type: u8, payload: &[u8]) {
    output.push(content_type);
    output.extend_from_slice(&TLS_1_2);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
}

fn validate_config(config: &ObfsTlsConfig) -> io::Result<()> {
    if config.max_client_hello_bytes < 64
        || config.max_client_hello_bytes > u16::MAX as usize + 5
        || config.max_initial_payload == 0
        || config.max_initial_payload > MAX_TLS_RECORD_PAYLOAD
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid simple-obfs TLS resource limits",
        ));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(invalid_error(message))
}

fn invalid_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    fn make_client_hello(ticket: &[u8], host: &str) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXT_SESSION_TICKET.to_be_bytes());
        extensions.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        extensions.extend_from_slice(ticket);
        let host = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&TLS_1_2);
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&[9; 32]);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0xcca8u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![
            1,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);
        handshake
    }

    #[test]
    fn extracts_ticket_and_sni_from_well_formed_client_hello() {
        let hello = parse_client_hello(&make_client_hello(b"ss-initial", "Example.COM")).unwrap();
        assert_eq!(hello.initial_payload, b"ss-initial");
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
        assert_eq!(hello.session_id, [9; 32]);
    }

    #[test]
    fn rejects_truncation_duplicate_ticket_and_inconsistent_lengths() {
        let mut truncated = make_client_hello(b"x", "a.test");
        truncated.pop();
        assert!(parse_client_hello(&truncated).is_err());

        let mut duplicate = make_client_hello(b"x", "a.test");
        let old_len = duplicate.len();
        duplicate.extend_from_slice(&EXT_SESSION_TICKET.to_be_bytes());
        duplicate.extend_from_slice(&1u16.to_be_bytes());
        duplicate.push(b'y');
        let extension_len_offset = 4 + 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1;
        let extension_len = u16::from_be_bytes([
            duplicate[extension_len_offset],
            duplicate[extension_len_offset + 1],
        ]) + 5;
        duplicate[extension_len_offset..extension_len_offset + 2]
            .copy_from_slice(&extension_len.to_be_bytes());
        let handshake_len = duplicate.len() - 4;
        duplicate[1] = ((handshake_len >> 16) & 0xff) as u8;
        duplicate[2] = ((handshake_len >> 8) & 0xff) as u8;
        duplicate[3] = (handshake_len & 0xff) as u8;
        assert_eq!(duplicate.len(), old_len + 5);
        assert!(parse_client_hello(&duplicate).is_err());

        let mut bad_length = make_client_hello(b"x", "a.test");
        bad_length[3] = bad_length[3].wrapping_add(1);
        assert!(parse_client_hello(&bad_length).is_err());
    }

    #[test]
    fn server_first_flight_has_consistent_record_boundaries() {
        // Test the pure framing helper independently of asynchronous I/O.
        let mut output = Vec::new();
        append_record(&mut output, CONTENT_APPLICATION_DATA, &[0x5a; 16_384]);
        assert_eq!(&output[..5], &[0x17, 0x03, 0x03, 0x40, 0x00]);
        assert_eq!(output.len(), 16_389);
    }

    #[tokio::test]
    async fn stream_reads_initial_ticket_then_fragmented_application_records() {
        let (mut client, server) = tokio::io::duplex(65_536);
        let mut stream =
            ObfsTlsStream::new(Box::new(TestStream(server)), [3; 32], b"initial".to_vec());
        let sender = tokio::spawn(async move {
            let mut wire = Vec::new();
            append_record(&mut wire, CONTENT_APPLICATION_DATA, b"one");
            append_record(&mut wire, CONTENT_APPLICATION_DATA, b"two");
            for byte in wire {
                client.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let mut plaintext = [0u8; 13];
        stream.read_exact(&mut plaintext).await.unwrap();
        assert_eq!(&plaintext, b"initialonetwo");
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn stream_writes_server_flight_then_application_record() {
        let (mut client, server) = tokio::io::duplex(65_536);
        let session_id = [0x44; 32];
        let writer = tokio::spawn(async move {
            let mut stream =
                ObfsTlsStream::new(Box::new(TestStream(server)), session_id, b"x".to_vec());
            stream.write_all(b"first").await.unwrap();
            stream.write_all(b"second").await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut server_hello_header = [0u8; 5];
        client.read_exact(&mut server_hello_header).await.unwrap();
        assert_eq!(server_hello_header[0], CONTENT_HANDSHAKE);
        let hello_len =
            u16::from_be_bytes([server_hello_header[3], server_hello_header[4]]) as usize;
        let mut hello = vec![0u8; hello_len];
        client.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello[39..71], &session_id);

        let mut change_cipher_spec = [0u8; 6];
        client.read_exact(&mut change_cipher_spec).await.unwrap();
        assert_eq!(change_cipher_spec[0], CONTENT_CHANGE_CIPHER_SPEC);
        let mut first_header = [0u8; 5];
        client.read_exact(&mut first_header).await.unwrap();
        assert_eq!(first_header[0], CONTENT_HANDSHAKE);
        let mut first = vec![0u8; u16::from_be_bytes([first_header[3], first_header[4]]) as usize];
        client.read_exact(&mut first).await.unwrap();
        assert_eq!(first, b"first");

        let mut second_header = [0u8; 5];
        client.read_exact(&mut second_header).await.unwrap();
        assert_eq!(second_header[0], CONTENT_APPLICATION_DATA);
        let mut second =
            vec![0u8; u16::from_be_bytes([second_header[3], second_header[4]]) as usize];
        client.read_exact(&mut second).await.unwrap();
        assert_eq!(second, b"second");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn stream_rejects_truncated_and_oversized_application_records() {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut stream = ObfsTlsStream::new(Box::new(TestStream(server)), [0; 32], Vec::new());
        client
            .write_all(&[0x17, 0x03, 0x03, 0x40, 0x01])
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let error = stream.read(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let (mut client, server) = tokio::io::duplex(1024);
        let mut stream = ObfsTlsStream::new(Box::new(TestStream(server)), [0; 32], Vec::new());
        client.write_all(&[0x17, 0x03]).await.unwrap();
        client.shutdown().await.unwrap();
        let error = stream.read(&mut byte).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
