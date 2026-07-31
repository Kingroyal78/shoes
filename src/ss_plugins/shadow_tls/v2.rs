use std::io;

use aws_lc_rs::hmac;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    record::{CONTENT_TYPE_APPLICATION_DATA, TlsRecordReader, validate_client_hello_record},
    stream::ShadowTlsV2Stream,
};

#[derive(Clone)]
pub struct ShadowTlsV2Config {
    initial_hmac: RollingHmac,
    pub fallback_after_application_records: usize,
}

impl std::fmt::Debug for ShadowTlsV2Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShadowTlsV2Config")
            .field("password", &"[REDACTED]")
            .field(
                "fallback_after_application_records",
                &self.fallback_after_application_records,
            )
            .finish()
    }
}

impl ShadowTlsV2Config {
    pub fn new(password: impl AsRef<[u8]>) -> io::Result<Self> {
        let password = password.as_ref();
        if password.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowTLS v2 password must not be empty",
            ));
        }
        Ok(Self {
            initial_hmac: RollingHmac::new(password),
            fallback_after_application_records: 2,
        })
    }
}

pub struct ShadowTlsFallback<C, H> {
    pub client: C,
    pub camouflage: H,
}

impl<C, H> ShadowTlsFallback<C, H>
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn relay(mut self) -> io::Result<()> {
        tokio::io::copy_bidirectional(&mut self.client, &mut self.camouflage)
            .await
            .map(|_| ())
    }
}

pub enum ShadowTlsV2Outcome<C, H> {
    Authenticated(ShadowTlsV2Stream<C>),
    Fallback(ShadowTlsFallback<C, H>),
}

#[derive(Clone)]
struct RollingHmac {
    context: hmac::Context,
    last: Option<[u8; 8]>,
    has_content: bool,
}

impl RollingHmac {
    fn new(password: &[u8]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, password);
        Self {
            context: hmac::Context::with_key(&key),
            last: None,
            has_content: false,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        if self.has_content {
            self.last = Some(self.current());
        }
        self.context.update(bytes);
        self.has_content = true;
    }

    fn current(&self) -> [u8; 8] {
        let signature = self.context.clone().sign();
        let mut truncated = [0u8; 8];
        truncated.copy_from_slice(&signature.as_ref()[..8]);
        truncated
    }

    fn authenticates(&self, candidate: &[u8]) -> bool {
        if !self.has_content || candidate.len() != 8 {
            return false;
        }
        if bool::from(self.current().ct_eq(candidate)) {
            return true;
        }
        self.last
            .as_ref()
            .is_some_and(|last| bool::from(last.ct_eq(candidate)))
    }
}

/// Performs the ShadowTLS v2 handshake against an already connected camouflage
/// server. Authentication failures are relayed to that server instead of being
/// exposed to the inner Shadowsocks handler.
pub async fn accept_v2<C, H>(
    client: C,
    camouflage: H,
    config: &ShadowTlsV2Config,
) -> io::Result<ShadowTlsV2Outcome<C, H>>
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, mut client_write) = tokio::io::split(client);
    let (mut camouflage_read, mut camouflage_write) = tokio::io::split(camouflage);
    let mut client_reader = TlsRecordReader::new(client_read);

    let client_hello = match client_reader.next_record().await {
        Ok(record) => record,
        Err(failure) if failure.error.kind() == io::ErrorKind::InvalidData => {
            camouflage_write.write_all(&failure.consumed).await?;
            camouflage_write.flush().await?;
            return Ok(ShadowTlsV2Outcome::Fallback(ShadowTlsFallback {
                client: client_reader.into_inner().unsplit(client_write),
                camouflage: camouflage_read.unsplit(camouflage_write),
            }));
        }
        Err(failure) => return Err(failure.error),
    };
    if validate_client_hello_record(&client_hello).is_err() {
        client_hello.write_to(&mut camouflage_write).await?;
        camouflage_write.flush().await?;
        return Ok(ShadowTlsV2Outcome::Fallback(ShadowTlsFallback {
            client: client_reader.into_inner().unsplit(client_write),
            camouflage: camouflage_read.unsplit(camouflage_write),
        }));
    }
    client_hello.write_to(&mut camouflage_write).await?;
    camouflage_write.flush().await?;

    let mut server_hmac = config.initial_hmac.clone();
    let mut application_mismatches = 0usize;
    // ShadowTLS v2 authenticates the camouflage server's raw copy/write
    // transcript. Record-level updates change the "previous digest" boundary
    // and break real clients when one copy chunk contains several TLS records.
    let mut camouflage_buffer = vec![0u8; 32 * 1024];

    loop {
        tokio::select! {
            client_record = client_reader.next_record() => {
                let client_record = match client_record {
                    Ok(record) => record,
                    Err(failure) if failure.error.kind() == io::ErrorKind::InvalidData => {
                        camouflage_write.write_all(&failure.consumed).await?;
                        camouflage_write.flush().await?;
                        return Ok(ShadowTlsV2Outcome::Fallback(ShadowTlsFallback {
                            client: client_reader.into_inner().unsplit(client_write),
                            camouflage: camouflage_read.unsplit(camouflage_write),
                        }));
                    }
                    Err(failure) => return Err(failure.error),
                };
                if client_record.content_type == CONTENT_TYPE_APPLICATION_DATA
                    && client_record.payload.len() >= 8
                    && server_hmac.authenticates(&client_record.payload[..8])
                {
                    return Ok(ShadowTlsV2Outcome::Authenticated(
                        ShadowTlsV2Stream::new(
                            client_reader.into_inner().unsplit(client_write),
                            client_record.payload[8..].to_vec(),
                        )
                    ));
                }

                if client_record.content_type == CONTENT_TYPE_APPLICATION_DATA {
                    application_mismatches = application_mismatches.saturating_add(1);
                }
                client_record.write_to(&mut camouflage_write).await?;
                camouflage_write.flush().await?;
                if application_mismatches > config.fallback_after_application_records {
                    return Ok(ShadowTlsV2Outcome::Fallback(ShadowTlsFallback {
                        client: client_reader.into_inner().unsplit(client_write),
                        camouflage: camouflage_read.unsplit(camouflage_write),
                    }));
                }
            }
            read = camouflage_read.read(&mut camouflage_buffer) => {
                let read = read?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "camouflage server closed during ShadowTLS v2 handshake",
                    ));
                }
                let wire = &camouflage_buffer[..read];
                server_hmac.update(wire);
                client_write.write_all(wire).await?;
                client_write.flush().await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncReadExt, AsyncWrite, ReadBuf, duplex};

    use super::super::record::{CONTENT_TYPE_HANDSHAKE, TlsRecord, read_record};
    use super::*;

    fn client_hello() -> TlsRecord {
        TlsRecord::new(CONTENT_TYPE_HANDSHAKE, 0x0301, vec![1, 0, 0, 1, 7]).unwrap()
    }

    struct ChunkedCamouflage {
        read_chunks: VecDeque<Vec<u8>>,
        chunk_offset: usize,
    }

    impl AsyncRead for ChunkedCamouflage {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.read_chunks.front().map(Vec::len) {
                Some(chunk_len) => {
                    let read = {
                        let chunk = self.read_chunks.front().expect("chunk disappeared");
                        let available = &chunk[self.chunk_offset..];
                        let read = available.len().min(output.remaining());
                        output.put_slice(&available[..read]);
                        read
                    };
                    self.chunk_offset += read;
                    if self.chunk_offset == chunk_len {
                        self.read_chunks.pop_front();
                        self.chunk_offset = 0;
                    }
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for ChunkedCamouflage {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn authenticates_current_server_transcript_and_preserves_early_data() {
        let (mut client_peer, client) = duplex(4096);
        let (camouflage, mut camouflage_peer) = duplex(4096);
        let config = ShadowTlsV2Config::new("secret").unwrap();

        let server = tokio::spawn(async move { accept_v2(client, camouflage, &config).await });
        client_hello().write_to(&mut client_peer).await.unwrap();
        let forwarded = read_record(&mut camouflage_peer).await.unwrap();
        assert_eq!(forwarded, client_hello());

        let response = TlsRecord::new(CONTENT_TYPE_HANDSHAKE, 0x0303, vec![2, 0, 0, 0]).unwrap();
        response.write_to(&mut camouflage_peer).await.unwrap();
        let _ = read_record(&mut client_peer).await.unwrap();

        let mut hmac = RollingHmac::new(b"secret");
        hmac.update(&response.encode());
        let mut payload = hmac.current().to_vec();
        payload.extend_from_slice(b"early");
        TlsRecord::new(CONTENT_TYPE_APPLICATION_DATA, 0x0303, payload)
            .unwrap()
            .write_to(&mut client_peer)
            .await
            .unwrap();

        let mut accepted = match server.await.unwrap().unwrap() {
            ShadowTlsV2Outcome::Authenticated(stream) => stream,
            ShadowTlsV2Outcome::Fallback(_) => panic!("unexpected fallback"),
        };
        let mut early = [0u8; 5];
        accepted.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");
    }

    #[tokio::test]
    async fn previous_digest_tracks_raw_camouflage_write_chunks_not_tls_records() {
        let first_chunk = [
            TlsRecord::new(CONTENT_TYPE_HANDSHAKE, 0x0303, vec![1]).unwrap(),
            TlsRecord::new(CONTENT_TYPE_HANDSHAKE, 0x0303, vec![2]).unwrap(),
            TlsRecord::new(CONTENT_TYPE_APPLICATION_DATA, 0x0303, vec![3]).unwrap(),
        ]
        .into_iter()
        .flat_map(|record| record.encode())
        .collect::<Vec<_>>();
        let second_chunk = [
            TlsRecord::new(CONTENT_TYPE_APPLICATION_DATA, 0x0303, vec![4]).unwrap(),
            TlsRecord::new(CONTENT_TYPE_APPLICATION_DATA, 0x0303, vec![5]).unwrap(),
        ]
        .into_iter()
        .flat_map(|record| record.encode())
        .collect::<Vec<_>>();
        let camouflage = ChunkedCamouflage {
            read_chunks: VecDeque::from([first_chunk.clone(), second_chunk]),
            chunk_offset: 0,
        };
        let (mut client_peer, client) = duplex(4096);
        let mut config = ShadowTlsV2Config::new("secret").unwrap();
        config.fallback_after_application_records = 0;

        let server = tokio::spawn(async move { accept_v2(client, camouflage, &config).await });
        client_hello().write_to(&mut client_peer).await.unwrap();
        for _ in 0..5 {
            read_record(&mut client_peer).await.unwrap();
        }

        let mut hmac = RollingHmac::new(b"secret");
        hmac.update(&first_chunk);
        TlsRecord::new(
            CONTENT_TYPE_APPLICATION_DATA,
            0x0303,
            hmac.current().to_vec(),
        )
        .unwrap()
        .write_to(&mut client_peer)
        .await
        .unwrap();

        assert!(matches!(
            server.await.unwrap().unwrap(),
            ShadowTlsV2Outcome::Authenticated(_)
        ));
    }

    #[tokio::test]
    async fn tampered_authentication_falls_back() {
        let (mut client_peer, client) = duplex(4096);
        let (camouflage, mut camouflage_peer) = duplex(4096);
        let mut config = ShadowTlsV2Config::new("secret").unwrap();
        config.fallback_after_application_records = 0;

        let server = tokio::spawn(async move { accept_v2(client, camouflage, &config).await });
        client_hello().write_to(&mut client_peer).await.unwrap();
        let _ = read_record(&mut camouflage_peer).await.unwrap();

        let response = TlsRecord::new(CONTENT_TYPE_HANDSHAKE, 0x0303, vec![2, 0, 0, 0]).unwrap();
        response.write_to(&mut camouflage_peer).await.unwrap();
        let _ = read_record(&mut client_peer).await.unwrap();

        TlsRecord::new(CONTENT_TYPE_APPLICATION_DATA, 0x0303, vec![0; 8])
            .unwrap()
            .write_to(&mut client_peer)
            .await
            .unwrap();

        assert!(matches!(
            server.await.unwrap().unwrap(),
            ShadowTlsV2Outcome::Fallback(_)
        ));
        let relayed = read_record(&mut camouflage_peer).await.unwrap();
        assert_eq!(relayed.payload, vec![0; 8]);
    }

    #[tokio::test]
    async fn malformed_probe_prefix_is_preserved_for_fallback() {
        let (mut client_peer, client) = duplex(4096);
        let (camouflage, mut camouflage_peer) = duplex(4096);
        let config = ShadowTlsV2Config::new("secret").unwrap();

        let server = tokio::spawn(async move { accept_v2(client, camouflage, &config).await });
        let invalid_header = [1, 3, 3, 0, 0];
        tokio::io::AsyncWriteExt::write_all(&mut client_peer, &invalid_header)
            .await
            .unwrap();

        assert!(matches!(
            server.await.unwrap().unwrap(),
            ShadowTlsV2Outcome::Fallback(_)
        ));
        let mut forwarded = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut camouflage_peer, &mut forwarded)
            .await
            .unwrap();
        assert_eq!(forwarded, invalid_header);
    }

    #[test]
    fn previous_server_transcript_digest_is_accepted() {
        let mut hmac = RollingHmac::new(b"secret");
        hmac.update(b"first");
        let previous = hmac.current();
        hmac.update(b"second");
        assert!(hmac.authenticates(&previous));
    }

    #[test]
    fn configuration_debug_output_redacts_password() {
        let config = ShadowTlsV2Config::new("do-not-log-this").unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("do-not-log-this"));
    }
}
