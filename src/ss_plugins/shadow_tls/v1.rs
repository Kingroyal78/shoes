use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::record::{
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE, invalid_data, read_record,
    validate_client_hello_record,
};

#[derive(Clone, Copy, Debug)]
pub struct ShadowTlsV1Config {
    /// ShadowTLS v1 is a TLS 1.2-only protocol.
    pub require_tls12_records: bool,
}

impl Default for ShadowTlsV1Config {
    fn default() -> Self {
        Self {
            require_tls12_records: true,
        }
    }
}

/// Completes the v1 camouflage handshake and returns the client stream at the
/// exact boundary where the inner Shadowsocks stream begins.
pub async fn accept_v1<C, H>(client: C, camouflage: H, config: ShadowTlsV1Config) -> io::Result<C>
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (camouflage_read, camouflage_write) = tokio::io::split(camouflage);

    let client_to_camouflage = relay_until_finished(client_read, camouflage_write, true, config);
    let camouflage_to_client = relay_until_finished(camouflage_read, client_write, false, config);

    let ((client_read, camouflage_write), (camouflage_read, client_write)) =
        tokio::try_join!(client_to_camouflage, camouflage_to_client)?;

    drop(camouflage_read.unsplit(camouflage_write));
    Ok(client_read.unsplit(client_write))
}

async fn relay_until_finished<R, W>(
    mut reader: ReadHalf<R>,
    mut writer: WriteHalf<W>,
    client_direction: bool,
    config: ShadowTlsV1Config,
) -> io::Result<(ReadHalf<R>, WriteHalf<W>)>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncRead + AsyncWrite + Unpin,
{
    let mut saw_change_cipher_spec = false;
    let mut first = true;

    loop {
        let record = read_record(&mut reader).await?;
        let is_first = first;
        if is_first && client_direction {
            validate_client_hello_record(&record)?;
        }
        first = false;

        if config.require_tls12_records
            && record.legacy_version != 0x0303
            && !(is_first && client_direction)
        {
            return Err(invalid_data(
                "ShadowTLS v1 handshake used a non-TLS-1.2 record version",
            ));
        }

        let finished = match record.content_type {
            CONTENT_TYPE_HANDSHAKE => saw_change_cipher_spec,
            CONTENT_TYPE_CHANGE_CIPHER_SPEC if !saw_change_cipher_spec => {
                saw_change_cipher_spec = true;
                false
            }
            CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                return Err(invalid_data(
                    "duplicate TLS ChangeCipherSpec in ShadowTLS v1 handshake",
                ));
            }
            _ => {
                return Err(invalid_data(
                    "unexpected TLS record during ShadowTLS v1 handshake",
                ));
            }
        };

        record.write_to(&mut writer).await?;
        writer.flush().await?;
        if finished {
            return Ok((reader, writer));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::super::record::TlsRecord;
    use super::*;

    fn handshake(payload: &[u8]) -> TlsRecord {
        TlsRecord::new(CONTENT_TYPE_HANDSHAKE, 0x0303, payload.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn v1_relay_stops_without_consuming_inner_data() {
        let (mut client_peer, client_server) = duplex(1024);
        let (camouflage_server, mut camouflage_peer) = duplex(1024);

        let task = tokio::spawn(accept_v1(
            client_server,
            camouflage_server,
            ShadowTlsV1Config::default(),
        ));

        let client_hello =
            TlsRecord::new(CONTENT_TYPE_HANDSHAKE, 0x0301, vec![1, 0, 0, 1, 9]).unwrap();
        client_hello.write_to(&mut client_peer).await.unwrap();
        TlsRecord::new(CONTENT_TYPE_CHANGE_CIPHER_SPEC, 0x0303, vec![1])
            .unwrap()
            .write_to(&mut client_peer)
            .await
            .unwrap();
        handshake(&[20, 0, 0, 0])
            .write_to(&mut client_peer)
            .await
            .unwrap();

        let _ = super::super::record::read_record(&mut camouflage_peer)
            .await
            .unwrap();
        let _ = super::super::record::read_record(&mut camouflage_peer)
            .await
            .unwrap();
        let _ = super::super::record::read_record(&mut camouflage_peer)
            .await
            .unwrap();

        handshake(&[2, 0, 0, 0])
            .write_to(&mut camouflage_peer)
            .await
            .unwrap();
        TlsRecord::new(CONTENT_TYPE_CHANGE_CIPHER_SPEC, 0x0303, vec![1])
            .unwrap()
            .write_to(&mut camouflage_peer)
            .await
            .unwrap();
        handshake(&[20, 0, 0, 0])
            .write_to(&mut camouflage_peer)
            .await
            .unwrap();

        for _ in 0..3 {
            let _ = super::super::record::read_record(&mut client_peer)
                .await
                .unwrap();
        }

        let mut accepted = task.await.unwrap().unwrap();
        client_peer.write_all(b"inner").await.unwrap();
        let mut inner = [0u8; 5];
        accepted.read_exact(&mut inner).await.unwrap();
        assert_eq!(&inner, b"inner");
    }
}
