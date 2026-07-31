use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const TLS_RECORD_HEADER_LEN: usize = 5;
pub const MAX_TLS_RECORD_PAYLOAD: usize = (1 << 14) + 2048;

pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsRecord {
    pub content_type: u8,
    pub legacy_version: u16,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    pub fn new(content_type: u8, legacy_version: u16, payload: Vec<u8>) -> io::Result<Self> {
        validate_content_type(content_type)?;
        validate_legacy_version(legacy_version)?;
        if payload.len() > MAX_TLS_RECORD_PAYLOAD {
            return Err(invalid_data(
                "TLS record payload exceeds the configured limit",
            ));
        }
        Ok(Self {
            content_type,
            legacy_version,
            payload,
        })
    }

    pub fn wire_len(&self) -> usize {
        TLS_RECORD_HEADER_LEN + self.payload.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.wire_len());
        wire.push(self.content_type);
        wire.extend_from_slice(&self.legacy_version.to_be_bytes());
        wire.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(&self.payload);
        wire
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.encode()).await
    }
}

pub async fn read_record<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<TlsRecord> {
    read_record_lossless(reader)
        .await
        .map_err(|failure| failure.error)
}

#[derive(Debug)]
pub(crate) struct RecordReadError {
    pub error: io::Error,
    pub consumed: Vec<u8>,
}

pub(crate) struct TlsRecordReader<R> {
    inner: R,
    buffered: Vec<u8>,
    expected_wire_len: Option<usize>,
}

impl<R> TlsRecordReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffered: Vec::with_capacity(TLS_RECORD_HEADER_LEN),
            expected_wire_len: None,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> TlsRecordReader<R> {
    /// Cancellation-safe record reading: bytes consumed before `Pending` remain
    /// owned by this reader when a surrounding `select!` cancels the future.
    pub async fn next_record(&mut self) -> Result<TlsRecord, RecordReadError> {
        while self.buffered.len() < TLS_RECORD_HEADER_LEN {
            self.read_more(TLS_RECORD_HEADER_LEN).await?;
        }
        if self.expected_wire_len.is_none() {
            let content_type = self.buffered[0];
            let legacy_version = u16::from_be_bytes([self.buffered[1], self.buffered[2]]);
            let payload_len = u16::from_be_bytes([self.buffered[3], self.buffered[4]]) as usize;
            if let Err(error) = validate_content_type(content_type)
                .and_then(|_| validate_legacy_version(legacy_version))
            {
                return Err(self.fail(error));
            }
            if payload_len > MAX_TLS_RECORD_PAYLOAD {
                return Err(self.fail(invalid_data(
                    "TLS record payload exceeds the configured limit",
                )));
            }
            self.expected_wire_len = Some(TLS_RECORD_HEADER_LEN + payload_len);
        }

        let expected = match self.expected_wire_len {
            Some(expected) => expected,
            None => {
                return Err(self.fail(invalid_data("TLS record reader lost its length state")));
            }
        };
        while self.buffered.len() < expected {
            self.read_more(expected).await?;
        }
        let wire = std::mem::take(&mut self.buffered);
        self.expected_wire_len = None;
        let content_type = wire[0];
        let legacy_version = u16::from_be_bytes([wire[1], wire[2]]);
        Ok(TlsRecord {
            content_type,
            legacy_version,
            payload: wire[TLS_RECORD_HEADER_LEN..].to_vec(),
        })
    }

    async fn read_more(&mut self, target: usize) -> Result<(), RecordReadError> {
        let mut temporary = [0u8; 4096];
        let requested = (target - self.buffered.len()).min(temporary.len());
        match self.inner.read(&mut temporary[..requested]).await {
            Ok(0) => Err(self.fail(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated TLS record",
            ))),
            Ok(read) => {
                self.buffered.extend_from_slice(&temporary[..read]);
                Ok(())
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    fn fail(&mut self, error: io::Error) -> RecordReadError {
        self.expected_wire_len = None;
        RecordReadError {
            error,
            consumed: std::mem::take(&mut self.buffered),
        }
    }
}

pub(crate) async fn read_record_lossless<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<TlsRecord, RecordReadError> {
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    let mut consumed = Vec::with_capacity(TLS_RECORD_HEADER_LEN);
    read_exact_lossless(reader, &mut header, &mut consumed).await?;
    let content_type = header[0];
    let legacy_version = u16::from_be_bytes([header[1], header[2]]);
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    validate_content_type(content_type).map_err(|error| RecordReadError {
        error,
        consumed: consumed.clone(),
    })?;
    validate_legacy_version(legacy_version).map_err(|error| RecordReadError {
        error,
        consumed: consumed.clone(),
    })?;
    if payload_len > MAX_TLS_RECORD_PAYLOAD {
        return Err(RecordReadError {
            error: invalid_data("TLS record payload exceeds the configured limit"),
            consumed,
        });
    }

    let mut payload = vec![0u8; payload_len];
    read_exact_lossless(reader, &mut payload, &mut consumed).await?;
    Ok(TlsRecord {
        content_type,
        legacy_version,
        payload,
    })
}

async fn read_exact_lossless<R: AsyncRead + Unpin>(
    reader: &mut R,
    output: &mut [u8],
    consumed: &mut Vec<u8>,
) -> Result<(), RecordReadError> {
    let mut filled = 0usize;
    while filled < output.len() {
        match reader.read(&mut output[filled..]).await {
            Ok(0) => {
                return Err(RecordReadError {
                    error: io::Error::new(io::ErrorKind::UnexpectedEof, "truncated TLS record"),
                    consumed: std::mem::take(consumed),
                });
            }
            Ok(read) => {
                consumed.extend_from_slice(&output[filled..filled + read]);
                filled += read;
            }
            Err(error) => {
                return Err(RecordReadError {
                    error,
                    consumed: std::mem::take(consumed),
                });
            }
        }
    }
    Ok(())
}

pub fn validate_client_hello_record(record: &TlsRecord) -> io::Result<()> {
    if record.content_type != CONTENT_TYPE_HANDSHAKE {
        return Err(invalid_data(
            "the first ShadowTLS record is not a handshake record",
        ));
    }
    if record.legacy_version != 0x0301 && record.legacy_version != 0x0303 {
        return Err(invalid_data(
            "the ClientHello record version is not TLS 1.0 or TLS 1.2",
        ));
    }
    if record.payload.len() < 4 || record.payload[0] != 1 {
        return Err(invalid_data(
            "the first ShadowTLS handshake message is not ClientHello",
        ));
    }
    let declared = ((record.payload[1] as usize) << 16)
        | ((record.payload[2] as usize) << 8)
        | record.payload[3] as usize;
    if declared + 4 != record.payload.len() {
        return Err(invalid_data(
            "fragmented or trailing ClientHello handshake data is unsupported",
        ));
    }
    Ok(())
}

fn validate_content_type(content_type: u8) -> io::Result<()> {
    if (CONTENT_TYPE_CHANGE_CIPHER_SPEC..=24).contains(&content_type) {
        Ok(())
    } else {
        Err(invalid_data("invalid TLS record content type"))
    }
}

fn validate_legacy_version(version: u16) -> io::Result<()> {
    if (0x0301..=0x0303).contains(&version) {
        Ok(())
    } else {
        Err(invalid_data("invalid TLS legacy record version"))
    }
}

pub(crate) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn fragmented_record_is_reassembled() {
        let (mut writer, mut reader) = duplex(64);
        let task = tokio::spawn(async move {
            for part in [&[23, 3][..], &[3, 0, 4, 1][..], &[2, 3, 4][..]] {
                writer.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let record = read_record(&mut reader).await.unwrap();
        assert_eq!(record.content_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(record.legacy_version, 0x0303);
        assert_eq!(record.payload, [1, 2, 3, 4]);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_record_is_rejected() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&[23, 3, 3, 0, 4, 1, 2]).await.unwrap();
        writer.shutdown().await.unwrap();

        let error = read_record(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn stateful_reader_survives_select_cancellation_after_partial_header() {
        let (mut writer, reader) = duplex(64);
        let mut reader = TlsRecordReader::new(reader);
        writer.write_all(&[23, 3]).await.unwrap();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), reader.next_record())
                .await
                .is_err()
        );

        writer.write_all(&[3, 0, 2, 7, 8]).await.unwrap();
        assert_eq!(reader.next_record().await.unwrap().payload, [7, 8]);
    }

    #[test]
    fn client_hello_must_be_a_single_complete_message() {
        let record = TlsRecord::new(22, 0x0301, vec![1, 0, 0, 1, 7]).unwrap();
        validate_client_hello_record(&record).unwrap();

        let trailing = TlsRecord::new(22, 0x0301, vec![1, 0, 0, 1, 7, 0]).unwrap();
        assert!(validate_client_hello_record(&trailing).is_err());
    }
}
