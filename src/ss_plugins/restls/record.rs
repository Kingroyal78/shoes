// Protocol structure derived from 3andne/restls (BSD-3-Clause).

use std::{collections::VecDeque, io};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const TLS_RECORD_HEADER_LEN: usize = 5;
/// Restls permits a 32 KiB script target plus its 20-byte maximum auth/nonce
/// overhead. This is intentionally larger than ordinary TLSCiphertext.
pub const MAX_TLS_RECORD_PAYLOAD: usize = (1 << 15) + 20;
const MAX_DECODER_BUFFER: usize = (MAX_TLS_RECORD_PAYLOAD + TLS_RECORD_HEADER_LEN) * 4;

pub const RECORD_CHANGE_CIPHER_SPEC: u8 = 20;
pub const RECORD_ALERT: u8 = 21;
pub const RECORD_HANDSHAKE: u8 = 22;
pub const RECORD_APPLICATION_DATA: u8 = 23;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsRecord {
    pub content_type: u8,
    pub legacy_version: u16,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    pub fn new(content_type: u8, legacy_version: u16, payload: Vec<u8>) -> io::Result<Self> {
        validate_header(content_type, legacy_version, payload.len())?;
        Ok(Self {
            content_type,
            legacy_version,
            payload,
        })
    }

    pub fn header(&self) -> [u8; TLS_RECORD_HEADER_LEN] {
        let length = self.payload.len() as u16;
        [
            self.content_type,
            (self.legacy_version >> 8) as u8,
            self.legacy_version as u8,
            (length >> 8) as u8,
            length as u8,
        ]
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(TLS_RECORD_HEADER_LEN + self.payload.len());
        encoded.extend_from_slice(&self.header());
        encoded.extend_from_slice(&self.payload);
        encoded
    }

    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut header = [0u8; TLS_RECORD_HEADER_LEN];
        reader.read_exact(&mut header).await?;
        let content_type = header[0];
        let legacy_version = u16::from_be_bytes([header[1], header[2]]);
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        validate_header(content_type, legacy_version, length)?;

        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await?;
        Ok(Self {
            content_type,
            legacy_version,
            payload,
        })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.encode()).await
    }

    pub fn handshake_messages(&self) -> io::Result<HandshakeMessages<'_>> {
        if self.content_type != RECORD_HANDSHAKE {
            return Err(invalid_data(
                "TLS record does not contain handshake messages",
            ));
        }
        Ok(HandshakeMessages {
            payload: &self.payload,
            cursor: 0,
        })
    }
}

pub struct HandshakeMessage<'a> {
    pub handshake_type: u8,
    pub body: &'a [u8],
}

pub struct HandshakeMessages<'a> {
    payload: &'a [u8],
    cursor: usize,
}

impl<'a> Iterator for HandshakeMessages<'a> {
    type Item = io::Result<HandshakeMessage<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == self.payload.len() {
            return None;
        }
        if self.payload.len() - self.cursor < 4 {
            self.cursor = self.payload.len();
            return Some(Err(invalid_data("truncated TLS handshake header")));
        }

        let start = self.cursor;
        let length = ((self.payload[start + 1] as usize) << 16)
            | ((self.payload[start + 2] as usize) << 8)
            | self.payload[start + 3] as usize;
        let end = match start
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
        {
            Some(end) if end <= self.payload.len() => end,
            _ => {
                self.cursor = self.payload.len();
                return Some(Err(invalid_data("truncated TLS handshake message")));
            }
        };
        self.cursor = end;
        Some(Ok(HandshakeMessage {
            handshake_type: self.payload[start],
            body: &self.payload[start + 4..end],
        }))
    }
}

#[derive(Debug, Default)]
pub struct TlsRecordDecoder {
    buffered: VecDeque<u8>,
}

pub struct AsyncTlsRecordReader<R> {
    inner: R,
    decoder: TlsRecordDecoder,
}

impl<R> AsyncTlsRecordReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            decoder: TlsRecordDecoder::default(),
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn buffered_len(&self) -> usize {
        self.decoder.buffered_len()
    }

    pub fn take_buffered(&mut self) -> Vec<u8> {
        self.decoder.buffered.drain(..).collect()
    }
}

impl<R: AsyncRead + Unpin> AsyncTlsRecordReader<R> {
    /// Cancellation-safe across `select!`: the decoder owns every byte already
    /// consumed from the socket.
    pub async fn next_record(&mut self) -> io::Result<TlsRecord> {
        loop {
            if let Some(record) = self.decoder.next_record()? {
                return Ok(record);
            }
            let mut temporary = [0u8; 4096];
            let read = self.inner.read(&mut temporary).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Restls TLS record",
                ));
            }
            self.decoder.push(&temporary[..read])?;
        }
    }
}

impl TlsRecordDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.buffered.len().saturating_add(bytes.len()) > MAX_DECODER_BUFFER {
            return Err(invalid_data("TLS decoder buffer limit exceeded"));
        }
        self.buffered.extend(bytes);
        Ok(())
    }

    pub fn next_record(&mut self) -> io::Result<Option<TlsRecord>> {
        if self.buffered.len() < TLS_RECORD_HEADER_LEN {
            return Ok(None);
        }
        let header: Vec<u8> = self
            .buffered
            .iter()
            .take(TLS_RECORD_HEADER_LEN)
            .copied()
            .collect();
        let content_type = header[0];
        let legacy_version = u16::from_be_bytes([header[1], header[2]]);
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        validate_header(content_type, legacy_version, length)?;
        if self.buffered.len() < TLS_RECORD_HEADER_LEN + length {
            return Ok(None);
        }

        self.buffered.drain(..TLS_RECORD_HEADER_LEN);
        let payload = self.buffered.drain(..length).collect();
        Ok(Some(TlsRecord {
            content_type,
            legacy_version,
            payload,
        }))
    }

    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }
}

fn validate_header(content_type: u8, version: u16, length: usize) -> io::Result<()> {
    if !(RECORD_CHANGE_CIPHER_SPEC..=24).contains(&content_type) {
        return Err(invalid_data("invalid TLS record content type"));
    }
    if !(0x0301..=0x0303).contains(&version) {
        return Err(invalid_data("invalid TLS legacy record version"));
    }
    if length > MAX_TLS_RECORD_PAYLOAD {
        return Err(invalid_data("TLS record exceeds the maximum accepted size"));
    }
    Ok(())
}

pub(crate) fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_handles_every_fragment_boundary() {
        let record = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, b"payload".to_vec())
            .unwrap()
            .encode();
        for boundary in 0..=record.len() {
            let mut decoder = TlsRecordDecoder::default();
            decoder.push(&record[..boundary]).unwrap();
            if boundary < record.len() {
                assert!(decoder.next_record().unwrap().is_none());
            }
            decoder.push(&record[boundary..]).unwrap();
            assert_eq!(decoder.next_record().unwrap().unwrap().payload, b"payload");
            assert_eq!(decoder.buffered_len(), 0);
        }
    }

    #[test]
    fn oversized_and_invalid_headers_are_rejected_before_allocation() {
        let mut decoder = TlsRecordDecoder::default();
        decoder.push(&[23, 3, 3, 0xff, 0xff]).unwrap();
        assert_eq!(
            decoder.next_record().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut decoder = TlsRecordDecoder::default();
        decoder.push(&[1, 3, 3, 0, 0]).unwrap();
        assert!(decoder.next_record().is_err());
    }

    #[test]
    fn handshake_iterator_rejects_truncation() {
        let record = TlsRecord::new(RECORD_HANDSHAKE, 0x0303, vec![2, 0, 0, 2, 1]).unwrap();
        assert!(
            record
                .handshake_messages()
                .unwrap()
                .next()
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn async_reader_retains_partial_record_when_cancelled() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = AsyncTlsRecordReader::new(reader);
        writer.write_all(&[23, 3]).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), reader.next_record())
                .await
                .is_err()
        );
        writer.write_all(&[3, 0, 2, 7, 8]).await.unwrap();
        assert_eq!(reader.next_record().await.unwrap().payload, [7, 8]);
    }
}
