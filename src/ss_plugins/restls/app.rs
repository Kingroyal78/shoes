// Restls V1 application-record authentication derived from 3andne/restls
// (BSD-3-Clause), with strict bounds and constant-time tag comparison.

use std::io;

use rand::RngExt;
use subtle::ConstantTimeEq;

use super::{
    auth::RestlsKey,
    record::{MAX_TLS_RECORD_PAYLOAD, RECORD_APPLICATION_DATA, TlsRecord, invalid_data},
    script::MAX_SCRIPT_TARGET,
};

pub use super::script::RestlsCommand;

const AUTH_TAG_LEN: usize = 8;
const MASK_LEN: usize = 4;
const AUTH_HEADER_LEN: usize = AUTH_TAG_LEN + MASK_LEN;
const TLS_MAX_PLAINTEXT: usize = 1 << 14;
const TO_CLIENT_MAGIC: &[u8] = b"server-to-client";
const TO_SERVER_MAGIC: &[u8] = b"client-to-server";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedAppRecord {
    pub data: Vec<u8>,
    pub command: RestlsCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedAppRecord {
    pub record: TlsRecord,
    pub consumed: usize,
    pub command: RestlsCommand,
}

#[derive(Clone)]
pub struct RestlsAppCodec {
    key: RestlsKey,
    server_random: [u8; 32],
    tls12_client_gcm: bool,
    tls12_server_gcm: bool,
    to_client_counter: u64,
    to_server_counter: u64,
    client_finished: Option<Vec<u8>>,
}

impl RestlsAppCodec {
    pub fn new(key: RestlsKey, server_random: [u8; 32], tls12_client_gcm: bool) -> Self {
        Self {
            key,
            server_random,
            tls12_client_gcm,
            tls12_server_gcm: false,
            to_client_counter: 0,
            to_server_counter: 0,
            client_finished: None,
        }
    }

    pub fn set_tls12_server_gcm(&mut self, enabled: bool) {
        self.tls12_server_gcm = enabled;
    }

    pub fn bind_first_client_record_to_finished(&mut self, record: Vec<u8>) -> io::Result<()> {
        if record.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ClientFinished binding must not be empty",
            ));
        }
        if self.client_finished.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ClientFinished binding was already configured",
            ));
        }
        self.client_finished = Some(record);
        Ok(())
    }

    pub(crate) fn replace_client_finished_binding(&mut self, record: Vec<u8>) -> io::Result<()> {
        if record.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ClientFinished binding must not be empty",
            ));
        }
        self.client_finished = Some(record);
        Ok(())
    }

    pub fn note_camouflage_record_to_client(&mut self) -> io::Result<()> {
        self.note_camouflage_records_to_client(1)
    }

    pub(crate) fn note_camouflage_records_to_client(&mut self, count: u64) -> io::Result<()> {
        self.to_client_counter = self
            .to_client_counter
            .checked_add(count)
            .ok_or_else(|| invalid_data("Restls to-client counter exhausted"))?;
        Ok(())
    }

    pub fn counters(&self) -> (u64, u64) {
        (self.to_client_counter, self.to_server_counter)
    }

    pub fn decode_from_client(&mut self, record: &TlsRecord) -> io::Result<DecodedAppRecord> {
        if record.content_type != RECORD_APPLICATION_DATA || record.legacy_version != 0x0303 {
            return Err(invalid_data(
                "Restls application data must use TLS application records",
            ));
        }
        let nonce_len = if self.tls12_client_gcm { 8 } else { 0 };
        if record.payload.len() < nonce_len + AUTH_HEADER_LEN {
            return Err(invalid_data("Restls application record is too short"));
        }
        if self.tls12_client_gcm {
            let nonce = u64::from_be_bytes(
                record.payload[..8]
                    .try_into()
                    .map_err(|_| invalid_data("truncated Restls TLS 1.2 nonce"))?,
            );
            let expected = self
                .to_server_counter
                .checked_add(1)
                .ok_or_else(|| invalid_data("Restls to-server counter exhausted"))?;
            if nonce != expected {
                return Err(invalid_data("Restls TLS 1.2 client nonce/counter mismatch"));
            }
        }

        let auth_offset = nonce_len;
        let masked_offset = auth_offset + AUTH_TAG_LEN;
        let data_offset = auth_offset + AUTH_HEADER_LEN;
        let actual_auth = &record.payload[auth_offset..masked_offset];
        let mut auth_hasher = self.directional_hasher(false);
        if let Some(finished) = &self.client_finished {
            auth_hasher.update(finished);
        }
        auth_hasher.update(&record.header());
        auth_hasher.update(&record.payload[..nonce_len]);
        auth_hasher.update(&record.payload[masked_offset..]);
        let expected_auth = auth_hasher.finalize();
        if !bool::from(actual_auth.ct_eq(&expected_auth.as_bytes()[..AUTH_TAG_LEN])) {
            return Err(invalid_data(
                "Restls application record authentication failed",
            ));
        }

        let mut masked = [0u8; MASK_LEN];
        masked.copy_from_slice(&record.payload[masked_offset..data_offset]);
        let mut mask_hasher = self.directional_hasher(false);
        let sample_end = (data_offset + 32).min(record.payload.len());
        mask_hasher.update(&record.payload[data_offset..sample_end]);
        let mask = mask_hasher.finalize();
        for (byte, mask) in masked.iter_mut().zip(&mask.as_bytes()[..MASK_LEN]) {
            *byte ^= *mask;
        }

        let data_len = u16::from_be_bytes([masked[0], masked[1]]) as usize;
        let available = record.payload.len() - data_offset;
        if data_len > available {
            return Err(invalid_data(
                "Restls declared data length exceeds the record payload",
            ));
        }
        let command = RestlsCommand::decode([masked[2], masked[3]])?;

        self.to_server_counter = self
            .to_server_counter
            .checked_add(1)
            .ok_or_else(|| invalid_data("Restls to-server counter exhausted"))?;
        self.client_finished = None;
        Ok(DecodedAppRecord {
            data: record.payload[data_offset..data_offset + data_len].to_vec(),
            command,
        })
    }

    pub fn encode_to_client(
        &mut self,
        data: &[u8],
        target_len: usize,
        command: RestlsCommand,
    ) -> io::Result<EncodedAppRecord> {
        let nonce_len = if self.tls12_server_gcm { 8 } else { 0 };
        let maximum_body = MAX_TLS_RECORD_PAYLOAD
            .checked_sub(nonce_len + AUTH_HEADER_LEN)
            .ok_or_else(|| invalid_data("invalid Restls record overhead"))?;
        if target_len > usize::from(MAX_SCRIPT_TARGET) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restls script target exceeds the TLS record limit",
            ));
        }

        // Restls scripts permit targets up to 32 KiB, but the official client
        // and server clamp every emitted record to TLS's 16 KiB plaintext
        // limit after accounting for the Restls auth header/explicit nonce.
        // Emitting the full script target creates a syntactically valid u16
        // record that real TLS stacks reject as oversized.
        let body_len = target_len
            .min(TLS_MAX_PLAINTEXT.saturating_sub(nonce_len + AUTH_HEADER_LEN))
            .min(maximum_body);
        let consumed = data.len().min(body_len);
        let mut payload = vec![0u8; nonce_len + AUTH_HEADER_LEN + body_len];
        if self.tls12_server_gcm {
            let nonce = self
                .to_client_counter
                .checked_add(1)
                .ok_or_else(|| invalid_data("Restls to-client counter exhausted"))?;
            payload[..8].copy_from_slice(&nonce.to_be_bytes());
        }
        let data_offset = nonce_len + AUTH_HEADER_LEN;
        payload[data_offset..data_offset + consumed].copy_from_slice(&data[..consumed]);
        rand::rng().fill(&mut payload[data_offset + consumed..]);

        let mut masked = [0u8; MASK_LEN];
        masked[..2].copy_from_slice(&(consumed as u16).to_be_bytes());
        masked[2..].copy_from_slice(&command.encode());
        let mut mask_hasher = self.directional_hasher(true);
        let sample_end = (data_offset + 32).min(payload.len());
        mask_hasher.update(&payload[data_offset..sample_end]);
        let mask = mask_hasher.finalize();
        for (byte, mask) in masked.iter_mut().zip(&mask.as_bytes()[..MASK_LEN]) {
            *byte ^= *mask;
        }
        let masked_offset = nonce_len + AUTH_TAG_LEN;
        payload[masked_offset..data_offset].copy_from_slice(&masked);

        let record = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, payload)?;
        let mut auth_hasher = self.directional_hasher(true);
        auth_hasher.update(&record.header());
        auth_hasher.update(&record.payload[..nonce_len]);
        auth_hasher.update(&record.payload[masked_offset..]);
        let authentication = auth_hasher.finalize();
        let auth_offset = nonce_len;
        let mut record = record;
        record.payload[auth_offset..auth_offset + AUTH_TAG_LEN]
            .copy_from_slice(&authentication.as_bytes()[..AUTH_TAG_LEN]);

        self.to_client_counter = self
            .to_client_counter
            .checked_add(1)
            .ok_or_else(|| invalid_data("Restls to-client counter exhausted"))?;
        Ok(EncodedAppRecord {
            record,
            consumed,
            command,
        })
    }

    fn directional_hasher(&self, to_client: bool) -> blake3::Hasher {
        let mut hasher = self.key.hasher();
        hasher.update(&self.server_random);
        if to_client {
            hasher.update(TO_CLIENT_MAGIC);
            hasher.update(&self.to_client_counter.to_be_bytes());
        } else {
            hasher.update(TO_SERVER_MAGIC);
            hasher.update(&self.to_server_counter.to_be_bytes());
        }
        hasher
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_client_record(
        codec: &RestlsAppCodec,
        data: &[u8],
        padding: usize,
        command: RestlsCommand,
        finished: Option<&[u8]>,
    ) -> TlsRecord {
        let nonce_len = if codec.tls12_client_gcm { 8 } else { 0 };
        let mut payload = vec![0u8; nonce_len + AUTH_HEADER_LEN + data.len() + padding];
        if nonce_len != 0 {
            payload[..8].copy_from_slice(&(codec.to_server_counter + 1).to_be_bytes());
        }
        let data_offset = nonce_len + AUTH_HEADER_LEN;
        payload[data_offset..data_offset + data.len()].copy_from_slice(data);
        payload[data_offset + data.len()..].fill(0xa5);

        let mut masked = [0u8; MASK_LEN];
        masked[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        masked[2..].copy_from_slice(&command.encode());
        let mut mask_hasher = codec.directional_hasher(false);
        let sample_end = (data_offset + 32).min(payload.len());
        mask_hasher.update(&payload[data_offset..sample_end]);
        for (byte, mask) in masked
            .iter_mut()
            .zip(&mask_hasher.finalize().as_bytes()[..MASK_LEN])
        {
            *byte ^= *mask;
        }
        let masked_offset = nonce_len + AUTH_TAG_LEN;
        payload[masked_offset..data_offset].copy_from_slice(&masked);

        let mut record = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, payload).unwrap();
        let mut auth = codec.directional_hasher(false);
        if let Some(finished) = finished {
            auth.update(finished);
        }
        auth.update(&record.header());
        auth.update(&record.payload[..nonce_len]);
        auth.update(&record.payload[masked_offset..]);
        record.payload[nonce_len..nonce_len + AUTH_TAG_LEN]
            .copy_from_slice(&auth.finalize().as_bytes()[..AUTH_TAG_LEN]);
        record
    }

    #[test]
    fn authenticates_and_decodes_client_data() {
        let key = RestlsKey::derive("password").unwrap();
        let mut codec = RestlsAppCodec::new(key, [4; 32], false);
        let record = encode_client_record(&codec, b"payload", 19, RestlsCommand::Response(2), None);
        let decoded = codec.decode_from_client(&record).unwrap();
        assert_eq!(decoded.data, b"payload");
        assert_eq!(decoded.command, RestlsCommand::Response(2));
        assert_eq!(codec.counters(), (0, 1));
    }

    #[test]
    fn tampering_replay_and_bad_length_are_rejected_without_advancing_counter() {
        let key = RestlsKey::derive("password").unwrap();
        let mut codec = RestlsAppCodec::new(key, [4; 32], false);
        let record = encode_client_record(&codec, b"payload", 0, RestlsCommand::Noop, None);

        let mut tampered = record.clone();
        *tampered.payload.last_mut().unwrap() ^= 1;
        assert!(codec.decode_from_client(&tampered).is_err());
        assert_eq!(codec.counters(), (0, 0));

        codec.decode_from_client(&record).unwrap();
        assert!(codec.decode_from_client(&record).is_err());
        assert_eq!(codec.counters(), (0, 1));
    }

    #[test]
    fn first_record_is_bound_to_client_finished() {
        let key = RestlsKey::derive("password").unwrap();
        let mut codec = RestlsAppCodec::new(key, [4; 32], false);
        codec
            .bind_first_client_record_to_finished(b"finished-record".to_vec())
            .unwrap();
        let record = encode_client_record(
            &codec,
            b"data",
            0,
            RestlsCommand::Noop,
            Some(b"finished-record"),
        );
        codec.decode_from_client(&record).unwrap();
    }

    #[test]
    fn tls12_nonce_is_checked() {
        let key = RestlsKey::derive("password").unwrap();
        let mut codec = RestlsAppCodec::new(key, [4; 32], true);
        let mut record = encode_client_record(&codec, b"data", 0, RestlsCommand::Noop, None);
        record.payload[..8].copy_from_slice(&9u64.to_be_bytes());
        assert!(codec.decode_from_client(&record).is_err());
    }

    #[test]
    fn full_script_target_is_clamped_to_tls_plaintext_and_larger_targets_are_rejected() {
        let key = RestlsKey::derive("password").unwrap();
        let mut codec = RestlsAppCodec::new(key, [4; 32], false);
        let encoded = codec
            .encode_to_client(b"data", usize::from(MAX_SCRIPT_TARGET), RestlsCommand::Noop)
            .unwrap();
        assert_eq!(encoded.consumed, 4);
        assert_eq!(encoded.record.payload.len(), TLS_MAX_PLAINTEXT);
        assert!(
            codec
                .encode_to_client(
                    b"data",
                    usize::from(MAX_SCRIPT_TARGET) + 1,
                    RestlsCommand::Noop,
                )
                .is_err()
        );
    }
}
