// Event-driven Restls server state machine derived from the original
// 3andne/restls server (BSD-3-Clause). Network ownership intentionally stays
// with the runtime graph so fallback, deadlines and task supervision are not
// hidden inside the protocol parser.

use std::io;

use super::{
    app::{DecodedAppRecord, EncodedAppRecord, RestlsAppCodec, RestlsCommand},
    auth::RestlsKey,
    hello::{ClientHello, ServerHello},
    record::{
        RECORD_APPLICATION_DATA, RECORD_CHANGE_CIPHER_SPEC, RECORD_HANDSHAKE, TlsRecord,
        invalid_data,
    },
};

const HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestlsServerStage {
    AwaitClientHello,
    AwaitServerHello,
    Tls13AwaitServerCcs,
    Tls13AwaitServerAuth,
    Tls13AwaitClientCcs,
    Tls13AwaitClientFinished,
    Tls13AwaitClientApplication,
    Tls12Handshake,
    Authenticated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestlsServerAction {
    /// Relay the record unchanged to the opposite side.
    Relay,
    /// Relay the record after this state machine has applied server auth.
    RelayMutated,
    /// Do not relay to the camouflage server; deliver this payload to Raw SS.
    Authenticated(DecodedAppRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tls12Flow {
    Initial,
    ClientKeyExchangeVerified,
    FullClientCcs,
    FullServerCcs,
    FullServerFinished,
    ResumeServerCcs,
    ResumeServerFinished,
    ResumeClientCcs,
}

#[derive(Clone)]
pub struct RestlsServerCore {
    key: RestlsKey,
    stage: RestlsServerStage,
    client_hello: Option<ClientHello>,
    server_hello: Option<ServerHello>,
    app_codec: Option<RestlsAppCodec>,
    tls12_flow: Tls12Flow,
    tls12_curve_id: Option<u16>,
    tls13_client_handshake_records: u64,
    tls13_target_raw_records: u64,
    tls13_did_resume: bool,
}

impl RestlsServerCore {
    pub fn new(password: impl AsRef<[u8]>) -> io::Result<Self> {
        Ok(Self::from_key(RestlsKey::derive(password)?))
    }

    pub(crate) fn from_key(key: RestlsKey) -> Self {
        Self {
            key,
            stage: RestlsServerStage::AwaitClientHello,
            client_hello: None,
            server_hello: None,
            app_codec: None,
            tls12_flow: Tls12Flow::Initial,
            tls12_curve_id: None,
            tls13_client_handshake_records: 0,
            tls13_target_raw_records: 0,
            tls13_did_resume: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn authenticated_for_test(key: RestlsKey, server_random: [u8; 32]) -> Self {
        let mut core = Self::from_key(key.clone());
        core.stage = RestlsServerStage::Authenticated;
        core.app_codec = Some(RestlsAppCodec::new(key, server_random, false));
        core
    }

    pub fn stage(&self) -> RestlsServerStage {
        self.stage
    }

    pub fn on_client_record(&mut self, record: &mut TlsRecord) -> io::Result<RestlsServerAction> {
        match self.stage {
            RestlsServerStage::AwaitClientHello => {
                let hello = ClientHello::parse(record)?;
                self.client_hello = Some(hello);
                self.stage = RestlsServerStage::AwaitServerHello;
                Ok(RestlsServerAction::Relay)
            }
            RestlsServerStage::AwaitServerHello
            | RestlsServerStage::Tls13AwaitServerCcs
            | RestlsServerStage::Tls13AwaitServerAuth => Err(invalid_data(
                "client record arrived before the camouflage ServerHello/auth",
            )),
            RestlsServerStage::Tls13AwaitClientCcs => {
                validate_ccs(record)?;
                self.stage = RestlsServerStage::Tls13AwaitClientFinished;
                Ok(RestlsServerAction::Relay)
            }
            RestlsServerStage::Tls13AwaitClientFinished => {
                if record.content_type != RECORD_APPLICATION_DATA {
                    return Err(invalid_data(
                        "expected encrypted TLS 1.3 ClientFinished record",
                    ));
                }
                self.codec_mut()?
                    .bind_first_client_record_to_finished(record.encode())?;
                self.tls13_client_handshake_records = 1;
                self.stage = RestlsServerStage::Tls13AwaitClientApplication;
                Ok(RestlsServerAction::Relay)
            }
            RestlsServerStage::Tls13AwaitClientApplication => {
                if record.content_type != RECORD_APPLICATION_DATA || record.legacy_version != 0x0303
                {
                    return Err(invalid_data(
                        "expected encrypted TLS 1.3 client handshake/application record",
                    ));
                }
                match self.codec_mut()?.decode_from_client(record) {
                    Ok(decoded) => {
                        self.account_tls13_early_target_records()?;
                        self.stage = RestlsServerStage::Authenticated;
                        Ok(RestlsServerAction::Authenticated(decoded))
                    }
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        self.codec_mut()?
                            .replace_client_finished_binding(record.encode())?;
                        self.tls13_client_handshake_records = self
                            .tls13_client_handshake_records
                            .checked_add(1)
                            .ok_or_else(|| invalid_data("too many TLS 1.3 client records"))?;
                        Ok(RestlsServerAction::Relay)
                    }
                    Err(error) => Err(error),
                }
            }
            RestlsServerStage::Tls12Handshake => self.on_tls12_client_record(record),
            RestlsServerStage::Authenticated => {
                let decoded = self.codec_mut()?.decode_from_client(record)?;
                Ok(RestlsServerAction::Authenticated(decoded))
            }
        }
    }

    pub fn on_camouflage_record(
        &mut self,
        record: &mut TlsRecord,
    ) -> io::Result<RestlsServerAction> {
        match self.stage {
            RestlsServerStage::AwaitClientHello => {
                Err(invalid_data("ServerHello arrived before ClientHello"))
            }
            RestlsServerStage::AwaitServerHello => {
                let hello = ServerHello::parse(record)?;
                if hello.is_tls13 {
                    self.key.verify_tls13_client_hello(
                        self.client_hello
                            .as_ref()
                            .ok_or_else(|| invalid_data("missing parsed ClientHello"))?,
                    )?;
                } else {
                    self.capture_tls12_curve(record)?;
                }
                self.app_codec = Some(RestlsAppCodec::new(
                    self.key.clone(),
                    hello.server_random,
                    hello.is_tls12_gcm,
                ));
                let is_tls13 = hello.is_tls13;
                self.tls13_did_resume = hello.selected_identity.is_some();
                self.server_hello = Some(hello);
                self.stage = if is_tls13 {
                    RestlsServerStage::Tls13AwaitServerCcs
                } else {
                    RestlsServerStage::Tls12Handshake
                };
                Ok(RestlsServerAction::Relay)
            }
            RestlsServerStage::Tls13AwaitServerCcs => {
                validate_ccs(record)?;
                self.stage = RestlsServerStage::Tls13AwaitServerAuth;
                Ok(RestlsServerAction::Relay)
            }
            RestlsServerStage::Tls13AwaitServerAuth => {
                if record.content_type != RECORD_APPLICATION_DATA {
                    return Err(invalid_data(
                        "expected encrypted TLS 1.3 server handshake record",
                    ));
                }
                self.apply_server_auth(record)?;
                self.stage = RestlsServerStage::Tls13AwaitClientCcs;
                Ok(RestlsServerAction::RelayMutated)
            }
            RestlsServerStage::Tls13AwaitClientCcs
            | RestlsServerStage::Tls13AwaitClientFinished => {
                self.count_tls13_early_target_record(record)?;
                Ok(RestlsServerAction::Relay)
            }
            RestlsServerStage::Tls13AwaitClientApplication => {
                self.count_tls13_early_target_record(record)?;
                Ok(RestlsServerAction::Relay)
            }
            RestlsServerStage::Tls12Handshake => self.on_tls12_server_record(record),
            RestlsServerStage::Authenticated => Err(invalid_data(
                "camouflage handshake data arrived after Restls authentication",
            )),
        }
    }

    pub fn encode_to_client(
        &mut self,
        data: &[u8],
        target_len: usize,
        command: RestlsCommand,
    ) -> io::Result<EncodedAppRecord> {
        if self.stage != RestlsServerStage::Authenticated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restls connection is not authenticated",
            ));
        }
        self.codec_mut()?
            .encode_to_client(data, target_len, command)
    }

    pub fn counters(&self) -> Option<(u64, u64)> {
        self.app_codec.as_ref().map(RestlsAppCodec::counters)
    }

    pub fn relay_post_auth_camouflage_record(&mut self, record: &TlsRecord) -> io::Result<()> {
        if self.stage != RestlsServerStage::Authenticated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restls connection is not authenticated",
            ));
        }
        if record.payload.len() + 5 >= 50 {
            self.codec_mut()?.note_camouflage_record_to_client()?;
        }
        Ok(())
    }

    fn on_tls12_client_record(&mut self, record: &mut TlsRecord) -> io::Result<RestlsServerAction> {
        match record.content_type {
            RECORD_CHANGE_CIPHER_SPEC => {
                validate_ccs(record)?;
                self.tls12_flow = match self.tls12_flow {
                    Tls12Flow::ClientKeyExchangeVerified => Tls12Flow::FullClientCcs,
                    Tls12Flow::ResumeServerFinished => Tls12Flow::ResumeClientCcs,
                    _ => return Err(invalid_data("unexpected client CCS in Restls TLS 1.2")),
                };
                Ok(RestlsServerAction::Relay)
            }
            RECORD_HANDSHAKE if self.tls12_flow == Tls12Flow::Initial => {
                let curve_id = self
                    .tls12_curve_id
                    .ok_or_else(|| invalid_data("TLS 1.2 server did not select an ECDHE curve"))?;
                self.key.verify_tls12_client_key_exchange(
                    self.client_hello
                        .as_ref()
                        .ok_or_else(|| invalid_data("missing ClientHello"))?,
                    curve_id,
                    record,
                )?;
                self.tls12_flow = Tls12Flow::ClientKeyExchangeVerified;
                Ok(RestlsServerAction::Relay)
            }
            RECORD_HANDSHAKE if self.tls12_flow == Tls12Flow::ResumeClientCcs => {
                self.codec_mut()?
                    .bind_first_client_record_to_finished(record.encode())?;
                Ok(RestlsServerAction::Relay)
            }
            RECORD_HANDSHAKE => Ok(RestlsServerAction::Relay),
            RECORD_APPLICATION_DATA
                if matches!(
                    self.tls12_flow,
                    Tls12Flow::FullServerFinished | Tls12Flow::ResumeClientCcs
                ) =>
            {
                let decoded = self.codec_mut()?.decode_from_client(record)?;
                self.stage = RestlsServerStage::Authenticated;
                Ok(RestlsServerAction::Authenticated(decoded))
            }
            _ => Err(invalid_data(
                "unexpected client record in Restls TLS 1.2 flow",
            )),
        }
    }

    fn on_tls12_server_record(&mut self, record: &mut TlsRecord) -> io::Result<RestlsServerAction> {
        match record.content_type {
            RECORD_CHANGE_CIPHER_SPEC => {
                validate_ccs(record)?;
                self.tls12_flow = match self.tls12_flow {
                    Tls12Flow::Initial => Tls12Flow::ResumeServerCcs,
                    Tls12Flow::FullClientCcs => Tls12Flow::FullServerCcs,
                    _ => return Err(invalid_data("unexpected server CCS in Restls TLS 1.2")),
                };
                Ok(RestlsServerAction::Relay)
            }
            RECORD_HANDSHAKE if self.tls12_flow == Tls12Flow::FullServerCcs => {
                self.apply_server_auth(record)?;
                self.tls12_flow = Tls12Flow::FullServerFinished;
                Ok(RestlsServerAction::RelayMutated)
            }
            RECORD_HANDSHAKE if self.tls12_flow == Tls12Flow::ResumeServerCcs => {
                self.key.verify_tls12_session_ticket(
                    self.client_hello
                        .as_ref()
                        .ok_or_else(|| invalid_data("missing ClientHello"))?,
                )?;
                self.apply_server_auth(record)?;
                self.tls12_flow = Tls12Flow::ResumeServerFinished;
                Ok(RestlsServerAction::RelayMutated)
            }
            RECORD_HANDSHAKE => {
                self.capture_tls12_curve(record)?;
                Ok(RestlsServerAction::Relay)
            }
            RECORD_APPLICATION_DATA
                if matches!(
                    self.tls12_flow,
                    Tls12Flow::FullServerFinished | Tls12Flow::ResumeServerFinished
                ) =>
            {
                self.codec_mut()?.note_camouflage_record_to_client()?;
                Ok(RestlsServerAction::Relay)
            }
            _ => Err(invalid_data(
                "unexpected server record in Restls TLS 1.2 flow",
            )),
        }
    }

    fn apply_server_auth(&mut self, record: &mut TlsRecord) -> io::Result<()> {
        let parrot_gcm = self.key.apply_server_auth(
            self.server_hello
                .as_ref()
                .ok_or_else(|| invalid_data("missing ServerHello"))?,
            record,
        )?;
        self.codec_mut()?.set_tls12_server_gcm(parrot_gcm);
        Ok(())
    }

    fn count_tls13_early_target_record(&mut self, record: &TlsRecord) -> io::Result<()> {
        if record.content_type != RECORD_APPLICATION_DATA || record.legacy_version != 0x0303 {
            return Err(invalid_data(
                "unexpected TLS 1.3 server-flight record after server authentication",
            ));
        }
        self.tls13_target_raw_records = self
            .tls13_target_raw_records
            .checked_add(1)
            .ok_or_else(|| invalid_data("too many TLS 1.3 target records"))?;
        Ok(())
    }

    fn account_tls13_early_target_records(&mut self) -> io::Result<()> {
        let expected_server_flight_records = if self.tls13_did_resume {
            1
        } else if self.tls13_client_handshake_records > 1 {
            4
        } else {
            3
        };
        let extra = self
            .tls13_target_raw_records
            .saturating_sub(expected_server_flight_records);
        self.codec_mut()?.note_camouflage_records_to_client(extra)
    }

    fn capture_tls12_curve(&mut self, record: &TlsRecord) -> io::Result<()> {
        if record.content_type != RECORD_HANDSHAKE {
            return Ok(());
        }
        for message in record.handshake_messages()? {
            let message = message?;
            if message.handshake_type != HANDSHAKE_SERVER_KEY_EXCHANGE {
                continue;
            }
            if message.body.len() < 3 || message.body[0] != 3 {
                return Err(invalid_data(
                    "Restls TLS 1.2 requires a named-curve ServerKeyExchange",
                ));
            }
            let curve_id = u16::from_be_bytes([message.body[1], message.body[2]]);
            if !matches!(curve_id, 29 | 23 | 24) {
                return Err(invalid_data("unsupported TLS 1.2 ECDHE curve"));
            }
            if self.tls12_curve_id.replace(curve_id).is_some() {
                return Err(invalid_data("duplicate TLS 1.2 ServerKeyExchange"));
            }
        }
        Ok(())
    }

    fn codec_mut(&mut self) -> io::Result<&mut RestlsAppCodec> {
        self.app_codec
            .as_mut()
            .ok_or_else(|| invalid_data("Restls application codec is not initialized"))
    }
}

fn validate_ccs(record: &TlsRecord) -> io::Result<()> {
    if record.content_type == RECORD_CHANGE_CIPHER_SPEC
        && record.legacy_version == 0x0303
        && record.payload == [1]
    {
        Ok(())
    } else {
        Err(invalid_data("malformed TLS ChangeCipherSpec record"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&kind.to_be_bytes());
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value);
        output
    }

    fn tls13_client_hello(key: &RestlsKey) -> TlsRecord {
        let key_share_auth = [0, 29, 1, 2, 3];
        let mut hasher = key.hasher();
        hasher.update(&key_share_auth);
        let mut session_id = [0u8; 32];
        session_id[..16].copy_from_slice(&hasher.finalize().as_bytes()[..16]);

        let mut extensions = extension(0x002b, &[2, 3, 4]);
        extensions.extend_from_slice(&extension(0x0033, &[0, 7, 0, 29, 0, 3, 1, 2, 3]));
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let length = body.len();
        let mut payload = vec![
            1,
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            length as u8,
        ];
        payload.extend_from_slice(&body);
        TlsRecord::new(RECORD_HANDSHAKE, 0x0301, payload).unwrap()
    }

    fn tls13_resumed_client_hello(key: &RestlsKey) -> TlsRecord {
        let key_share_auth = [0, 29, 1, 2, 3];
        let psk_identity = b"session-ticket";
        let mut hasher = key.hasher();
        hasher.update(&key_share_auth);
        hasher.update(psk_identity);
        let mut session_id = [0u8; 32];
        session_id[..16].copy_from_slice(&hasher.finalize().as_bytes()[..16]);

        let mut extensions = extension(0x002b, &[2, 3, 4]);
        extensions.extend_from_slice(&extension(0x0033, &[0, 7, 0, 29, 0, 3, 1, 2, 3]));
        let mut identities = Vec::new();
        identities.extend_from_slice(&(psk_identity.len() as u16).to_be_bytes());
        identities.extend_from_slice(psk_identity);
        identities.extend_from_slice(&0u32.to_be_bytes());
        let mut psk = Vec::new();
        psk.extend_from_slice(&(identities.len() as u16).to_be_bytes());
        psk.extend_from_slice(&identities);
        psk.extend_from_slice(&2u16.to_be_bytes());
        psk.extend_from_slice(&[1, 0xa5]);
        extensions.extend_from_slice(&extension(0x0029, &psk));

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let length = body.len();
        let mut payload = vec![
            1,
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            length as u8,
        ];
        payload.extend_from_slice(&body);
        TlsRecord::new(RECORD_HANDSHAKE, 0x0301, payload).unwrap()
    }

    fn tls13_server_hello() -> TlsRecord {
        let mut extensions = extension(0x002b, &[3, 4]);
        extensions.extend_from_slice(&extension(0x0033, &[0, 29, 0, 3, 4, 5, 6]));
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[8; 32]);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let length = body.len();
        let mut payload = vec![
            2,
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            length as u8,
        ];
        payload.extend_from_slice(&body);
        TlsRecord::new(RECORD_HANDSHAKE, 0x0303, payload).unwrap()
    }

    fn tls13_resumed_server_hello() -> TlsRecord {
        let mut extensions = extension(0x002b, &[3, 4]);
        extensions.extend_from_slice(&extension(0x0033, &[0, 29, 0, 3, 4, 5, 6]));
        extensions.extend_from_slice(&extension(0x0029, &[0, 0]));
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[8; 32]);
        body.push(0);
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let length = body.len();
        let mut payload = vec![
            2,
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            length as u8,
        ];
        payload.extend_from_slice(&body);
        TlsRecord::new(RECORD_HANDSHAKE, 0x0303, payload).unwrap()
    }

    fn client_app_record(
        key: &RestlsKey,
        server_random: [u8; 32],
        finished: &[u8],
        data: &[u8],
    ) -> TlsRecord {
        const AUTH_LEN: usize = 8;
        const MASK_LEN: usize = 4;
        let mut payload = vec![0u8; AUTH_LEN + MASK_LEN + data.len()];
        payload[AUTH_LEN + MASK_LEN..].copy_from_slice(data);

        let mut mask = key.hasher();
        mask.update(&server_random);
        mask.update(b"client-to-server");
        mask.update(&0u64.to_be_bytes());
        mask.update(data);
        let mask = mask.finalize();
        let mut masked = [0u8; MASK_LEN];
        masked[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
        for (byte, mask) in masked.iter_mut().zip(&mask.as_bytes()[..MASK_LEN]) {
            *byte ^= *mask;
        }
        payload[AUTH_LEN..AUTH_LEN + MASK_LEN].copy_from_slice(&masked);

        let mut record = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, payload).unwrap();
        let mut auth = key.hasher();
        auth.update(&server_random);
        auth.update(b"client-to-server");
        auth.update(&0u64.to_be_bytes());
        auth.update(finished);
        auth.update(&record.header());
        auth.update(&record.payload[AUTH_LEN..]);
        record.payload[..AUTH_LEN].copy_from_slice(&auth.finalize().as_bytes()[..AUTH_LEN]);
        record
    }

    #[test]
    fn tls13_handshake_reaches_strict_application_boundary() {
        let key = RestlsKey::derive("password").unwrap();
        let mut core = RestlsServerCore::new("password").unwrap();
        let mut client_hello = tls13_client_hello(&key);
        assert_eq!(
            core.on_client_record(&mut client_hello).unwrap(),
            RestlsServerAction::Relay
        );
        let mut server_hello = tls13_server_hello();
        core.on_camouflage_record(&mut server_hello).unwrap();
        assert_eq!(core.stage(), RestlsServerStage::Tls13AwaitServerCcs);

        let mut ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_camouflage_record(&mut ccs).unwrap();
        let mut encrypted = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![4; 32]).unwrap();
        assert_eq!(
            core.on_camouflage_record(&mut encrypted).unwrap(),
            RestlsServerAction::RelayMutated
        );
        assert_eq!(core.stage(), RestlsServerStage::Tls13AwaitClientCcs);

        let mut bad_ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![2]).unwrap();
        assert!(core.on_client_record(&mut bad_ccs).is_err());
        assert_eq!(core.stage(), RestlsServerStage::Tls13AwaitClientCcs);
    }

    #[test]
    fn tls13_accepts_multiple_encrypted_client_handshake_records() {
        let key = RestlsKey::derive("password").unwrap();
        let mut core = RestlsServerCore::new("password").unwrap();
        let mut client_hello = tls13_client_hello(&key);
        core.on_client_record(&mut client_hello).unwrap();
        let mut server_hello = tls13_server_hello();
        core.on_camouflage_record(&mut server_hello).unwrap();
        let mut server_ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_camouflage_record(&mut server_ccs).unwrap();
        let mut server_auth = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![4; 32]).unwrap();
        core.on_camouflage_record(&mut server_auth).unwrap();
        let mut client_ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_client_record(&mut client_ccs).unwrap();

        let mut first_handshake =
            TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![0x31; 48]).unwrap();
        assert_eq!(
            core.on_client_record(&mut first_handshake).unwrap(),
            RestlsServerAction::Relay
        );
        let mut final_finished =
            TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![0x32; 52]).unwrap();
        assert_eq!(
            core.on_client_record(&mut final_finished).unwrap(),
            RestlsServerAction::Relay
        );

        let mut application = client_app_record(&key, [8; 32], &final_finished.encode(), b"inner");
        assert_eq!(
            core.on_client_record(&mut application).unwrap(),
            RestlsServerAction::Authenticated(DecodedAppRecord {
                data: b"inner".to_vec(),
                command: RestlsCommand::Noop,
            })
        );
        assert_eq!(core.counters(), Some((0, 1)));
    }

    #[test]
    fn tls13_accounts_only_extra_early_target_records() {
        let key = RestlsKey::derive("password").unwrap();
        let mut core = RestlsServerCore::new("password").unwrap();
        let mut client_hello = tls13_client_hello(&key);
        core.on_client_record(&mut client_hello).unwrap();
        let mut server_hello = tls13_server_hello();
        core.on_camouflage_record(&mut server_hello).unwrap();
        let mut server_ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_camouflage_record(&mut server_ccs).unwrap();
        let mut server_auth = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![4; 32]).unwrap();
        core.on_camouflage_record(&mut server_auth).unwrap();

        for marker in 0..2 {
            let mut target_record =
                TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![marker; 64]).unwrap();
            assert_eq!(
                core.on_camouflage_record(&mut target_record).unwrap(),
                RestlsServerAction::Relay
            );
        }

        let mut client_ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_client_record(&mut client_ccs).unwrap();
        let mut first_handshake =
            TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![0x41; 48]).unwrap();
        core.on_client_record(&mut first_handshake).unwrap();

        for marker in 2..6 {
            let mut target_record =
                TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![marker; 64]).unwrap();
            assert_eq!(
                core.on_camouflage_record(&mut target_record).unwrap(),
                RestlsServerAction::Relay
            );
        }

        let mut final_finished =
            TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![0x42; 52]).unwrap();
        core.on_client_record(&mut final_finished).unwrap();
        let mut application = client_app_record(&key, [8; 32], &final_finished.encode(), b"inner");
        assert!(matches!(
            core.on_client_record(&mut application).unwrap(),
            RestlsServerAction::Authenticated(_)
        ));

        // A full handshake with multiple client-handshake records accounts for
        // four ordinary early target records; only the two extras affect Restls.
        assert_eq!(core.counters(), Some((2, 1)));
    }

    #[test]
    fn tls13_resumption_accounts_one_ordinary_early_target_record() {
        let key = RestlsKey::derive("password").unwrap();
        let mut core = RestlsServerCore::new("password").unwrap();
        let mut client_hello = tls13_resumed_client_hello(&key);
        core.on_client_record(&mut client_hello).unwrap();
        let mut server_hello = tls13_resumed_server_hello();
        core.on_camouflage_record(&mut server_hello).unwrap();
        let mut server_ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_camouflage_record(&mut server_ccs).unwrap();
        let mut server_auth = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![4; 32]).unwrap();
        core.on_camouflage_record(&mut server_auth).unwrap();

        for marker in 0..3 {
            let mut target_record =
                TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![marker; 64]).unwrap();
            core.on_camouflage_record(&mut target_record).unwrap();
        }

        let mut client_ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_client_record(&mut client_ccs).unwrap();
        let mut finished = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![0x51; 48]).unwrap();
        core.on_client_record(&mut finished).unwrap();
        let mut application = client_app_record(&key, [8; 32], &finished.encode(), b"inner");
        assert!(matches!(
            core.on_client_record(&mut application).unwrap(),
            RestlsServerAction::Authenticated(_)
        ));

        assert_eq!(core.counters(), Some((2, 1)));
    }

    #[test]
    fn tampered_tls13_client_auth_never_mutates_server_flight() {
        let mut core = RestlsServerCore::new("password").unwrap();
        let key = RestlsKey::derive("password").unwrap();
        let mut client_hello = tls13_client_hello(&key);
        *client_hello.payload.last_mut().unwrap() ^= 1;
        core.on_client_record(&mut client_hello).unwrap();

        let mut server_hello = tls13_server_hello();
        let original = server_hello.clone();
        assert!(core.on_camouflage_record(&mut server_hello).is_err());
        assert_eq!(server_hello, original);
        assert_eq!(core.stage(), RestlsServerStage::AwaitServerHello);
    }

    #[test]
    fn server_auth_rejects_short_encrypted_record() {
        let key = RestlsKey::derive("password").unwrap();
        let mut core = RestlsServerCore::new("password").unwrap();
        let mut client_hello = tls13_client_hello(&key);
        core.on_client_record(&mut client_hello).unwrap();
        let mut server_hello = tls13_server_hello();
        core.on_camouflage_record(&mut server_hello).unwrap();
        let mut ccs = TlsRecord::new(RECORD_CHANGE_CIPHER_SPEC, 0x0303, vec![1]).unwrap();
        core.on_camouflage_record(&mut ccs).unwrap();

        let mut short = TlsRecord::new(RECORD_APPLICATION_DATA, 0x0303, vec![0; 15]).unwrap();
        assert!(core.on_camouflage_record(&mut short).is_err());
    }
}
