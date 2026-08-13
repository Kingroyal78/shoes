use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::pki_types::pem::PemObject;

pub fn create_client_config(
    verify_webpki: bool,
    server_fingerprints: Vec<String>,
    alpn_protocols: Vec<String>,
    enable_sni: bool,
    client_key_and_cert: Option<(Vec<u8>, Vec<u8>)>,
    tls13_only: bool,
) -> rustls::ClientConfig {
    let builder = rustls::ClientConfig::builder_with_provider(get_crypto_provider());
    let builder = if tls13_only {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
    } else {
        builder.with_safe_default_protocol_versions().unwrap()
    };

    let builder = if verify_webpki {
        let webpki_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            get_root_cert_store(),
            get_crypto_provider(),
        )
        .build()
        .unwrap();
        if !server_fingerprints.is_empty() {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                    supported_algs: get_supported_algorithms(),
                    server_fingerprints: process_fingerprints(&server_fingerprints).unwrap(),
                    webpki_verifier: Some(Arc::into_inner(webpki_verifier).unwrap()),
                }))
        } else {
            builder.with_webpki_verifier(webpki_verifier)
        }
    } else if !server_fingerprints.is_empty() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                supported_algs: get_supported_algorithms(),
                server_fingerprints: process_fingerprints(&server_fingerprints).unwrap(),
                webpki_verifier: None,
            }))
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(get_disabled_verifier())
    };

    let mut config = match client_key_and_cert {
        Some((key_bytes, cert_bytes)) => {
            // Parse all certificates from the PEM file (client cert + intermediates if any)
            let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_bytes)
                .map(|cert| cert.unwrap().into_owned())
                .collect();

            let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_bytes).unwrap();
            builder
                .with_client_auth_cert(certs, privkey)
                .expect("Could not parse client certificate")
        }
        None => builder.with_no_client_auth(),
    };

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.enable_sni = enable_sni;
    config
}

#[derive(Debug)]
pub struct ServerFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    server_fingerprints: BTreeSet<Vec<u8>>,
    webpki_verifier: Option<rustls::client::WebPkiServerVerifier>,
}

impl rustls::client::danger::ServerCertVerifier for ServerFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref webpki_verifier) = self.webpki_verifier {
            let _ = webpki_verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }

        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.server_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown server fingerprint: {hex_fingerprint}"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

#[derive(Debug)]
pub struct DisabledVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn get_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTANCE: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

fn get_supported_algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    get_crypto_provider().signature_verification_algorithms
}

fn get_disabled_verifier() -> Arc<DisabledVerifier> {
    static INSTANCE: OnceLock<Arc<DisabledVerifier>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            Arc::new(DisabledVerifier {
                supported_algs: get_supported_algorithms(),
            })
        })
        .clone()
}

fn get_root_cert_store() -> Arc<rustls::RootCertStore> {
    static INSTANCE: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(root_store)
        })
        .clone()
}

/// Creates a simple TLS ClientConfig with root CA verification.
/// Used by hickory-resolver for DoT/DoH connections.
pub fn create_dns_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(get_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates((*get_root_cert_store()).clone())
        .with_no_client_auth()
}

/// Builds a server config from material this process vouches for.
///
/// Panics on anything malformed, which is the right answer for a local file an
/// operator placed and `shoes validate` already read back. Material that
/// arrives over the wire must go through [`try_create_server_config`] instead.
pub fn create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    ca_cert_bytes: Vec<Vec<u8>>,
    alpn_protocols: &[String],
    client_fingerprints: &[String],
) -> rustls::ServerConfig {
    try_create_server_config(
        cert_bytes,
        key_bytes,
        ca_cert_bytes,
        alpn_protocols,
        client_fingerprints,
    )
    .expect("bad certificate/key")
}

/// Builds a server config from material that has not been vetted.
///
/// A panel node form is a text box: a truncated certificate, a key belonging
/// to a different certificate, or a CA bundle with a stray line all arrive
/// here as ordinary input. Unwrapping on those would take down a process whose
/// contract is to refuse the generation and keep serving the last known good
/// one, so every step reports instead.
pub fn try_create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    ca_cert_bytes: Vec<Vec<u8>>,
    alpn_protocols: &[String],
    client_fingerprints: &[String],
) -> std::io::Result<rustls::ServerConfig> {
    // The whole chain: server certificate first, then any intermediates.
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert_bytes)
        .map(|cert| cert.map(|cert| cert.into_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid_data(format!("certificate is not valid PEM: {error}")))?;
    if certs.is_empty() {
        return Err(invalid_data("certificate contains no PEM certificate"));
    }

    log::debug!(
        "TLS server config: loaded {} certificate(s) in chain",
        certs.len()
    );

    let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes)
        .map_err(|error| invalid_data(format!("private key is not valid PEM: {error}")))?;

    let webpki_verifier = if ca_cert_bytes.is_empty() {
        None
    } else {
        let mut store = rustls::RootCertStore::empty();
        for ca_cert in ca_cert_bytes.iter() {
            // Every certificate in the blob, not just the first: a trust
            // anchor is routinely pasted in as a root plus its intermediates,
            // and silently keeping one of them rejects clients issued under
            // the rest with nothing to explain why.
            let anchors = rustls::pki_types::CertificateDer::pem_slice_iter(ca_cert)
                .map(|cert| cert.map(|cert| cert.into_owned()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| invalid_data(format!("client CA is not valid PEM: {error}")))?;
            if anchors.is_empty() {
                return Err(invalid_data("client CA contains no PEM certificate"));
            }
            for anchor in anchors {
                store
                    .add(anchor)
                    .map_err(|error| invalid_data(format!("client CA is unusable: {error}")))?;
            }
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(store),
            get_crypto_provider(),
        )
        .build()
        .map_err(|error| invalid_data(format!("client CA cannot verify anything: {error}")))?;
        Some(verifier)
    };

    let builder = rustls::ServerConfig::builder_with_provider(get_crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid_data(format!("no usable TLS protocol versions: {error}")))?;
    // Always wraps in ClientFingerprintVerifier even for CA-only auth, because
    // WebPkiClientVerifier's root_hint_subjects() decides on its own what to
    // disclose; this type keeps that choice here.
    let builder = if client_fingerprints.is_empty() && webpki_verifier.is_none() {
        builder.with_no_client_auth()
    } else {
        let root_hint_subjects = webpki_verifier
            .as_ref()
            .map(|verifier| verifier.root_hint_subjects().to_vec())
            .unwrap_or_default();
        builder.with_client_cert_verifier(Arc::new(ClientFingerprintVerifier {
            supported_algs: get_supported_algorithms(),
            webpki_verifier,
            client_fingerprints: process_fingerprints(client_fingerprints)?,
            root_hint_subjects,
        }))
    };
    let mut config = builder.with_single_cert(certs, privkey).map_err(|error| {
        invalid_data(format!("certificate and private key do not pair: {error}"))
    })?;

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.max_fragment_size = None;
    config.max_early_data_size = u32::MAX;
    config.ignore_client_order = true;

    Ok(config)
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

pub fn process_fingerprints(client_fingerprints: &[String]) -> std::io::Result<BTreeSet<Vec<u8>>> {
    let mut result = BTreeSet::new();

    for fingerprint in client_fingerprints {
        // Remove any colons and whitespace
        let clean_fp = fingerprint.replace(":", "").replace(" ", "");

        if clean_fp.len() % 2 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid client fingerprint, odd number of hex chars: {fingerprint}"),
            ));
        }

        let bytes = (0..clean_fp.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean_fp[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid client fingerprint, could not convert to hex: {fingerprint}"),
                )
            })?;

        result.insert(bytes);
    }

    Ok(result)
}

#[derive(Debug)]
pub struct ClientFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    webpki_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    client_fingerprints: BTreeSet<Vec<u8>>,
    root_hint_subjects: Vec<rustls::DistinguishedName>,
}

impl rustls::server::danger::ClientCertVerifier for ClientFingerprintVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // Empty unless a client CA is configured, so a listener that only
        // pins fingerprints still tells an unauthenticated prober nothing.
        //
        // With a CA configured the hint has to go out: Go's TLS client -- and
        // so every Mihomo build -- sends no certificate at all when the
        // request carries no acceptable CA names, which made mutual TLS look
        // enabled while every client was refused for presenting nothing.
        &self.root_hint_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if let Some(ref webpki_verifier) = self.webpki_verifier {
            let result = webpki_verifier.verify_client_cert(end_entity, intermediates, now);
            if result.is_ok() {
                return Ok(rustls::server::danger::ClientCertVerified::assertion());
            }
        }

        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.client_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown client fingerprint: {hex_fingerprint}"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway material, inline because the repository ignores *.pem and a
    // fixture file that cannot be committed compiles here and nowhere else.
    /// Self-signed `CN=shoes-test-cert`.
    const CERT: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIDFTCCAf2gAwIBAgIUOCLlcEQcF9l+Np0hBqS9ETNpTU8wDQYJKoZIhvcNAQEL\n\
BQAwGjEYMBYGA1UEAwwPc2hvZXMtdGVzdC1jZXJ0MB4XDTI2MDgxMzA5NTIwNFoX\n\
DTM2MDgxMDA5NTIwNFowGjEYMBYGA1UEAwwPc2hvZXMtdGVzdC1jZXJ0MIIBIjAN\n\
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvO0B/AUk1qDFpBvntJCSoLN181Yf\n\
isZXC1fRvHPGOk6xwLRUg5H1kbcOKsNiMELEpsbDagE33OHqTN0qbdQUKtwjbNrW\n\
3A5bsnhwRhdMTOvzx9zvOHP7LxMAkyAwcL2YuqOfMTZ89f7Xr+5YruIIdoJ+FPrx\n\
wk813qYQVDrOsciijCro1q9stFOe0qy4lFPvqXQa170q4+Tsnx46CXcyFt+fR6hw\n\
GEwiPP61FD/d8g0t8PdASFp/kQ9nl5guSL26zIEv3nK9Gty9NOZRe+OTMa5MYmcY\n\
4Dv3yPL4YnKw6oCn4vJgap7WGfd3DLhtPRgb8CICf1wdtd9HiIEcQJ0HPwIDAQAB\n\
o1MwUTAdBgNVHQ4EFgQUlyRzGr1UiNKRIHVYcN9sJkxz7W4wHwYDVR0jBBgwFoAU\n\
lyRzGr1UiNKRIHVYcN9sJkxz7W4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n\
AQsFAAOCAQEAj/3wjrBoOp/gkjkgHaD+bjmzsrXcf/MePAYjjjubxxvtkaC282v5\n\
K3GuHhGqdc5s+nLRzkYa0zgFJ3/rVtOciiypx3+QLsO9LO1CGmeAHV6rNdljv5Ml\n\
swepO0S18oXZugmkVELZDuUEGaEmHuTOJXldSGYxP9GtJ+YfwjRvTH+gRHWTKkBa\n\
sx3L5KJMTFRSZnJudP/g3YfJDi7nxUOXGjrOZH9/jYRhp6uWxJHKigSVVw9NGQJ5\n\
B2CjjT9M0rGsxPVxckGQAL2kg94KAUFsnuS00FFEQhTO5Dy+bM9CqMm6bI454A9F\n\
jlv/Fy/eimkSjCA7sr/QuFBksOxDm4yVIg==\n\
-----END CERTIFICATE-----\n";
    /// The key for [`CERT`].
    const KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC87QH8BSTWoMWk\n\
G+e0kJKgs3XzVh+KxlcLV9G8c8Y6TrHAtFSDkfWRtw4qw2IwQsSmxsNqATfc4epM\n\
3Spt1BQq3CNs2tbcDluyeHBGF0xM6/PH3O84c/svEwCTIDBwvZi6o58xNnz1/tev\n\
7liu4gh2gn4U+vHCTzXephBUOs6xyKKMKujWr2y0U57SrLiUU++pdBrXvSrj5Oyf\n\
HjoJdzIW359HqHAYTCI8/rUUP93yDS3w90BIWn+RD2eXmC5IvbrMgS/ecr0a3L00\n\
5lF745MxrkxiZxjgO/fI8vhicrDqgKfi8mBqntYZ93cMuG09GBvwIgJ/XB2130eI\n\
gRxAnQc/AgMBAAECggEASH2ebc+hd3Mf8ty8NtXkVSIXB4QLvUlmW9VaBjfcH0JT\n\
xQ/Mf+Fw+vTkzDbFBaSQ5TdOAu4tu6S5rL2OCq89/8YRF7MOj0g5Gg1JczN8VOWS\n\
WCVnat9hyYm+hjVrMM8m+7JNomn4X8FljD1lrNDRE3v1meJCAl83WdOZX2BjL+aV\n\
5vEeCBGApnz2PcT5Q8rjqPsUiNpXGMzZt7vA3l8t4CdnMexHzO5MOHoMsKAkgGv7\n\
orLBWV2+OuvrjQaZkc+Ja78Obg5pj7cBFHStlsYmWT/HT/qj5NAe1Wq1BfY/PO1S\n\
zmnlbP2GJjNR6junf8FOb0qu+UKcFFVrJ0Q70F6V3QKBgQDc0EuOcyP2Ngm57DST\n\
PhTqaMVZgKT9c/8uUTZn/9x2oNX/eL3Rd8h80pSe39YMGtwoF1cf4y03OAnECZsE\n\
jaPiPVyCMtPmA8jVTCNS+Mfg884UH4iYzwpV2C1tqxTTUDtSsKjs2LBHqqe5ElGa\n\
2bArQ1I65cZtt/QOQpJItC2QPQKBgQDbB+d3kvGxD5i9EomvrMRwgk18q10O5lS8\n\
ALFqaRh2St1xbvjaxTQE4QnA6C332SbAE8glHh9LONXY+LFRiCWy1o2zveftw/wx\n\
YEa7gr1AgLqXtFMPt6W+NLMXMW+4TNFylF9Z2wwvUppt0+dq5Vb3ss/OugyKHdGn\n\
6pX6AkTRKwKBgA3hql5SLriTvRjLGKMJDBeQbpep1rV4TVqEEH+JPjrW8Z0V4hkB\n\
BsGSG3XBbJtmNODwVrHSfk0yYKrKT8yBewQGB4LH3zpekomWN8JHkYk6yoHJWbUB\n\
jwzGglSapLyEFrakFHqPRMW8nL6twCOT+9c8bDb3qvnKzrT2ymt3qEWhAoGBANAV\n\
5EtvaPqkLKGD2Rby9fVFdcQ5MUGUhW/O4L6NddX8LgE0Qmvk6hSwjwmcCv/qZ6wX\n\
nw/UXDqkllV5f0xMIjSTLTBT/OGgThnCs7A09wMuyRaTFE5cVLQtcO9Z4h+fq2RF\n\
nYjKV/slaN1qcfLWSxcr480sZ/lXdvUmIrHQMfzdAoGAGj177SXEk7wN0PhH1Xt4\n\
UdkM+d5BRaW4UnladNK2HED3WyyWCTWLb3IJFFqoVG32CK5fr7Hc7FobgS2U7eiO\n\
J50qO2N+2Ia8KDnqsLcQryEWUCWRDhtEtZWEAfkLl5J/4XCAXgMyX4P7ovU9jyB2\n\
XQb/ylz06/6bGHQX2/uaQJ8=\n\
-----END PRIVATE KEY-----\n";
    /// A key belonging to a different certificate.
    const OTHER_KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCKQVC9s0Ociq6y\n\
gg1/PT+FckfgHp2z9tLvuDMrFQFskHeUJuVMul51AeeZ0jc0YZadAYl5qOY5oYYn\n\
wl2X1he7HinfSTIxIGcSCGkent0dkS9kjQNwOVl6w1iBdAWKft5NCAGxQIbWsHf/\n\
iB6yFZSG7qmtpDm0CnoaVsQKllTfePoaK7rYRMdiViebvxU73+XzGthfRxMP+3gO\n\
G8yg3QnBL/VQeLLo59sk6gCqN/OmUELd2eOszDLPU0jW6QpQR1O27+2+tFdkq+KK\n\
kJcnLu43hxZYsUWGGD+duEntRSY0FGJv8BBwFGrnY9xzi/gtUPviiuj8V4Tz5z50\n\
gMYAzCnTAgMBAAECggEARE6T8T3OBFxChuCZgYmFxk1ZtKH7wawLuLOV2E3HB9fy\n\
tKho9vlHbOD1h/qkGsWyb70QKqMnqEalLSSrMDbvP5xeDLsxyLLdKbwtD5tm3NJc\n\
C35eOgajrnMwWbk0eaJH++AeUfBzDkRe7UnX/J2L5gSpoah3d/wLKtM+hYqTwVre\n\
rISvR44kITCHU9u6Xz0CrTyry5B4GQebLlwwD+IQFgHHRPjxkQpcom5gFGK1TrgD\n\
O2VTgSDEua263jWjbUbv7NAMFB4hwSwD4tVCBY+l+w0XVM7DqjJroMeX2tQGIJB6\n\
zCzyytxBIXVOMp8aDueUVWoce4pfXjni2Xdy4xQN7QKBgQC/hXISQ8ogWFyFbBLx\n\
s5DyR2pzlVYdEBTkM0T77+SKv5nO2NctyPfmKGP040EQLMwwpI7/xhhqaJZPdbDU\n\
ovb6G35fgKncVT+/IpnGVvu7ooW1RI0xbPaGNEeNdpM1SvFkvXg+IwbKBwzbnV7/\n\
urWqltDqqqtILUc+YH9r11RbTQKBgQC4zQvijfYHIfknsyIH5Hv0boD92gpLkZ5y\n\
gbB+iXphST3oFMcO+2MqT8m/PSL77N+PADF38R7br1+FpREfxgCOAv/rjvCZxAK2\n\
TiEdfUkzR7mtsN+YS3JEOFhH+EZ61pd9kUOMtji8vHlFiNSd69T61U+x5GbfbRjC\n\
cz/WGpjJnwKBgQCbLRhbzCk9Q9rTD9nZlFBgvZR2ygzXx2vl6dR+/MQD13Jbsj3G\n\
jwqspRU4GdlhrapTz0E949dsgAkpoIYCA3hw9U3TO4BlUX0w9Gv71AZq5SfI0x5D\n\
abHk0v8Wk3h6uZoUsZ93WRHrJwM3/a43LaR7726edGILPQR4ed9EFVf4EQKBgFEZ\n\
o2KcfGEq9qYGhiPCkOd3a2J8QtJhKJEF+0e825lAREvKeoVHq4BRHa+wi97VWFLw\n\
ecUyayFr+Fa1VyuDgJDSHi/pPgutKqeI6B2B8xLvIjxoh+fVDGOF+rAy8/NKo5b2\n\
nhdtjL6/U9VBNFXNvl0KKfxeyQq6XQhQ/a3fZDfvAoGAfaW9nrcthJf0XmQMLTVg\n\
dKDUef3uAMw8sb/ue/80YzZNxOjj33uz2oniYSvSolGdwo0NcKvHYWALhzWH1doD\n\
ckFLQ2Us3qQiQlayeKh1wsynyKZ/BSfN3pBnwYECUQnO6Mi35BZhUvwhCXoiyCSy\n\
IUMT5+VnY50g7vE87YY5NMI=\n\
-----END PRIVATE KEY-----\n";

    /// Panel material is operator-typed text. Every malformed shape has to come
    /// back as an error, because the caller refuses the generation on one and
    /// the process dies on a panic.
    #[test]
    fn unusable_material_is_reported_rather_than_panicking() {
        for (label, cert, key) in [
            (
                "truncated certificate",
                "-----BEGIN CERTIFICATE-----\nnope\n",
                KEY,
            ),
            ("empty certificate", "", KEY),
            ("garbage key", CERT, "-----BEGIN PRIVATE KEY-----\nnope\n"),
            ("key from another certificate", CERT, OTHER_KEY),
        ] {
            let result = try_create_server_config(
                cert.as_bytes(),
                key.as_bytes(),
                Vec::new(),
                &["http/1.1".to_string()],
                &[],
            );
            assert!(result.is_err(), "{label} must be reported, not accepted");
        }

        assert!(
            try_create_server_config(
                CERT.as_bytes(),
                KEY.as_bytes(),
                Vec::new(),
                &["http/1.1".to_string()],
                &[],
            )
            .is_ok(),
            "a matching pair must still build"
        );
    }

    /// A trust anchor is routinely pasted in as a bundle. Keeping only the
    /// first certificate would refuse every client issued under the rest.
    #[test]
    fn every_certificate_in_a_client_ca_bundle_becomes_an_anchor() {
        let bundle = format!("{CERT}\n{CERT}");
        let single = try_create_server_config(
            CERT.as_bytes(),
            KEY.as_bytes(),
            vec![CERT.as_bytes().to_vec()],
            &["http/1.1".to_string()],
            &[],
        );
        assert!(single.is_ok(), "one anchor must build");

        let bundled = try_create_server_config(
            CERT.as_bytes(),
            KEY.as_bytes(),
            vec![bundle.into_bytes()],
            &["http/1.1".to_string()],
            &[],
        );
        assert!(bundled.is_ok(), "a bundle must build too");

        let broken = try_create_server_config(
            CERT.as_bytes(),
            KEY.as_bytes(),
            vec![b"-----BEGIN CERTIFICATE-----\nnope\n".to_vec()],
            &["http/1.1".to_string()],
            &[],
        );
        assert!(broken.is_err(), "an unusable anchor must be reported");
    }
}
