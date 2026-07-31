#![cfg(feature = "e2e-client")]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

const UUID: [u8; 16] = [
    0xd6, 0x85, 0xae, 0xf3, 0xb3, 0xc4, 0x49, 0x32, 0x9a, 0x9d, 0xd0, 0xc2, 0xf6, 0x72, 0x7d, 0xfa,
];
const UUID_TEXT: &str = "d685aef3-b3c4-4932-9a9d-d0c2f6727dfa";
const PASSWORD: &str = "tuic-0rtt-test-password";
const PAYLOAD: &[u8] = b"tuic-real-0rtt-pre-auth-packet";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_session_ticket_pauses_early_packet_until_authentication() -> io::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| io::Error::other(format!("failed to generate certificate: {e}")))?;
    let cert_der = certified.cert.der().clone();
    let temp_dir = tempfile::tempdir()?;
    let cert_path = temp_dir.path().join("tuic-0rtt-cert.pem");
    let key_path = temp_dir.path().join("tuic-0rtt-key.pem");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.signing_key.serialize_pem())?;

    let server_addr = reserve_udp_address()?;
    let server_addr_text = server_addr.to_string();
    let cert_path_text = cert_path.to_string_lossy().into_owned();
    let key_path_text = key_path.to_string_lossy().into_owned();
    let server_task = tokio::spawn(async move {
        shoes::e2e_server::run_quic_proxy_server(
            &server_addr_text,
            "tuic",
            PASSWORD,
            Some(UUID_TEXT),
            &cert_path_text,
            &key_path_text,
            true,
        )
        .await
    });

    sleep(Duration::from_millis(150)).await;
    assert!(
        !server_task.is_finished(),
        "TUIC test server stopped during startup"
    );

    let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target_addr = target.local_addr()?;
    let endpoint = make_client_endpoint(cert_der)?;

    // Complete an ordinary connection first. Reusing this endpoint and its
    // rustls session store supplies the ticket for the next connection.
    let first = endpoint
        .connect(server_addr, "localhost")
        .map_err(|e| io::Error::other(format!("first TUIC connect setup failed: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("first TUIC connect failed: {e}")))?;
    send_authenticate(&first).await?;
    send_packet(&first, target_addr, b"ticket-request").await?;
    let (ticket_request, target_peer) = timeout(Duration::from_secs(2), recv_target_from(&target))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "first TUIC packet did not reach the ticket target",
            )
        })??;
    assert_eq!(ticket_request, b"ticket-request");
    target.send_to(b"ticket-response", target_peer).await?;
    let mut ticket_response = timeout(Duration::from_secs(2), first.accept_uni())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "server did not send a post-handshake TUIC response",
            )
        })??;
    let ticket_response = ticket_response
        .read_to_end(2048)
        .await
        .map_err(|e| io::Error::other(format!("failed to read TUIC response: {e}")))?;
    assert!(ticket_response.ends_with(b"ticket-response"));
    sleep(Duration::from_millis(100)).await;
    first.close(0u32.into(), b"ticket acquired");
    sleep(Duration::from_millis(100)).await;

    let connecting = endpoint
        .connect(server_addr, "localhost")
        .map_err(|e| io::Error::other(format!("resumed TUIC connect setup failed: {e}")))?;
    let (resumed, zero_rtt_accepted) = connecting.into_0rtt().map_err(|_| {
        io::Error::other("resumed TUIC connection did not have a cached session ticket")
    })?;

    // Send a real TUIC PACKET command before AUTH while the resumed handshake
    // is still in progress. The target must remain untouched during this gap.
    send_packet(&resumed, target_addr, PAYLOAD).await?;
    let accepted = timeout(Duration::from_secs(2), zero_rtt_accepted)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "0-RTT acceptance timed out"))?;
    if !accepted {
        return Err(io::Error::other(
            "server rejected the resumed connection's 0-RTT data",
        ));
    }
    assert!(
        timeout(Duration::from_millis(250), recv_target(&target))
            .await
            .is_err(),
        "pre-authentication TUIC packet reached its UDP target"
    );

    send_authenticate(&resumed).await?;
    let received = timeout(Duration::from_secs(2), recv_target(&target))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "paused TUIC packet was not resumed after authentication",
            )
        })??;
    assert_eq!(received, PAYLOAD);

    resumed.close(0u32.into(), b"test complete");

    // A separate connection proves the failure path: even a completely
    // buffered task preceding an invalid AUTH must never be forwarded.
    let rejected = endpoint
        .connect(server_addr, "localhost")
        .map_err(|e| io::Error::other(format!("rejected TUIC connect setup failed: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("rejected TUIC connect failed: {e}")))?;
    send_packet(&rejected, target_addr, b"must-not-be-forwarded").await?;
    send_authenticate_with_password(&rejected, "incorrect-password").await?;
    assert!(
        timeout(Duration::from_millis(350), recv_target(&target))
            .await
            .is_err(),
        "TUIC packet with invalid authentication reached its UDP target"
    );

    rejected.close(0u32.into(), b"invalid-auth case complete");
    endpoint.wait_idle().await;
    server_task.abort();
    Ok(())
}

fn reserve_udp_address() -> io::Result<SocketAddr> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    socket.local_addr()
}

fn make_client_endpoint(cert_der: CertificateDer<'static>) -> io::Result<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert_der)
        .map_err(|e| io::Error::other(format!("failed to trust test certificate: {e}")))?;

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = true;
    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|e| io::Error::other(format!("invalid QUIC client TLS config: {e}")))?;
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));

    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

async fn send_authenticate(connection: &quinn::Connection) -> io::Result<()> {
    send_authenticate_with_password(connection, PASSWORD).await
}

async fn send_authenticate_with_password(
    connection: &quinn::Connection,
    password: &str,
) -> io::Result<()> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, &UUID, password.as_bytes())
        .map_err(|e| io::Error::other(format!("failed to derive TUIC auth token: {e:?}")))?;

    let mut stream = connection.open_uni().await?;
    stream.write_all(&[5, 0]).await?;
    stream.write_all(&UUID).await?;
    stream.write_all(&token).await?;
    stream
        .finish()
        .map_err(|e| io::Error::other(format!("failed to finish TUIC auth stream: {e}")))
}

async fn send_packet(
    connection: &quinn::Connection,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let SocketAddr::V4(target) = target else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the TUIC 0-RTT test target must use IPv4",
        ));
    };
    let payload_size: u16 = payload
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "test payload too large"))?;

    let mut frame = Vec::with_capacity(17 + payload.len());
    frame.extend_from_slice(&[5, 2]); // TUIC v5 PACKET
    frame.extend_from_slice(&1u16.to_be_bytes()); // association ID
    frame.extend_from_slice(&0u16.to_be_bytes()); // packet ID
    frame.extend_from_slice(&[1, 0]); // fragment total / fragment ID
    frame.extend_from_slice(&payload_size.to_be_bytes());
    frame.push(1); // IPv4 address
    frame.extend_from_slice(&target.ip().octets());
    frame.extend_from_slice(&target.port().to_be_bytes());
    frame.extend_from_slice(payload);

    let mut stream = connection.open_uni().await?;
    stream.write_all(&frame).await?;
    stream
        .finish()
        .map_err(|e| io::Error::other(format!("failed to finish TUIC packet stream: {e}")))
}

async fn recv_target(socket: &UdpSocket) -> io::Result<Vec<u8>> {
    recv_target_from(socket).await.map(|(payload, _)| payload)
}

async fn recv_target_from(socket: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; 2048];
    let (len, peer) = socket.recv_from(&mut buf).await?;
    Ok((buf[..len].to_vec(), peer))
}
