use super::*;

use bytes::Buf;
use http::{HeaderMap, Method, Request, StatusCode};
use tokio::task::JoinHandle;

use crate::rustls_config_util::{create_client_config, create_server_config};

const TEST_SERVER_NAME: &str = "localhost";
const TEST_MASQUERADE_BODY: &[u8] = b"ordinary h3 site";
const TEST_MASQUERADE_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

#[derive(Debug)]
struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

struct TestServer {
    endpoint: quinn::Endpoint,
    accept_task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.endpoint.close(0u32.into(), b"test complete");
    }
}

struct TestClient {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    driver_task: JoinHandle<()>,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

fn test_users() -> Hysteria2ServerUsers {
    Hysteria2ServerUsers::new(vec![Hysteria2ServerUser::new(
        "user-password".to_string(),
        None,
    )])
    .unwrap()
}

impl Drop for TestClient {
    fn drop(&mut self) {
        self.driver_task.abort();
        self.connection.close(0u32.into(), b"test complete");
        self.endpoint.close(0u32.into(), b"test complete");
    }
}

fn test_quic_server_config() -> quinn::ServerConfig {
    let certified = rcgen::generate_simple_self_signed(vec![TEST_SERVER_NAME.to_string()]).unwrap();
    let tls_config = create_server_config(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
        Vec::new(),
        &["h3".to_string()],
        &[],
    );
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap();
    quinn::ServerConfig::with_crypto(Arc::new(quic_config))
}

fn test_quic_client_config() -> quinn::ClientConfig {
    let tls_config =
        create_client_config(false, Vec::new(), vec!["h3".to_string()], true, None, true);
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    quinn::ClientConfig::new(Arc::new(quic_config))
}

fn start_test_server() -> (TestServer, SocketAddr) {
    let endpoint =
        quinn::Endpoint::server(test_quic_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = endpoint.local_addr().unwrap();
    let accept_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            tokio::spawn(async move {
                let connection = incoming.await.unwrap();
                let h3_connection = h3_quinn::Connection::new(connection.clone());
                let mut h3_connection = h3::server::Connection::<_, Bytes>::new(h3_connection)
                    .await
                    .unwrap();
                let users = test_users();
                let masquerade = Hysteria2Masquerade::try_new(
                    404,
                    TEST_MASQUERADE_CONTENT_TYPE,
                    Bytes::from_static(TEST_MASQUERADE_BODY),
                )
                .unwrap();

                let _ = auth_or_masquerade_connection(
                    &mut h3_connection,
                    &users,
                    true,
                    0,
                    false,
                    &masquerade,
                )
                .await;
                let _ = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
            });
        }
    });

    (
        TestServer {
            endpoint,
            accept_task,
        },
        server_address,
    )
}

async fn connect_test_client(server_address: SocketAddr) -> TestClient {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(test_quic_client_config());
    let connection = endpoint
        .connect(server_address, TEST_SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, send_request) = h3::client::new(h3_connection).await.unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    TestClient {
        endpoint,
        connection,
        driver_task,
        send_request,
    }
}

async fn request(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    request: Request<()>,
) -> TestResponse {
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }

    TestResponse {
        status,
        headers,
        body: body.freeze(),
    }
}

fn ordinary_request(method: Method, path: &str) -> Request<()> {
    Request::builder()
        .method(method)
        .uri(format!("https://{TEST_SERVER_NAME}{path}"))
        .body(())
        .unwrap()
}

fn auth_request(password: &str) -> Request<()> {
    Request::builder()
        .method(Method::POST)
        .uri("https://hysteria/auth")
        .header("hysteria-auth", password)
        .header("hysteria-cc-rx", "1048576")
        .body(())
        .unwrap()
}

fn assert_static_response(response: &TestResponse, expect_body: bool) {
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers.get(http::header::CONTENT_TYPE).unwrap(),
        TEST_MASQUERADE_CONTENT_TYPE
    );
    assert_eq!(
        response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        TEST_MASQUERADE_BODY.len()
    );
    if expect_body {
        assert_eq!(response.body.as_ref(), TEST_MASQUERADE_BODY);
    } else {
        assert!(response.body.is_empty());
    }
}

#[tokio::test]
async fn serves_durable_static_masquerade_and_preserves_hysteria_auth_over_real_h3() {
    let (_server, server_address) = start_test_server();
    let mut client = connect_test_client(server_address).await;

    let ordinary_get = request(&mut client.send_request, ordinary_request(Method::GET, "/")).await;
    assert_static_response(&ordinary_get, true);

    let ordinary_head = request(
        &mut client.send_request,
        ordinary_request(Method::HEAD, "/"),
    )
    .await;
    assert_static_response(&ordinary_head, false);
    assert_eq!(ordinary_head.status, ordinary_get.status);
    assert_eq!(ordinary_head.headers, ordinary_get.headers);

    let wrong_auth = request(&mut client.send_request, auth_request("wrong-password")).await;
    assert_static_response(&wrong_auth, true);
    assert_eq!(wrong_auth.status, ordinary_get.status);
    assert_eq!(wrong_auth.headers, ordinary_get.headers);
    assert_eq!(wrong_auth.body, ordinary_get.body);

    let second_get = request(
        &mut client.send_request,
        ordinary_request(Method::GET, "/another"),
    )
    .await;
    assert_static_response(&second_get, true);

    tokio::time::sleep(AUTH_TIMEOUT + Duration::from_millis(100)).await;

    let late_get = request(
        &mut client.send_request,
        ordinary_request(Method::GET, "/after-auth-window"),
    )
    .await;
    assert_static_response(&late_get, true);

    let late_correct_auth = request(&mut client.send_request, auth_request("user-password")).await;
    assert_static_response(&late_correct_auth, true);

    drop(client);

    let mut authenticated_client = connect_test_client(server_address).await;
    let auth_response = request(
        &mut authenticated_client.send_request,
        auth_request("user-password"),
    )
    .await;
    assert_eq!(auth_response.status, StatusCode::from_u16(233).unwrap());
    assert_eq!(auth_response.headers.get("hysteria-udp").unwrap(), "true");
    assert_eq!(auth_response.headers.get("hysteria-cc-rx").unwrap(), "0");
    assert!(
        !auth_response
            .headers
            .get("hysteria-padding")
            .unwrap()
            .is_empty()
    );
    assert!(auth_response.body.is_empty());
}
