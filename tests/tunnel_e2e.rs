use rust_proxy::tunnel::{self, AgentRegistry, BindEntry, BindRegistry};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

lazy_static::lazy_static! {
    static ref E2E_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::new(());
}

struct TestDirectory {
    original: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl TestDirectory {
    fn enter() -> Self {
        let original = std::env::current_dir().unwrap();
        let path = std::env::temp_dir().join(format!(
            "rust-proxy-e2e-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir(&path).unwrap();
        std::env::set_current_dir(&path).unwrap();
        Self { original, path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.original).unwrap();
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn free_socks_port() -> u16 {
    for port in tunnel::SOCKS_PORT_MIN..=tunnel::SOCKS_PORT_MAX {
        if TcpListener::bind(("127.0.0.1", port)).await.is_ok() {
            return port;
        }
    }
    panic!("no free SOCKS port")
}

async fn wait_for_agent(registry: &AgentRegistry, agent_id: &str) {
    for _ in 0..100 {
        if registry.contains_key(agent_id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("agent did not register")
}

async fn request_api(port: u16, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = connect_local(port).await;
    for (index, part) in parts.iter().enumerate() {
        stream.write_all(part).await.unwrap();
        if index + 1 < parts.len() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

async fn connect_local(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("local server did not start")
}

async fn socks_connect_reply(port: u16, target_port: u16, password: &str) -> (TcpStream, [u8; 10]) {
    let mut stream = connect_local(port).await;
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    stream
        .write_all(&[1, 4, b'u', b's', b'e', b'r', password.len() as u8])
        .await
        .unwrap();
    stream.write_all(password.as_bytes()).await.unwrap();
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 0]);
    stream.write_all(&[5, 1, 0, 1, 127, 0, 0, 1]).await.unwrap();
    stream.write_all(&target_port.to_be_bytes()).await.unwrap();
    let mut connect_reply = [0u8; 10];
    stream.read_exact(&mut connect_reply).await.unwrap();
    (stream, connect_reply)
}

async fn connect_socks(port: u16, target_port: u16, password: &str) -> TcpStream {
    let (stream, connect_reply) = socks_connect_reply(port, target_port, password).await;
    assert_eq!(connect_reply[..2], [5, 0]);
    stream
}

async fn connect_http(port: u16, target_port: u16) -> TcpStream {
    let mut stream = connect_local(port).await;
    stream.write_all(format!(
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Authorization: Basic dXNlcjpnb29k\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let mut reply = vec![0u8; expected.len()];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, expected);
    stream
}

#[tokio::test]
async fn v2_agent_pins_tls_and_blocks_private_egress() {
    let _test_lock = E2E_TEST_LOCK.lock().await;
    let _directory = TestDirectory::enter();
    let fingerprint = rust_proxy::tls::load_or_create_server_tls()
        .unwrap()
        .fingerprint;
    let control_port = free_port().await;
    let api_port = free_port().await;
    let registry: AgentRegistry = Arc::new(dashmap::DashMap::new());
    let bind_registry: BindRegistry = Arc::new(dashmap::DashMap::new());
    let server = tokio::spawn(tunnel::run_server(
        control_port,
        api_port,
        Some("agent-password".into()),
        "admin-password".into(),
        Arc::clone(&registry),
        Arc::clone(&bind_registry),
        Arc::new(dashmap::DashMap::new()),
    ));

    let (agent_stop_tx, agent_stop_rx) = tokio::sync::mpsc::channel(1);
    let agent = tokio::spawn(tunnel::run_agent_with_fingerprint(
        format!("127.0.0.1:{control_port}"),
        "v2-agent".into(),
        Some("agent-password".into()),
        fingerprint,
        Some(agent_stop_rx),
    ));
    wait_for_agent(&registry, "v2-agent").await;
    assert_eq!(registry.get("v2-agent").unwrap().protocol_version, 2);
    let mut device = None;
    for _ in 0..100 {
        let response = request_api(
            api_port,
            &[b"GET /api/state HTTP/1.1\r\nX-Server-Password: admin-password\r\n\r\n".to_vec()],
        )
        .await;
        let body = &response[response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4..];
        let state: serde_json::Value = serde_json::from_slice(body).unwrap();
        device = state["agents"]
            .as_array()
            .and_then(|agents| agents.iter().find(|agent| agent["id"] == "v2-agent"))
            .and_then(|agent| agent.get("device"))
            .cloned();
        if device.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let device = device.expect("v2 fixture did not publish STATUS");
    assert_eq!(device["carrier"], "PC fixture");
    assert_eq!(device["proto"], 2);
    assert!(device["received_at"].as_u64().is_some());

    let (bad_agent_stop_tx, bad_agent_stop_rx) = tokio::sync::mpsc::channel(1);
    let bad_agent = tokio::spawn(tunnel::run_agent_with_fingerprint(
        format!("127.0.0.1:{control_port}"),
        "bad-v2-agent".into(),
        Some("agent-password".into()),
        "00".repeat(32),
        Some(bad_agent_stop_rx),
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!registry.contains_key("bad-v2-agent"));
    let _ = bad_agent_stop_tx.send(()).await;
    tokio::time::timeout(Duration::from_secs(5), bad_agent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let socks_port = free_socks_port().await;
    let listener = tunnel::bind_socks_listener(socks_port).await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    bind_registry.insert(
        socks_port,
        BindEntry {
            agent_id: "v2-agent".into(),
            port: socks_port,
            usage: Arc::new(AtomicU64::new(0)),
            max_conns: tunnel::DEFAULT_MAX_CONNS,
            connection_limit: Arc::new(Semaphore::new(tunnel::DEFAULT_MAX_CONNS)),
            user: None,
            pass: None,
            shutdown_tx: Some(shutdown_tx),
        },
    );
    let socks = tokio::spawn(tunnel::run_socks_listener(
        listener,
        "v2-agent".into(),
        Arc::clone(&registry),
        Arc::clone(&bind_registry),
        None,
        None,
        shutdown_rx,
    ));

    let mut client = connect_local(socks_port).await;
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
        .await
        .unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..2], [5, 4]);

    let _ = agent_stop_tx.send(()).await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    socks.abort();
    server.abort();
}

#[tokio::test]
async fn socks_relay_http_body_and_unbind_work_end_to_end() {
    let _test_lock = E2E_TEST_LOCK.lock().await;
    let _directory = TestDirectory::enter();
    let control_port = free_port().await;
    let api_port = free_port().await;
    let registry: AgentRegistry = Arc::new(dashmap::DashMap::new());
    let bind_registry: BindRegistry = Arc::new(dashmap::DashMap::new());
    let cumulative_usage = Arc::new(dashmap::DashMap::new());
    let server = tokio::spawn(tunnel::run_server(
        control_port,
        api_port,
        Some("agent-password".into()),
        "admin-password".into(),
        Arc::clone(&registry),
        Arc::clone(&bind_registry),
        Arc::clone(&cumulative_usage),
    ));

    let login_body = br#"{"password":"admin-password"}"#.to_vec();
    let login_header = format!(
        "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        login_body.len()
    )
    .into_bytes();
    let login_response = request_api(api_port, &[login_header, login_body]).await;
    assert!(String::from_utf8_lossy(&login_response).starts_with("HTTP/1.1 200"));
    let oversized = request_api(
        api_port,
        &[b"POST /api/login HTTP/1.1\r\nContent-Length: 65537\r\n\r\n".to_vec()],
    )
    .await;
    assert!(String::from_utf8_lossy(&oversized).starts_with("HTTP/1.1 413"));

    let (agent_stop_tx, agent_stop_rx) = tokio::sync::mpsc::channel(1);
    let agent = tokio::spawn(tunnel::run_agent(
        format!("127.0.0.1:{control_port}"),
        "e2e-agent".into(),
        Some("agent-password".into()),
        Some(agent_stop_rx),
    ));
    wait_for_agent(&registry, "e2e-agent").await;

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                tokio::io::copy(&mut reader, &mut writer).await.unwrap();
            });
        }
    });

    let socks_port = free_socks_port().await;
    let socks_listener = tunnel::bind_socks_listener(socks_port).await.unwrap();
    let (bind_shutdown_tx, bind_shutdown_rx) = tokio::sync::watch::channel(false);
    bind_registry.insert(
        socks_port,
        BindEntry {
            agent_id: "e2e-agent".into(),
            port: socks_port,
            usage: Arc::new(AtomicU64::new(0)),
            max_conns: tunnel::DEFAULT_MAX_CONNS,
            connection_limit: Arc::new(Semaphore::new(tunnel::DEFAULT_MAX_CONNS)),
            user: Some("user".into()),
            pass: Some("good".into()),
            shutdown_tx: Some(bind_shutdown_tx),
        },
    );
    let socks = tokio::spawn(tunnel::run_socks_listener(
        socks_listener,
        "e2e-agent".into(),
        Arc::clone(&registry),
        Arc::clone(&bind_registry),
        Some("user".into()),
        Some("good".into()),
        bind_shutdown_rx,
    ));

    let mut rejected = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    rejected
        .write_all(&[5, 1, 2, 1, 4, b'u', b's', b'e', b'r', 3, b'b', b'a', b'd'])
        .await
        .unwrap();
    let mut rejected_reply = [0u8; 4];
    rejected.read_exact(&mut rejected_reply).await.unwrap();
    assert_eq!(rejected_reply, [5, 2, 1, 1]);

    let mut client = connect_socks(socks_port, echo_port, "good").await;
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    assert!(registry
        .get("e2e-agent")
        .is_some_and(|agent| agent.usage.load(std::sync::atomic::Ordering::Relaxed) >= 8));
    assert!(bind_registry
        .get(&socks_port)
        .is_some_and(|bind| bind.usage.load(std::sync::atomic::Ordering::Relaxed) >= 8));

    let mut http_client = connect_http(socks_port, echo_port).await;
    http_client.write_all(b"http").await.unwrap();
    let mut http_echoed = [0u8; 4];
    http_client.read_exact(&mut http_echoed).await.unwrap();
    assert_eq!(&http_echoed, b"http");
    http_client.shutdown().await.unwrap();

    let mut absolute = connect_local(socks_port).await;
    absolute.write_all(format!(
        "GET http://127.0.0.1:{echo_port}/through-http HTTP/1.1\r\nHost: ignored.example\r\nProxy-Authorization: Basic dXNlcjpnb29k\r\nConnection: keep-alive\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut forwarded = [0u8; 512];
    let forwarded_len = tokio::time::timeout(Duration::from_secs(2), absolute.read(&mut forwarded))
        .await
        .unwrap()
        .unwrap();
    let forwarded = std::str::from_utf8(&forwarded[..forwarded_len]).unwrap();
    assert!(forwarded.starts_with("GET /through-http HTTP/1.1\r\n"));
    assert!(forwarded.contains("Connection: close\r\n"));
    assert!(!forwarded.contains("Connection: keep-alive"));
    absolute.shutdown().await.unwrap();

    let mut http_rejected = connect_local(socks_port).await;
    http_rejected
        .write_all(
            b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpiYWQ=\r\n\r\n",
        )
        .await
        .unwrap();
    let mut rejected_http_reply = [0u8; 256];
    let rejected_len = http_rejected.read(&mut rejected_http_reply).await.unwrap();
    let rejected_http_reply = std::str::from_utf8(&rejected_http_reply[..rejected_len]).unwrap();
    assert!(rejected_http_reply.starts_with("HTTP/1.1 407"));
    assert!(rejected_http_reply.contains("Proxy-Authenticate: Basic realm=\"proxy\""));

    let mut missing_auth_http = connect_local(socks_port).await;
    missing_auth_http
        .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut missing_auth_reply = [0u8; 64];
    let missing_auth_len = missing_auth_http
        .read(&mut missing_auth_reply)
        .await
        .unwrap();
    assert!(std::str::from_utf8(&missing_auth_reply[..missing_auth_len])
        .unwrap()
        .starts_with("HTTP/1.1 407"));

    let closed_target_port = free_port().await;
    let mut target_failed_http = connect_local(socks_port).await;
    target_failed_http.write_all(format!(
        "CONNECT 127.0.0.1:{closed_target_port} HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpnb29k\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut target_failed_reply = [0u8; 64];
    let target_failed_len = target_failed_http
        .read(&mut target_failed_reply)
        .await
        .unwrap();
    assert!(
        std::str::from_utf8(&target_failed_reply[..target_failed_len])
            .unwrap()
            .starts_with("HTTP/1.1 502")
    );

    let mut malformed_http = connect_local(socks_port).await;
    malformed_http.write_all(b"INVALID\r\n\r\n").await.unwrap();
    let mut malformed_http_reply = [0u8; 64];
    let malformed_len = malformed_http
        .read(&mut malformed_http_reply)
        .await
        .unwrap();
    assert!(std::str::from_utf8(&malformed_http_reply[..malformed_len])
        .unwrap()
        .starts_with("HTTP/1.1 400"));

    let mut oversized_http = connect_local(socks_port).await;
    oversized_http.write_all(&vec![b'G'; 8193]).await.unwrap();
    let mut oversized_http_reply = [0u8; 1];
    match oversized_http.read(&mut oversized_http_reply).await {
        Ok(0) | Err(_) => {}
        Ok(bytes) => panic!("oversized HTTP header stayed open with {bytes} bytes"),
    }

    let unbind_body = format!("{{\"port\":{socks_port}}}").into_bytes();
    let unbind_header = format!(
        "POST /api/unbind HTTP/1.1\r\nX-Server-Password: admin-password\r\nContent-Length: {}\r\n\r\n",
        unbind_body.len()
    ).into_bytes();
    let unbind_response = request_api(api_port, &[unbind_header, unbind_body]).await;
    assert!(String::from_utf8_lossy(&unbind_response).starts_with("HTTP/1.1 200"));
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut [0u8; 1]))
        .await
        .unwrap()
    {
        Ok(0) | Err(_) => {}
        Ok(bytes) => panic!("unbind left SOCKS client open with {bytes} bytes"),
    }

    let _ = agent_stop_tx.send(()).await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    for _ in 0..100 {
        if cumulative_usage
            .get("e2e-agent")
            .is_some_and(|usage| *usage > 0)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(cumulative_usage
        .get("e2e-agent")
        .is_some_and(|usage| *usage > 0));
    tokio::time::timeout(Duration::from_secs(2), socks)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    echo.abort();
    server.abort();
}

#[tokio::test]
async fn bind_connection_limit_rejects_excess_socks_and_http_connections() {
    let _test_lock = E2E_TEST_LOCK.lock().await;
    let _directory = TestDirectory::enter();
    let control_port = free_port().await;
    let api_port = free_port().await;
    let registry: AgentRegistry = Arc::new(dashmap::DashMap::new());
    let bind_registry: BindRegistry = Arc::new(dashmap::DashMap::new());
    let server = tokio::spawn(tunnel::run_server(
        control_port,
        api_port,
        Some("agent-password".into()),
        "admin-password".into(),
        Arc::clone(&registry),
        Arc::clone(&bind_registry),
        Arc::new(dashmap::DashMap::new()),
    ));

    let (agent_stop_tx, agent_stop_rx) = tokio::sync::mpsc::channel(1);
    let agent = tokio::spawn(tunnel::run_agent(
        format!("127.0.0.1:{control_port}"),
        "limit-agent".into(),
        Some("agent-password".into()),
        Some(agent_stop_rx),
    ));
    wait_for_agent(&registry, "limit-agent").await;

    let unauthorized_response =
        request_api(api_port, &[b"GET /api/state HTTP/1.1\r\n\r\n".to_vec()]).await;
    assert!(String::from_utf8_lossy(&unauthorized_response).starts_with("HTTP/1.1 401"));

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        loop {
            let (stream, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                tokio::io::copy(&mut reader, &mut writer).await.unwrap();
            });
        }
    });

    let socks_port = free_socks_port().await;
    let invalid_body = format!(
        "{{\"agent_id\":\"limit-agent\",\"port\":{socks_port},\"user\":\"user\",\"pass\":\"good\",\"max_conns\":0}}"
    )
    .into_bytes();
    let invalid_header = format!(
        "POST /api/bind HTTP/1.1\r\nX-Server-Password: admin-password\r\nContent-Length: {}\r\n\r\n",
        invalid_body.len()
    )
    .into_bytes();
    let invalid_response = request_api(api_port, &[invalid_header, invalid_body]).await;
    let invalid_response = String::from_utf8_lossy(&invalid_response);
    assert!(invalid_response.starts_with("HTTP/1.1 400"));
    assert!(invalid_response.contains(r#"{"error":"Invalid max_conns"}"#));

    let socks_listener = tunnel::bind_socks_listener(socks_port).await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let connection_limit = Arc::new(Semaphore::new(10));
    bind_registry.insert(
        socks_port,
        BindEntry {
            agent_id: "limit-agent".into(),
            port: socks_port,
            usage: Arc::new(AtomicU64::new(0)),
            max_conns: 10,
            connection_limit: Arc::clone(&connection_limit),
            user: Some("user".into()),
            pass: Some("good".into()),
            shutdown_tx: Some(shutdown_tx.clone()),
        },
    );
    let socks = tokio::spawn(tunnel::run_socks_listener(
        socks_listener,
        "limit-agent".into(),
        Arc::clone(&registry),
        Arc::clone(&bind_registry),
        Some("user".into()),
        Some("good".into()),
        shutdown_rx,
    ));

    let mut clients = Vec::with_capacity(10);
    for _ in 0..10 {
        clients.push(connect_socks(socks_port, echo_port, "good").await);
    }
    assert_eq!(connection_limit.available_permits(), 0);

    let state_response = request_api(
        api_port,
        &[b"GET /api/state HTTP/1.1\r\nX-Server-Password: admin-password\r\n\r\n".to_vec()],
    )
    .await;
    let state_body = &state_response[state_response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4..];
    let state: serde_json::Value = serde_json::from_slice(state_body).unwrap();
    let bind = state["binds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|bind| bind["port"] == socks_port)
        .unwrap();
    assert_eq!(bind["active_conns"], 10);
    assert_eq!(bind["max_conns"], 10);

    let mut excess_http = connect_local(socks_port).await;
    excess_http.write_all(format!(
        "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\nProxy-Authorization: Basic dXNlcjpnb29k\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut http_reply = [0u8; 64];
    let http_reply_len = excess_http.read(&mut http_reply).await.unwrap();
    assert!(std::str::from_utf8(&http_reply[..http_reply_len])
        .unwrap()
        .starts_with("HTTP/1.1 429"));

    let (_excess_socks, socks_reply) = socks_connect_reply(socks_port, echo_port, "good").await;
    assert_eq!(socks_reply[..2], [5, 2]);
    assert_eq!(connection_limit.available_permits(), 0);

    clients.pop().unwrap().shutdown().await.unwrap();
    for _ in 0..100 {
        if connection_limit.available_permits() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(connection_limit.available_permits(), 1);

    let mut reopened = connect_socks(socks_port, echo_port, "good").await;
    reopened.shutdown().await.unwrap();
    for _ in 0..100 {
        if connection_limit.available_permits() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(connection_limit.available_permits(), 1);

    let closed_target_port = free_port().await;
    let (_failed, failed_reply) = socks_connect_reply(socks_port, closed_target_port, "good").await;
    assert_eq!(failed_reply[..2], [5, 4]);
    for _ in 0..100 {
        if connection_limit.available_permits() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(connection_limit.available_permits(), 1);

    drop(clients);
    for _ in 0..100 {
        if connection_limit.available_permits() == 10 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(connection_limit.available_permits(), 10);

    if let Some(bind) = bind_registry.get(&socks_port) {
        assert_eq!(
            bind.max_conns
                .saturating_sub(bind.connection_limit.available_permits()),
            0
        );
    } else {
        panic!("bind disappeared before shutdown");
    }

    let _ = agent_stop_tx.send(()).await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), socks)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    echo.abort();
    server.abort();
}

#[tokio::test]
async fn idle_server_sockets_close_within_the_handshake_timeout() {
    let _test_lock = E2E_TEST_LOCK.lock().await;
    let control_port = free_port().await;
    let api_port = free_port().await;
    let registry: AgentRegistry = Arc::new(dashmap::DashMap::new());
    let bind_registry: BindRegistry = Arc::new(dashmap::DashMap::new());
    let server = tokio::spawn(tunnel::run_server(
        control_port,
        api_port,
        Some("agent-password".into()),
        "admin-password".into(),
        Arc::clone(&registry),
        Arc::clone(&bind_registry),
        Arc::new(dashmap::DashMap::new()),
    ));

    let socks_port = free_socks_port().await;
    let socks_listener = tunnel::bind_socks_listener(socks_port).await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let socks = tokio::spawn(tunnel::run_socks_listener(
        socks_listener,
        "offline-agent".into(),
        registry,
        bind_registry,
        Some("user".into()),
        Some("good".into()),
        shutdown_rx,
    ));

    let (mut control, mut api, mut data, mut socks_client) = (
        connect_local(control_port).await,
        connect_local(api_port).await,
        connect_local(control_port).await,
        connect_local(socks_port).await,
    );
    data.write_all(&[0x01]).await.unwrap();
    let mut offline_http = connect_local(socks_port).await;
    offline_http
        .write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpnb29k\r\n\r\n",
        )
        .await
        .unwrap();
    let mut offline_reply = [0u8; 64];
    let offline_len = offline_http.read(&mut offline_reply).await.unwrap();
    assert!(std::str::from_utf8(&offline_reply[..offline_len])
        .unwrap()
        .starts_with("HTTP/1.1 503"));
    let (mut control_buf, mut api_buf, mut data_buf, mut socks_buf) =
        ([0u8; 1], [0u8; 1], [0u8; 1], [0u8; 1]);
    let (control_closed, api_closed, data_closed, socks_closed) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(6), control.read(&mut control_buf)),
        tokio::time::timeout(Duration::from_secs(6), api.read(&mut api_buf)),
        tokio::time::timeout(Duration::from_secs(6), data.read(&mut data_buf)),
        tokio::time::timeout(Duration::from_secs(6), socks_client.read(&mut socks_buf)),
    );
    for result in [control_closed, api_closed, data_closed, socks_closed] {
        assert!(
            matches!(result, Ok(Ok(0) | Err(_))),
            "idle socket stayed open"
        );
    }

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), socks)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.abort();
}
