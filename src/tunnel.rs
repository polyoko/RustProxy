use anyhow::Result;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

use crate::security;
use crate::socks5;
use crate::tunnel_common::{
    AgentRequestRegistry, BandwidthTrackedStream, OpenRequestRegistry, OpenResult, TunnelCmd,
    TunnelSignalTx,
};

const CMD_REQUIRE_CONN: u8 = 0x01;
const CMD_UDP_SESSION: u8 = 0x03;
const CMD_RESET_IP: u8 = 0x04;
const CMD_PING: u8 = 0x06;
const CMD_OPEN: u8 = 0x10;
const CMD_STATUS: u8 = 0x11;
const V2_DATA_CONNECTION: u8 = 0x02;
const V2_STATUS_OK: u8 = 0x00;
const V2_STATUS_BLOCKED: u8 = 0x02;
const V2_STATUS_UNREACHABLE: u8 = 0x04;
const MAX_STATUS_BYTES: usize = 1024;
const STATUS_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
const STATUS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
pub const SOCKS_PORT_MIN: u16 = 51300;
pub const SOCKS_PORT_MAX: u16 = 51399;
// ponytail: one browser opens 20-100 sockets; 256 keeps 2 fds/conn under the 1024 fd limit of older Android.
pub const DEFAULT_MAX_CONNS: usize = 256;
pub const MAX_CONNS: usize = 65_535;
const AGENT_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
const AGENT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);
const AGENT_UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const RESET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const RECONNECT_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_API_REQUEST_BYTES: usize = 64 * 1024;
const API_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(any(target_os = "android", target_os = "linux"))]
const TCP_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

pub fn is_socks_port(port: u16) -> bool {
    (SOCKS_PORT_MIN..=SOCKS_PORT_MAX).contains(&port)
}

lazy_static::lazy_static! {
    static ref DNS_CACHE: DashMap<String, (SocketAddr, std::time::Instant)> = DashMap::new();
}
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

struct ResetResult {
    old_ip: String,
    new_ip: String,
    took_ms: u128,
}

struct ResetWaiter {
    old_ip: String,
    started_at: tokio::time::Instant,
    response_tx: tokio::sync::oneshot::Sender<ResetResult>,
}

#[derive(Clone, Deserialize, Serialize)]
struct DeviceStatus {
    carrier: String,
    net: String,
    signal: u8,
    battery: u8,
    temp_c: f32,
    charging: bool,
    health: String,
    app: String,
    proto: u8,
    assistant: bool,
    transport: String,
}

#[derive(Clone, Serialize)]
struct DeviceSnapshot {
    #[serde(flatten)]
    device: DeviceStatus,
    received_at: u64,
    #[serde(skip)]
    received: std::time::Instant,
}

fn parse_device_status(payload: &[u8]) -> Result<DeviceStatus> {
    let status: DeviceStatus = serde_json::from_slice(payload)?;
    anyhow::ensure!(status.signal <= 4, "signal must be 0-4");
    anyhow::ensure!(status.battery <= 100, "battery must be 0-100");
    anyhow::ensure!(
        status.temp_c.is_finite() && (-100.0..=150.0).contains(&status.temp_c),
        "invalid temperature"
    );
    anyhow::ensure!(status.proto == 2, "STATUS proto must be 2");
    anyhow::ensure!(
        matches!(status.transport.as_str(), "cellular" | "wifi"),
        "invalid transport"
    );
    anyhow::ensure!(
        status.carrier.len() <= 128
            && status.net.len() <= 32
            && status.health.len() <= 32
            && status.app.len() <= 64,
        "STATUS field too long"
    );
    Ok(status)
}

fn record_device_status(device: &RwLock<Option<DeviceSnapshot>>, payload: &[u8]) -> Result<bool> {
    let status = parse_device_status(payload)?;
    let mut device = device
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if device
        .as_ref()
        .is_some_and(|snapshot| snapshot.received.elapsed() < STATUS_MIN_INTERVAL)
    {
        return Ok(false);
    }
    *device = Some(DeviceSnapshot {
        device: status,
        received_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        received: std::time::Instant::now(),
    });
    Ok(true)
}

async fn discard_control_bytes<S>(stream: &mut S, mut remaining: usize) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = [0; MAX_STATUS_BYTES];
    while remaining != 0 {
        let bytes = remaining.min(buffer.len());
        stream.read_exact(&mut buffer[..bytes]).await?;
        remaining -= bytes;
    }
    Ok(())
}

fn configure_tunnel_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if let Err(error) = socket2::SockRef::from(stream).set_tcp_user_timeout(Some(TCP_USER_TIMEOUT))
    {
        warn!("Could not set TCP_USER_TIMEOUT: {}", error);
    }
}

pub struct AgentEntry {
    pub control_tx: mpsc::Sender<TunnelCmd>,
    pub addr: SocketAddr,
    pub active_requests: Arc<DashMap<u32, tokio::sync::oneshot::Sender<TcpStream>>>,
    pub pending_opens: OpenRequestRegistry,
    pub protocol_version: u8,
    device: Arc<RwLock<Option<DeviceSnapshot>>>,
    pub usage: Arc<AtomicU64>,
    pub os_type: u8,
    pub reset_token: String,
    reset_waiter: Arc<tokio::sync::Mutex<Option<ResetWaiter>>>,
    pub resetting: Arc<AtomicBool>,
}

pub type AgentRegistry = Arc<DashMap<String, AgentEntry>>;

pub struct BindEntry {
    pub agent_id: String,
    pub port: u16,
    pub usage: Arc<AtomicU64>,
    pub max_conns: usize,
    pub connection_limit: Arc<Semaphore>,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

pub type BindRegistry = Arc<DashMap<u16, BindEntry>>;

pub struct BoundSocksListener {
    listener: TcpListener,
    port: u16,
}

fn api_bind_addr(api_port: u16, public: bool) -> String {
    format!(
        "{}:{api_port}",
        if public { "0.0.0.0" } else { "127.0.0.1" }
    )
}

pub async fn run_server(
    control_port: u16,
    api_port: u16,
    agent_password: Option<String>,
    admin_password: String,
    registry: AgentRegistry,
    bind_registry: BindRegistry,
    cumulative_usage: Arc<DashMap<String, u64>>,
) -> Result<()> {
    info!(
        "Starting Multi-Agent Tunnel SERVER on port {}",
        control_port
    );

    let tls = Arc::new(crate::tls::load_or_create_server_tls()?);
    let bind_addr = format!("0.0.0.0:{}", control_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("Tunnel Listener active on {}", bind_addr);

    let api_bind = api_bind_addr(
        api_port,
        std::env::var("RUST_PROXY_API_BIND").as_deref() == Ok("0.0.0.0"),
    );
    if let Ok(api_listener) = TcpListener::bind(&api_bind).await {
        info!("API Listener active on {}", api_bind);
        let registry_for_api = Arc::clone(&registry);
        let bind_registry_for_api = Arc::clone(&bind_registry);
        let agent_pw_clone = agent_password.clone();
        let admin_pw_clone = admin_password.clone();
        let fingerprint = tls.fingerprint.clone();
        tokio::spawn(async move {
            loop {
                match api_listener.accept().await {
                    Ok((stream, addr)) => {
                        let reg_clone = Arc::clone(&registry_for_api);
                        let breg_clone = Arc::clone(&bind_registry_for_api);
                        let agent_pw = agent_pw_clone.clone();
                        let admin_pw = admin_pw_clone.clone();
                        let fingerprint = fingerprint.clone();
                        tokio::spawn(async move {
                            handle_api_connection(
                                stream,
                                addr,
                                reg_clone,
                                breg_clone,
                                agent_pw,
                                admin_pw,
                                control_port,
                                fingerprint,
                            )
                            .await;
                        });
                    }
                    Err(error) => {
                        error!("API accept error: {}", error);
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
        });
    } else {
        warn!("Failed to bind API listener on {}", api_bind);
    }

    loop {
        match listener.accept().await {
            Ok((mut stream, addr)) => {
                let ip_str = addr.ip().to_string();
                if security::is_blacklisted(&ip_str) {
                    warn!("Blocked blacklisted IP: {}", ip_str);
                    continue;
                }

                let registry_clone = Arc::clone(&registry);
                let usage_clone = Arc::clone(&cumulative_usage);
                let agent_pw_clone = agent_password.clone();
                let tls_acceptor = tls.acceptor.clone();

                tokio::spawn(async move {
                    configure_tunnel_stream(&stream);
                    let mut type_buf = [0u8; 1];
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut type_buf)).await
                    {
                        Ok(Ok(1)) => {}
                        Ok(Err(_)) | Err(_) => return,
                        _ => return,
                    }

                    match type_buf[0] {
                        0x00 => {
                            if stream.read_exact(&mut type_buf).await.is_err() {
                                return;
                            }
                            if let Err(e) = handle_control_connection(
                                stream,
                                addr,
                                agent_pw_clone,
                                registry_clone,
                                usage_clone,
                                HANDSHAKE_TIMEOUT,
                                1,
                            )
                            .await
                            {
                                error!("Control Connection Error [{}]: {}", addr, e);
                            }
                        }
                        0x01 => {
                            if stream.read_exact(&mut type_buf).await.is_err() {
                                return;
                            }
                            if let Err(e) = handle_data_connection(
                                stream,
                                addr,
                                registry_clone,
                                HANDSHAKE_TIMEOUT,
                            )
                            .await
                            {
                                error!("Data Connection Error [{}]: {}", addr, e);
                            }
                        }
                        0x16 => match tokio::time::timeout(
                            HANDSHAKE_TIMEOUT,
                            tls_acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(tls_stream)) => {
                                if let Err(e) = handle_control_connection(
                                    tls_stream,
                                    addr,
                                    agent_pw_clone,
                                    registry_clone,
                                    usage_clone,
                                    HANDSHAKE_TIMEOUT,
                                    2,
                                )
                                .await
                                {
                                    error!("TLS control connection error [{}]: {}", addr, e);
                                }
                            }
                            Ok(Err(error)) => {
                                warn!("TLS handshake failed from {}: {}", addr, error)
                            }
                            Err(_) => warn!("TLS handshake timed out from {}", addr),
                        },
                        V2_DATA_CONNECTION => {
                            if stream.read_exact(&mut type_buf).await.is_err() {
                                return;
                            }
                            if let Err(e) = handle_v2_data_connection(
                                stream,
                                addr,
                                registry_clone,
                                HANDSHAKE_TIMEOUT,
                            )
                            .await
                            {
                                error!("V2 data connection error [{}]: {}", addr, e);
                            }
                        }
                        _ => warn!("Unknown connection type from {}", addr),
                    }
                });
            }
            Err(e) => {
                error!("Server accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }
}

async fn handle_control_connection<S>(
    mut stream: S,
    addr: SocketAddr,
    server_pw: Option<String>,
    registry: AgentRegistry,
    cumulative_usage: Arc<DashMap<String, u64>>,
    handshake_timeout: std::time::Duration,
    protocol_version: u8,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (agent_id, captured_pw) = tokio::time::timeout(handshake_timeout, async {
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf).await?;
        let mut id_buf = vec![0u8; len_buf[0] as usize];
        stream.read_exact(&mut id_buf).await?;
        stream.read_exact(&mut len_buf).await?;
        let mut pw_buf = vec![0u8; len_buf[0] as usize];
        stream.read_exact(&mut pw_buf).await?;
        Ok::<_, anyhow::Error>((String::from_utf8(id_buf)?, String::from_utf8(pw_buf)?))
    })
    .await
    .map_err(|_| anyhow::anyhow!("Control handshake timed out"))??;

    let expected_pw = server_pw.as_deref().unwrap_or("");
    if server_pw.is_some() && captured_pw != expected_pw {
        warn!(
            "Agent Auth failed for '{}' from {}: invalid password",
            agent_id, addr
        );
        security::report_failure(&addr.ip().to_string());
        return Ok(());
    }
    security::report_success(&addr.ip().to_string());
    let mut os_buf = [0u8; 1];
    let os_type = match tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read_exact(&mut os_buf),
    )
    .await
    {
        Ok(Ok(_)) => os_buf[0],
        _ => 0, // 0 = PC
    };

    debug!(
        "Agent '{}' connected from {} (OS: {})",
        agent_id, addr, os_type
    );

    let previous_agent = registry.get(&agent_id).map(|entry| {
        (
            entry.reset_token.clone(),
            Arc::clone(&entry.reset_waiter),
            Arc::clone(&entry.usage),
        )
    });
    let (control_tx, mut control_rx) = mpsc::channel::<TunnelCmd>(100);
    let active_requests = Arc::new(DashMap::new());
    let pending_opens = Arc::new(DashMap::new());
    let device = Arc::new(RwLock::new(None));
    let usage = previous_agent
        .as_ref()
        .map(|(_, _, usage)| Arc::clone(usage))
        .unwrap_or_else(|| {
            Arc::new(AtomicU64::new(
                cumulative_usage.get(&agent_id).map(|v| *v).unwrap_or(0),
            ))
        });
    let reset_token = match previous_agent.as_ref() {
        Some((token, _, _)) => token.clone(),
        None => crate::session::random_token()?,
    };
    let reset_waiter = Arc::new(tokio::sync::Mutex::new(None));
    let resetting = Arc::new(AtomicBool::new(false));
    registry.insert(
        agent_id.clone(),
        AgentEntry {
            control_tx,
            active_requests: Arc::clone(&active_requests),
            pending_opens: Arc::clone(&pending_opens),
            protocol_version,
            device: Arc::clone(&device),
            addr,
            usage: Arc::clone(&usage),
            os_type,
            reset_token,
            reset_waiter,
            resetting,
        },
    );

    if let Some((_, previous_reset_waiter, _)) = previous_agent {
        if let Some(waiter) = previous_reset_waiter.lock().await.take() {
            let _ = waiter.response_tx.send(ResetResult {
                old_ip: waiter.old_ip,
                new_ip: addr.ip().to_string(),
                took_ms: waiter.started_at.elapsed().as_millis(),
            });
        }
    }

    let mut control_stream = stream;
    let id_for_cleanup = agent_id.clone();
    let registry_for_cleanup = Arc::clone(&registry);

    let mut monitor_buf = [0u8; 1];
    let mut server_ping_interval = tokio::time::interval(AGENT_PING_INTERVAL);
    let mut last_activity = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = server_ping_interval.tick() => {
                if last_activity.elapsed() > AGENT_IDLE_TIMEOUT {
                    warn!("Agent '{}' timed out on server (No ping for {:?}). Dropping.", agent_id, AGENT_IDLE_TIMEOUT);
                    break;
                }
            }
            cmd_opt = control_rx.recv() => {
                match cmd_opt {
                    Some(cmd) => {
                        let buf = match (protocol_version, cmd) {
                            (1, TunnelCmd::RequireConn(id)) => {
                                let mut b = vec![CMD_REQUIRE_CONN];
                                b.extend_from_slice(&id.to_be_bytes());
                                b
                            }
                            (2, TunnelCmd::Open { token, target }) => {
                                let mut b = vec![CMD_OPEN];
                                b.extend_from_slice(&token);
                                b.extend_from_slice(&target);
                                b
                            }
                            (_, TunnelCmd::UdpSession(port)) => {
                                let mut b = vec![CMD_UDP_SESSION];
                                b.extend_from_slice(&port.to_be_bytes());
                                b
                            }
                            (_, TunnelCmd::ResetIp) => vec![CMD_RESET_IP],
                            (1, TunnelCmd::Open { .. }) | (2, TunnelCmd::RequireConn(_)) => continue,
                            _ => continue,
                        };
                        if let Err(e) = control_stream.write_all(&buf).await {
                            error!("Failed to send command to agent '{}': {}", agent_id, e);
                            break;
                        }
                    }
                    None => break,
                }
            }
            res = control_stream.read(&mut monitor_buf) => {
                match res {
                    Ok(n) if n > 0 => {
                        last_activity = tokio::time::Instant::now();
                        let cmd = monitor_buf[0];
                        if cmd == CMD_PING {
                            let _ = control_stream.write_all(&[CMD_PING]).await;
                        } else if protocol_version == 2 && cmd == CMD_STATUS {
                            let mut length = [0; 2];
                            if control_stream.read_exact(&mut length).await.is_err() {
                                break;
                            }
                            let length = u16::from_be_bytes(length) as usize;
                            if length > MAX_STATUS_BYTES {
                                warn!("Ignoring oversized STATUS from agent '{}'", agent_id);
                                if discard_control_bytes(&mut control_stream, length).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                            let mut payload = vec![0; length];
                            if control_stream.read_exact(&mut payload).await.is_err() {
                                break;
                            }
                            match record_device_status(&device, &payload) {
                                Ok(true) => debug!("Updated STATUS for agent '{}'", agent_id),
                                Ok(false) => debug!("Ignoring rate-limited STATUS from agent '{}'", agent_id),
                                Err(error) => warn!("Ignoring invalid STATUS from agent '{}': {}", agent_id, error),
                            }
                        } else {
                            warn!("Unknown command from agent: {}", cmd);
                        }
                    }
                    _ => {
                        debug!("Agent '{}' disconnected", agent_id);
                        break;
                    }
                }
            }
        }
    }

    active_requests.clear();
    pending_opens.clear();
    cumulative_usage
        .entry(agent_id.clone())
        .and_modify(|total| *total = (*total).max(usage.load(Ordering::Relaxed)))
        .or_insert_with(|| usage.load(Ordering::Relaxed));

    let waiting_for_reset = registry_for_cleanup
        .get(&id_for_cleanup)
        .map(|entry| {
            preserves_resetting_agent(entry.addr, addr, entry.resetting.load(Ordering::Relaxed))
        })
        .unwrap_or(false);
    if waiting_for_reset {
        debug!(
            "Agent '{}' disconnected while reset is in progress; waiting for re-registration",
            agent_id
        );
    } else {
        debug!("Agent '{}' disconnected, removing from registry", agent_id);
        registry_for_cleanup.remove_if(&id_for_cleanup, |_, entry| entry.addr == addr);
    }
    Ok(())
}

/// Real client IP for ban accounting. Forwarding headers are trusted only when the
/// TCP peer is private/loopback (Coolify's Traefik behind Cloudflare); a direct
/// internet client cannot spoof them.
fn api_client_ip(peer: IpAddr, cf_ip: Option<&str>, forwarded_for: Option<&str>) -> String {
    let trusted = match peer {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    let from_header = cf_ip
        // rightmost entry was appended by our own proxy, so it cannot be forged
        .or_else(|| forwarded_for.and_then(|v| v.rsplit(',').next()))
        .and_then(|v| v.trim().parse::<IpAddr>().ok());
    match from_header {
        Some(ip) if trusted => ip.to_string(),
        _ => peer.to_string(),
    }
}

async fn handle_api_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    registry: AgentRegistry,
    bind_registry: BindRegistry,
    agent_password: Option<String>,
    admin_password: String,
    control_port: u16,
    tls_fingerprint: String,
) {
    let request_str = match read_api_request(&mut stream).await {
        Ok(Some(request)) => request,
        Ok(None) | Err(ApiRequestError::Incomplete) => return,
        Err(ApiRequestError::TooLarge) => {
            let _ = stream.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"Payload too large\"}").await;
            return;
        }
    };

    // Split header and body
    let mut header_body = request_str.splitn(2, "\r\n\r\n");
    let header_str = header_body.next().unwrap_or("");
    let body_str = header_body.next().unwrap_or("").trim_matches(char::from(0));

    let mut lines = header_str.lines();
    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let path = parts[1];

    // Parse Headers
    let mut host = String::new();
    let mut x_pw = String::new();
    let mut cookie_header = String::new();
    let mut is_https = false;
    let mut cf_ip = None;
    let mut forwarded_for = None;
    for line in lines {
        let l_lower = line.to_lowercase();
        if l_lower.starts_with("host:") {
            host = line[5..].trim().to_string();
            if let Some(idx) = host.find(':') {
                host = host[..idx].to_string();
            }
        } else if l_lower.starts_with("x-server-password:") {
            x_pw = line[18..].trim().to_string();
        } else if l_lower.starts_with("cookie:") {
            cookie_header = line[7..].trim().to_string();
        } else if let Some(proto) = l_lower.strip_prefix("x-forwarded-proto:") {
            is_https = proto.trim() == "https";
        } else if l_lower.starts_with("cf-connecting-ip:") {
            cf_ip = Some(line[17..].trim().to_string());
        } else if l_lower.starts_with("x-forwarded-for:") {
            forwarded_for = Some(line[16..].trim().to_string());
        }
    }

    let peer_ip = api_client_ip(peer_addr.ip(), cf_ip.as_deref(), forwarded_for.as_deref());
    if security::is_blacklisted(&peer_ip) {
        let _ = stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"Too many attempts\"}").await;
        return;
    }

    let expected_pw = admin_password;
    let session_token = crate::session::token_from_cookie_header(&cookie_header);
    let is_authed = crate::session::constant_time_eq(&x_pw, &expected_pw)
        || session_token.is_some_and(crate::session::is_valid);

    // Path Validation
    let (base_path, query) = if let Some(idx) = path.find('?') {
        (&path[..idx], &path[idx + 1..])
    } else {
        (path, "")
    };

    if base_path == "/" || base_path == "/index.html" {
        let html = include_str!("web_ui.html");
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", html.len(), html);
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if method == "POST" && base_path == "/api/login" {
        let password = serde_json::from_str::<serde_json::Value>(body_str)
            .ok()
            .and_then(|json| json["password"].as_str().map(String::from));
        let resp = match password {
                None => "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"Bad request\"}".to_string(),
                Some(pw) if !crate::session::constant_time_eq(&pw, &expected_pw) => {
                    security::report_failure(&peer_ip);
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"Unauthorized\"}".to_string()
                }
                Some(_) => {
                    security::report_success(&peer_ip);
                    match crate::session::create() {
                    Ok(token) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}\r\nConnection: close\r\n\r\n{{\"ok\":true}}",
                        crate::session::set_cookie_header(&token, is_https)
                    ),
                    Err(e) => {
                        error!("Failed to create dashboard session: {}", e);
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":\"Internal error\"}".to_string()
                    }
                    }
                }
            };
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if method == "POST" && base_path == "/api/logout" {
        if let Some(token) = session_token {
            crate::session::revoke(token);
        }
        let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}\r\nConnection: close\r\n\r\n{{\"ok\":true}}",
                crate::session::clear_cookie_header(is_https)
            );
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if base_path.starts_with("/api/") && !is_authed {
        security::report_failure(&peer_ip);
        let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Unauthorized\"}";
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if base_path.starts_with("/api/") {
        security::report_success(&peer_ip);
    }

    if base_path == "/qr" {
        if !is_authed {
            security::report_failure(&peer_ip);
            let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nUnauthorized";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }
        security::report_success(&peer_ip);
        let vps_ip = if host.is_empty() { "127.0.0.1" } else { &host };
        let public_host = std::env::var("RUST_PROXY_PUBLIC_HOST")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| vps_ip.to_string());
        let public_port = std::env::var("RUST_PROXY_PUBLIC_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|port| *port != 0)
            .unwrap_or(control_port);
        let payload = serde_json::json!({
            "h": public_host,
            "p": public_port,
            "pwd": agent_password.unwrap_or_default(),
            "fp": tls_fingerprint,
        });
        let qrcode = match qrcode::QrCode::new(payload.to_string().as_bytes()) {
            Ok(q) => q,
            Err(e) => {
                let resp = format!("HTTP/1.1 500 Internal Server Error\r\n\r\nQR Error: {}", e);
                let _ = stream.write_all(resp.as_bytes()).await;
                return;
            }
        };
        let svg = qrcode.render::<qrcode::render::svg::Color>().build();
        let html = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n\
                 <html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\
                 <style>body {{ display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f0f0; }} \
                 .qr-container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 80%; max-width: 400px; }} \
                 svg {{ width: 100%; height: auto; }}</style></head>\
                 <body><div class=\"qr-container\">{}</div></body></html>",
                svg
            );
        let _ = stream.write_all(html.as_bytes()).await;
        return;
    }

    if query.split('&').any(|part| part == "reset_ip") {
        let token = query.split('&').find_map(|part| {
            part.split_once('=')
                .and_then(|(key, value)| (key == "token").then_some(value))
        });
        let agent_id = base_path.trim_start_matches('/');
        let Some(token) = token else {
            let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Unauthorized\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        };
        let Some(agent) = registry.get(agent_id) else {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Agent not found\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        };
        if !crate::session::constant_time_eq(token, &agent.reset_token) {
            let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Unauthorized\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }
        if agent.os_type != 1 {
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Agent is not Android\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }
        let old_ip = agent.addr.ip().to_string();
        let agent_addr = agent.addr;
        let control_tx = agent.control_tx.clone();
        let reset_waiter = Arc::clone(&agent.reset_waiter);
        let resetting = Arc::clone(&agent.resetting);
        let active_requests = Arc::clone(&agent.active_requests);
        let pending_opens = Arc::clone(&agent.pending_opens);
        drop(agent);

        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        let reset_in_progress = {
            let mut reset = reset_waiter.lock().await;
            if reset.is_some() {
                true
            } else {
                *reset = Some(ResetWaiter {
                    old_ip,
                    started_at: tokio::time::Instant::now(),
                    response_tx,
                });
                false
            }
        };
        if reset_in_progress {
            let resp = "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Reset in progress\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }
        resetting.store(true, Ordering::SeqCst);
        active_requests.clear();
        pending_opens.clear();
        if control_tx.send(TunnelCmd::ResetIp).await.is_err() {
            reset_waiter.lock().await.take();
            resetting.store(false, Ordering::SeqCst);
            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Failed to command agent\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }

        let resp = match tokio::time::timeout(RESET_TIMEOUT, response_rx).await {
            Ok(Ok(result)) => {
                let body = serde_json::json!({
                    "status": "rotated",
                    "old_ip": result.old_ip,
                    "new_ip": result.new_ip,
                    "took_ms": result.took_ms,
                })
                .to_string();
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)
            }
            Ok(Err(_)) | Err(_) => {
                reset_waiter.lock().await.take();
                resetting.store(false, Ordering::SeqCst);
                registry.remove_if(agent_id, |_, entry| entry.addr == agent_addr);
                "HTTP/1.1 504 Gateway Timeout\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Reset timeout\"}".to_string()
            }
        };
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if base_path == "/api/state" {
        let mut agents_arr = Vec::new();
        let mut agent_ip_counts = std::collections::HashMap::new();
        for entry in registry.iter() {
            *agent_ip_counts
                .entry(entry.value().addr.ip().to_string())
                .or_insert(0usize) += 1;
        }
        for entry in registry.iter() {
            let usage_mb = entry.value().usage.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0;
            let ip = entry.value().addr.ip().to_string();
            let device = entry
                .value()
                .device
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            agents_arr.push(serde_json::json!({
                    "id": entry.key(),
                    "addr": entry.value().addr.to_string(),
                    "usage_mb": format!("{:.2}", usage_mb),
                    "os": if entry.value().os_type == 1 { "Android" } else { "PC" },
                    "proto_version": entry.value().protocol_version,
                    "device": device,
                    "status": if entry.value().resetting.load(Ordering::Relaxed) { "resetting" } else { "connected" },
                    "shared_ip": agent_ip_counts.get(&ip).copied().unwrap_or_default() > 1,
                    "reset_url": format!("/{}?reset_ip&token={}", entry.key(), entry.value().reset_token)
                }));
        }
        let mut binds_arr = Vec::new();
        for entry in bind_registry.iter() {
            let bind = entry.value();
            let usage_mb = bind.usage.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0;
            binds_arr.push(serde_json::json!({
                    "port": entry.key(),
                    "agent_id": bind.agent_id,
                    "user": bind.user.clone().unwrap_or_default(),
                    // admin-only endpoint; operators need the full proxy string to hand out
                    "pass": bind.pass.clone().unwrap_or_default(),
                    "usage_mb": format!("{:.2}", usage_mb),
                    "active_conns": bind.max_conns.saturating_sub(bind.connection_limit.available_permits()),
                    "max_conns": bind.max_conns
                }));
        }
        let payload = serde_json::json!({
            "agents": agents_arr,
            "binds": binds_arr,
            "socks_host": std::env::var("RUST_PROXY_SOCKS_HOST").unwrap_or_default(),
            "socks_port_min": SOCKS_PORT_MIN,
            "socks_port_max": SOCKS_PORT_MAX
        });
        let body = payload.to_string();
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if method == "POST" && base_path == "/api/bind" {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
            let max_conns = match json.get("max_conns") {
                Some(value) => match value
                    .as_u64()
                    .filter(|value| (1..=MAX_CONNS as u64).contains(value))
                {
                    Some(value) => value as usize,
                    None => {
                        let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid max_conns\"}";
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }
                },
                None => DEFAULT_MAX_CONNS,
            };
            if let (Some(id), Some(port)) = (
                json["agent_id"].as_str(),
                json["port"]
                    .as_u64()
                    .and_then(|port| u16::try_from(port).ok()),
            ) {
                let socks_user = json["user"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                let socks_pass = json["pass"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(String::from);

                if socks_user.is_none() || socks_pass.is_none() {
                    let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Missing credentials\"}";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }

                if !is_socks_port(port) {
                    let resp = format!(
                            "HTTP/1.1 422 Unprocessable Content\r\nContent-Type: application/json\r\n\r\n{{\"error\":\"Port must be between {} and {}\"}}",
                            SOCKS_PORT_MIN, SOCKS_PORT_MAX
                        );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                if !registry.contains_key(id) {
                    let resp = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Agent not found\"}";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                if bind_registry.contains_key(&port) {
                    let resp = "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Port already bound\"}";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }

                let socks_listener = match bind_socks_listener(port).await {
                    Ok(listener) => listener,
                    Err(e) => {
                        let resp = format!(
                                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\n\r\n{{\"error\":\"Port unavailable: {}\"}}",
                                e
                            );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }
                };
                let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                let usage = Arc::new(std::sync::atomic::AtomicU64::new(0));

                bind_registry.insert(
                    port,
                    crate::tunnel::BindEntry {
                        agent_id: id.to_string(),
                        port,
                        usage: Arc::clone(&usage),
                        max_conns,
                        connection_limit: Arc::new(Semaphore::new(max_conns)),
                        user: socks_user.clone(),
                        pass: socks_pass.clone(),
                        shutdown_tx: Some(shutdown_tx),
                    },
                );

                let reg = Arc::clone(&registry);
                let b_reg = Arc::clone(&bind_registry);
                let id_clone = id.to_string();

                tokio::spawn(async move {
                    if let Err(e) = crate::tunnel::run_socks_listener(
                        socks_listener,
                        id_clone,
                        reg,
                        b_reg,
                        socks_user,
                        socks_pass,
                        shutdown_rx,
                    )
                    .await
                    {
                        log::error!("SOCKS Listener Error on port {}: {}", port, e);
                    }
                });
                let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"bound\"}";
                let _ = stream.write_all(resp.as_bytes()).await;
                return;
            }
        }
        let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid JSON\"}";
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if method == "POST" && base_path == "/api/unbind" {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
            if let Some(port) = json["port"].as_u64() {
                let port = port as u16;
                if let Some(mut entry) = bind_registry.get_mut(&port) {
                    if let Some(tx) = entry.shutdown_tx.take() {
                        let _ = tx.send(true);
                    }
                }
                let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"unbound\"}";
                let _ = stream.write_all(resp.as_bytes()).await;
                return;
            }
        }
        let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid JSON\"}";
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    if base_path == "/api/blacklist" {
        if method == "GET" {
            let bl = crate::security::get_blacklist();
            let body = serde_json::json!({ "blacklist": bl }).to_string();
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        } else if method == "POST" || method == "DELETE" {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) {
                if let Some(ip) = json["ip"].as_str() {
                    if method == "POST" {
                        crate::security::add_to_blacklist(ip.to_string());
                    } else {
                        crate::security::remove_from_blacklist(ip);
                    }
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"success\"}";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
            }
            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid JSON\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }
    }

    let resp =
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Not Found\"}";
    let _ = stream.write_all(resp.as_bytes()).await;
}

enum ApiRequestError {
    Incomplete,
    TooLarge,
}

async fn read_api_request(
    stream: &mut TcpStream,
) -> std::result::Result<Option<String>, ApiRequestError> {
    tokio::time::timeout(API_READ_TIMEOUT, async {
        let mut request = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
            {
                let content_length = content_length(&request[..header_end])?;
                let total_length = header_end
                    .checked_add(content_length)
                    .ok_or(ApiRequestError::TooLarge)?;
                if total_length > MAX_API_REQUEST_BYTES {
                    return Err(ApiRequestError::TooLarge);
                }
                while request.len() < total_length {
                    let read = stream
                        .read(&mut chunk)
                        .await
                        .map_err(|_| ApiRequestError::Incomplete)?;
                    if read == 0 {
                        return Err(ApiRequestError::Incomplete);
                    }
                    if request.len() + read > MAX_API_REQUEST_BYTES {
                        return Err(ApiRequestError::TooLarge);
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                return String::from_utf8(request[..total_length].to_vec())
                    .map(Some)
                    .map_err(|_| ApiRequestError::Incomplete);
            }
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|_| ApiRequestError::Incomplete)?;
            if read == 0 {
                return Ok(None);
            }
            if request.len() + read > MAX_API_REQUEST_BYTES {
                return Err(ApiRequestError::TooLarge);
            }
            request.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .unwrap_or(Err(ApiRequestError::Incomplete))
}

fn content_length(header: &[u8]) -> std::result::Result<usize, ApiRequestError> {
    let header = std::str::from_utf8(header).map_err(|_| ApiRequestError::Incomplete)?;
    header
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim())
        })
        .map(|value| value.parse().map_err(|_| ApiRequestError::Incomplete))
        .unwrap_or(Ok(0))
}

async fn handle_data_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    registry: AgentRegistry,
    handshake_timeout: std::time::Duration,
) -> Result<()> {
    configure_tunnel_stream(&stream);
    let (agent_id, request_id) = tokio::time::timeout(handshake_timeout, async {
        let mut len_buf = [0u8; 1];
        stream.read_exact(&mut len_buf).await?;
        let mut id_buf = vec![0u8; len_buf[0] as usize];
        stream.read_exact(&mut id_buf).await?;
        let mut request_id_buf = [0u8; 4];
        stream.read_exact(&mut request_id_buf).await?;
        Ok::<_, anyhow::Error>((
            String::from_utf8(id_buf)?,
            u32::from_be_bytes(request_id_buf),
        ))
    })
    .await
    .map_err(|_| anyhow::anyhow!("Data handshake timed out"))??;

    let active_requests = if let Some(agent) = registry.get(&agent_id) {
        Some(Arc::clone(&agent.active_requests))
    } else {
        None
    };

    if let Some(active_requests) = active_requests {
        if let Some((_, tx)) = active_requests.remove(&request_id) {
            let _ = tx.send(stream);
        } else {
            warn!(
                "Data connection for unknown/expired request {} from agent '{}'",
                request_id, agent_id
            );
        }
        Ok(())
    } else {
        warn!(
            "Data connection for unknown agent '{}' from {}",
            agent_id, addr
        );
        Ok(())
    }
}

pub async fn bind_socks_listener(socks_port: u16) -> Result<BoundSocksListener> {
    if !is_socks_port(socks_port) {
        anyhow::bail!(
            "port must be between {} and {}",
            SOCKS_PORT_MIN,
            SOCKS_PORT_MAX
        );
    }
    Ok(BoundSocksListener {
        listener: TcpListener::bind(format!("0.0.0.0:{}", socks_port)).await?,
        port: socks_port,
    })
}

pub async fn run_socks_listener(
    bound_listener: BoundSocksListener,
    agent_id: String,
    registry: AgentRegistry,
    bind_registry: BindRegistry,
    socks_user: Option<String>,
    socks_pass: Option<String>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let BoundSocksListener {
        listener: socks_listener,
        port: socks_port,
    } = bound_listener;
    let bind_usage = if let Some(bind) = bind_registry.get(&socks_port) {
        Arc::clone(&bind.usage)
    } else {
        Arc::new(AtomicU64::new(0))
    };
    let connection_limit = if let Some(bind) = bind_registry.get(&socks_port) {
        Arc::clone(&bind.connection_limit)
    } else {
        Arc::new(Semaphore::new(DEFAULT_MAX_CONNS))
    };

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                debug!("SOCKS5 Listener on port {} shutdown requested by user", socks_port);
                    break;
                }
            }
            accept_res = socks_listener.accept() => {
                match accept_res {
                    Ok((client_stream, addr)) => {
                        let connection_permit = Arc::clone(&connection_limit).try_acquire_owned().ok();
                        let limit_reached = connection_permit.is_none();
                        if limit_reached {
                            warn!("Connection limit reached on port {}; rejecting client from {}", socks_port, addr);
                        }

                        let agent_info = if limit_reached {
                            None
                        } else {
                            registry.get(&agent_id).map(|agent| {
                                (
                                agent.control_tx.clone(),
                                Arc::clone(&agent.active_requests),
                                Arc::clone(&agent.pending_opens),
                                agent.protocol_version,
                                Arc::clone(&agent.usage),
                                Arc::clone(&agent.resetting),
                                )
                            })
                        };
                        let (signal_tx, agent_active_requests, agent_pending_opens, protocol_version, agent_usage, resetting) = if let Some((signal_tx, agent_active_requests, agent_pending_opens, protocol_version, agent_usage, resetting)) = agent_info {
                            debug!("SOCKS Client connected to '{}' from {}", agent_id, addr);
                            (Some(signal_tx), Some(agent_active_requests), Some(agent_pending_opens), protocol_version, agent_usage, Some(resetting))
                        } else {
                            if !limit_reached {
                                warn!("Agent '{}' is currently offline. Rejecting SOCKS client from {}", agent_id, addr);
                            }
                            (None, None, None, 1, Arc::new(AtomicU64::new(0)), None)
                        };

                        let bind_usage_clone = Arc::clone(&bind_usage);
                        let s_user = socks_user.clone();
                        let s_pass = socks_pass.clone();
                        let timing_agent = agent_id.clone();
                        let mut client_shutdown = shutdown_rx.clone();
                        tokio::spawn(async move {
                            let _connection_permit = connection_permit;
                            let _ = client_stream.set_nodelay(true);
                            if *client_shutdown.borrow() {
                                return;
                            }
                            let result = tokio::select! {
                                result = handle_proxy_client(client_stream, signal_tx, agent_active_requests, agent_pending_opens, protocol_version, s_user, s_pass, agent_usage, Some(bind_usage_clone), socks_port, Some(timing_agent), resetting, limit_reached) => result,
                                _ = client_shutdown.changed() => Ok(()),
                            };
                            if let Err(e) = result {
                                error!("SOCKS Client Error [{}]: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("SOCKS accept error: {}", e);
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
        }
    }

    bind_registry.remove(&socks_port);
    Ok(())
}

async fn handle_v2_data_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    registry: AgentRegistry,
    handshake_timeout: std::time::Duration,
) -> Result<()> {
    configure_tunnel_stream(&stream);
    let (token, status) = tokio::time::timeout(handshake_timeout, async {
        let mut token = [0; 16];
        stream.read_exact(&mut token).await?;
        let mut status = [0];
        stream.read_exact(&mut status).await?;
        Ok::<_, anyhow::Error>((token, status[0]))
    })
    .await
    .map_err(|_| anyhow::anyhow!("V2 data handshake timed out"))??;

    // ponytail: scans live agents because the v2 header intentionally contains only a token;
    // add a global token index if the fleet size makes this measurable.
    let sender = registry
        .iter()
        .find_map(|entry| entry.pending_opens.remove(&token).map(|(_, sender)| sender));
    let Some(sender) = sender else {
        warn!(
            "V2 data connection with an unknown or expired token from {}",
            addr
        );
        return Ok(());
    };
    let result: OpenResult = if status == V2_STATUS_OK {
        Ok(stream)
    } else if status == V2_STATUS_BLOCKED || status == V2_STATUS_UNREACHABLE {
        Err(status)
    } else {
        Err(V2_STATUS_UNREACHABLE)
    };
    let _ = sender.send(result);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_proxy_client(
    stream: TcpStream,
    signal_tx: Option<TunnelSignalTx>,
    data_rx: Option<AgentRequestRegistry>,
    open_rx: Option<OpenRequestRegistry>,
    protocol_version: u8,
    user: Option<String>,
    password: Option<String>,
    agent_usage: Arc<AtomicU64>,
    bind_usage: Option<Arc<AtomicU64>>,
    socks_port: u16,
    timing_agent: Option<String>,
    resetting: Option<Arc<AtomicBool>>,
    limit_reached: bool,
) -> Result<()> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) if first[0] == 0x05 => {
            socks5::handle_client(
                stream,
                signal_tx,
                data_rx,
                open_rx,
                protocol_version,
                user,
                password,
                agent_usage,
                bind_usage,
                socks_port,
                timing_agent,
                resetting,
                limit_reached,
            )
            .await
        }
        Ok(Ok(1)) if first[0].is_ascii_alphabetic() => {
            crate::http_proxy::handle_client(
                stream,
                signal_tx,
                data_rx,
                open_rx,
                protocol_version,
                user,
                password,
                agent_usage,
                bind_usage,
                socks_port,
                timing_agent,
                resetting,
                limit_reached,
            )
            .await
        }
        _ => Ok(()),
    }
}

pub async fn run_agent(
    server_addr: String,
    agent_id: String,
    server_pw: Option<String>,
    shutdown_rx: Option<tokio::sync::mpsc::Receiver<()>>,
) -> Result<()> {
    run_agent_with_cache_path(
        server_addr,
        agent_id,
        server_pw,
        shutdown_rx,
        "agent_cache.json".into(),
        None,
    )
    .await
}

pub async fn run_agent_with_fingerprint(
    server_addr: String,
    agent_id: String,
    server_pw: Option<String>,
    fingerprint: String,
    shutdown_rx: Option<tokio::sync::mpsc::Receiver<()>>,
) -> Result<()> {
    run_agent_with_cache_path(
        server_addr,
        agent_id,
        server_pw,
        shutdown_rx,
        "agent_cache.json".into(),
        Some(fingerprint),
    )
    .await
}

pub(crate) async fn run_agent_with_cache_path(
    mut server_addr: String,
    agent_id: String,
    server_pw: Option<String>,
    mut shutdown_rx: Option<tokio::sync::mpsc::Receiver<()>>,
    cache_path: String,
    fingerprint: Option<String>,
) -> Result<()> {
    server_addr = server_addr.replace("http://", "").replace("https://", "");
    if server_addr.ends_with('/') {
        server_addr.pop();
    }
    if !server_addr.contains(':') {
        server_addr.push_str(":8080");
    }

    let cache_mgr = crate::cache::CacheManager::new(&cache_path);
    let mut agent_cache = cache_mgr.load_agent().unwrap_or_default();

    // The caller owns the configured ID; the cache only preserves usage totals.
    agent_cache.agent_id = agent_id;

    debug!(
        "Starting Tunnel AGENT '{}' (Cumulative Usage: {} MB) connecting to {}",
        agent_cache.agent_id,
        agent_cache.cumulative_usage / 1024 / 1024,
        server_addr
    );

    let global_agent_usage = Arc::new(AtomicU64::new(agent_cache.cumulative_usage));
    let usage_for_sync = Arc::clone(&global_agent_usage);
    let id_for_sync = agent_cache.agent_id.clone();
    let cache_path_for_sync = cache_path.clone();
    let (usage_stop_tx, mut usage_stop_rx) = tokio::sync::oneshot::channel();
    let usage_sync = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    let update = crate::cache::AgentCache {
                        agent_id: id_for_sync.clone(),
                        cumulative_usage: usage_for_sync.load(Ordering::Relaxed),
                    };
                    let _ = crate::cache::CacheManager::new(&cache_path_for_sync).save_agent(&update);
                }
                _ = &mut usage_stop_rx => break,
            }
        }
    });

    let effective_agent_id = agent_cache.agent_id.clone();
    let mut backoff = std::time::Duration::from_secs(1);
    let result = loop {
        crate::report_android_status("connecting", None);
        match if let Some(fingerprint) = fingerprint.as_deref() {
            run_agent_session_v2(
                &server_addr,
                &effective_agent_id,
                server_pw.as_deref(),
                fingerprint,
                Arc::clone(&global_agent_usage),
                &mut shutdown_rx,
            )
            .await
        } else {
            run_agent_session(
                &server_addr,
                &effective_agent_id,
                server_pw.as_deref(),
                Arc::clone(&global_agent_usage),
                &mut shutdown_rx,
            )
            .await
        } {
            Ok(true) => break Ok(()),
            Ok(false) => {
                crate::report_android_status("disconnected", Some("Control connection closed"));
                warn!("Control connection closed; reconnecting.");
            }
            Err(error) => {
                crate::report_android_status("disconnected", Some(&error.to_string()));
                warn!("Agent connection failed: {}; reconnecting.", error);
            }
        }

        let delay = reconnect_delay(backoff, reconnect_entropy());
        debug!("Retrying agent connection in {:?}", delay);
        if wait_for_shutdown(delay, &mut shutdown_rx).await {
            break Ok(());
        }
        backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_MAX_DELAY);
    };

    let _ = usage_stop_tx.send(());
    let _ = usage_sync.await;
    let _ = cache_mgr.save_agent(&crate::cache::AgentCache {
        agent_id: effective_agent_id,
        cumulative_usage: global_agent_usage.load(Ordering::Relaxed),
    });
    result
}

fn reconnect_entropy() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

fn reconnect_delay(base: std::time::Duration, entropy: u32) -> std::time::Duration {
    let jitter_ms = (base.as_millis() as u64 / 4).max(1);
    base + std::time::Duration::from_millis(u64::from(entropy) % (jitter_ms + 1))
}

fn preserves_resetting_agent(
    entry_addr: SocketAddr,
    disconnected_addr: SocketAddr,
    resetting: bool,
) -> bool {
    entry_addr == disconnected_addr && resetting
}

async fn wait_for_shutdown(
    delay: std::time::Duration,
    shutdown_rx: &mut Option<tokio::sync::mpsc::Receiver<()>>,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        _ = wait_for_stop(shutdown_rx) => true,
    }
}

async fn wait_for_stop(shutdown_rx: &mut Option<tokio::sync::mpsc::Receiver<()>>) {
    match shutdown_rx {
        Some(rx) => {
            let _ = rx.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn run_agent_session(
    server_addr: &str,
    agent_id: &str,
    server_pw: Option<&str>,
    global_agent_usage: Arc<AtomicU64>,
    shutdown_rx: &mut Option<tokio::sync::mpsc::Receiver<()>>,
) -> Result<bool> {
    debug!("Connecting to control server at {}", server_addr);
    let connect_future = TcpStream::connect(&server_addr);
    let mut control_stream = tokio::select! {
        result = tokio::time::timeout(tokio::time::Duration::from_secs(15), connect_future) => match result {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err(anyhow::anyhow!("Connection timeout to {}", server_addr)),
        },
        _ = wait_for_stop(shutdown_rx) => return Ok(true),
    };
    configure_tunnel_stream(&control_stream);
    let mut handshake = vec![0x00];
    handshake.push(agent_id.len() as u8);
    handshake.extend_from_slice(agent_id.as_bytes());

    let agt_pw = server_pw.unwrap_or_default();
    handshake.push(agt_pw.len() as u8);
    handshake.extend_from_slice(agt_pw.as_bytes());
    #[cfg(target_os = "android")]
    handshake.push(1);
    #[cfg(not(target_os = "android"))]
    handshake.push(0);

    control_stream.write_all(&handshake).await?;
    crate::report_android_status("connected", None);

    let mut ping_interval = tokio::time::interval(AGENT_PING_INTERVAL);
    let mut last_pong = tokio::time::Instant::now();

    loop {
        let mut buf = [0u8; 1];
        tokio::select! {
            _ = ping_interval.tick() => {
                if last_pong.elapsed() > AGENT_IDLE_TIMEOUT {
                    error!("Connection deemed dead (Ping Timeout). Dropping...");
                    return Ok(false);
                }
                if tokio::time::timeout(tokio::time::Duration::from_secs(5), control_stream.write_all(&[CMD_PING])).await.is_err() {
                    error!("Failed to write keepalive ping. Dropping...");
                    return Ok(false);
                }
            }
            _ = wait_for_stop(shutdown_rx) => {
                debug!("Agent shutdown signal received");
                return Ok(true);
            }
            res = control_stream.read_exact(&mut buf) => {
                match res {
                    Ok(_) => {
                        let cmd = buf[0];
                        match cmd {
                            CMD_PING => {
                                last_pong = tokio::time::Instant::now();
                            }
                            CMD_REQUIRE_CONN => {
                                let mut id_buf = [0u8; 4];
                                if control_stream.read_exact(&mut id_buf).await.is_ok() {
                                    let req_id = u32::from_be_bytes(id_buf);
                                    let server_addr_clone = server_addr.to_string();
                                    let id_clone = agent_id.to_string();
                                    let usage_clone = Arc::clone(&global_agent_usage);
                                    tokio::spawn(async move {
                                         if let Err(e) = handle_agent_data_conn(server_addr_clone, id_clone, usage_clone, req_id).await {
                                             error!("Agent data connection failed: {}", e);
                                         }
                                    });
                                } else {
                                    break;
                                }
                            }
                            CMD_UDP_SESSION => {
                                let mut port_buf = [0u8; 2];
                                if control_stream.read_exact(&mut port_buf).await.is_ok() {
                                    let port = u16::from_be_bytes(port_buf);
                                    debug!("Server requested UDP Session on port {}", port);
                                    let server_addr_clone = server_addr.to_string();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_agent_udp_session(server_addr_clone, port).await {
                                            error!("Agent UDP session failed: {}", e);
                                        }
                                    });
                                } else {
                                    break;
                                }
                            }
                            CMD_RESET_IP => {
                                debug!("Server requested IP Reset (Flight Mode)");
                                #[cfg(target_os = "android")]
                                {
                                    tokio::spawn(async move {
                                        let _ = tokio::task::spawn_blocking(move || {
                                            crate::trigger_flight_mode_reset();
                                        }).await;
                                    });
                                }
                                #[cfg(not(target_os = "android"))]
                                {
                                    warn!("Ignoring IP reset request on a non-Android agent");
                                }
                            }
                            _ => warn!("Unknown command from server: {}", cmd),
                        }
                    }
                    Err(e) => {
                        error!("Control connection lost: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(false)
}

async fn run_agent_session_v2(
    server_addr: &str,
    agent_id: &str,
    server_pw: Option<&str>,
    fingerprint: &str,
    global_agent_usage: Arc<AtomicU64>,
    shutdown_rx: &mut Option<tokio::sync::mpsc::Receiver<()>>,
) -> Result<bool> {
    debug!("Connecting to TLS control server at {}", server_addr);
    let tcp = tokio::select! {
        result = tokio::time::timeout(tokio::time::Duration::from_secs(15), TcpStream::connect(server_addr)) => match result {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err(anyhow::anyhow!("Connection timeout to {}", server_addr)),
        },
        _ = wait_for_stop(shutdown_rx) => return Ok(true),
    };
    configure_tunnel_stream(&tcp);
    let server_name = crate::tls::server_name(server_addr)?;
    let connector = crate::tls::client_connector(fingerprint)?;
    let mut control_stream = match tokio::time::timeout(
        tokio::time::Duration::from_secs(15),
        connector.connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.to_string().contains("Server key mismatch") => {
            return Err(anyhow::anyhow!("Server key mismatch"));
        }
        Ok(Err(error)) => return Err(anyhow::anyhow!("TLS handshake failed: {error}")),
        Err(_) => return Err(anyhow::anyhow!("TLS handshake timeout to {}", server_addr)),
    };

    let mut handshake = Vec::new();
    handshake.push(agent_id.len() as u8);
    handshake.extend_from_slice(agent_id.as_bytes());
    let password = server_pw.unwrap_or_default();
    handshake.push(password.len() as u8);
    handshake.extend_from_slice(password.as_bytes());
    #[cfg(target_os = "android")]
    handshake.push(1);
    #[cfg(not(target_os = "android"))]
    handshake.push(0);
    control_stream.write_all(&handshake).await?;
    crate::report_android_status("connected", None);

    let mut ping_interval = tokio::time::interval(AGENT_PING_INTERVAL);
    let mut status_interval = tokio::time::interval(STATUS_MIN_INTERVAL);
    status_interval.tick().await;
    let mut last_pong = tokio::time::Instant::now();
    let mut last_status = None;
    if let Some(status) = device_status_json() {
        if send_device_status(&mut control_stream, &status).await? {
            last_status = Some(status);
        }
    }
    let mut status_sent_at = tokio::time::Instant::now();
    loop {
        let mut command = [0u8; 1];
        tokio::select! {
            _ = ping_interval.tick() => {
                if last_pong.elapsed() > AGENT_IDLE_TIMEOUT {
                    return Ok(false);
                }
                if tokio::time::timeout(tokio::time::Duration::from_secs(5), control_stream.write_all(&[CMD_PING])).await.is_err() {
                    return Ok(false);
                }
            }
            _ = status_interval.tick() => {
                if let Some(status) = device_status_json() {
                    if last_status.as_deref() != Some(status.as_str()) || status_sent_at.elapsed() >= STATUS_REFRESH_INTERVAL {
                        if send_device_status(&mut control_stream, &status).await? {
                            last_status = Some(status);
                            status_sent_at = tokio::time::Instant::now();
                        } else {
                            warn!("Skipping oversized device STATUS");
                        }
                    }
                }
            }
            _ = wait_for_stop(shutdown_rx) => return Ok(true),
            result = control_stream.read_exact(&mut command) => match result {
                Ok(_) => match command[0] {
                    CMD_PING => last_pong = tokio::time::Instant::now(),
                    CMD_OPEN => {
                        let mut token = [0; 16];
                        if control_stream.read_exact(&mut token).await.is_err() {
                            break;
                        }
                        let target = match read_v2_target(&mut control_stream).await {
                            Ok(target) => target,
                            Err(error) => {
                                warn!("Invalid v2 OPEN from server: {}", error);
                                break;
                            }
                        };
                        let server_addr = server_addr.to_string();
                        let usage = Arc::clone(&global_agent_usage);
                        tokio::spawn(async move {
                            if let Err(error) = handle_agent_v2_open(server_addr, token, target, usage).await {
                                error!("Agent v2 data connection failed: {}", error);
                            }
                        });
                    }
                    CMD_UDP_SESSION => {
                        let mut port = [0; 2];
                        if control_stream.read_exact(&mut port).await.is_err() {
                            break;
                        }
                        let server_addr = server_addr.to_string();
                        tokio::spawn(async move {
                            if let Err(error) = handle_agent_udp_session(server_addr, u16::from_be_bytes(port)).await {
                                error!("Agent UDP session failed: {}", error);
                            }
                        });
                    }
                    CMD_RESET_IP => trigger_agent_ip_reset(),
                    command => warn!("Unknown v2 command from server: {}", command),
                },
                Err(error) => {
                    debug!("TLS control connection lost: {}", error);
                    break;
                }
            }
        }
    }
    Ok(false)
}

fn device_status_json() -> Option<String> {
    #[cfg(target_os = "android")]
    {
        crate::collect_android_device_status()
    }
    #[cfg(not(target_os = "android"))]
    {
        Some(
            serde_json::json!({
                "carrier": "PC fixture",
                "net": "unknown",
                "signal": 4,
                "battery": 100,
                "temp_c": 25.0,
                "charging": true,
                "health": "good",
                "app": env!("CARGO_PKG_VERSION"),
                "proto": 2,
                "assistant": false,
                "transport": "wifi",
            })
            .to_string(),
        )
    }
}

async fn send_device_status<S>(stream: &mut S, status: &str) -> Result<bool>
where
    S: AsyncWrite + Unpin,
{
    if status.len() > MAX_STATUS_BYTES {
        return Ok(false);
    }
    stream.write_all(&[CMD_STATUS]).await?;
    stream
        .write_all(&(status.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(status.as_bytes()).await?;
    Ok(true)
}

fn trigger_agent_ip_reset() {
    #[cfg(target_os = "android")]
    tokio::spawn(async move {
        let _ = tokio::task::spawn_blocking(crate::trigger_flight_mode_reset).await;
    });
    #[cfg(not(target_os = "android"))]
    warn!("Ignoring IP reset request on a non-Android agent");
}

async fn read_v2_target<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut atyp = [0; 1];
    stream.read_exact(&mut atyp).await?;
    let (host, ipv6) = match atyp[0] {
        0x01 => {
            let mut address = [0; 4];
            stream.read_exact(&mut address).await?;
            (std::net::Ipv4Addr::from(address).to_string(), false)
        }
        0x03 => {
            let mut length = [0; 1];
            stream.read_exact(&mut length).await?;
            let mut host = vec![0; length[0] as usize];
            stream.read_exact(&mut host).await?;
            let host = String::from_utf8(host)?;
            anyhow::ensure!(!host.is_empty(), "empty hostname");
            (host, false)
        }
        0x04 => {
            let mut address = [0; 16];
            stream.read_exact(&mut address).await?;
            (std::net::Ipv6Addr::from(address).to_string(), true)
        }
        value => anyhow::bail!("unsupported address type {value}"),
    };
    let mut port = [0; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    Ok(if ipv6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

async fn handle_agent_v2_open(
    server_addr: String,
    token: [u8; 16],
    target: String,
    usage: Arc<AtomicU64>,
) -> Result<()> {
    let (server, target) = tokio::join!(
        tokio::time::timeout(
            tokio::time::Duration::from_secs(8),
            TcpStream::connect(&server_addr)
        ),
        tokio::time::timeout(
            tokio::time::Duration::from_secs(8),
            connect_v2_target(&target)
        ),
    );
    let mut server = match server {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Err(anyhow::anyhow!("V2 data connection timeout")),
    };
    configure_tunnel_stream(&server);
    let target = match target {
        Ok(Ok(stream)) => stream,
        Ok(Err(status)) => {
            server.write_all(&[V2_DATA_CONNECTION]).await?;
            server.write_all(&token).await?;
            server.write_all(&[status]).await?;
            return Ok(());
        }
        Err(_) => {
            server.write_all(&[V2_DATA_CONNECTION]).await?;
            server.write_all(&token).await?;
            server.write_all(&[V2_STATUS_UNREACHABLE]).await?;
            return Ok(());
        }
    };
    configure_tunnel_stream(&target);
    server.write_all(&[V2_DATA_CONNECTION]).await?;
    server.write_all(&token).await?;
    server.write_all(&[V2_STATUS_OK]).await?;
    let mut server = BandwidthTrackedStream {
        inner: server,
        counter: usage,
        secondary_counter: None,
    };
    let mut target = target;
    let _ = tokio::io::copy_bidirectional(&mut server, &mut target).await;
    Ok(())
}

async fn connect_v2_target(target: &str) -> std::result::Result<TcpStream, u8> {
    let mut candidates = tokio::net::lookup_host(target)
        .await
        .map_err(|_| V2_STATUS_UNREACHABLE)?;
    let mut blocked = false;
    while let Some(address) = candidates.next() {
        if blocked_egress(address) {
            blocked = true;
            continue;
        }
        if let Ok(stream) = TcpStream::connect(address).await {
            return Ok(stream);
        }
    }
    Err(if blocked {
        V2_STATUS_BLOCKED
    } else {
        V2_STATUS_UNREACHABLE
    })
}

fn blocked_egress(address: SocketAddr) -> bool {
    if address.port() == 25 {
        return true;
    }
    match address.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || octets[..2] == [0xfe, 0x80]
            {
                return true;
            }
            if let Some(ip) = ip.to_ipv4() {
                return blocked_egress(SocketAddr::new(IpAddr::V4(ip), address.port()));
            }
            false
        }
    }
}

async fn handle_agent_data_conn(
    server_addr: String,
    agent_id: String,
    usage: Arc<AtomicU64>,
    request_id: u32,
) -> Result<()> {
    let mut stream = TcpStream::connect(&server_addr).await?;
    configure_tunnel_stream(&stream);
    let mut handshake = vec![0x01];
    handshake.push(agent_id.len() as u8);
    handshake.extend_from_slice(agent_id.as_bytes());
    handshake.extend_from_slice(&request_id.to_be_bytes());
    stream.write_all(&handshake).await?;

    // Agent acts as SOCKS server for the Tunneled connection (No Auth needed internally)
    socks5::handle_client(
        stream, None, None, None, 1, None, None, usage, None, 0, None, None, false,
    )
    .await
}

async fn handle_agent_udp_session(server_addr_str: String, server_udp_port: u16) -> Result<()> {
    let server_tcp_addr: SocketAddr = tokio::net::lookup_host(&server_addr_str)
        .await?
        .next()
        .ok_or(anyhow::anyhow!("Could not resolve {}", server_addr_str))?;

    let server_udp_addr = SocketAddr::new(server_tcp_addr.ip(), server_udp_port);
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let _ = socket.set_nonblocking(true);

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    socket.bind(&bind_addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;

    debug!("Agent UDP bound at {}", socket.local_addr()?);
    socket.send_to(b"GROWBOT_HOLE", server_udp_addr).await?;
    let mut pkts_to_vps = 0u64;
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut last_activity = tokio::time::Instant::now();

    let mut buf = vec![0u8; 65535 + 32];
    loop {
        let received = tokio::select! {
            _ = keepalive.tick() => {
                if last_activity.elapsed() >= AGENT_UDP_IDLE_TIMEOUT {
                    return Ok(());
                }
                let _ = socket.send_to(b"GROWBOT_HOLE", server_udp_addr).await;
                continue;
            }
            received = socket.recv_from(&mut buf[32..]) => received,
        };
        let (read_len, src) = match received {
            Ok(v) => v,
            Err(e) => {
                log::debug!("UDP agent recv error (transient): {}", e);
                tokio::task::yield_now().await;
                continue;
            }
        };
        last_activity = tokio::time::Instant::now();

        if src == server_udp_addr {
            if read_len < 4 {
                continue;
            }
            let addr_type = buf[32 + 3];
            let header_len = match addr_type {
                0x01 => 10,
                0x03 => 4 + 1 + (buf[32 + 4] as usize) + 2,
                _ => 0,
            };

            if header_len == 0 || read_len < header_len {
                continue;
            }

            let target_res = match addr_type {
                0x01 => {
                    let ip =
                        std::net::Ipv4Addr::new(buf[32 + 4], buf[32 + 5], buf[32 + 6], buf[32 + 7]);
                    let port = u16::from_be_bytes([buf[32 + 8], buf[32 + 9]]);
                    Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
                }
                0x03 => {
                    let domain_len = buf[32 + 4] as usize;
                    let domain_str = String::from_utf8_lossy(&buf[32 + 5..32 + 5 + domain_len]);
                    let port = u16::from_be_bytes([
                        buf[32 + 5 + domain_len],
                        buf[32 + 5 + domain_len + 1],
                    ]);
                    let addr_str = format!("{}:{}", domain_str, port);

                    if let Some(entry) = DNS_CACHE.get(&addr_str) {
                        let (addr, instant) = *entry;
                        if instant.elapsed() < DNS_CACHE_TTL {
                            Some(addr)
                        } else {
                            drop(entry);
                            DNS_CACHE.remove(&addr_str);
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            };

            let target_final = if target_res.is_none() && addr_type == 0x03 {
                let domain_len = buf[32 + 4] as usize;
                let addr_str = format!(
                    "{}:{}",
                    String::from_utf8_lossy(&buf[32 + 5..32 + 5 + domain_len]),
                    u16::from_be_bytes([buf[32 + 5 + domain_len], buf[32 + 5 + domain_len + 1]])
                );
                if let Ok(mut addrs) = tokio::net::lookup_host(addr_str.clone()).await {
                    if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                        DNS_CACHE.insert(addr_str, (addr, std::time::Instant::now()));
                        Some(addr)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                target_res
            };

            if let Some(target) = target_final {
                if target.is_ipv4() {
                    let payload = &buf[32 + header_len..32 + read_len];
                    if let Err(e) = socket.send_to(payload, target).await {
                        log::warn!(target: "bind_telemetry", "UDP target send failed: {}", e);
                    }
                }
            }
        } else {
            let h_len = match src {
                SocketAddr::V4(addr) => {
                    let start = 32 - 10;
                    buf[start..start + 3].copy_from_slice(&[0x00, 0x00, 0x00]);
                    buf[start + 3] = 0x01;
                    buf[start + 4..start + 8].copy_from_slice(&addr.ip().octets());
                    buf[start + 8..start + 10].copy_from_slice(&src.port().to_be_bytes());
                    10
                }
                SocketAddr::V6(_) => continue,
            };

            // The complete frame is from (32 - h_len) up to (32 + read_len)
            let frame_start = 32 - h_len;
            let frame_end = 32 + read_len;
            let final_packet = &buf[frame_start..frame_end];

            pkts_to_vps += 1;
            if pkts_to_vps % 100 == 1 {
                log::debug!(target: "bind_telemetry", "UDP Back-fwd to VPS ({} bytes, pkts={})", read_len, pkts_to_vps);
            }
            if let Err(e) = socket.send_to(final_packet, server_udp_addr).await {
                log::warn!(target: "bind_telemetry", "UDP Back-fwd to server failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_port_range_is_inclusive() {
        assert!(!is_socks_port(SOCKS_PORT_MIN - 1));
        assert!(is_socks_port(SOCKS_PORT_MIN));
        assert!(is_socks_port(SOCKS_PORT_MAX));
        assert!(!is_socks_port(SOCKS_PORT_MAX + 1));
    }

    #[test]
    fn api_client_ip_trusts_forwarding_headers_only_from_private_peers() {
        let proxy: IpAddr = "172.18.0.2".parse().unwrap();
        let public: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(api_client_ip(proxy, Some("1.2.3.4"), Some("9.9.9.9, 5.6.7.8")), "1.2.3.4");
        assert_eq!(api_client_ip(proxy, None, Some("9.9.9.9, 5.6.7.8")), "5.6.7.8");
        assert_eq!(api_client_ip(proxy, Some("garbage"), None), "172.18.0.2");
        assert_eq!(api_client_ip(proxy, None, None), "172.18.0.2");
        assert_eq!(api_client_ip(public, Some("1.2.3.4"), Some("5.6.7.8")), "203.0.113.9");
    }

    #[test]
    fn api_bind_defaults_private_and_allows_the_container_proxy() {
        assert_eq!(api_bind_addr(8081, false), "127.0.0.1:8081");
        assert_eq!(api_bind_addr(8081, true), "0.0.0.0:8081");
    }

    #[test]
    fn reconnect_delay_has_bounded_jitter() {
        let base = std::time::Duration::from_secs(4);
        assert_eq!(reconnect_delay(base, 0), base);
        assert!(reconnect_delay(base, u32::MAX) <= base + std::time::Duration::from_secs(1));
    }

    #[test]
    fn disconnect_keeps_only_a_resetting_current_agent() {
        let current: SocketAddr = "192.0.2.10:8080".parse().unwrap();
        let other: SocketAddr = "192.0.2.11:8080".parse().unwrap();
        assert!(preserves_resetting_agent(current, current, true));
        assert!(!preserves_resetting_agent(current, current, false));
        assert!(!preserves_resetting_agent(current, other, true));
    }

    #[test]
    fn v2_egress_filter_blocks_private_ranges_and_smtp() {
        for address in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.1.1:443",
            "100.64.0.1:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "203.0.113.1:25",
        ] {
            assert!(blocked_egress(address.parse().unwrap()), "{address}");
        }
        assert!(!blocked_egress("203.0.113.1:443".parse().unwrap()));
    }

    #[test]
    fn device_status_rejects_invalid_fields() {
        let valid = br#"{"carrier":"carrier","net":"LTE","signal":4,"battery":50,"temp_c":30.0,"charging":false,"health":"good","app":"1.0","proto":2,"assistant":true,"transport":"cellular"}"#;
        assert!(parse_device_status(valid).is_ok());
        assert!(parse_device_status(&valid[..20]).is_err());
        assert!(parse_device_status(br#"{"carrier":"carrier","net":"LTE","signal":5,"battery":50,"temp_c":30.0,"charging":false,"health":"good","app":"1.0","proto":2,"assistant":true,"transport":"cellular"}"#).is_err());
    }
}
