use anyhow::Result;
use log::{info, error, warn};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::net::SocketAddr;
use tokio::sync::mpsc;
use dashmap::DashMap;

use crate::socks5;
use crate::tunnel_common::TunnelCmd;
use crate::security;

const CMD_REQUIRE_CONN: u8 = 0x01;
const CMD_UDP_SESSION: u8 = 0x03;
const CMD_RESET_IP: u8 = 0x04;
const CMD_IP_RESET_SUCCESS: u8 = 0x05;
const CMD_PING: u8 = 0x06;
pub const SOCKS_PORT_MIN: u16 = 51300;
pub const SOCKS_PORT_MAX: u16 = 51399;

pub fn is_socks_port(port: u16) -> bool {
    (SOCKS_PORT_MIN..=SOCKS_PORT_MAX).contains(&port)
}

lazy_static::lazy_static! {
    static ref DNS_CACHE: DashMap<String, (SocketAddr, std::time::Instant)> = DashMap::new();
}
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

pub struct AgentEntry {
    pub control_tx: mpsc::Sender<TunnelCmd>,
    pub addr: SocketAddr,
    pub active_requests: Arc<DashMap<u32, tokio::sync::oneshot::Sender<TcpStream>>>,
    pub usage: Arc<AtomicU64>,
    pub os_type: u8,
    pub ip_reset_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<bool>>>>,
}

pub type AgentRegistry = Arc<DashMap<String, AgentEntry>>;

pub struct BindEntry {
    pub agent_id: String,
    pub port: u16,
    pub usage: Arc<AtomicU64>,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

pub type BindRegistry = Arc<DashMap<u16, BindEntry>>;

pub struct BoundSocksListener {
    listener: TcpListener,
    port: u16,
}

pub async fn run_server(
    control_port: u16, 
    api_port: u16,
    server_pw: Option<String>, 
    api_server_pw: Option<String>,
    registry: AgentRegistry, 
    bind_registry: BindRegistry,
    cumulative_usage: Arc<DashMap<String, u64>>
) -> Result<()> {
    info!("Starting Multi-Agent Tunnel SERVER on port {}", control_port);
    
    let bind_addr = format!("0.0.0.0:{}", control_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("Tunnel Listener active on {}", bind_addr);

    let api_bind = format!("0.0.0.0:{}", api_port);
    if let Ok(api_listener) = TcpListener::bind(&api_bind).await {
        info!("API Listener active on {}", api_bind);
        let registry_for_api = Arc::clone(&registry);
        let bind_registry_for_api = Arc::clone(&bind_registry);
        let api_pw_clone = api_server_pw.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = api_listener.accept().await {
                    let reg_clone = Arc::clone(&registry_for_api);
                    let breg_clone = Arc::clone(&bind_registry_for_api);
                    let pw_clone = api_pw_clone.clone();
                    tokio::spawn(async move {
                        handle_api_connection(stream, reg_clone, breg_clone, pw_clone, control_port).await;
                    });
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
                let server_pw_clone = server_pw.clone();
                
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    let mut type_buf = [0u8; 1];
                    if stream.read_exact(&mut type_buf).await.is_err() { return; }

                    match type_buf[0] {
                        0x00 => {
                            if let Err(e) = handle_control_connection(stream, addr, server_pw_clone, registry_clone, usage_clone).await {
                                error!("Control Connection Error [{}]: {}", addr, e);
                            }
                        }
                        0x01 => {
                            if let Err(e) = handle_data_connection(stream, addr, registry_clone).await {
                                error!("Data Connection Error [{}]: {}", addr, e);
                            }
                        }
                        _ => warn!("Unknown connection type from {}", addr),
                    }
                });
            }
            Err(e) => error!("Server accept error: {}", e),
        }
    }
}

async fn handle_control_connection(
    mut stream: TcpStream, 
    addr: SocketAddr, 
    server_pw: Option<String>, 
    registry: AgentRegistry,
    cumulative_usage: Arc<DashMap<String, u64>>
) -> Result<()> {
    let mut len_buf = [0u8; 1];
    
    stream.read_exact(&mut len_buf).await?;
    let id_len = len_buf[0] as usize;
    let mut id_buf = vec![0u8; id_len];
    stream.read_exact(&mut id_buf).await?;
    let agent_id = String::from_utf8(id_buf)?;
    stream.read_exact(&mut len_buf).await?;
    let pw_len = len_buf[0] as usize;
    let mut pw_buf = vec![0u8; pw_len];
    stream.read_exact(&mut pw_buf).await?;
    let captured_pw = String::from_utf8_lossy(&pw_buf);

    let expected_pw = server_pw.as_deref().unwrap_or("");
    if server_pw.is_some() && captured_pw != expected_pw {
        warn!("Agent Auth failed for '{}' from {}: invalid password", agent_id, addr);
        security::report_failure(&addr.ip().to_string());
        return Ok(());
    }
    security::report_success(&addr.ip().to_string());
    let mut os_buf = [0u8; 1];
    let os_type = match tokio::time::timeout(std::time::Duration::from_millis(500), stream.read_exact(&mut os_buf)).await {
        Ok(Ok(_)) => os_buf[0],
        _ => 0, // 0 = PC
    };

    info!("Agent '{}' connected from {} (OS: {})", agent_id, addr, os_type);

    let (control_tx, mut control_rx) = mpsc::channel::<TunnelCmd>(100);
    let active_requests = Arc::new(DashMap::new());
    let initial_usage = cumulative_usage.get(&agent_id).map(|v| *v).unwrap_or(0);
    let usage = Arc::new(AtomicU64::new(initial_usage));
    let ip_reset_tx = Arc::new(tokio::sync::Mutex::new(None));
    registry.insert(agent_id.clone(), AgentEntry {
        control_tx,
        active_requests: Arc::clone(&active_requests),
        addr,
        usage: Arc::clone(&usage),
        os_type,
        ip_reset_tx: Arc::clone(&ip_reset_tx),
    });

    let mut control_stream = stream;
    let _ = control_stream.set_nodelay(true);
    let id_for_cleanup = agent_id.clone();
    let registry_for_cleanup = Arc::clone(&registry);

    let mut monitor_buf = [0u8; 1];
    let mut server_ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(20));
    let mut last_activity = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = server_ping_interval.tick() => {
                if last_activity.elapsed() > tokio::time::Duration::from_secs(90) {
                    warn!("Agent '{}' timed out on server (No ping for 90s). Dropping.", agent_id);
                    break;
                }
            }
            cmd_opt = control_rx.recv() => {
                match cmd_opt {
                    Some(cmd) => {
                        let buf = match cmd {
                            TunnelCmd::RequireConn(id) => {
                                let mut b = vec![CMD_REQUIRE_CONN];
                                b.extend_from_slice(&id.to_be_bytes());
                                b
                            }
                            TunnelCmd::UdpSession(port) => {
                                let mut b = vec![CMD_UDP_SESSION];
                                b.extend_from_slice(&port.to_be_bytes());
                                b
                            }
                            TunnelCmd::ResetIp => {
                                vec![CMD_RESET_IP]
                            }
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
                        if cmd == CMD_IP_RESET_SUCCESS {
                            let mut lock = ip_reset_tx.lock().await;
                            if let Some(tx) = lock.take() {
                                let _ = tx.send(true);
                            }
                        } else if cmd == CMD_PING {
                            let _ = control_stream.write_all(&[CMD_PING]).await;
                        } else {
                            warn!("Unknown command from agent: {}", cmd);
                        }
                    }
                    _ => {
                        info!("Agent '{}' disconnected", agent_id);
                        break;
                    }
                }
            }
        }
    }

    info!("Agent '{}' disconnected, removing from registry", agent_id);
    registry_for_cleanup.remove_if(&id_for_cleanup, |_, entry| entry.addr == addr);
    Ok(())
}

async fn handle_api_connection(mut stream: TcpStream, registry: AgentRegistry, bind_registry: BindRegistry, server_pw: Option<String>, control_port: u16) {
    let mut buf = vec![0u8; 8192];
    if let Ok(n) = stream.read(&mut buf).await {
        if n == 0 { return; }
        let request_str = String::from_utf8_lossy(&buf[..n]);
        
        // Split header and body
        let mut header_body = request_str.splitn(2, "\r\n\r\n");
        let header_str = header_body.next().unwrap_or("");
        let body_str = header_body.next().unwrap_or("").trim_matches(char::from(0));

        let mut lines = header_str.lines();
        let request_line = lines.next().unwrap_or("");
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 { return; }
        
        let method = parts[0];
        let path = parts[1];

        // Parse Headers
        let mut host = String::new();
        let mut x_pw = String::new();
        for line in lines {
            let l_lower = line.to_lowercase();
            if l_lower.starts_with("host:") {
                host = line[5..].trim().to_string();
                if let Some(idx) = host.find(':') { host = host[..idx].to_string(); }
            } else if l_lower.starts_with("x-server-password:") {
                x_pw = line[18..].trim().to_string();
            }
        }

        let expected_pw = server_pw.clone().unwrap_or_default();
        let mut is_authed = expected_pw.is_empty() || x_pw == expected_pw;

        // Path Validation
        let (base_path, query) = if let Some(idx) = path.find('?') {
            (&path[..idx], &path[idx + 1..])
        } else {
            (path, "")
        };

        // Query auth fallback
        for pair in query.split('&') {
            let mut kv = pair.split('=');
            if let (Some("pwd"), Some(val)) = (kv.next(), kv.next()) {
                if !expected_pw.is_empty() && val == expected_pw {
                    is_authed = true;
                }
            }
        }

        if base_path == "/" || base_path == "/index.html" {
            let html = include_str!("web_ui.html");
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", html.len(), html);
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }

        if base_path.starts_with("/api/") && !is_authed {
            let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Unauthorized\"}";
            let _ = stream.write_all(resp.as_bytes()).await;
            return;
        }

        if base_path == "/qr" {
            if !is_authed {
                let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nUnauthorized";
                let _ = stream.write_all(resp.as_bytes()).await;
                return;
            }
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
                "pwd": expected_pw
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

        if base_path.ends_with("?reset_ip") || query == "reset_ip" || query.starts_with("reset_ip&") {
            if !expected_pw.is_empty() && !is_authed {
                let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Unauthorized\"}";
                let _ = stream.write_all(resp.as_bytes()).await;
                return;
            }
            let agent_id = base_path.trim_start_matches('/');
            if let Some(agent) = registry.get(agent_id) {
                if agent.os_type != 1 {
                    let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Agent is not Android\"}";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }
                let (tx, _rx) = tokio::sync::oneshot::channel();
                {
                    let mut lock = agent.ip_reset_tx.lock().await;
                    *lock = Some(tx);
                }
                if agent.control_tx.send(TunnelCmd::ResetIp).await.is_ok() {
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"reset_command_sent\"}";
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    let resp = "HTTP/1.1 500 Error\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Failed to command agent\"}";
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            } else {
                let resp = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Agent not found\"}";
                let _ = stream.write_all(resp.as_bytes()).await;
            }
            return;
        }

        if base_path == "/api/state" {
            let mut agents_arr = Vec::new();
            for entry in registry.iter() {
                let usage_mb = entry.value().usage.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0;
                agents_arr.push(serde_json::json!({
                    "id": entry.key(),
                    "addr": entry.value().addr.to_string(),
                    "usage_mb": format!("{:.2}", usage_mb),
                    "os": if entry.value().os_type == 1 { "Android" } else { "PC" }
                }));
            }
            let mut binds_arr = Vec::new();
            for entry in bind_registry.iter() {
                let usage_mb = entry.value().usage.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0;
                binds_arr.push(serde_json::json!({
                    "port": entry.key(),
                    "agent_id": entry.value().agent_id,
                    "user": entry.value().user.clone().unwrap_or_default(),
                    "pass": entry.value().pass.clone().unwrap_or_default(),
                    "usage_mb": format!("{:.2}", usage_mb)
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
                if let (Some(id), Some(port)) = (
                    json["agent_id"].as_str(),
                    json["port"].as_u64().and_then(|port| u16::try_from(port).ok()),
                ) {
                    let socks_user = json["user"].as_str().filter(|s| !s.is_empty()).map(String::from);
                    let socks_pass = json["pass"].as_str().filter(|s| !s.is_empty()).map(String::from);

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
                    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
                    let usage = Arc::new(std::sync::atomic::AtomicU64::new(0));

                    bind_registry.insert(port, crate::tunnel::BindEntry {
                        agent_id: id.to_string(),
                        port,
                        usage: Arc::clone(&usage),
                        user: socks_user.clone(),
                        pass: socks_pass.clone(),
                        shutdown_tx: Some(shutdown_tx),
                    });

                    let reg = Arc::clone(&registry);
                    let b_reg = Arc::clone(&bind_registry);
                    let id_clone = id.to_string();
                    
                    tokio::spawn(async move {
                        if let Err(e) = crate::tunnel::run_socks_listener(socks_listener, id_clone, reg, b_reg, socks_user, socks_pass, shutdown_rx).await {
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
                            let _ = tx.send(());
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

        let resp = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Not Found\"}";
        let _ = stream.write_all(resp.as_bytes()).await;
    }
}

async fn handle_data_connection(mut stream: TcpStream, addr: SocketAddr, registry: AgentRegistry) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let mut len_buf = [0u8; 1];
    stream.read_exact(&mut len_buf).await?;
    let id_len = len_buf[0] as usize;
    let mut id_buf = vec![0u8; id_len];
    stream.read_exact(&mut id_buf).await?;
    let agent_id = String::from_utf8(id_buf)?;

    let active_requests = if let Some(agent) = registry.get(&agent_id) {
        Some(Arc::clone(&agent.active_requests))
    } else {
        None
    };

    if let Some(active_requests) = active_requests {
        let mut id_buf = [0u8; 4];
        if stream.read_exact(&mut id_buf).await.is_err() { return Ok(()); }
        let request_id = u32::from_be_bytes(id_buf);
        
        if let Some((_, tx)) = active_requests.remove(&request_id) {
            let _ = tx.send(stream);
        } else {
            warn!("Data connection for unknown/expired request {} from agent '{}'", request_id, agent_id);
        }
        Ok(())
    } else {
        warn!("Data connection for unknown agent '{}' from {}", agent_id, addr);
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
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
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

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!("SOCKS5 Listener on port {} shutdown requested by user", socks_port);
                break;
            }
            accept_res = socks_listener.accept() => {
                match accept_res {
                    Ok((mut client_stream, addr)) => {
                        let agent_info = if let Some(agent) = registry.get(&agent_id) {
                            Some((
                                agent.control_tx.clone(),
                                Arc::clone(&agent.active_requests),
                                Arc::clone(&agent.usage),
                            ))
                        } else {
                            None
                        };

                        if let Some((signal_tx, agent_active_requests, agent_usage)) = agent_info {
                            info!("SOCKS Client connected to '{}' from {}", agent_id, addr);
                            let bind_usage_clone = Arc::clone(&bind_usage);
                            let s_user = socks_user.clone();
                            let s_pass = socks_pass.clone();
                            
                            tokio::spawn(async move {
                                let _ = client_stream.set_nodelay(true);
                                if let Err(e) = socks5::handle_client(client_stream, Some(signal_tx), Some(agent_active_requests), s_user, s_pass, agent_usage, Some(bind_usage_clone), socks_port).await {
                                    error!("SOCKS Client Error [{}]: {}", addr, e);
                                }
                            });
                        } else {
                            warn!("Agent '{}' is currently offline. Rejecting SOCKS client from {}", agent_id, addr);
                            tokio::spawn(async move {
                                let _ = client_stream.set_nodelay(true);
                                // Write SOCKS5 Host Unreachable error (0x04)
                                let _ = client_stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                            });
                        }
                    }
                    Err(e) => error!("SOCKS accept error: {}", e),
                }
            }
        }
    }
    
    bind_registry.remove(&socks_port);
    Ok(())
}

pub async fn run_agent(mut server_addr: String, agent_id: String, server_pw: Option<String>, mut shutdown_rx: Option<tokio::sync::mpsc::Receiver<()>>) -> Result<()> {
    server_addr = server_addr.replace("http://", "").replace("https://", "");
    if server_addr.ends_with('/') {
        server_addr.pop();
    }
    if !server_addr.contains(':') {
        server_addr.push_str(":8080");
    }

    info!("Connecting to control server at {}", server_addr);
    let cache_path = "agent_cache.json";
    let cache_mgr = crate::cache::CacheManager::new(cache_path);
    let mut agent_cache = cache_mgr.load_agent().unwrap_or_default();
    
    if agent_cache.agent_id.is_empty() {
        agent_cache.agent_id = agent_id.clone();
    }
    
    info!("Starting Tunnel AGENT '{}' (Cumulative Usage: {} MB) connecting to {}", 
        agent_cache.agent_id, agent_cache.cumulative_usage / 1024 / 1024, server_addr);

    let global_agent_usage = Arc::new(AtomicU64::new(agent_cache.cumulative_usage));
    let usage_for_sync = Arc::clone(&global_agent_usage);
    let id_for_sync = agent_cache.agent_id.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let current_usage = usage_for_sync.load(Ordering::Relaxed);
            let update = crate::cache::AgentCache {
                agent_id: id_for_sync.clone(),
                cumulative_usage: current_usage,
            };
            let _ = crate::cache::CacheManager::new("agent_cache.json").save_agent(&update);
        }
    });

    
    let connect_future = TcpStream::connect(&server_addr);
    let mut control_stream = match tokio::time::timeout(tokio::time::Duration::from_secs(15), connect_future).await {
        Ok(Ok(s)) => s,
        _ => return Err(anyhow::anyhow!("Connection timeout to {}", server_addr)),
    };
    control_stream.set_nodelay(true)?;
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
    
    let _ = control_stream.set_nodelay(true);
    control_stream.write_all(&handshake).await?;
    let (ip_reset_resp_tx, mut ip_reset_resp_rx) = mpsc::channel::<()>(5);

    let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
    let mut last_pong = tokio::time::Instant::now();

    loop {
        let mut buf = [0u8; 1];
        tokio::select! {
            _ = ping_interval.tick() => {
                if last_pong.elapsed() > tokio::time::Duration::from_secs(45) {
                    error!("Connection deemed dead (Ping Timeout). Dropping...");
                    return Ok(());
                }
                if tokio::time::timeout(tokio::time::Duration::from_secs(5), control_stream.write_all(&[CMD_PING])).await.is_err() {
                    error!("Failed to write keepalive ping. Dropping...");
                    return Ok(());
                }
            }
            Some(_) = ip_reset_resp_rx.recv() => {
                let _ = control_stream.write_all(&[CMD_IP_RESET_SUCCESS]).await;
            }
            _ = async {
                if let Some(ref mut rx) = shutdown_rx {
                    // Wait for the channel to yield a value (Some) or be closed (None)
                    let _ = rx.recv().await;
                    info!("Agent shutdown signal received (or channel closed)");
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                return Ok(());
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
                                if let Ok(_) = control_stream.read_exact(&mut id_buf).await {
                                    let req_id = u32::from_be_bytes(id_buf);
                                    let server_addr_clone = server_addr.clone();
                                    let id_clone = agent_id.clone();
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
                                if let Ok(_) = control_stream.read_exact(&mut port_buf).await {
                                    let port = u16::from_be_bytes(port_buf);
                                    info!("Server requested UDP Session on port {}", port);
                                    let server_addr_clone = server_addr.clone();
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
                                info!("Server requested IP Reset (Flight Mode)");
                                #[cfg(target_os = "android")]
                                {
                                    let tx = ip_reset_resp_tx.clone();
                                    tokio::spawn(async move {
                                        let _ = tokio::task::spawn_blocking(move || {
                                            crate::trigger_flight_mode_reset();
                                        }).await;
                                        let _ = tx.send(()).await;
                                    });
                                }
                                #[cfg(not(target_os = "android"))]
                                {
                                    let _ = ip_reset_resp_tx.send(()).await;
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
    
    Ok(())
}

async fn handle_agent_data_conn(server_addr: String, agent_id: String, usage: Arc<AtomicU64>, request_id: u32) -> Result<()> {
    let mut stream = TcpStream::connect(&server_addr).await?;
    let _ = stream.set_nodelay(true);
    let mut handshake = vec![0x01];
    handshake.push(agent_id.len() as u8);
    handshake.extend_from_slice(agent_id.as_bytes());
    handshake.extend_from_slice(&request_id.to_be_bytes());
    stream.write_all(&handshake).await?; 
    
    // Agent acts as SOCKS server for the Tunneled connection (No Auth needed internally)
    socks5::handle_client(stream, None, None, None, None, usage, None, 0).await
}

async fn handle_agent_udp_session(server_addr_str: String, server_udp_port: u16) -> Result<()> {
    let server_tcp_addr: SocketAddr = tokio::net::lookup_host(&server_addr_str).await?
        .next().ok_or(anyhow::anyhow!("Could not resolve {}", server_addr_str))?;
        
    let server_udp_addr = SocketAddr::new(server_tcp_addr.ip(), server_udp_port);
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let _ = socket.set_nonblocking(true);
    
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    socket.bind(&bind_addr.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;
    
    info!("Agent UDP bound at {}", socket.local_addr()?);
    socket.send_to(b"GROWBOT_HOLE", server_udp_addr).await?;
    let mut pkts_to_vps = 0u64;
    
    let mut buf = vec![0u8; 65535 + 32];
    loop {
        let (read_len, src) = match socket.recv_from(&mut buf[32..]).await {
            Ok(v) => v,
            Err(e) => {
                log::debug!("UDP agent recv error (transient): {}", e);
                tokio::task::yield_now().await;
                continue;
            }
        };
        
        if src == server_udp_addr {
            if read_len < 4 { continue; }
            let addr_type = buf[32 + 3];
            let header_len = match addr_type {
                0x01 => 10,
                0x03 => 4 + 1 + (buf[32 + 4] as usize) + 2,
                _ => 0,
            };
            
            if header_len == 0 || read_len < header_len { continue; }

            let target_res = match addr_type {
                0x01 => {
                    let ip = std::net::Ipv4Addr::new(buf[32 + 4], buf[32 + 5], buf[32 + 6], buf[32 + 7]);
                    let port = u16::from_be_bytes([buf[32 + 8], buf[32 + 9]]);
                    Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
                }
                0x03 => {
                    let domain_len = buf[32 + 4] as usize;
                    let domain_str = String::from_utf8_lossy(&buf[32 + 5 .. 32 + 5 + domain_len]);
                    let port = u16::from_be_bytes([buf[32 + 5 + domain_len], buf[32 + 5 + domain_len + 1]]);
                    let addr_str = format!("{}:{}", domain_str, port);
                    
                    if let Some(entry) = DNS_CACHE.get(&addr_str) {
                        let (addr, instant) = *entry;
                        if instant.elapsed() < DNS_CACHE_TTL { Some(addr) } else { drop(entry); DNS_CACHE.remove(&addr_str); None }
                    } else { None }
                }
                _ => None,
            };
            
            let target_final = if target_res.is_none() && addr_type == 0x03 {
                let domain_len = buf[32 + 4] as usize;
                let addr_str = format!("{}:{}", String::from_utf8_lossy(&buf[32 + 5 .. 32 + 5 + domain_len]), u16::from_be_bytes([buf[32 + 5 + domain_len], buf[32 + 5 + domain_len + 1]]));
                if let Ok(mut addrs) = tokio::net::lookup_host(addr_str.clone()).await {
                    if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                        DNS_CACHE.insert(addr_str, (addr, std::time::Instant::now()));
                        Some(addr)
                    } else { None }
                } else { None }
            } else { target_res };
            
            if let Some(target) = target_final {
                if target.is_ipv4() {
                    let payload = &buf[32 + header_len .. 32 + read_len];
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
                    buf[start + 4 .. start + 8].copy_from_slice(&addr.ip().octets());
                    buf[start + 8 .. start + 10].copy_from_slice(&src.port().to_be_bytes());
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
                log::info!(target: "bind_telemetry", "UDP Back-fwd to VPS ({} bytes, pkts={})", read_len, pkts_to_vps);
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
}
