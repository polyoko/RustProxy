use anyhow::{anyhow, Context, Result};
use log::{debug, error, warn};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::security;
use crate::tunnel::{SOCKS_PORT_MAX, SOCKS_PORT_MIN};
use crate::tunnel_common::{
    AgentRequestRegistry, BandwidthTrackedStream, OpenRequestRegistry, TunnelCmd, TunnelSignalTx,
};
use crate::udp::handle_udp_associate;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;
use tokio::time::{timeout, Duration};

static NEXT_UDP_PORT: AtomicU32 = AtomicU32::new(0);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

fn is_tunneled_udp_client(client_ip: IpAddr, source: SocketAddr) -> bool {
    source.ip() == client_ip
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_client(
    mut stream: TcpStream,
    signal_tx: Option<TunnelSignalTx>,
    data_rx: Option<AgentRequestRegistry>,
    open_rx: Option<OpenRequestRegistry>,
    protocol_version: u8,
    socks_user: Option<String>,
    socks_pw: Option<String>,
    agent_usage: Arc<AtomicU64>,
    bind_usage: Option<Arc<AtomicU64>>,
    socks_port: u16,
    timing_agent: Option<String>,
    resetting: Option<Arc<AtomicBool>>,
    limit_reached: bool,
) -> Result<()> {
    let peer = stream.peer_addr().ok();
    if let Some(p) = peer {
        let ip_str = p.ip().to_string();
        if security::is_blacklisted(&ip_str) {
            warn!("Blocked blacklisted IP: {}", ip_str);
            return Ok(());
        }
    }

    debug!("Starting SOCKS5 Handshake for {:?}", peer);
    let _ = stream.set_nodelay(true);

    if let Err(e) = timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut stream, socks_user.as_deref(), socks_pw.as_deref()),
    )
    .await
    .map_err(|_| anyhow!("SOCKS handshake timed out"))?
    {
        // Only wrong credentials count toward the ban; disconnects/protocol errors (scanners, health checks) don't.
        if e.to_string() == "Invalid SOCKS credentials" {
            if let Some(p) = peer {
                security::report_failure(&p.ip().to_string());
            }
        }
        return Err(e);
    }

    if let Some(p) = peer {
        security::report_success(&p.ip().to_string());
    }

    debug!(
        "Handshake & Auth success for {:?}, waiting for request",
        peer
    );

    let (cmd, addr) = read_request(&mut stream)
        .await
        .context("Read request failed")?;

    debug!("Request: cmd={}, addr={}", cmd, addr);

    if limit_reached {
        write_reply(
            &mut stream,
            0x02,
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        return Ok(());
    }

    match cmd {
        CMD_CONNECT => {
            handle_connect(
                &mut stream,
                addr,
                signal_tx,
                data_rx,
                open_rx,
                protocol_version,
                agent_usage,
                bind_usage,
                socks_port,
                timing_agent.as_deref(),
                resetting.as_deref(),
            )
            .await
        }
        CMD_UDP_ASSOCIATE => {
            handle_udp_associate_request(
                &mut stream,
                addr,
                signal_tx,
                agent_usage,
                bind_usage,
                socks_port,
            )
            .await
        }
        _ => {
            error!("Unsupported command: {}", cmd);
            write_reply(
                &mut stream,
                0x07,
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            )
            .await?;
            Ok(())
        }
    }
}

async fn handshake(
    stream: &mut TcpStream,
    expected_user: Option<&str>,
    expected_pw: Option<&str>,
) -> Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf[0] != SOCKS_VERSION {
        return Err(anyhow!("Unsupported SOCKS version: {}", buf[0]));
    }

    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    if let (Some(u), Some(p)) = (expected_user, expected_pw) {
        // Must use Password Auth
        if methods.contains(&0x02) {
            stream.write_all(&[SOCKS_VERSION, 0x02]).await?;
            let mut sub_buf = [0u8; 2];
            stream.read_exact(&mut sub_buf).await?;
            if sub_buf[0] != 0x01 {
                return Err(anyhow!("Invalid SOCKS Auth sub-negotiation version"));
            }
            let ulen = sub_buf[1] as usize;
            let mut user_buf = vec![0u8; ulen];
            stream.read_exact(&mut user_buf).await?;
            let captured_user = String::from_utf8_lossy(&user_buf);

            let mut plen_buf = [0u8; 1];
            stream.read_exact(&mut plen_buf).await?;
            let plen = plen_buf[0] as usize;
            let mut pass_buf = vec![0u8; plen];
            stream.read_exact(&mut pass_buf).await?;
            let captured_pass = String::from_utf8_lossy(&pass_buf);

            if captured_user == u && captured_pass == p {
                stream.write_all(&[0x01, 0x00]).await?; // Success
                Ok(())
            } else {
                stream.write_all(&[0x01, 0x01]).await?; // Failure
                Err(anyhow!("Invalid SOCKS credentials"))
            }
        } else {
            stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            Err(anyhow!("Client does not support password auth"))
        }
    } else if methods.contains(&0x00) {
        stream.write_all(&[SOCKS_VERSION, 0x00]).await?;
        Ok(())
    } else {
        stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        Err(anyhow!("Client requires auth but server has none"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connect(
    stream: &mut TcpStream,
    target_addr: String,
    signal_tx: Option<TunnelSignalTx>,
    data_rx: Option<AgentRequestRegistry>,
    open_rx: Option<OpenRequestRegistry>,
    protocol_version: u8,
    agent_usage: Arc<AtomicU64>,
    bind_usage: Option<Arc<AtomicU64>>,
    socks_port: u16,
    timing_agent: Option<&str>,
    resetting: Option<&AtomicBool>,
) -> Result<()> {
    match open_target(
        &target_addr,
        signal_tx,
        data_rx,
        open_rx,
        protocol_version,
        socks_port,
        timing_agent,
        resetting,
    )
    .await
    {
        Ok(target_stream) => {
            let local_addr = target_stream
                .local_addr()
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
            write_reply(stream, 0x00, &local_addr).await?;

            let mut target_stream = BandwidthTrackedStream {
                inner: target_stream,
                counter: agent_usage,
                secondary_counter: bind_usage,
            };
            if let Err(e) = tokio::io::copy_bidirectional(stream, &mut target_stream).await {
                error!("Relay error: {}", e);
            }

            debug!("Connection to {} finished", target_addr);
            Ok(())
        }
        Err(e) => {
            error!("Failed to connect to {}: {}", target_addr, e);
            write_reply(
                stream,
                0x04,
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            )
            .await?;
            Err(anyhow!(e.to_string()))
        }
    }
}

#[derive(Debug)]
pub enum ConnectError {
    AgentUnavailable(anyhow::Error),
    Target(anyhow::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentUnavailable(error) | Self::Target(error) => error.fmt(f),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn open_target(
    target_addr: &str,
    signal_tx: Option<TunnelSignalTx>,
    data_rx: Option<AgentRequestRegistry>,
    open_rx: Option<OpenRequestRegistry>,
    protocol_version: u8,
    socks_port: u16,
    timing_agent: Option<&str>,
    resetting: Option<&AtomicBool>,
) -> std::result::Result<TcpStream, ConnectError> {
    let log_target = format!("bind:{}", socks_port);
    debug!(target: &log_target, "Connect request for {}", target_addr);
    let started = Instant::now();
    let mut data_conn_ms = 0;
    let mut greeting_rtt_ms = 0;
    let mut connect_reply_ms = 0;

    let stream = async {
        if protocol_version == 2 {
            let (Some(tx), Some(registry)) = (signal_tx, open_rx) else {
                return Err(ConnectError::AgentUnavailable(anyhow!("Agent is offline")));
            };
            if resetting.is_some_and(|resetting| resetting.load(Ordering::SeqCst)) {
                return Err(ConnectError::AgentUnavailable(anyhow!(
                    "Agent is resetting"
                )));
            }
            let (wait_tx, wait_rx) = tokio::sync::oneshot::channel();
            let token = reserve_open_token(&registry).map_err(ConnectError::AgentUnavailable)?;
            registry.insert(token, wait_tx);
            let target = encode_target_address(target_addr).map_err(ConnectError::Target)?;
            if let Err(error) = tx.send(TunnelCmd::Open { token, target }).await {
                registry.remove(&token);
                return Err(ConnectError::AgentUnavailable(error.into()));
            }
            match timeout(Duration::from_secs(10), wait_rx).await {
                Ok(Ok(Ok(stream))) => {
                    data_conn_ms = started.elapsed().as_millis();
                    Ok(stream)
                }
                Ok(Ok(Err(_))) => {
                    registry.remove(&token);
                    return Err(ConnectError::Target(anyhow!(
                        "Agent could not reach target"
                    )));
                }
                Ok(Err(_)) => {
                    registry.remove(&token);
                    return Err(ConnectError::AgentUnavailable(anyhow!(
                        "Agent data channel dropped"
                    )));
                }
                Err(_) => {
                    registry.remove(&token);
                    return Err(ConnectError::AgentUnavailable(anyhow!(
                        "Timeout waiting for agent data connection"
                    )));
                }
            }
        } else if let (Some(tx), Some(registry)) = (signal_tx, data_rx) {
            if resetting.is_some_and(|resetting| resetting.load(Ordering::SeqCst)) {
                return Err(ConnectError::AgentUnavailable(anyhow!(
                    "Agent is resetting"
                )));
            }
            let (wait_tx, wait_rx) = tokio::sync::oneshot::channel::<TcpStream>();
            let request_id =
                reserve_request_id(&registry, wait_tx).map_err(ConnectError::AgentUnavailable)?;

            if resetting.is_some_and(|resetting| resetting.load(Ordering::SeqCst)) {
                registry.remove(&request_id);
                return Err(ConnectError::AgentUnavailable(anyhow!(
                    "Agent is resetting"
                )));
            }

            debug!(
                "Requesting Tunnel Connection for {} (id={})",
                target_addr, request_id
            );
            if let Err(error) = tx.send(TunnelCmd::RequireConn(request_id)).await {
                registry.remove(&request_id);
                return Err(ConnectError::AgentUnavailable(error.into()));
            }

            let mut agent_stream = match timeout(Duration::from_secs(10), wait_rx).await {
                Ok(Ok(stream)) => {
                    data_conn_ms = started.elapsed().as_millis();
                    stream
                }
                Ok(Err(_)) => {
                    registry.remove(&request_id);
                    return Err(ConnectError::AgentUnavailable(anyhow!(
                        "Agent data channel dropped for request {}",
                        request_id
                    )));
                }
                Err(_) => {
                    registry.remove(&request_id);
                    data_conn_ms = started.elapsed().as_millis();
                    return Err(ConnectError::AgentUnavailable(anyhow!(
                        "Timeout waiting for agent data connection for request {}",
                        request_id
                    )));
                }
            };

            let greeting_started = Instant::now();
            let mut request = vec![SOCKS_VERSION, 0x01, 0x00];
            request.extend(build_connect_packet(target_addr).map_err(ConnectError::Target)?);
            agent_stream
                .write_all(&request)
                .await
                .map_err(|error| ConnectError::AgentUnavailable(error.into()))?;
            let mut buf = [0u8; 2];
            agent_stream
                .read_exact(&mut buf)
                .await
                .map_err(|error| ConnectError::AgentUnavailable(error.into()))?;
            greeting_rtt_ms = greeting_started.elapsed().as_millis();
            if buf != [SOCKS_VERSION, 0x00] {
                return Err(ConnectError::AgentUnavailable(anyhow!(
                    "Agent refused handshake: {:?}",
                    buf
                )));
            }

            let connect_started = Instant::now();
            let (rep, _) = read_packet(&mut agent_stream)
                .await
                .map_err(ConnectError::AgentUnavailable)?;
            connect_reply_ms = connect_started.elapsed().as_millis();
            if rep != 0x00 {
                return Err(ConnectError::Target(anyhow!(
                    "Agent reported error connecting to target: {}",
                    rep
                )));
            }
            agent_stream
                .set_nodelay(true)
                .map_err(|error| ConnectError::AgentUnavailable(error.into()))?;
            Ok(agent_stream)
        } else if timing_agent.is_some() {
            Err(ConnectError::AgentUnavailable(anyhow!("Agent is offline")))
        } else {
            let stream = TcpStream::connect(target_addr)
                .await
                .context("Failed to connect to target")
                .map_err(ConnectError::Target)?;
            stream
                .set_nodelay(true)
                .map_err(|error| ConnectError::Target(error.into()))?;
            Ok(stream)
        }
    }
    .await;

    let result = match &stream {
        Ok(_) => "ok",
        Err(ConnectError::AgentUnavailable(_)) => "agent_offline",
        Err(ConnectError::Target(_)) => "error",
    };
    log_connect_timing(
        timing_agent,
        socks_port,
        target_addr,
        data_conn_ms,
        greeting_rtt_ms,
        connect_reply_ms,
        started.elapsed().as_millis(),
        result,
    );
    stream
}

fn reserve_request_id(
    registry: &AgentRequestRegistry,
    sender: tokio::sync::oneshot::Sender<TcpStream>,
) -> Result<u32> {
    for _ in 0..32 {
        let token = crate::session::random_token()?;
        let request_id = u32::from_str_radix(&token[..8], 16)?;
        if let dashmap::mapref::entry::Entry::Vacant(entry) = registry.entry(request_id) {
            entry.insert(sender);
            return Ok(request_id);
        }
    }
    Err(anyhow!("Could not reserve a tunnel request ID"))
}

fn reserve_open_token(registry: &OpenRequestRegistry) -> Result<[u8; 16]> {
    for _ in 0..32 {
        let token = crate::session::random_token()?;
        let mut value = [0; 16];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&token[index * 2..index * 2 + 2], 16)?;
        }
        if !registry.contains_key(&value) {
            return Ok(value);
        }
    }
    Err(anyhow!("Could not reserve a tunnel token"))
}

#[allow(clippy::too_many_arguments)]
fn log_connect_timing(
    agent: Option<&str>,
    port: u16,
    target: &str,
    data_conn_ms: u128,
    greeting_rtt_ms: u128,
    connect_reply_ms: u128,
    total_ms: u128,
    result: &str,
) {
    let Some(agent) = agent else { return };
    debug!(target: "timing", "{}", timing_line(agent, port, target, data_conn_ms, greeting_rtt_ms, connect_reply_ms, total_ms, result));
}

#[allow(clippy::too_many_arguments)]
fn timing_line(
    agent: &str,
    port: u16,
    target: &str,
    data_conn_ms: u128,
    greeting_rtt_ms: u128,
    connect_reply_ms: u128,
    total_ms: u128,
    result: &str,
) -> String {
    let clean = |value: &str| value.replace(['\r', '\n'], "");
    format!(
        "timing agent={} port={} target={} data_conn_ms={} greeting_rtt_ms={} connect_reply_ms={} total_ms={} result={}",
        clean(agent), port, clean(target), data_conn_ms, greeting_rtt_ms, connect_reply_ms, total_ms, result,
    )
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::{is_tunneled_udp_client, timing_line};

    #[test]
    fn timing_line_keeps_the_parser_contract_on_one_line() {
        assert_eq!(
            timing_line("phone\n1", 51314, "example.com:443\r", 200, 50, 75, 330, "timeout"),
            "timing agent=phone1 port=51314 target=example.com:443 data_conn_ms=200 greeting_rtt_ms=50 connect_reply_ms=75 total_ms=330 result=timeout",
        );
    }

    #[test]
    fn tunneled_udp_only_accepts_the_tcp_client_ip() {
        let client_ip = "192.0.2.10".parse().unwrap();
        assert!(is_tunneled_udp_client(
            client_ip,
            "192.0.2.10:60000".parse().unwrap()
        ));
        assert!(!is_tunneled_udp_client(
            client_ip,
            "192.0.2.11:60000".parse().unwrap()
        ));
    }
}

// Reuse read_request logic for generic packet reading (Request or Reply)
async fn read_packet(stream: &mut TcpStream) -> Result<(u8, String)> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;

    if buf[0] != SOCKS_VERSION {
        return Err(anyhow!("Invalid SOCKS version in packet"));
    }

    let cmd_or_rep = buf[1];
    let atyp = buf[3];

    let addr = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            ip.to_string()
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf)?
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        _ => return Err(anyhow!("Unsupported address type: {}", atyp)),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    let target = if atyp == ATYP_IPV6 {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    };
    Ok((cmd_or_rep, target))
}

// Helper to separate read_request which logs specific things?
// No, we can just replace `read_request` with `read_packet` usage or call it.
async fn read_request(stream: &mut TcpStream) -> Result<(u8, String)> {
    read_packet(stream).await
}

pub fn validate_target(addr_str: &str) -> Result<()> {
    encode_target_address(addr_str).map(|_| ())
}

fn build_connect_packet(addr_str: &str) -> Result<Vec<u8>> {
    let mut buf = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    buf.extend(encode_target_address(addr_str)?);
    Ok(buf)
}

pub fn encode_target_address(addr_str: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(addr_str.len() + 3);
    if let Ok(socket_addr) = addr_str.parse::<SocketAddr>() {
        match socket_addr {
            SocketAddr::V4(addr) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&addr.ip().octets());
            }
        }
        buf.extend_from_slice(&socket_addr.port().to_be_bytes());
    } else {
        // Fallback to Domain
        // Split port
        let Some((domain, port_str)) = addr_str.rsplit_once(':') else {
            return Err(anyhow!("Invalid address format: {}", addr_str));
        };
        if domain.is_empty()
            || domain.len() > u8::MAX as usize
            || domain.contains(':')
            || domain.contains(char::is_whitespace)
        {
            return Err(anyhow!("Invalid domain: {}", domain));
        }
        let port = port_str.parse::<u16>()?;

        buf.push(ATYP_DOMAIN);
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
    }
    Ok(buf)
}

async fn handle_udp_associate_request(
    stream: &mut TcpStream,
    client_req_addr: String,
    signal_tx: Option<TunnelSignalTx>,
    agent_usage: Arc<AtomicU64>,
    bind_usage: Option<Arc<AtomicU64>>,
    socks_port: u16,
) -> Result<()> {
    let log_target = format!("bind:{}", socks_port);
    debug!(target: &log_target, "UDP Associate request from {}", client_req_addr);

    // We need the client's actual IP to distinguish traffic.
    let client_peer_addr = stream.peer_addr()?;
    let client_ip = client_peer_addr.ip();

    if let Some(signal_tx) = signal_tx {
        let socket = bind_public_udp_socket().await?;

        let local_addr = socket.local_addr()?;
        let port = local_addr.port();
        let public_addr = public_udp_addr(stream, port).await?;

        debug!("Bound Public UDP for Tunnel Session at {}", local_addr);

        // 2. Signal Agent to start UDP Session
        if let Err(e) = signal_tx.send(TunnelCmd::UdpSession(port)).await {
            error!("Failed to signal UdpSession: {}", e);
            return Err(e.into());
        }

        // 3. Reply to Client
        write_reply(stream, 0x00, &public_addr).await?;

        let socket = std::sync::Arc::new(socket);
        let mut agent_addr: Option<SocketAddr> = None;
        let mut client_udp_addr: Option<SocketAddr> = None;
        let mut pkts_to_agent = 0u64;
        let mut pkts_to_client = 0u64;

        let udp_task = {
            let socket = socket.clone();
            let agent_usage = agent_usage.clone();
            let bind_usage = bind_usage.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, src)) => {
                            if is_tunneled_udp_client(client_ip, src) {
                                if client_udp_addr.is_none() || client_udp_addr != Some(src) {
                                    debug!(target: &log_target, "Client UDP detected/changed: {}", src);
                                    client_udp_addr = Some(src);
                                }

                                // Forward to Agent
                                if let Some(agent) = agent_addr {
                                    agent_usage.fetch_add(len as u64, Ordering::Relaxed);
                                    if let Some(ref b) = bind_usage {
                                        b.fetch_add(len as u64, Ordering::Relaxed);
                                    }
                                    pkts_to_agent += 1;
                                    if pkts_to_agent % 100 == 1 {
                                        debug!(target: &log_target, "UDP [C -> A] Handled pkts: {}, Bytes: {}", pkts_to_agent, len);
                                    }
                                    if let Err(e) = socket.send_to(&buf[0..len], agent).await {
                                        warn!(target: &log_target, "UDP fwd to agent failed: {}", e);
                                    }
                                }
                            } else if len == 12 && &buf[0..12] == b"GROWBOT_HOLE" {
                                if agent_addr.is_none() || agent_addr != Some(src) {
                                    debug!(target: &log_target, "Agent UDP detected/changed: {}", src);
                                    agent_addr = Some(src);
                                }
                                debug!(target: &log_target, "Agent Hole-Punch Magic received from {}", src);
                            } else if agent_addr == Some(src) {
                                let payload = &buf[0..len];
                                // Forward to Client
                                if let Some(client) = client_udp_addr {
                                    agent_usage.fetch_add(len as u64, Ordering::Relaxed);
                                    if let Some(ref b) = bind_usage {
                                        b.fetch_add(len as u64, Ordering::Relaxed);
                                    }
                                    pkts_to_client += 1;
                                    if pkts_to_client % 100 == 1 {
                                        debug!(target: &log_target, "UDP [A -> C] Handled pkts: {}, Bytes: {}", pkts_to_client, len);
                                    }
                                    if let Err(e) = socket.send_to(payload, client).await {
                                        warn!(target: &log_target, "UDP fwd to client failed: {}", e);
                                    }
                                }
                            } else {
                                warn!(target: &log_target, "Dropped UDP packet from non-client host {}", src.ip());
                            }
                        }
                        Err(e) => {
                            log::debug!(target: &log_target, "UDP recv error (transient): {}", e);
                            tokio::task::yield_now().await;
                        }
                    }
                }
            })
        };

        let _ = stream.read(&mut [0u8; 1]).await;
        udp_task.abort();
    } else {
        handle_udp_associate_local(stream).await?;
    }

    Ok(())
}

async fn handle_udp_associate_local(stream: &mut TcpStream) -> Result<()> {
    let socket = bind_public_udp_socket().await?;
    let udp_local_addr = socket.local_addr()?;
    let bind_addr = public_udp_addr(stream, udp_local_addr.port()).await?;

    debug!(
        "UDP bound to {}, telling client {}",
        udp_local_addr, bind_addr
    );
    write_reply(stream, 0x00, &bind_addr).await?;

    let udp_task = tokio::spawn(async move {
        if let Err(e) = handle_udp_associate(socket).await {
            error!("UDP Associate error: {}", e);
        }
    });

    let mut buf = [0u8; 1];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            _ => {}
        }
    }
    udp_task.abort();
    Ok(())
}

async fn bind_public_udp_socket() -> Result<UdpSocket> {
    let port_count = u32::from(SOCKS_PORT_MAX - SOCKS_PORT_MIN + 1);
    for _ in 0..port_count {
        let port =
            SOCKS_PORT_MIN + (NEXT_UDP_PORT.fetch_add(1, Ordering::Relaxed) % port_count) as u16;
        match UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(socket) => return Ok(socket),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(anyhow!(
        "No UDP ports available in {}-{}",
        SOCKS_PORT_MIN,
        SOCKS_PORT_MAX
    ))
}

async fn public_udp_addr(stream: &TcpStream, port: u16) -> Result<SocketAddr> {
    let ip = match std::env::var("RUST_PROXY_SOCKS_HOST") {
        Ok(host) if !host.is_empty() => tokio::net::lookup_host((host.as_str(), port))
            .await?
            .find(|addr| addr.is_ipv4())
            .map(|addr| addr.ip())
            .ok_or_else(|| anyhow!("RUST_PROXY_SOCKS_HOST has no IPv4 address"))?,
        _ => stream.local_addr()?.ip(),
    };
    Ok(SocketAddr::new(ip, port))
}

async fn write_reply(stream: &mut TcpStream, rep: u8, addr: &SocketAddr) -> Result<()> {
    let mut buf = vec![SOCKS_VERSION, rep, 0x00];

    match addr {
        SocketAddr::V4(addr) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(_) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&[0, 0, 0, 0]);
        }
    }

    buf.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&buf).await?;
    Ok(())
}
