use anyhow::{anyhow, Result, Context};
use log::{info, error, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::udp::handle_udp_associate;
use crate::tunnel::{SOCKS_PORT_MAX, SOCKS_PORT_MIN};
use crate::tunnel_common::{TunnelCmd, TunnelSignalTx, AgentRequestRegistry};
use crate::security;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::time::{timeout, Duration};

lazy_static::lazy_static! {
    static ref NEXT_REQUEST_ID: AtomicU32 = AtomicU32::new(1);
}
static NEXT_UDP_PORT: AtomicU32 = AtomicU32::new(0);

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;

pub async fn handle_client(
    mut stream: TcpStream, 
    signal_tx: Option<TunnelSignalTx>, 
    data_rx: Option<AgentRequestRegistry>, 
    socks_user: Option<String>, 
    socks_pw: Option<String>, 
    agent_usage: Arc<AtomicU64>,
    bind_usage: Option<Arc<AtomicU64>>,
    socks_port: u16,
) -> Result<()> {
    let peer = stream.peer_addr().ok();
    if let Some(p) = peer {
        let ip_str = p.ip().to_string();
        if security::is_blacklisted(&ip_str) {
            warn!("Blocked blacklisted IP: {}", ip_str);
            return Ok(());
        }
    }
    
    info!("Starting SOCKS5 Handshake for {:?}", peer);
    let _ = stream.set_nodelay(true);
    
    if let Err(e) = handshake(&mut stream, socks_user.as_deref(), socks_pw.as_deref()).await {
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

    info!("Handshake & Auth success for {:?}, waiting for request", peer);
    
    let (cmd, addr) = read_request(&mut stream).await.context("Read request failed")?;
    
    info!("Request: cmd={}, addr={}", cmd, addr);

    match cmd {
        CMD_CONNECT => {
            handle_connect(&mut stream, addr, signal_tx, data_rx, agent_usage, bind_usage, socks_port).await
        }
        CMD_UDP_ASSOCIATE => {
             handle_udp_associate_request(&mut stream, addr, signal_tx, agent_usage, bind_usage, socks_port).await
        }
        _ => {
            error!("Unsupported command: {}", cmd);
            write_reply(&mut stream, 0x07, &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).await?;
            Ok(())
        }
    }
}

async fn handshake(stream: &mut TcpStream, expected_user: Option<&str>, expected_pw: Option<&str>) -> Result<()> {
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
                return Ok(());
            } else {
                stream.write_all(&[0x01, 0x01]).await?; // Failure
                return Err(anyhow!("Invalid SOCKS credentials"));
            }
        } else {
            stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            return Err(anyhow!("Client does not support password auth"));
        }
    } else {
        if methods.contains(&0x00) {
            stream.write_all(&[SOCKS_VERSION, 0x00]).await?;
            Ok(())
        } else {
            stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
            Err(anyhow!("Client requires auth but server has none"))
        }
    }
}

async fn handle_connect(
    stream: &mut TcpStream, 
    target_addr: String, 
    signal_tx: Option<TunnelSignalTx>, 
    data_rx: Option<AgentRequestRegistry>, 
    agent_usage: Arc<AtomicU64>,
    bind_usage: Option<Arc<AtomicU64>>,
    socks_port: u16,
) -> Result<()> {
    let log_target = format!("bind:{}", socks_port);
    info!(target: &log_target, "Connect request for {}", target_addr);
    
    let target_stream_result = if let (Some(tx), Some(registry)) = (signal_tx, data_rx) {
        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::SeqCst);
        let (wait_tx, wait_rx) = tokio::sync::oneshot::channel::<TcpStream>();
        
        registry.insert(request_id, wait_tx);
        
        info!("Requesting Tunnel Connection for {} (id={})", target_addr, request_id);
        if let Err(e) = tx.send(TunnelCmd::RequireConn(request_id)).await {
            error!("Failed to signal agent: {}", e);
            registry.remove(&request_id);
            return Err(e.into());
        }
        
        match timeout(Duration::from_secs(10), wait_rx).await {
            Ok(Ok(mut agent_stream)) => {
                agent_stream.write_all(&[0x05, 0x01, 0x00]).await?;
                
                let mut buf = [0u8; 2];
                agent_stream.read_exact(&mut buf).await?;
                if buf[0] != 0x05 || buf[1] != 0x00 {
                    return Err(anyhow!("Agent refused handshake: {:?}", buf));
                }
                
                let req = build_connect_packet(&target_addr)?;
                agent_stream.write_all(&req).await?;
                
                let (rep, _bind_addr) = read_packet(&mut agent_stream).await?;
                if rep != 0x00 {
                     return Err(anyhow!("Agent reported error connecting to target: {}", rep));
                }
                
                Ok(agent_stream)
            },
            Ok(Err(_)) => {
                registry.remove(&request_id);
                Err(anyhow::anyhow!("Agent data channel dropped for request {}", request_id))
            },
            Err(_) => {
                registry.remove(&request_id);
                Err(anyhow::anyhow!("Timeout waiting for agent data connection for request {}", request_id))
            }
        }
    } else {
        let stream = TcpStream::connect(&target_addr).await.context("Failed to connect to target")?;
        let _ = stream.set_nodelay(true);
        Ok::<TcpStream, anyhow::Error>(stream)
    };

    match target_stream_result {
        Ok(target_stream) => {
            target_stream.set_nodelay(true)?;
             let local_addr = target_stream.local_addr().unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0));
             write_reply(stream, 0x00, &local_addr).await?;
             
             let (mut client_reader, mut client_writer) = tokio::io::split(stream);
             let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);

             let client_to_target = async {
                 let mut buf = vec![0u8; 32768];
                 loop {
                     let n = client_reader.read(&mut buf).await?;
                     if n == 0 { break; }
                     agent_usage.fetch_add(n as u64, Ordering::Relaxed);
                     if let Some(ref b) = bind_usage { b.fetch_add(n as u64, Ordering::Relaxed); }
                     target_writer.write_all(&buf[..n]).await?;
                 }
                 Ok::<(), std::io::Error>(())
             };
 
             let target_to_client = async {
                 let mut buf = vec![0u8; 32768];
                 loop {
                     let n = target_reader.read(&mut buf).await?;
                     if n == 0 { break; }
                     agent_usage.fetch_add(n as u64, Ordering::Relaxed);
                     if let Some(ref b) = bind_usage { b.fetch_add(n as u64, Ordering::Relaxed); }
                     client_writer.write_all(&buf[..n]).await?;
                 }
                 Ok::<(), std::io::Error>(())
             };

             if let Err(e) = tokio::try_join!(client_to_target, target_to_client) {
                 error!("Relay error: {}", e);
             }
              
              info!("Connection to {} finished", target_addr);
              Ok(())
        }
        Err(e) => {
            error!("Failed to connect to {}: {}", target_addr, e);
            write_reply(stream, 0x04, &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)).await?;
            Err(e)
        }
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
        _ => return Err(anyhow!("Unsupported address type: {}", atyp)),
    };
    
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    
    Ok((cmd_or_rep, format!("{}:{}", addr, port)))
}

// Helper to separate read_request which logs specific things?
// No, we can just replace `read_request` with `read_packet` usage or call it.
async fn read_request(stream: &mut TcpStream) -> Result<(u8, String)> {
    read_packet(stream).await
}

fn build_connect_packet(addr_str: &str) -> Result<Vec<u8>> {
    let mut buf = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    if let Ok(socket_addr) = addr_str.parse::<SocketAddr>() {
        match socket_addr {
            SocketAddr::V4(addr) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&addr.ip().octets());
            }
            _ => return Err(anyhow!("IPv6 not supported in client builder")),
        }
        buf.extend_from_slice(&socket_addr.port().to_be_bytes());
    } else {
        // Fallback to Domain
        // Split port
        let parts: Vec<&str> = addr_str.rsplitn(2, ':').collect();
        if parts.len() != 2 {
             return Err(anyhow!("Invalid address format: {}", addr_str));
        }
        let port_str = parts[0];
        let domain = parts[1];
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
    info!(target: &log_target, "UDP Associate request from {}", client_req_addr);
    
    // We need the client's actual IP to distinguish traffic.
    let client_peer_addr = stream.peer_addr()?; 
    let _client_ip = client_peer_addr.ip();
    
    if let Some(signal_tx) = signal_tx {
        let socket = bind_public_udp_socket().await?;
        
        let local_addr = socket.local_addr()?;
        let port = local_addr.port();
        let public_addr = public_udp_addr(stream, port).await?;
        
        info!("Bound Public UDP for Tunnel Session at {}", local_addr);
        
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
                            let is_client = if let Some(c) = client_udp_addr {
                                src == c
                            } else if let Some(a) = agent_addr {
                                src != a
                            } else {
                                if len >= 12 && &buf[0..12] == b"GROWBOT_HOLE" {
                                    false
                                } else {
                                    true
                                }
                            };

                            if is_client {
                                if client_udp_addr.is_none() || client_udp_addr != Some(src) {
                                    info!(target: &log_target, "Client UDP detected/changed: {}", src);
                                    client_udp_addr = Some(src);
                                }
                                
                                 // Forward to Agent
                                 if let Some(agent) = agent_addr {
                                     agent_usage.fetch_add(len as u64, Ordering::Relaxed);
                                     if let Some(ref b) = bind_usage { b.fetch_add(len as u64, Ordering::Relaxed); }
                                     pkts_to_agent += 1;
                                     if pkts_to_agent % 100 == 1 {
                                         info!(target: &log_target, "UDP [C -> A] Handled pkts: {}, Bytes: {}", pkts_to_agent, len);
                                     }
                                     if let Err(e) = socket.send_to(&buf[0..len], agent).await {
                                         warn!(target: &log_target, "UDP fwd to agent failed: {}", e);
                                     }
                                 }
                            } else {
                                if agent_addr.is_none() || agent_addr != Some(src) {
                                    info!(target: &log_target, "Agent UDP detected/changed: {}", src);
                                    agent_addr = Some(src);
                                }
                                
                                let payload = &buf[0..len];
                                if payload.len() == 12 && &payload[0..12] == b"GROWBOT_HOLE" {
                                    info!(target: &log_target, "Agent Hole-Punch Magic received from {}", src);
                                    continue;
                                }
                                
                                // Forward to Client
                                if let Some(client) = client_udp_addr {
                                      agent_usage.fetch_add(len as u64, Ordering::Relaxed);
                                      if let Some(ref b) = bind_usage { b.fetch_add(len as u64, Ordering::Relaxed); }
                                      pkts_to_client += 1;
                                      if pkts_to_client % 100 == 1 {
                                          info!(target: &log_target, "UDP [A -> C] Handled pkts: {}, Bytes: {}", pkts_to_client, len);
                                      }
                                      if let Err(e) = socket.send_to(payload, client).await {
                                          warn!(target: &log_target, "UDP fwd to client failed: {}", e);
                                      }
                                 }
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
    
    info!("UDP bound to {}, telling client {}", udp_local_addr, bind_addr);
    write_reply(stream, 0x00, &bind_addr).await?;
    
    let udp_task = tokio::spawn(async move {
        if let Err(e) = handle_udp_associate(socket).await {
            error!("UDP Associate error: {}", e);
        }
    });

    let mut buf = [0u8; 1];
    loop { match stream.read(&mut buf).await { Ok(0)|Err(_) => break, _=>{} } }
    udp_task.abort();
    Ok(())
}

async fn bind_public_udp_socket() -> Result<UdpSocket> {
    let port_count = u32::from(SOCKS_PORT_MAX - SOCKS_PORT_MIN + 1);
    for _ in 0..port_count {
        let port = SOCKS_PORT_MIN + (NEXT_UDP_PORT.fetch_add(1, Ordering::Relaxed) % port_count) as u16;
        match UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(socket) => return Ok(socket),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(anyhow!("No UDP ports available in {}-{}", SOCKS_PORT_MIN, SOCKS_PORT_MAX))
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
             buf.extend_from_slice(&[0,0,0,0]);
        }
    }
    
    buf.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&buf).await?;
    Ok(())
}
