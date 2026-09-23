use anyhow::{anyhow, Result};
use log::{debug, error};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const MAX_PACKET_SIZE: usize = 65535;

pub async fn handle_udp_associate(socket: UdpSocket) -> Result<()> {
    let mut buf = [0u8; MAX_PACKET_SIZE];

    let mut client_addr: Option<SocketAddr> = None;

    loop {
        let (len, src_addr) = socket.recv_from(&mut buf).await?;

        if client_addr.is_none() {
            client_addr = Some(src_addr);
            debug!("UDP Client identified as {}", src_addr);
        }

        let client = client_addr.unwrap();

        if src_addr == client {
            if len < 10 {
                // Minimal header size (RSV(2)+FRAG(1)+ATYP(1)+IPV4(4)+PORT(2))
                continue;
            }

            let frag = buf[2];
            if frag != 0 {
                continue;
            }

            let (header_len, target_addr) = match parse_header(&buf[3..len]).await {
                Ok(res) => res,
                Err(e) => {
                    error!("Failed to parse UDP header: {}", e);
                    continue;
                }
            };

            let payload = &buf[3 + header_len..len];

            debug!(
                "Forwarding UDP {} bytes to target {}",
                payload.len(),
                target_addr
            );

            if let Err(e) = socket.send_to(payload, &target_addr).await {
                error!("Failed to forward UDP to {}: {}", target_addr, e);
            }
        } else {
            let mut header = vec![0x00, 0x00, 0x00];
            match src_addr {
                SocketAddr::V4(addr) => {
                    header.push(ATYP_IPV4);
                    header.extend_from_slice(&addr.ip().octets());
                }
                SocketAddr::V6(addr) => {
                    header.push(ATYP_IPV6);
                    header.extend_from_slice(&addr.ip().octets());
                }
            }
            header.extend_from_slice(&src_addr.port().to_be_bytes());

            header.extend_from_slice(&buf[0..len]);

            if let Err(e) = socket.send_to(&header, client).await {
                error!("Failed to send UDP back to client: {}", e);
            }
        }
    }
}

async fn parse_header(buf: &[u8]) -> Result<(usize, SocketAddr)> {
    let atyp = buf[0];
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 7 {
                return Err(anyhow!("Header too short"));
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((7, SocketAddr::new(IpAddr::V4(ip), port)))
        }
        ATYP_DOMAIN => {
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err(anyhow!("Header too short for domain"));
            }
            let domain_bytes = &buf[2..2 + len];
            let domain = String::from_utf8_lossy(domain_bytes);
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);

            let addr_str = format!("{}:{}", domain, port);
            match tokio::net::lookup_host(addr_str).await {
                Ok(mut iter) => {
                    if let Some(addr) = iter.next() {
                        Ok((2 + len + 2, addr))
                    } else {
                        Err(anyhow!("Could not resolve domain {}", domain))
                    }
                }
                Err(e) => Err(anyhow!("Resolution failed for {}: {}", domain, e)),
            }
        }
        ATYP_IPV6 => Err(anyhow!("IPv6 not supported in UDP yet")),
        _ => Err(anyhow!("Unknown ATYP {}", atyp)),
    }
}
