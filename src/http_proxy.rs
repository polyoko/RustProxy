use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::security;
use crate::socks5::{self, ConnectError};
use crate::tunnel_common::{
    AgentRequestRegistry, BandwidthTrackedStream, OpenRequestRegistry, TunnelSignalTx,
};

const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEADER_BYTES: usize = 8 * 1024;

enum Request {
    Connect { target: String },
    Absolute { target: String, outbound: Vec<u8> },
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_client(
    mut client: TcpStream,
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
    let peer = client.peer_addr().ok();
    if let Some(peer) = peer {
        if security::is_blacklisted(&peer.ip().to_string()) {
            return Ok(());
        }
    }

    let (header, remainder) = match timeout(HEADER_TIMEOUT, read_header(&mut client)).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) | Err(_) => return Ok(()),
    };
    let (request, authorization) = match parse_request(&header) {
        Ok(value) => value,
        Err(()) => return write_response(&mut client, "400 Bad Request", None).await,
    };

    if !authorized(
        authorization.as_deref(),
        user.as_deref(),
        password.as_deref(),
    ) {
        if let Some(peer) = peer {
            security::report_failure(&peer.ip().to_string());
        }
        return write_response(
            &mut client,
            "407 Proxy Authentication Required",
            Some("Proxy-Authenticate: Basic realm=\"proxy\"\r\n"),
        )
        .await;
    }
    if let Some(peer) = peer {
        security::report_success(&peer.ip().to_string());
    }

    if limit_reached {
        return write_response(&mut client, "429 Too Many Requests", None).await;
    }

    let (target, outbound, is_connect) = match request {
        Request::Connect { target } => (target, Vec::new(), true),
        Request::Absolute { target, outbound } => (target, outbound, false),
    };
    let target = match socks5::open_target(
        &target,
        signal_tx,
        data_rx,
        open_rx,
        protocol_version,
        socks_port,
        timing_agent.as_deref(),
        resetting.as_deref(),
    )
    .await
    {
        Ok(stream) => stream,
        Err(ConnectError::AgentUnavailable(_)) => {
            return write_response(&mut client, "503 Service Unavailable", None).await
        }
        Err(ConnectError::Target(_)) => {
            return write_response(&mut client, "502 Bad Gateway", None).await
        }
    };

    let mut target = BandwidthTrackedStream {
        inner: target,
        counter: agent_usage,
        secondary_counter: bind_usage,
    };
    if !outbound.is_empty() {
        target.write_all(&outbound).await?;
    }
    if !remainder.is_empty() {
        target.write_all(&remainder).await?;
    }
    if is_connect {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
    Ok(())
}

async fn read_header(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        {
            anyhow::ensure!(end <= MAX_HEADER_BYTES, "HTTP header too large");
            let remainder = request.split_off(end);
            return Ok((request, remainder));
        }
        anyhow::ensure!(request.len() <= MAX_HEADER_BYTES, "HTTP header too large");
        let read = stream.read(&mut chunk).await?;
        anyhow::ensure!(read != 0, "HTTP client disconnected");
        request.extend_from_slice(&chunk[..read]);
    }
}

fn parse_request(header: &[u8]) -> std::result::Result<(Request, Option<String>), ()> {
    let header = std::str::from_utf8(header).map_err(|_| ())?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or(())?;
    let target = request_parts.next().ok_or(())?;
    let version = request_parts.next().ok_or(())?;
    if request_parts.next().is_some() || version != "HTTP/1.1" {
        return Err(());
    }

    let mut authorization = None;
    let mut outbound_headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.eq_ignore_ascii_case("proxy-authorization")
            && authorization.replace(value.trim().to_string()).is_some()
        {
            return Err(());
        }
        if !name.eq_ignore_ascii_case("connection") {
            outbound_headers.push(line);
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        socks5::validate_target(target).map_err(|_| ())?;
        return Ok((
            Request::Connect {
                target: target.to_string(),
            },
            authorization,
        ));
    }

    let (target, path) = absolute_target(target)?;
    let mut outbound = format!("{} {} HTTP/1.1\r\n", method, path).into_bytes();
    for line in outbound_headers {
        outbound.extend_from_slice(line.as_bytes());
        outbound.extend_from_slice(b"\r\n");
    }
    outbound.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok((Request::Absolute { target, outbound }, authorization))
}

fn absolute_target(uri: &str) -> std::result::Result<(String, String), ()> {
    let rest = uri.strip_prefix("http://").ok_or(())?;
    let split_at = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..split_at];
    if authority.is_empty() || authority.contains('@') {
        return Err(());
    }
    let path = match &rest[split_at..] {
        "" => "/".to_string(),
        value if value.starts_with('/') => value.to_string(),
        value if value.starts_with('?') => format!("/{}", value),
        _ => return Err(()),
    };
    let target = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{}:80", authority)
    };
    socks5::validate_target(&target).map_err(|_| ())?;
    Ok((target, path))
}

fn authorized(authorization: Option<&str>, user: Option<&str>, password: Option<&str>) -> bool {
    let (Some(authorization), Some(user), Some(password)) = (authorization, user, password) else {
        return false;
    };
    let mut parts = authorization.split_whitespace();
    let (Some(scheme), Some(value), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return false;
    }
    let Ok(credentials) = STANDARD.decode(value) else {
        return false;
    };
    let Ok(credentials) = std::str::from_utf8(&credentials) else {
        return false;
    };
    crate::session::constant_time_eq(credentials, &format!("{}:{}", user, password))
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    extra_headers: Option<&str>,
) -> Result<()> {
    stream
        .write_all(
            format!(
                "HTTP/1.1 {}\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
                status,
                extra_headers.unwrap_or("")
            )
            .as_bytes(),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{absolute_target, authorized};

    #[test]
    fn parses_absolute_http_targets_and_basic_auth() {
        assert_eq!(
            absolute_target("http://example.com/path?q=1"),
            Ok(("example.com:80".into(), "/path?q=1".into()))
        );
        assert!(authorized(
            Some("Basic dXNlcjpwYXNz"),
            Some("user"),
            Some("pass")
        ));
        assert!(!authorized(
            Some("Basic dXNlcjpiYWQ="),
            Some("user"),
            Some("pass")
        ));
    }
}
