use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use dashmap::DashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub enum TunnelCmd {
    RequireConn(u32),
    Open { token: [u8; 16], target: Vec<u8> },
    UdpSession(u16),
    ResetIp,
}

pub type TunnelSignalTx = mpsc::Sender<TunnelCmd>;
pub type AgentRequestRegistry = Arc<DashMap<u32, tokio::sync::oneshot::Sender<TcpStream>>>;
pub type OpenRequestRegistry = Arc<DashMap<[u8; 16], tokio::sync::oneshot::Sender<OpenResult>>>;
pub type OpenResult = std::result::Result<TcpStream, u8>;

pub struct BandwidthTrackedStream {
    pub inner: TcpStream,
    pub counter: Arc<AtomicU64>,
    pub secondary_counter: Option<Arc<AtomicU64>>,
}

impl BandwidthTrackedStream {
    fn count(&self, bytes: usize) {
        self.counter.fetch_add(bytes as u64, Ordering::Relaxed);
        if let Some(counter) = &self.secondary_counter {
            counter.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }
}

impl AsyncRead for BandwidthTrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let after = buf.filled().len();
            self.count(after - before);
        }
        res
    }
}

impl AsyncWrite for BandwidthTrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.count(*n);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
