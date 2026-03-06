use tokio::sync::mpsc;
use tokio::net::TcpStream;
use std::sync::Arc;

use std::sync::atomic::{AtomicU64, Ordering};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use dashmap::DashMap;

#[derive(Debug)]
pub enum TunnelCmd {
    RequireConn(u32),
    UdpSession(u16),
    ResetIp,
}

pub type TunnelSignalTx = mpsc::Sender<TunnelCmd>;
pub type AgentRequestRegistry = Arc<DashMap<u32, tokio::sync::oneshot::Sender<TcpStream>>>;

pub struct BandwidthTrackedStream {
    pub inner: TcpStream,
    pub counter: Arc<AtomicU64>,
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
            self.counter.fetch_add((after - before) as u64, Ordering::Relaxed);
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
            self.counter.fetch_add(*n as u64, Ordering::Relaxed);
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
