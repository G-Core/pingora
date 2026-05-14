// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `IdleStream`: `AsyncRead`/`AsyncWrite` wrapper that force-closes the
//! underlying transport on bidirectional inactivity.
//!
//! Per-byte hot path is a single `last_activity` field write; the tokio
//! `Sleep` is only re-armed when it fires.

use std::fmt::{self, Debug};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

use crate::protocols::{
    raw_connect::ProxyDigest,
    tls::{digest::SslDigest, TlsRef},
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl, Stream,
    TimingDigest, UniqueID, UniqueIDType, ALPN,
};

/// `Stream` wrapper closing the transport on bidirectional inactivity.
/// Per-byte hot path is a `last_activity` field write — no timer-wheel touch.
pub struct IdleStream {
    inner: Stream,
    idle_timeout: Duration,
    sleep: Pin<Box<Sleep>>,
    last_activity: Instant,
}

impl IdleStream {
    /// Wrap `inner` with a peer-inactivity timeout of `idle_timeout`.
    pub fn new(inner: Stream, idle_timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            inner,
            idle_timeout,
            sleep: Box::pin(tokio::time::sleep(idle_timeout)),
            last_activity: now,
        }
    }
}

impl IdleStream {
    fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn check_idle_timer(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if self.sleep.as_mut().poll(cx).is_ready() {
            let now = Instant::now();
            if now.saturating_duration_since(self.last_activity) >= self.idle_timeout {
                return Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "downstream idle timeout",
                ));
            }
            // Spurious fire — re-arm and re-register the waker.
            let next = self.last_activity + self.idle_timeout;
            self.sleep.as_mut().reset(next);
            let _ = self.sleep.as_mut().poll(cx);
        }
        None
    }
}

impl AsyncRead for IdleStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(e) = self.check_idle_timer(cx) {
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.note_activity();
        }
        res
    }
}

impl AsyncWrite for IdleStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.check_idle_timer(cx) {
            return Poll::Ready(Err(e));
        }
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.note_activity();
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.check_idle_timer(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.check_idle_timer(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.check_idle_timer(cx) {
            return Poll::Ready(Err(e));
        }
        let res = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.note_activity();
            }
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[async_trait]
impl Shutdown for IdleStream {
    async fn shutdown(&mut self) {
        self.inner.shutdown().await
    }
}

impl UniqueID for IdleStream {
    fn id(&self) -> UniqueIDType {
        self.inner.id()
    }
}

impl Ssl for IdleStream {
    fn get_ssl(&self) -> Option<&TlsRef> {
        self.inner.get_ssl()
    }
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.inner.get_ssl_digest()
    }
    fn selected_alpn_proto(&self) -> Option<ALPN> {
        self.inner.selected_alpn_proto()
    }
}

impl GetTimingDigest for IdleStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_timing_digest()
    }
    fn get_read_pending_time(&self) -> Duration {
        self.inner.get_read_pending_time()
    }
    fn get_write_pending_time(&self) -> Duration {
        self.inner.get_write_pending_time()
    }
}

impl GetProxyDigest for IdleStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_proxy_digest()
    }
    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.inner.set_proxy_digest(digest)
    }
}

impl GetSocketDigest for IdleStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_socket_digest()
    }
    fn set_socket_digest(&mut self, digest: SocketDigest) {
        self.inner.set_socket_digest(digest)
    }
}

#[async_trait]
impl Peek for IdleStream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> std::io::Result<bool> {
        // try_peek bypasses poll_read; race it against the idle timer so the
        // h2c-preface-stall / silent-client case is bounded too.
        let res = {
            let peek_fut = self.inner.try_peek(buf);
            tokio::pin!(peek_fut);
            tokio::select! {
                biased;
                _ = self.sleep.as_mut() => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "downstream idle timeout",
                    ));
                }
                res = &mut peek_fut => res,
            }
        };
        if matches!(res, Ok(true)) {
            self.note_activity();
        }
        res
    }
}

impl Debug for IdleStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdleStream")
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Uses `tokio::io::duplex` rather than `tokio_test::io::Mock` because Mock
    // has a strict "all queued data must be consumed" Drop assertion that
    // conflicts with our tests, which intentionally let the timer fire before
    // any bytes are read. Pingora's `ext_io_impl` block implements the full IO
    // trait set for `DuplexStream`, so it can be `Box::new`'d into a `Stream`.

    #[tokio::test(start_paused = true)]
    async fn timer_fires_on_no_reads() {
        // Hold the writer half alive (so the read side stays open, not EOF)
        // but never write anything to it. The IdleStream's read should time
        // out at idle_timeout.
        let (_keep_writer_alive, reader_half) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(reader_half), Duration::from_millis(50));
        let mut buf = [0u8; 16];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn timer_resets_on_successful_read() {
        // Bytes arrive at t≈30ms, then a long quiet stretch. With
        // idle_timeout = 50ms, the first read succeeds and the next read
        // times out ~50ms after the previous read — not 50ms after
        // construction.
        let (mut writer, reader_half) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(reader_half), Duration::from_millis(50));

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            writer.write_all(b"hello").await.unwrap();
            // Keep writer half alive — closing would EOF the reader and the
            // subsequent read would return Ok(0) instead of timing out.
            std::future::pending::<()>().await;
        });

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn writes_reset_timer() {
        // 40ms elapse, then a write — must reset the 50ms timer so a quick
        // read attempt after the write is Pending (not TimedOut).
        let (our_half, _peer_kept_alive) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(our_half), Duration::from_millis(50));
        tokio::time::sleep(Duration::from_millis(40)).await;
        stream.write_all(b"out").await.unwrap();
        let mut buf = [0u8; 16];
        let outcome = tokio::time::timeout(Duration::from_millis(40), stream.read(&mut buf)).await;
        assert!(outcome.is_err(), "expected read Pending; got {outcome:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn timer_still_fires_after_writes_when_traffic_stops() {
        let (our_half, _peer_kept_alive) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(our_half), Duration::from_millis(50));
        stream.write_all(b"out").await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let mut buf = [0u8; 16];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_write_times_out() {
        // Buffer (16) << payload (1024) + peer that never drains: first ~16
        // bytes succeed and reset the timer, the rest block until the idle
        // timer fires. duplex(>=1024) would let the write complete in one go,
        // making the test a tautology.
        let (our_half, _peer_kept_alive) = tokio::io::duplex(16);
        let mut stream = IdleStream::new(Box::new(our_half), Duration::from_millis(50));
        let big = [0u8; 1024];
        let err = stream.write_all(&big).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
