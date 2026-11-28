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

use crate::protocols::digest::TimingDigest;
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::tls::SslDigest;
use crate::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Rebind, Shutdown, SocketDigest, Ssl,
    UniqueID, UniqueIDType, ALPN,
};
use crate::tls::TlsStream as S2NTlsStream;
use crate::utils::tls::get_organization_serial_bytes;
use async_trait::async_trait;
use log::debug;
use pingora_s2n::hash_certificate;
use std::fmt::Debug;
use std::io::Result as IoResult;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Stream wrapper that will automatically flush all writes depending on the value of
/// `auto_flush`. That is, it will always call `poll_flush` on every invocation of
/// `poll_write` or `poll_write_vectored`.
///
/// The underlying transport stream implementation (pingora_core::protocols::l4::stream::Stream)
/// used by Pingora buffers writes to the TCP connection. During the handshake process
/// s2n-tls does not flush writes to the TCP connection, which can lead to scenarios
/// where writes are never sent over the connection causing the handshake process to hang
/// and timeout. This wrapper ensures that all writes are flushed to the TCP connection
/// during the handshake process.
pub struct AutoFlushableStream<T: AsyncRead + AsyncWrite + Unpin> {
    stream: T,
    auto_flush: bool,
}

impl<T> AutoFlushableStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: T, auto_flush: bool) -> Self {
        AutoFlushableStream { stream, auto_flush }
    }

    pub fn set_auto_flush(&mut self, auto_flush: bool) {
        self.auto_flush = auto_flush;
    }
}

impl<T> AsyncRead for AutoFlushableStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for AutoFlushableStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<IoResult<usize>> {
        let write = Pin::new(&mut self.stream).poll_write(cx, buf);
        if self.auto_flush {
            let _ = Pin::new(&mut self.stream).poll_flush(cx);
        }
        write
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        let write = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        if self.auto_flush {
            let _ = Pin::new(&mut self.stream).poll_flush(cx);
        }
        write
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct TlsStream<T: AsyncRead + AsyncWrite + Unpin> {
    stream: S2NTlsStream<AutoFlushableStream<T>>,
    digest: Option<Arc<SslDigest>>,
    pub(super) timing: TimingDigest,
}

impl<T> TlsStream<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    pub fn from_s2n_stream(
        stream: S2NTlsStream<AutoFlushableStream<T>>,
        handshake_duration: Duration,
    ) -> TlsStream<T> {
        let timing = TimingDigest {
            established_ts: SystemTime::now(),
            establishment_duration: Some(handshake_duration),
            offload_wait_duration: None,
        };
        let digest = Some(Arc::new(SslDigest::from_stream(Some(&stream))));
        TlsStream {
            stream,
            digest,
            timing,
        }
    }
}

impl<T> TlsStream<T>
where
    T: Rebind + AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn rebind_inner(&mut self) -> IoResult<()> {
        let inner: &mut T = self.stream.get_mut();
        inner.rebind()
    }
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> Deref for AutoFlushableStream<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> DerefMut for AutoFlushableStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> Deref for TlsStream<T> {
    type Target = S2NTlsStream<AutoFlushableStream<T>>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> DerefMut for TlsStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> Ssl for TlsStream<T> {
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.ssl_digest()
    }

    fn selected_alpn_proto(&self) -> Option<ALPN> {
        let stream = self.stream.as_ref();
        let proto = stream.application_protocol();

        match proto {
            None => None,
            Some(raw) => ALPN::from_wire_selected(raw),
        }
    }
}

impl<T> TlsStream<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    pub fn ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.digest.clone()
    }
}

impl<T> AsyncRead for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        debug!("poll_read");
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for TlsStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

impl<T> UniqueID for TlsStream<T>
where
    T: UniqueID + AsyncRead + AsyncWrite + Unpin,
{
    fn id(&self) -> UniqueIDType {
        self.stream.get_ref().id()
    }
}

impl<S> GetSocketDigest for TlsStream<S>
where
    S: GetSocketDigest + AsyncRead + AsyncWrite + std::marker::Unpin,
{
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.stream.get_ref().get_socket_digest()
    }
    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.stream.get_mut().set_socket_digest(socket_digest)
    }
}

impl<S> GetTimingDigest for TlsStream<S>
where
    S: GetTimingDigest + AsyncRead + AsyncWrite + std::marker::Unpin,
{
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        let mut ts_vec = self.stream.get_ref().get_timing_digest();
        ts_vec.push(Some(self.timing.clone()));
        ts_vec
    }

    fn get_read_pending_time(&self) -> Duration {
        self.stream.get_ref().get_read_pending_time()
    }

    fn get_write_pending_time(&self) -> Duration {
        self.stream.get_ref().get_write_pending_time()
    }
}

impl<S> GetProxyDigest for TlsStream<S>
where
    S: GetProxyDigest + AsyncRead + AsyncWrite + std::marker::Unpin,
{
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.stream.get_ref().get_proxy_digest()
    }
}

impl SslDigest {
    fn from_stream<T: AsyncRead + AsyncWrite + Unpin>(stream: Option<&S2NTlsStream<T>>) -> Self {
        let conn = stream.unwrap().as_ref();

        let cipher = conn.cipher_suite().unwrap_or_default().to_string();
        let version = conn
            .actual_protocol_version()
            .map(|v| format!("{:?}", v))
            .unwrap_or_default()
            .to_string();

        let mut organization = None;
        let mut serial_number = None;
        let mut cert_digest = None;

        if let Ok(cert_chain) = conn.peer_cert_chain() {
            if let Some(Ok(cert)) = cert_chain.iter().next() {
                if let Ok(raw_cert) = cert.der() {
                    if let Ok((org, serial)) = get_organization_serial_bytes(raw_cert) {
                        organization = org;
                        serial_number = Some(serial);
                    }
                    cert_digest = Some(hash_certificate(raw_cert));
                }
            }
        }

        SslDigest::new(
            cipher,
            version,
            organization,
            serial_number,
            cert_digest.unwrap_or_default(),
        )
    }
}

impl<S: AsyncRead + AsyncWrite + std::marker::Unpin> Peek for TlsStream<S> {}

#[async_trait]
impl<S: Shutdown + AsyncRead + AsyncWrite + std::marker::Unpin + Send> Shutdown for TlsStream<S> {
    async fn shutdown(&mut self) -> () {
        self.get_mut().shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::{AutoFlushableStream, TlsStream};
    use crate::listeners::tls::TlsSettings;
    use crate::protocols::l4::stream::Stream as L4Stream;
    use crate::protocols::tls::server::handshake;
    use crate::protocols::Rebind;
    use pingora_s2n::{Config, IgnoreVerifyHostnameCallback, TlsConnector, DEFAULT_TLS13};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn rebind_moves_the_wrapped_transport_to_the_current_runtime() {
        let cert_path = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
        let key_path = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));
        let cert = std::fs::read(&cert_path).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsSettings::intermediate(&cert_path, &key_path)
            .unwrap()
            .build();

        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = handshake(&acceptor, L4Stream::from(tcp)).await.unwrap();
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf).await.unwrap();
                tls.write_all(&buf).await.unwrap();
            });
        });

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut tls = runtime_a.block_on(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let inner = AutoFlushableStream::new(L4Stream::from(tcp), true);
            let mut builder = Config::builder();
            builder.set_security_policy(&DEFAULT_TLS13).unwrap();
            builder
                .set_verify_host_callback(IgnoreVerifyHostnameCallback::new())
                .unwrap();
            builder.trust_pem(&cert).unwrap();
            let config = builder.build().unwrap();
            let mut s2n = TlsConnector::new(config)
                .connect("localhost", inner)
                .await
                .unwrap();
            s2n.get_mut().set_auto_flush(false);
            TlsStream::from_s2n_stream(s2n, Duration::ZERO)
        });
        drop(runtime_a);

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            Rebind::rebind(&mut tls).expect("rebind onto the new runtime");
            tokio::time::timeout(Duration::from_secs(5), async {
                tls.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            })
            .await
            .expect("the wrapped transport must move to the taking runtime");
        });
        server.join().unwrap();
        drop(tls);
    }
}
