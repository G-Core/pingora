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
use crate::protocols::tls::{SslDigest, ALPN};
use crate::protocols::{Peek, Ssl, UniqueID, UniqueIDType};
use crate::tls::{self, ssl, tokio_ssl::SslStream as InnerSsl};
use crate::utils::tls::{get_organization, get_serial};
use log::warn;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::cell::RefCell;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "boringssl")]
use pingora_boringssl as ssl_lib;

#[cfg(feature = "openssl")]
use pingora_openssl as ssl_lib;

use ssl_lib::{hash::MessageDigest, ssl::SslRef};

/// The TLS connection
#[derive(Debug)]
pub struct SslStream<T> {
    ssl: InnerSsl<T>,
    digest: Option<Arc<SslDigest>>,
    pub(super) timing: TimingDigest,
}

impl<T> SslStream<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    /// Create a new TLS connection from the given `stream`
    ///
    /// The caller needs to perform [`Self::connect()`] or [`Self::accept()`] to perform TLS
    /// handshake after.
    pub fn new(ssl: ssl::Ssl, stream: T) -> Result<Self> {
        let mut ssl = ssl;
        // BoringSSL re-checks the retry buffer's address unless this mode is set;
        // coalesced vectored writes rebuild that buffer on every poll.
        ssl.set_mode(ssl_lib::ssl::SslMode::ACCEPT_MOVING_WRITE_BUFFER);
        let ssl = InnerSsl::new(ssl, stream)
            .explain_err(TLSHandshakeFailure, |e| format!("ssl stream error: {e}"))?;

        Ok(SslStream {
            ssl,
            digest: None,
            timing: Default::default(),
        })
    }

    /// Connect to the remote TLS server as a client
    pub async fn connect(&mut self) -> Result<(), ssl::Error> {
        Self::clear_error();
        let handshake_start = Instant::now();
        Pin::new(&mut self.ssl).connect().await?;
        self.timing.establishment_duration = Some(handshake_start.elapsed());
        self.timing.established_ts = SystemTime::now();
        self.digest = Some(Arc::new(SslDigest::from_ssl(self.ssl())));
        Ok(())
    }

    /// Finish the TLS handshake from client as a server
    pub async fn accept(&mut self) -> Result<(), ssl::Error> {
        Self::clear_error();
        let handshake_start = Instant::now();
        Pin::new(&mut self.ssl).accept().await?;
        self.timing.establishment_duration = Some(handshake_start.elapsed());
        self.timing.established_ts = SystemTime::now();
        self.digest = Some(Arc::new(SslDigest::from_ssl(self.ssl())));
        Ok(())
    }

    #[inline]
    fn clear_error() {
        let errs = tls::error::ErrorStack::get();
        if !errs.errors().is_empty() {
            warn!("Clearing dirty TLS error stack: {}", errs);
        }
    }
}

impl<T> SslStream<T> {
    pub fn ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.digest.clone()
    }

    /// Attempts to obtain a mutable reference to the SslDigest.
    /// This method returns `None` if the SslDigest is currently held by other references.
    pub(crate) fn ssl_digest_mut(&mut self) -> Option<&mut SslDigest> {
        Arc::get_mut(self.digest.as_mut()?)
    }
}

use std::ops::{Deref, DerefMut};

impl<T> Deref for SslStream<T> {
    type Target = InnerSsl<T>;

    fn deref(&self) -> &Self::Target {
        &self.ssl
    }
}

impl<T> DerefMut for SslStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ssl
    }
}

impl<T> AsyncRead for SslStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Self::clear_error();
        Pin::new(&mut self.ssl).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for SslStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Self::clear_error();
        Pin::new(&mut self.ssl).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Self::clear_error();
        Pin::new(&mut self.ssl).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Self::clear_error();
        Pin::new(&mut self.ssl).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Self::clear_error();
        let mut pending = bufs.iter().filter(|buf| !buf.is_empty());
        let Some(first) = pending.next() else {
            return Poll::Ready(Ok(0));
        };
        let mut pending = pending.peekable();
        if first.len() >= TLS_MAX_PLAINTEXT || pending.peek().is_none() {
            return Pin::new(&mut self.ssl).poll_write(cx, first);
        }

        // A nested TLS write on this thread finds the scratch taken and uses the
        // no-copy path above.
        let Some(mut scratch) = TLS_WRITE_SCRATCH
            .try_with(|cell| cell.borrow_mut().take())
            .ok()
            .flatten()
        else {
            return Pin::new(&mut self.ssl).poll_write(cx, first);
        };
        scratch.clear();
        let mut truncated = false;
        for buf in std::iter::once(first).chain(pending) {
            if scratch.len() == TLS_MAX_PLAINTEXT {
                break;
            }
            let take = (TLS_MAX_PLAINTEXT - scratch.len()).min(buf.len());
            match buf.get(..take) {
                Some(prefix) => scratch.extend_from_slice(prefix),
                None => {
                    truncated = true;
                    break;
                }
            }
        }
        let result = if truncated {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS write slice shorter than its bounded prefix",
            )))
        } else {
            Pin::new(&mut self.ssl).poll_write(cx, &scratch)
        };
        let _ = TLS_WRITE_SCRATCH.try_with(|cell| *cell.borrow_mut() = Some(scratch));
        result
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

const TLS_MAX_PLAINTEXT: usize = 16384;

thread_local! {
    static TLS_WRITE_SCRATCH: RefCell<Option<Vec<u8>>> = const { RefCell::new(Some(Vec::new())) };
}

impl<T> UniqueID for SslStream<T>
where
    T: UniqueID,
{
    fn id(&self) -> UniqueIDType {
        self.ssl.get_ref().id()
    }
}

impl<T> Ssl for SslStream<T> {
    fn get_ssl(&self) -> Option<&ssl::SslRef> {
        Some(self.ssl())
    }

    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.ssl_digest()
    }

    /// Return selected ALPN if any
    fn selected_alpn_proto(&self) -> Option<ALPN> {
        let ssl = self.get_ssl()?;
        ALPN::from_wire_selected(ssl.selected_alpn_protocol()?)
    }
}

impl SslDigest {
    pub fn from_ssl(ssl: &SslRef) -> Self {
        let cipher = match ssl.current_cipher() {
            Some(c) => c.name(),
            None => "",
        };

        let (cert_digest, org, sn) = match ssl.peer_certificate() {
            Some(cert) => {
                let cert_digest = match cert.digest(MessageDigest::sha256()) {
                    Ok(c) => c.as_ref().to_vec(),
                    Err(_) => Vec::new(),
                };
                (cert_digest, get_organization(&cert), get_serial(&cert).ok())
            }
            None => (Vec::new(), None, None),
        };

        SslDigest::new(cipher, ssl.version_str(), org, sn, cert_digest)
    }
}

// TODO: implement Peek if needed
impl<T> Peek for SslStream<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IoSlice;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    struct CountingIo {
        inner: DuplexStream,
        written: Arc<Mutex<Vec<u8>>>,
        write_calls: Arc<AtomicUsize>,
        pending_writes: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for CountingIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.pending_writes.load(Ordering::Relaxed) > 0 {
                self.pending_writes.fetch_sub(1, Ordering::Relaxed);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    self.write_calls.fetch_add(1, Ordering::Relaxed);
                    self.written
                        .lock()
                        .expect("ciphertext")
                        .extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
                other => other,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct TlsPair {
        server: SslStream<CountingIo>,
        client: SslStream<DuplexStream>,
        written: Arc<Mutex<Vec<u8>>>,
        write_calls: Arc<AtomicUsize>,
        pending_writes: Arc<AtomicUsize>,
    }

    impl TlsPair {
        fn ciphertext(&self) -> Vec<u8> {
            self.written.lock().expect("ciphertext").clone()
        }

        fn reset(&self) {
            self.written.lock().expect("ciphertext").clear();
            self.write_calls.store(0, Ordering::Relaxed);
        }

        fn app_data_records(&self) -> Vec<usize> {
            let ciphertext = self.ciphertext();
            let mut records = Vec::new();
            let mut i = 0;
            while i + 5 <= ciphertext.len() {
                let kind = ciphertext[i];
                let len = u16::from_be_bytes([ciphertext[i + 3], ciphertext[i + 4]]) as usize;
                if i + 5 + len > ciphertext.len() {
                    break;
                }
                if kind == 0x17 {
                    records.push(len);
                }
                i += 5 + len;
            }
            records
        }
    }

    async fn tls_pair() -> TlsPair {
        use ssl::{SslContext, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion};

        let cert = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
        let key = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));

        let mut server_builder = SslContext::builder(SslMethod::tls()).unwrap();
        server_builder
            .set_certificate_chain_file(cert)
            .expect("server certificate");
        server_builder
            .set_private_key_file(key, SslFiletype::PEM)
            .expect("server key");
        server_builder.set_options(SslOptions::NO_TICKET);
        let server_ctx = server_builder.build();

        let mut client_builder = SslContext::builder(SslMethod::tls()).unwrap();
        client_builder.set_verify(SslVerifyMode::NONE);
        client_builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        let client_ctx = client_builder.build();

        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let written = Arc::new(Mutex::new(Vec::new()));
        let write_calls = Arc::new(AtomicUsize::new(0));
        let pending_writes = Arc::new(AtomicUsize::new(0));

        let mut server = SslStream::new(
            ssl::Ssl::new(&server_ctx).unwrap(),
            CountingIo {
                inner: server_io,
                written: written.clone(),
                write_calls: write_calls.clone(),
                pending_writes: pending_writes.clone(),
            },
        )
        .unwrap();
        let mut client = SslStream::new(ssl::Ssl::new(&client_ctx).unwrap(), client_io).unwrap();

        tokio::try_join!(server.accept(), client.connect()).expect("TLS handshake");

        let pair = TlsPair {
            server,
            client,
            written,
            write_calls,
            pending_writes,
        };
        pair.reset();
        pair
    }

    async fn write_all_vectored<S>(stream: &mut S, mut slices: &mut [IoSlice<'_>])
    where
        S: AsyncWrite + Unpin,
    {
        let total: usize = slices.iter().map(|s| s.len()).sum();
        let mut written = 0;
        while written < total {
            let n = stream.write_vectored(slices).await.unwrap();
            assert_ne!(n, 0, "vectored write made no progress");
            written += n;
            IoSlice::advance_slices(&mut slices, n);
        }
    }

    #[tokio::test]
    async fn small_slices_coalesce_into_one_record() {
        let mut pair = tls_pair().await;
        let payloads: Vec<Vec<u8>> = (0..4).map(|i| vec![b'a' + i; 1000]).collect();
        let mut slices: Vec<IoSlice<'_>> = payloads.iter().map(|p| IoSlice::new(p)).collect();

        write_all_vectored(&mut pair.server, &mut slices).await;

        let expected: Vec<u8> = payloads.concat();
        let mut received = vec![0; expected.len()];
        pair.client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        assert_eq!(pair.app_data_records().len(), 1);
        assert_eq!(pair.write_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn slices_are_cut_at_one_record() {
        let mut pair = tls_pair().await;
        let payloads: Vec<Vec<u8>> = (0..3).map(|i| vec![b'a' + i; 8000]).collect();
        let mut slices: Vec<IoSlice<'_>> = payloads.iter().map(|p| IoSlice::new(p)).collect();

        write_all_vectored(&mut pair.server, &mut slices).await;

        let expected: Vec<u8> = payloads.concat();
        let mut received = vec![0; expected.len()];
        pair.client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        let records = pair.app_data_records();
        assert_eq!(records.len(), 2);
        assert!(
            (TLS_MAX_PLAINTEXT..TLS_MAX_PLAINTEXT + 32).contains(&records[0]),
            "first record must hold one full max-size plaintext chunk: {records:?}"
        );
    }

    #[tokio::test]
    async fn a_large_slice_takes_the_no_copy_path() {
        let mut pair = tls_pair().await;
        let payload = vec![b'z'; 20000];
        let mut slices = [IoSlice::new(&payload)];

        write_all_vectored(&mut pair.server, &mut slices).await;

        let mut received = vec![0; payload.len()];
        pair.client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert_eq!(pair.app_data_records().len(), 2);
    }

    #[tokio::test]
    async fn empty_slices_are_ignored() {
        let mut pair = tls_pair().await;
        assert_eq!(pair.server.write_vectored(&[]).await.unwrap(), 0);

        let a = [b'a'; 600];
        let b = [b'b'; 700];
        let mut slices = [
            IoSlice::new(&[]),
            IoSlice::new(&a),
            IoSlice::new(&[]),
            IoSlice::new(&b),
        ];
        write_all_vectored(&mut pair.server, &mut slices).await;

        let mut received = vec![0; 1300];
        pair.client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received[..600], &a);
        assert_eq!(&received[600..], &b);
        assert_eq!(pair.app_data_records().len(), 1);
    }

    #[tokio::test]
    async fn retries_after_the_transport_returns_pending() {
        let mut pair = tls_pair().await;
        pair.pending_writes.store(1, Ordering::Relaxed);
        let a = vec![b'a'; 1000];
        let b = vec![b'b'; 1000];
        let mut slices = [IoSlice::new(&a), IoSlice::new(&b)];

        write_all_vectored(&mut pair.server, &mut slices).await;

        let mut received = vec![0; 2000];
        pair.client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received[..1000], &a);
        assert_eq!(&received[1000..], &b);
        assert_eq!(pair.pending_writes.load(Ordering::Relaxed), 0);
        assert_eq!(pair.app_data_records().len(), 1);
    }

    #[tokio::test]
    async fn content_length_body_batch_coalesces_over_tls() {
        use crate::protocols::http::v1::body::BodyWriter;
        use bytes::Bytes;

        let mut pair = tls_pair().await;
        let chunks: Vec<Bytes> = (0..4).map(|i| Bytes::from(vec![b'a' + i; 1000])).collect();
        let mut writer = BodyWriter::new();
        writer.init_content_length(4000);

        writer
            .write_body_vec(&mut pair.server, &chunks)
            .await
            .unwrap();

        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.to_vec()).collect();
        let mut received = vec![0; expected.len()];
        pair.client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        assert_eq!(pair.app_data_records().len(), 1);
    }
}
