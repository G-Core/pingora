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

use log::debug;
use once_cell::sync::Lazy;
use pingora_error::{ErrorType, ErrorType::InternalError, OrErr, Result};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::listeners::tls::boringssl_openssl::alpn::valid_alpn;
use crate::listeners::TlsClientHello;
use crate::offload::OffloadRuntime;
pub use crate::protocols::tls::ALPN;
use crate::protocols::IO;
use crate::server::configuration::ServerConf;
use crate::tls::ex_data::Index;
use crate::tls::ssl::AlpnError;
use crate::tls::ssl::{
    NameType, Ssl, SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod, SslRef,
};
use crate::{
    listeners::{SharedTlsAcceptCallbacks, TlsAcceptCallbacks},
    protocols::tls::{
        server::{handshake, handshake_with_callback},
        SslStream,
    },
};
pub const TLS_CONF_ERR: ErrorType = ErrorType::Custom("TLSConfigError");

/// Typed ex_data slot for the captured ClientHello.  Using the typed `Index`
/// lets `SslRef::ex_data` / `replace_ex_data` (from boring / openssl) handle
/// the box, destructor, and clone-on-read mechanics safely — no raw FFI needed.
static CLIENT_HELLO_DATA_INDEX: Lazy<Index<Ssl, TlsClientHello>> = Lazy::new(|| {
    Ssl::new_ex_index::<TlsClientHello>().expect("failed to allocate client hello ex_data index")
});

pub(crate) fn client_hello_data(ssl: &SslRef) -> Option<TlsClientHello> {
    ssl.ex_data(*CLIENT_HELLO_DATA_INDEX).cloned()
}

pub(crate) fn set_client_hello_data(ssl: &mut SslRef, hello: TlsClientHello) {
    // `replace_ex_data` does the same first-write-wins / overwrite-in-place
    // semantics the previous raw-FFI implementation hand-rolled: returns the
    // old value (which we discard) if a previous capture existed, otherwise
    // installs a new boxed copy.  The registered destructor is `boring`'s
    // `free_data_box::<TlsClientHello>` which runs on SSL teardown.
    let _ = ssl.replace_ex_data(*CLIENT_HELLO_DATA_INDEX, hello);
}

/// Extract the raw extensions block from a ClientHello body (no 2-byte length prefix).
///
/// Skips: legacy_version (2) + random (32) + session_id + cipher_suites +
/// compression_methods, then returns the extensions payload without its length
/// prefix. Returns `Some(Arc::from(&[]))` for a valid ClientHello with no
/// extensions, and `None` for malformed/truncated input — callers treat `None`
/// as "JA4 unavailable" rather than "no extensions".
fn extract_extensions_bytes(body: &[u8]) -> Option<Arc<[u8]>> {
    // Skip legacy_version (2) + random (32)
    let after_fixed = body.get(34..)?;
    // Skip session_id (1-byte length + payload)
    let session_id_len = *after_fixed.first()? as usize;
    let after_session = after_fixed.get(1 + session_id_len..)?;
    // Skip cipher_suites (2-byte length + payload)
    let cipher_len = u16::from_be_bytes([*after_session.first()?, *after_session.get(1)?]) as usize;
    let after_ciphers = after_session.get(2 + cipher_len..)?;
    // Skip compression_methods (1-byte length + payload)
    let comp_len = *after_ciphers.first()? as usize;
    let after_comp = after_ciphers.get(1 + comp_len..)?;
    if after_comp.is_empty() {
        return Some(Arc::from(&[] as &[u8]));
    }
    // Read extensions length and return the payload (no length prefix).
    let ext_len = u16::from_be_bytes([*after_comp.first()?, *after_comp.get(1)?]) as usize;
    after_comp.get(2..2 + ext_len).map(Arc::from)
}

pub(crate) struct Acceptor {
    ssl_acceptor: SslAcceptor,
    callbacks: Option<SharedTlsAcceptCallbacks>,
    offload: Option<OffloadRuntime>,
}

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    accept_builder: SslAcceptorBuilder,
    callbacks: Option<TlsAcceptCallbacks>,
    offload_threadpool: Option<(usize, usize)>,
}

impl From<SslAcceptorBuilder> for TlsSettings {
    fn from(settings: SslAcceptorBuilder) -> Self {
        TlsSettings {
            accept_builder: settings,
            callbacks: None,
            offload_threadpool: None,
        }
    }
}

impl Deref for TlsSettings {
    type Target = SslAcceptorBuilder;

    fn deref(&self) -> &Self::Target {
        &self.accept_builder
    }
}

impl DerefMut for TlsSettings {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.accept_builder
    }
}

impl TlsSettings {
    /// Create a new [`TlsSettings`] with the [Mozilla Intermediate](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29)
    /// server side TLS settings. Users can adjust the TLS settings after this object is created.
    /// Return error if the provided certificate and private key are invalid or not found.
    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self> {
        let mut accept_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).or_err(
            TLS_CONF_ERR,
            "fail to create mozilla_intermediate_v5 Acceptor",
        )?;
        accept_builder
            .set_private_key_file(key_path, SslFiletype::PEM)
            .or_err_with(TLS_CONF_ERR, || format!("fail to read key file {key_path}"))?;
        accept_builder
            .set_certificate_chain_file(cert_path)
            .or_err_with(TLS_CONF_ERR, || {
                format!("fail to read cert file {cert_path}")
            })?;
        Ok(TlsSettings {
            accept_builder,
            callbacks: None,
            offload_threadpool: None,
        })
    }

    /// Create a new [`TlsSettings`] similar to [TlsSettings::intermediate()]. A struct that implements [TlsAcceptCallbacks]
    /// is needed to provide the certificate during the TLS handshake.
    pub fn with_callbacks(callbacks: TlsAcceptCallbacks) -> Result<Self> {
        let accept_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).or_err(
            TLS_CONF_ERR,
            "fail to create mozilla_intermediate_v5 Acceptor",
        )?;
        let mut settings = TlsSettings {
            accept_builder,
            callbacks: Some(callbacks),
            offload_threadpool: None,
        };
        settings
            .accept_builder
            .set_select_certificate_callback(|mut ch| {
                let body = ch.as_bytes();
                // The first 2 bytes of the ClientHello body are the legacy_version.
                let legacy_version = if body.len() >= 2 {
                    u16::from_be_bytes([body[0], body[1]])
                } else {
                    0
                };
                // None means malformed/truncated body — skip capture so JA4
                // is absent rather than incorrect (empty extension list).
                if let Some(extensions) = extract_extensions_bytes(body) {
                    let hello = TlsClientHello {
                        legacy_version,
                        cipher_suites: Arc::from(ch.ciphers()),
                        sni: ch.servername(NameType::HOST_NAME).map(|s| s.to_string()),
                        extensions,
                    };
                    set_client_hello_data(ch.ssl_mut(), hello);
                }
                Ok(())
            });
        Ok(settings)
    }

    /// Offload server-side TLS handshakes for this endpoint to dedicated
    /// single-threaded runtime pools.
    ///
    /// `shards` partitions accepted connections by connection id, and
    /// `threads_per_shard` controls how many single-threaded runtimes are
    /// available per shard. Both values must be greater than zero.
    ///
    /// # Panics
    ///
    /// Panics when either `shards` or `threads_per_shard` is zero.
    #[track_caller]
    pub fn set_offload_threadpool(&mut self, shards: usize, threads_per_shard: usize) {
        assert!(shards != 0, "shards must be greater than zero");
        assert!(
            threads_per_shard != 0,
            "threads_per_shard must be greater than zero"
        );
        self.offload_threadpool = Some((shards, threads_per_shard));
    }

    /// Offload server-side TLS handshakes using the downstream TLS offload
    /// settings in [`ServerConf`], when both values are set and non-zero.
    ///
    /// This helper lets callers wire configuration files into per-listener
    /// [`TlsSettings`]. If either configuration value is unset or zero,
    /// this method leaves handshake offload disabled.
    pub fn set_offload_threadpool_from_server_conf(&mut self, server_conf: &ServerConf) {
        if let Some((shards, threads_per_shard)) = server_conf.downstream_tls_offload_threadpool() {
            self.set_offload_threadpool(shards, threads_per_shard);
        }
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(ALPN::H2H1);
    }

    pub fn enable_h2_with_http2_check(
        &mut self,
        check_h2_h1: impl for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError>
            + 'static
            + Sync
            + Send,
        check_h2: impl for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError>
            + 'static
            + Sync
            + Send,
    ) {
        self.set_alpn_with_http2_check(ALPN::H2H1, check_h2_h1, check_h2);
    }

    /// Set the ALPN preference of this endpoint. See [`ALPN`] for more details
    pub fn set_alpn(&mut self, alpn: ALPN) {
        match alpn {
            ALPN::H2H1 => self
                .accept_builder
                .set_alpn_select_callback(alpn::prefer_h2),
            ALPN::H1 => self.accept_builder.set_alpn_select_callback(alpn::h1_only),
            ALPN::H2 => self.accept_builder.set_alpn_select_callback(alpn::h2_only),
            ALPN::Custom(custom) => {
                self.accept_builder
                    .set_alpn_select_callback(move |_, alpn_in| {
                        if !valid_alpn(alpn_in) {
                            return Err(AlpnError::NOACK);
                        }
                        match alpn::select_protocol(alpn_in, custom.protocol()) {
                            Some(p) => Ok(p),
                            None => Err(AlpnError::NOACK),
                        }
                    });
            }
        }
    }

    pub fn set_alpn_with_http2_check(
        &mut self,
        alpn: ALPN,
        check_h2_h1: impl for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError>
            + 'static
            + Sync
            + Send,
        check_h2: impl for<'a> Fn(&mut SslRef, &'a [u8]) -> Result<&'a [u8], AlpnError>
            + 'static
            + Sync
            + Send,
    ) {
        match alpn {
            ALPN::H2H1 => self.accept_builder.set_alpn_select_callback(check_h2_h1),
            ALPN::H1 => self.accept_builder.set_alpn_select_callback(alpn::h1_only),
            ALPN::H2 => self.accept_builder.set_alpn_select_callback(check_h2),
            ALPN::Custom(custom) => {
                self.accept_builder
                    .set_alpn_select_callback(move |_, alpn_in| {
                        if !valid_alpn(alpn_in) {
                            return Err(AlpnError::NOACK);
                        }
                        match alpn::select_protocol(alpn_in, custom.protocol()) {
                            Some(p) => Ok(p),
                            None => Err(AlpnError::NOACK),
                        }
                    });
            }
        }
    }

    pub(crate) fn build(self) -> Acceptor {
        Acceptor {
            ssl_acceptor: self.accept_builder.build(),
            callbacks: self.callbacks.map(SharedTlsAcceptCallbacks::from),
            offload: self.offload_threadpool.map(|(shards, threads_per_shard)| {
                OffloadRuntime::new("downstream TLS offload", shards, threads_per_shard)
            }),
        }
    }
}

impl Acceptor {
    pub async fn tls_handshake<S: IO + 'static>(&self, stream: S) -> Result<SslStream<S>> {
        debug!("new ssl session");
        if let Some(offload) = self.offload.as_ref() {
            let ssl_acceptor = self.ssl_acceptor.clone();
            let callbacks = self.callbacks.clone();
            let rt = offload.get_runtime(stream.id() as u64);
            rt.spawn(async move {
                if let Some(cb) = callbacks.as_ref() {
                    handshake_with_callback(&ssl_acceptor, stream, cb.as_ref()).await
                } else {
                    handshake(&ssl_acceptor, stream).await
                }
            })
            .await
            .or_err(InternalError, "TLS offload runtime failure")?
        } else if let Some(cb) = self.callbacks.as_ref() {
            handshake_with_callback(&self.ssl_acceptor, stream, cb.as_ref()).await
        } else {
            handshake(&self.ssl_acceptor, stream).await
        }
    }
}

pub mod alpn {
    use super::*;
    use crate::tls::ssl::{select_next_proto, AlpnError, SslRef};

    pub(super) fn valid_alpn(alpn_in: &[u8]) -> bool {
        if alpn_in.is_empty() {
            return false;
        }
        // TODO: can add more thorough validation here.
        true
    }

    /// Finds the first protocol in the client-offered ALPN list that matches the given protocol.
    ///
    /// This is a helper for ALPN negotiation. It iterates over the client's protocol list
    /// (in wire format) and returns the first protocol that matches proto
    /// The returned reference always points into `client_protocols`, so lifetimes are correct.
    pub(super) fn select_protocol<'a>(
        client_protocols: &'a [u8],
        proto: &[u8],
    ) -> Option<&'a [u8]> {
        let mut bytes = client_protocols;
        while !bytes.is_empty() {
            let len = bytes[0] as usize;
            bytes = &bytes[1..];
            if len == proto.len() && &bytes[..len] == proto {
                return Some(&bytes[..len]);
            }
            bytes = &bytes[len..];
        }
        None
    }

    // A standard implementation provided by the SSL lib is used below

    pub fn prefer_h2<'a>(_ssl: &mut SslRef, alpn_in: &'a [u8]) -> Result<&'a [u8], AlpnError> {
        if !valid_alpn(alpn_in) {
            return Err(AlpnError::NOACK);
        }
        match select_next_proto(ALPN::H2H1.to_wire_preference(), alpn_in) {
            Some(p) => Ok(p),
            _ => Err(AlpnError::NOACK), // unknown ALPN, just ignore it. Most clients will fallback to h1
        }
    }

    pub fn h1_only<'a>(_ssl: &mut SslRef, alpn_in: &'a [u8]) -> Result<&'a [u8], AlpnError> {
        if !valid_alpn(alpn_in) {
            return Err(AlpnError::NOACK);
        }
        match select_next_proto(ALPN::H1.to_wire_preference(), alpn_in) {
            Some(p) => Ok(p),
            _ => Err(AlpnError::NOACK), // unknown ALPN, just ignore it. Most clients will fallback to h1
        }
    }

    pub fn h2_only<'a>(_ssl: &mut SslRef, alpn_in: &'a [u8]) -> Result<&'a [u8], AlpnError> {
        if !valid_alpn(alpn_in) {
            return Err(AlpnError::ALERT_FATAL);
        }
        match select_next_proto(ALPN::H2.to_wire_preference(), alpn_in) {
            Some(p) => Ok(p),
            _ => Err(AlpnError::ALERT_FATAL), // cannot agree
        }
    }
}
