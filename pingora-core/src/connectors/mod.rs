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

//! Connecting to servers

pub mod http;
pub mod l4;
#[cfg(feature = "any_tls")]
mod tls;

#[cfg(not(feature = "any_tls"))]
use crate::tls::connectors as tls;

use crate::protocols::l4::ext::attach_connect_local_addr;
use crate::protocols::{GetSocketDigest, Rebind, Stream};
use crate::server::configuration::ServerConf;
use crate::upstreams::peer::{Peer, ALPN};

use crate::offload::OffloadRuntime;
pub use l4::Connect as L4Connect;
use l4::{connect as l4_connect, BindTo};
use log::{debug, error, warn};
use parking_lot::RwLock;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_pool::{ConnectionMeta, ConnectionPool};
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tls::TlsConnector;
use tokio::sync::{Mutex, OwnedMutexGuard};

#[derive(Clone, Debug)]
pub(crate) struct IdleConnection {
    connection: ConnectionMeta,
    idle_since: Instant,
}

impl IdleConnection {
    pub(crate) fn new(connection: ConnectionMeta) -> Self {
        Self {
            connection,
            idle_since: Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.idle_since.elapsed()
    }
}

/// Callback invoked when an idle upstream connection leaves the keep-alive pool
/// without being reused.
pub type PoolCallback = Arc<dyn Fn(Duration) + Send + Sync>;

/// The options to configure a [TransportConnector]
#[derive(Clone)]
pub struct ConnectorOptions {
    /// Path to the CA file used to validate server certs.
    ///
    /// If `None`, the CA in the [default](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_default_verify_paths.html)
    /// locations will be loaded
    pub ca_file: Option<String>,
    /// The maximum number of unique s2n configs to cache. Creating a new s2n config is an
    /// expensive operation, so we cache and re-use config objects with identical configurations.
    /// Defaults to a cache size of 10. A value of 0 disables the cache.
    ///
    /// WARNING: Disabling the s2n config cache can result in poor performance
    #[cfg(feature = "s2n")]
    pub s2n_config_cache_size: Option<usize>,
    /// The default client cert and key to use for mTLS
    ///
    /// Each individual connection can use their own cert key to override this.
    pub cert_key_file: Option<(String, String)>,
    /// When enabled allows TLS keys to be written to a file specified by the SSLKEYLOG
    /// env variable. This can be used by tools like Wireshark to decrypt traffic
    /// for debugging purposes.
    pub debug_ssl_keylog: bool,
    /// Effective global cap for the keepalive pool. Derived from
    /// `server_conf.upstream_keepalive_pool_size * server_conf.threads`
    /// in [`Self::from_server_conf`] so that operator-facing config keeps
    /// its per-worker meaning even though the pool itself now uses a single
    /// global LRU.
    pub keepalive_pool_size: usize,
    /// Optionally offload the connection establishment to dedicated thread pools
    ///
    /// TCP and TLS connection establishment can be CPU intensive. Sometimes such tasks can slow
    /// down the entire service, which causes timeouts which leads to more connections which
    /// snowballs the issue. Use this option to isolate these CPU intensive tasks from impacting
    /// other traffic.
    ///
    /// Syntax: (#pools, #thread in each pool)
    pub offload_threadpool: Option<(usize, usize)>,
    /// Bind to any of the given source IPv6 addresses
    pub bind_to_v4: Vec<SocketAddr>,
    /// Bind to any of the given source IPv4 addresses
    pub bind_to_v6: Vec<SocketAddr>,
    /// Optional callback for observing how long upstream connections stayed idle
    /// before leaving the keep-alive pool without reuse.
    pub keepalive_pool_callback: Option<PoolCallback>,
    /// How long a released connection stays in the per-worker L1 cache. Zero
    /// disables L1 and releases straight to the shared pool.
    pub l1_window: Duration,
    /// Maximum connections held per worker in L1.
    pub l1_capacity: usize,
}

impl ConnectorOptions {
    /// Derive the [ConnectorOptions] from a [ServerConf]
    pub fn from_server_conf(server_conf: &ServerConf) -> Self {
        // create SocketAddrs with port 0 for src addr bind

        let bind_to_v4 = server_conf
            .client_bind_to_ipv4
            .iter()
            .map(|v4| {
                let ip = v4.parse().unwrap();
                SocketAddr::new(ip, 0)
            })
            .collect();

        let bind_to_v6 = server_conf
            .client_bind_to_ipv6
            .iter()
            .map(|v6| {
                let ip = v6.parse().unwrap();
                SocketAddr::new(ip, 0)
            })
            .collect();
        ConnectorOptions {
            ca_file: server_conf.ca_file.clone(),
            cert_key_file: None, // TODO: use it
            #[cfg(feature = "s2n")]
            s2n_config_cache_size: server_conf.s2n_config_cache_size,
            debug_ssl_keylog: server_conf.upstream_debug_ssl_keylog,
            keepalive_pool_size: server_conf
                .upstream_keepalive_pool_size
                .saturating_mul(server_conf.threads.max(1)),
            offload_threadpool: server_conf.upstream_connect_offload_threadpool(),
            bind_to_v4,
            bind_to_v6,
            keepalive_pool_callback: None,
            l1_window: Duration::from_millis(server_conf.upstream_pool_l1_window_millis),
            l1_capacity: server_conf.upstream_pool_l1_capacity,
        }
    }

    /// Create a new [ConnectorOptions] with the given keepalive pool size
    pub fn new(keepalive_pool_size: usize) -> Self {
        ConnectorOptions {
            ca_file: None,
            #[cfg(feature = "s2n")]
            s2n_config_cache_size: None,
            cert_key_file: None,
            debug_ssl_keylog: false,
            keepalive_pool_size,
            offload_threadpool: None,
            bind_to_v4: vec![],
            bind_to_v6: vec![],
            keepalive_pool_callback: None,
            l1_window: Duration::ZERO,
            l1_capacity: 0,
        }
    }
}

/// A pooled connection plus the runtime whose IO driver currently holds its
/// registration. Taking it on another runtime rebinds it.
struct OwnerStream {
    stream: Stream,
    runtime: tokio::runtime::Id,
}

impl std::fmt::Debug for OwnerStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerStream")
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl tokio::io::AsyncRead for OwnerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

/// Pool reuse counters, all monotonic and cheap to read at scrape time.
#[derive(Default)]
pub struct PoolCounters {
    l1_hit: AtomicU64,
    l2_hit: AtomicU64,
    l1_expired: AtomicU64,
    rebind: AtomicU64,
}

impl PoolCounters {
    pub fn l1_hit(&self) -> u64 {
        self.l1_hit.load(Ordering::Relaxed)
    }
    pub fn l2_hit(&self) -> u64 {
        self.l2_hit.load(Ordering::Relaxed)
    }
    pub fn l1_expired(&self) -> u64 {
        self.l1_expired.load(Ordering::Relaxed)
    }
    pub fn rebind_count(&self) -> u64 {
        self.rebind.load(Ordering::Relaxed)
    }
}

struct L1Entry {
    key: u64,
    stream: OwnerStream,
    idle_timeout: Option<Duration>,
    released_at: Instant,
}

impl L1Entry {
    /// When the entry must leave L1: the idle deadline or the window, whichever is first.
    fn deadline(&self, window: Duration) -> Instant {
        self.released_at + self.idle_timeout.map_or(window, |idle| idle.min(window))
    }
}

fn idle_deadline_passed(idle_timeout: Option<Duration>, released_at: Instant) -> bool {
    idle_timeout.is_some_and(|timeout| released_at.elapsed() >= timeout)
}

/// One connector's L1 state on one worker thread.
#[derive(Default)]
struct L1Bucket {
    entries: Vec<L1Entry>,
    /// L1 hits not yet added to the shared counter.
    pending_hits: u64,
    hits_since: Option<Instant>,
    /// The runtime running this bucket's sweeper, and the sweeper itself.
    sweeper: Option<(tokio::runtime::Id, tokio::task::AbortHandle)>,
}

thread_local! {
    static L1: RefCell<HashMap<u64, L1Bucket>> = RefCell::new(HashMap::new());
}

static NEXT_CONNECTOR_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_REBIND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn fail_next_rebind() {
    FAIL_NEXT_REBIND.with(|flag| flag.set(true));
}

fn remaining_idle_timeout(
    idle_timeout: Option<Duration>,
    released_at: Instant,
) -> Option<Duration> {
    idle_timeout.map(|timeout| timeout.saturating_sub(released_at.elapsed()))
}

type PooledSlot = Arc<Mutex<Option<OwnerStream>>>;
type SharedPool = Arc<ConnectionPool<PooledSlot>>;

fn rebind_stream(stream: &mut Stream) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_REBIND.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::other("injected rebind failure"));
    }
    Rebind::rebind(&mut **stream)
}

/// Move a pooled stream onto the current IO driver if another runtime owns it.
fn rebind_if_needed(stream: &mut OwnerStream, counters: &PoolCounters) -> bool {
    let current = tokio::runtime::Handle::current().id();
    if stream.runtime == current {
        return true;
    }
    if rebind_stream(&mut stream.stream).is_err() {
        debug!("failed to rebind pooled stream; dropping it");
        return false;
    }
    stream.runtime = current;
    counters.rebind.fetch_add(1, Ordering::Relaxed);
    true
}

/// L1 windows above this are clamped, keeping every deadline computation in range.
const MAX_L1_WINDOW: Duration = Duration::from_secs(3600);

/// The shared pool with its callback and counters.
#[derive(Clone)]
struct PoolHandles {
    pool: SharedPool,
    callback: Option<PoolCallback>,
    counters: Arc<PoolCounters>,
}

impl PoolHandles {
    /// Park `stream` in the shared pool; `idle_since` is when it last went idle.
    fn release(
        &self,
        mut stream: OwnerStream,
        key: u64,
        idle_timeout: Option<Duration>,
        idle_since: Instant,
    ) {
        // The watcher below is spawned on this runtime, so the stream's registration
        // must belong to it too.
        if !rebind_if_needed(&mut stream, &self.counters) {
            return;
        }
        let meta = ConnectionMeta::new(key, stream.stream.id());
        let pooled: PooledSlot = Arc::new(Mutex::new(None));
        let locked_stream = OwnedMutexGuard::map(
            pooled
                .clone()
                .try_lock_owned()
                .expect("newly created mutex must be unlocked"),
            |slot| slot.insert(stream),
        );
        let (notify_close, watch_use) = self.pool.put(&meta, pooled);
        let pool = Arc::clone(&self.pool);
        let callback = self.callback.clone();
        tokio::runtime::Handle::current().spawn(async move {
            if pool
                .idle_poll(locked_stream, &meta, idle_timeout, notify_close, watch_use)
                .await
            {
                if let Some(callback) = callback {
                    callback(idle_since.elapsed());
                }
            }
        });
    }

    fn release_entry(&self, entry: L1Entry) {
        let remaining = remaining_idle_timeout(entry.idle_timeout, entry.released_at);
        self.release(entry.stream, entry.key, remaining, entry.released_at);
    }

    /// An entry whose L1 hold ended: close it past its idle deadline, else hand it to L2.
    fn expire(&self, entry: L1Entry) {
        self.counters.l1_expired.fetch_add(1, Ordering::Relaxed);
        if !idle_deadline_passed(entry.idle_timeout, entry.released_at) {
            return self.release_entry(entry);
        }
        if let Some(callback) = &self.callback {
            callback(entry.released_at.elapsed());
        }
    }
}

fn earliest(wake: &mut Option<Instant>, at: Instant) {
    *wake = Some(wake.map_or(at, |wake| wake.min(at)));
}

/// Expires one worker's L1 entries and flushes its L1 hit count, until the bucket has neither
/// or the connector is dropped.
async fn sweep_l1(id: u64, window: Duration, handles: PoolHandles, connector: Weak<()>) {
    loop {
        let now = Instant::now();
        let gone = connector.strong_count() == 0;
        let mut expired = Vec::new();
        let (flush, wake) = L1.with(|cache| {
            let mut cache = cache.borrow_mut();
            let Some(bucket) = cache.get_mut(&id) else {
                return (0, None);
            };
            let mut wake = None;
            for entry in std::mem::take(&mut bucket.entries) {
                let deadline = entry.deadline(window);
                if gone {
                    continue;
                }
                if deadline > now {
                    earliest(&mut wake, deadline);
                    bucket.entries.push(entry);
                } else {
                    expired.push(entry);
                }
            }
            let mut flush = 0;
            if let Some(since) = bucket.hits_since {
                let at = since + window;
                if gone || at <= now {
                    bucket.hits_since = None;
                    flush = std::mem::take(&mut bucket.pending_hits);
                } else {
                    earliest(&mut wake, at);
                }
            }
            if wake.is_none() {
                cache.remove(&id);
            }
            (flush, wake)
        });
        if flush > 0 {
            handles.counters.l1_hit.fetch_add(flush, Ordering::Relaxed);
        }
        for entry in expired {
            handles.expire(entry);
        }
        let Some(at) = wake else {
            return;
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
    }
}

/// [TransportConnector] provides APIs to connect to servers via TCP or TLS with connection reuse
pub struct TransportConnector {
    tls_ctx: tls::Connector,
    /// The stream is taken out of the `Option` when the connection is reused.
    pool: PoolHandles,
    offload: Option<OffloadRuntime>,
    bind_to_v4: Vec<SocketAddr>,
    bind_to_v6: Vec<SocketAddr>,
    preferred_http_version: PreferredHttpVersion,
    /// Wrapped in `Arc` so external consumers (e.g. proxy services) can clone a reference
    /// for periodic metric reporting without needing access to the connector itself.
    unexpected_data_conn_count: Arc<AtomicU64>,
    l1_window: Duration,
    l1_capacity: usize,
    id: u64,
    /// Weakly held by the L1 sweepers, which end when the connector is dropped.
    alive: Arc<()>,
}

const DEFAULT_POOL_SIZE: usize = 128;

impl TransportConnector {
    /// Create a new [TransportConnector] with the given [ConnectorOptions]
    pub fn new(mut options: Option<ConnectorOptions>) -> Self {
        let pool_size = options
            .as_ref()
            .map_or(DEFAULT_POOL_SIZE, |c| c.keepalive_pool_size);
        // Take the offloading setting there because this layer has implement offloading,
        // so no need for stacks at lower layer to offload again.
        let offload = options.as_mut().and_then(|o| o.offload_threadpool.take());
        let bind_to_v4 = options
            .as_ref()
            .map_or_else(Vec::new, |o| o.bind_to_v4.clone());
        let bind_to_v6 = options
            .as_ref()
            .map_or_else(Vec::new, |o| o.bind_to_v6.clone());
        let keepalive_pool_callback = options
            .as_ref()
            .and_then(|o| o.keepalive_pool_callback.clone());
        let l1_window = options
            .as_ref()
            .map_or(Duration::ZERO, |o| o.l1_window.min(MAX_L1_WINDOW));
        let l1_capacity = options.as_ref().map_or(0, |o| o.l1_capacity);
        TransportConnector {
            tls_ctx: tls::Connector::new(options),
            pool: PoolHandles {
                pool: Arc::new(ConnectionPool::new(pool_size)),
                callback: keepalive_pool_callback,
                counters: Arc::new(PoolCounters::default()),
            },
            offload: offload.map(|v| OffloadRuntime::new("upstream connect offload", v.0, v.1)),
            bind_to_v4,
            bind_to_v6,
            preferred_http_version: PreferredHttpVersion::new(),
            unexpected_data_conn_count: Arc::new(AtomicU64::new(0)),
            l1_window,
            l1_capacity,
            id: NEXT_CONNECTOR_ID.fetch_add(1, Ordering::Relaxed),
            alive: Arc::new(()),
        }
    }

    /// Connect to the given server [Peer]
    ///
    /// No connection is reused.
    pub async fn new_stream<P: Peer + Send + Sync + 'static>(&self, peer: &P) -> Result<Stream> {
        let rt = self
            .offload
            .as_ref()
            .map(|o| o.get_runtime(peer.reuse_hash()));
        let bind_to = l4::bind_to_random(peer, &self.bind_to_v4, &self.bind_to_v6);
        let alpn_override = self.preferred_http_version.get(peer);
        let stream = if let Some(rt) = rt {
            let peer = peer.clone();
            let tls_ctx = self.tls_ctx.clone();
            let offload_start = Instant::now();
            let mut stream = rt
                .spawn(async move {
                    let offload_wait = offload_start.elapsed();
                    do_connect(
                        &peer,
                        bind_to,
                        alpn_override,
                        &tls_ctx.ctx,
                        Some(offload_wait),
                    )
                    .await
                })
                .await
                .or_err(InternalError, "offload runtime failure")??;
            // The offload runtime owns the registration; move it to the caller's
            // runtime, which is the owner `release_stream` stamps.
            rebind_stream(&mut stream)
                .or_err(InternalError, "failed to rebind offloaded connection")?;
            stream
        } else {
            do_connect(peer, bind_to, alpn_override, &self.tls_ctx.ctx, None).await?
        };

        Ok(stream)
    }

    /// Try to find a reusable connection to the given server [Peer]
    pub async fn reused_stream<P: Peer + Send + Sync>(&self, peer: &P) -> Option<Stream> {
        if peer
            .get_peer_options()
            .is_some_and(|o| o.disable_keepalive_reuse)
        {
            return None;
        }
        if self.l1_is_active() {
            if let Some(stream) = self.take_from_l1(peer) {
                return Some(stream);
            }
        }
        match self.pool.pool.get(&peer.reuse_hash()) {
            Some(s) => {
                debug!("find reusable stream, trying to acquire it");
                // Wait for the idle poll to release the stream, then move it out under the lock.
                // The idle poll's guard keeps its own `Arc` for a moment after unlocking, so
                // `Arc::try_unwrap` here could still see a second owner.
                let stream = s.lock().await.take();
                match stream {
                    Some(owned) => self.adopt(peer, owned).inspect(|_| {
                        self.pool.counters.l2_hit.fetch_add(1, Ordering::Relaxed);
                    }),
                    None => {
                        // Unreachable: `pool.get()` hands each pooled entry to exactly one caller,
                        // and only this function takes the stream out of the slot.
                        error!("reusable stream was already taken");
                        None
                    }
                }
            }
            None => {
                debug!("No reusable connection found for {peer}");
                None
            }
        }
    }

    fn l1_is_active(&self) -> bool {
        self.l1_window > Duration::ZERO
            && self.l1_capacity > 0
            && tokio::runtime::Handle::try_current().is_ok_and(|handle| {
                handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread
            })
    }

    /// Check a pooled stream against the peer and the wire, then move it onto this runtime.
    fn adopt<P: Peer + Send + Sync>(&self, peer: &P, mut owned: OwnerStream) -> Option<Stream> {
        if !peer_matches(peer, &owned.stream) {
            return None;
        }
        // Probe before the rebind: a socket registered just now has no cached readiness, so a
        // probe after it would not see a close or unexpected data.
        let foreign = owned.runtime != tokio::runtime::Handle::current().id();
        match probe_idle(&mut owned.stream, &self.unexpected_data_conn_count) {
            IdleProbe::Reusable => {}
            // The owner's driver is gone, so its readiness cannot be read; the rebind decides.
            IdleProbe::DriverGone if foreign => {}
            _ => return None,
        }
        rebind_if_needed(&mut owned, &self.pool.counters).then_some(owned.stream)
    }

    fn take_from_l1<P: Peer + Send + Sync>(&self, peer: &P) -> Option<Stream> {
        let key = peer.reuse_hash();
        let entry = L1.with(|cache| {
            let mut cache = cache.borrow_mut();
            let bucket = cache.get_mut(&self.id)?;
            let index = bucket.entries.iter().position(|entry| entry.key == key)?;
            Some(bucket.entries.remove(index))
        })?;
        if idle_deadline_passed(entry.idle_timeout, entry.released_at) {
            // A take must never hand out a connection past its idle budget.
            self.pool.expire(entry);
            return None;
        }
        // Past the window but inside the idle deadline is still a hit: the sweeper only
        // bounds how long an unused entry stays local.
        let stream = self.adopt(peer, entry.stream)?;
        self.record_l1_hit();
        Some(stream)
    }

    fn record_l1_hit(&self) {
        let runtime = tokio::runtime::Handle::current().id();
        L1.with(|cache| {
            let mut cache = cache.borrow_mut();
            let bucket = cache.entry(self.id).or_default();
            bucket.pending_hits = bucket.pending_hits.saturating_add(1);
            bucket.hits_since.get_or_insert_with(Instant::now);
            self.ensure_sweeper(bucket, runtime);
        });
    }

    fn ensure_sweeper(&self, bucket: &mut L1Bucket, runtime: tokio::runtime::Id) {
        if bucket
            .sweeper
            .as_ref()
            .is_some_and(|(id, _)| *id == runtime)
        {
            return;
        }
        if let Some((_, stale)) = bucket.sweeper.take() {
            stale.abort();
        }
        let task = tokio::spawn(sweep_l1(
            self.id,
            self.l1_window,
            self.pool.clone(),
            Arc::downgrade(&self.alive),
        ));
        bucket.sweeper = Some((runtime, task.abort_handle()));
    }

    /// Return the [Stream] to the [TransportConnector] for connection reuse.
    ///
    /// Not all TCP/TLS connections can be reused. It is the caller's responsibility to make sure
    /// that protocol over the [Stream] supports connection reuse and the [Stream] itself is ready
    /// to be reused.
    ///
    /// If a [Stream] is dropped instead of being returned via this function. it will be closed.
    pub fn release_stream(
        &self,
        mut stream: Stream,
        key: u64, // usually peer.reuse_hash()
        idle_timeout: Option<Duration>,
    ) {
        if !test_reusable_stream(&mut stream, &self.unexpected_data_conn_count) {
            return;
        }
        let runtime = tokio::runtime::Handle::current().id();
        let owned = OwnerStream { stream, runtime };
        let released_at = Instant::now();
        if !self.l1_is_active() {
            self.pool.release(owned, key, idle_timeout, released_at);
            return;
        }
        let evicted = L1.with(|cache| {
            let mut cache = cache.borrow_mut();
            let bucket = cache.entry(self.id).or_default();
            let evicted =
                (bucket.entries.len() >= self.l1_capacity).then(|| bucket.entries.remove(0));
            bucket.entries.push(L1Entry {
                key,
                stream: owned,
                idle_timeout,
                released_at,
            });
            self.ensure_sweeper(bucket, runtime);
            evicted
        });
        if let Some(entry) = evicted {
            self.pool.release_entry(entry);
        }
    }

    /// Access the pool reuse counters.
    pub fn pool_counters(&self) -> Arc<PoolCounters> {
        Arc::clone(&self.pool.counters)
    }

    #[cfg(test)]
    fn l1_bucket<T>(&self, read: impl FnOnce(Option<&L1Bucket>) -> T) -> T {
        L1.with(|cache| read(cache.borrow().get(&self.id)))
    }

    /// Number of L1 hits counted on this worker since the last flush.
    #[cfg(test)]
    pub fn pending_l1_hits(&self) -> u64 {
        self.l1_bucket(|bucket| bucket.map_or(0, |bucket| bucket.pending_hits))
    }

    /// Replace the pool reuse counters with a shared instance.
    pub fn set_pool_counters(&mut self, counters: Arc<PoolCounters>) {
        self.pool.counters = counters;
    }

    /// Get a stream to the given server [Peer]
    ///
    /// This function will try to find a reusable [Stream] first. If there is none, a new connection
    /// will be made to the server.
    ///
    /// The returned boolean will indicate whether the stream is reused.
    pub async fn get_stream<P: Peer + Send + Sync + 'static>(
        &self,
        peer: &P,
    ) -> Result<(Stream, bool)> {
        let reused_stream = self.reused_stream(peer).await;
        if let Some(s) = reused_stream {
            Ok((s, true))
        } else {
            let s = self.new_stream(peer).await?;
            Ok((s, false))
        }
    }

    /// Tell the connector to always send h1 for ALPN for the given peer in the future.
    pub fn prefer_h1(&self, peer: &impl Peer) {
        self.preferred_http_version.add(peer, 1);
    }

    /// Return the number of times a pooled connection was found to contain unexpected data
    /// from the server.
    pub fn unexpected_data_connection_count(&self) -> u64 {
        self.unexpected_data_conn_count.load(Ordering::Relaxed)
    }

    /// Return a shared reference to the unexpected data connection counter.
    ///
    /// This allows external consumers (e.g. proxy services) to clone the `Arc` and
    /// periodically read the counter for metric reporting without needing ongoing
    /// access to the connector.
    pub fn unexpected_data_connection_counter(&self) -> Arc<AtomicU64> {
        self.unexpected_data_conn_count.clone()
    }
}

// Perform the actual L4 and tls connection steps while respecting the peer's
// connection timeout if there is one
async fn do_connect<P: Peer + Send + Sync>(
    peer: &P,
    bind_to: Option<BindTo>,
    alpn_override: Option<ALPN>,
    tls_ctx: &TlsConnector,
    offload_wait_duration: Option<Duration>,
) -> Result<Stream> {
    // Create the future that does the connections, but don't evaluate it until
    // we decide if we need a timeout or not
    let connect_future =
        do_connect_inner(peer, bind_to, alpn_override, tls_ctx, offload_wait_duration);

    match peer.total_connection_timeout() {
        Some(t) => match pingora_timeout::timeout(t, connect_future).await {
            Ok(res) => res,
            Err(_) => Error::e_explain(
                ConnectTimedout,
                format!("connecting to server {peer}, total-connection timeout {t:?}"),
            ),
        },
        None => connect_future.await,
    }
}

// Perform the actual L4 and tls connection steps with no timeout
async fn do_connect_inner<P: Peer + Send + Sync>(
    peer: &P,
    bind_to: Option<BindTo>,
    alpn_override: Option<ALPN>,
    tls_ctx: &TlsConnector,
    offload_wait_duration: Option<Duration>,
) -> Result<Stream> {
    let l4_connect_start = Instant::now();
    let mut stream = l4_connect(peer, bind_to).await?;
    stream.set_establishment_timing(l4_connect_start.elapsed(), offload_wait_duration);
    if peer.tls() {
        // Capture the local address before the handshake consumes the stream, so a TLS failure
        // can still report the address we connected from.
        // Arc clone plus a copy of the small SocketAddr, negligible next to the handshake.
        let local_addr = stream
            .get_socket_digest()
            .and_then(|digest| digest.local_addr().and_then(|addr| addr.as_inet()).copied());
        let tls_stream = tls::connect(stream, peer, alpn_override, tls_ctx)
            .await
            .map_err(|e| attach_connect_local_addr(e, local_addr))?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
}

struct PreferredHttpVersion {
    // TODO: shard to avoid the global lock
    versions: RwLock<HashMap<u64, u8>>, // <hash of peer, version>
}

// TODO: limit the size of this

impl PreferredHttpVersion {
    pub fn new() -> Self {
        PreferredHttpVersion {
            versions: RwLock::default(),
        }
    }

    pub fn add(&self, peer: &impl Peer, version: u8) {
        let key = peer.reuse_hash();
        let mut v = self.versions.write();
        v.insert(key, version);
    }

    pub fn get(&self, peer: &impl Peer) -> Option<ALPN> {
        let key = peer.reuse_hash();
        let v = self.versions.read();
        v.get(&key)
            .copied()
            .map(|v| if v == 1 { ALPN::H1 } else { ALPN::H2H1 })
    }
}

use futures::future::FutureExt;
use tokio::io::AsyncReadExt;

#[derive(PartialEq)]
enum IdleProbe {
    Reusable,
    Unusable,
    /// The read failed because the registration's runtime was shut down, not the socket.
    DriverGone,
}

/// Probe whether an idle stream is already closed or got unexpected data from the server.
fn probe_idle(stream: &mut Stream, unexpected_data_conn_count: &AtomicU64) -> IdleProbe {
    let mut buf = [0; 1];
    // tokio::task::unconstrained because now_or_never may yield None when the future is ready
    let result = tokio::task::unconstrained(stream.read(&mut buf[..])).now_or_never();
    match result {
        None => return IdleProbe::Reusable,
        Some(Ok(0)) => debug!("Idle connection is closed"),
        Some(Ok(_)) => {
            warn!("Unexpected data read in idle connection");
            unexpected_data_conn_count.fetch_add(1, Ordering::Relaxed);
        }
        Some(Err(e)) if e.raw_os_error().is_none() && e.kind() == std::io::ErrorKind::Other => {
            return IdleProbe::DriverGone;
        }
        Some(Err(e)) => debug!("Idle connection is broken: {e:?}"),
    }
    IdleProbe::Unusable
}

fn test_reusable_stream(stream: &mut Stream, unexpected_data_conn_count: &AtomicU64) -> bool {
    probe_idle(stream, unexpected_data_conn_count) == IdleProbe::Reusable
}

#[cfg(unix)]
fn peer_matches(peer: &impl Peer, stream: &Stream) -> bool {
    peer.matches_fd(stream.id())
}

#[cfg(windows)]
fn peer_matches(peer: &impl Peer, stream: &Stream) -> bool {
    use std::os::windows::io::{AsRawSocket, RawSocket};
    struct WrappedRawSocket(RawSocket);
    impl AsRawSocket for WrappedRawSocket {
        fn as_raw_socket(&self) -> RawSocket {
            self.0
        }
    }
    peer.matches_sock(WrappedRawSocket(stream.id() as RawSocket))
}

/// Test utilities for creating mock acceptors.
#[cfg(all(test, unix))]
pub(crate) mod test_utils {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    /// Generates a unique socket path for testing to avoid conflicts when running in parallel
    pub fn unique_uds_path(test_name: &str) -> String {
        format!(
            "/tmp/test_{test_name}_{:?}_{}.sock",
            std::thread::current().id(),
            std::process::id()
        )
    }

    /// A mock UDS server that accepts one connection, sends data, and waits for shutdown signal
    ///
    /// Returns: (ready_rx, shutdown_tx, server_handle)
    /// - ready_rx: Wait on this to know when server is ready to accept connections
    /// - shutdown_tx: Send on this to tell server to shut down
    /// - server_handle: Join handle for the server task
    pub fn spawn_mock_uds_server(
        socket_path: String,
        response: &'static [u8],
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_handle = tokio::spawn(async move {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).unwrap();
            // Signal that the server is ready to accept connections
            let _ = ready_tx.send(());

            if let Ok((mut stream, _addr)) = listener.accept().await {
                let _ = stream.write_all(response).await;
                // Keep the connection open until the test tells us to shutdown
                let _ = shutdown_rx.await;
            }
            let _ = std::fs::remove_file(&socket_path);
        });

        (ready_rx, shutdown_tx, server_handle)
    }

    /// A mock UDS server that immediately closes connections (for testing error handling)
    ///
    /// Returns: (ready_rx, shutdown_tx, server_handle)
    pub fn spawn_mock_uds_server_close_immediate(
        socket_path: String,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_handle = tokio::spawn(async move {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).unwrap();
            // Signal that the server is ready to accept connections
            let _ = ready_tx.send(());

            if let Ok((mut stream, _addr)) = listener.accept().await {
                let _ = stream.shutdown().await;
                // Wait for shutdown signal before cleaning up
                let _ = shutdown_rx.await;
            }
            let _ = std::fs::remove_file(&socket_path);
        });

        (ready_rx, shutdown_tx, server_handle)
    }
}

#[cfg(test)]
#[cfg(feature = "any_tls")]
mod tests {
    use std::time::Duration;

    use pingora_error::ErrorType;
    use tls::Connector;

    use super::*;
    use crate::protocols::Rebind;
    use crate::upstreams::peer::BasicPeer;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_connect() {
        let connector = TransportConnector::new(None);
        let peer = BasicPeer::new("1.1.1.1:80");
        // make a new connection to 1.1.1.1
        let stream = connector.new_stream(&peer).await.unwrap();
        let timing = stream.get_timing_digest();
        assert_eq!(timing.len(), 1);
        let l4_timing = timing[0].as_ref().unwrap();
        assert!(l4_timing.establishment_duration.is_some());
        assert!(l4_timing.offload_wait_duration.is_none());
        connector.release_stream(stream, peer.reuse_hash(), None);

        let (_, reused) = connector.get_stream(&peer).await.unwrap();
        assert!(reused);
    }

    #[tokio::test]
    async fn test_connect_with_offload_timing() {
        let mut conf = ConnectorOptions::new(1);
        conf.offload_threadpool = Some((1, 1));
        let connector = TransportConnector::new(Some(conf));
        let peer = BasicPeer::new("1.1.1.1:80");

        let stream = connector.new_stream(&peer).await.unwrap();
        let timing = stream.get_timing_digest();
        let l4_timing = timing[0].as_ref().unwrap();
        assert!(l4_timing.establishment_duration.is_some());
        assert!(l4_timing.offload_wait_duration.is_some());
    }

    #[tokio::test]
    async fn test_connect_tls() {
        let connector = TransportConnector::new(None);
        let mut peer = BasicPeer::new("1.1.1.1:443");
        // BasicPeer will use tls when SNI is set
        peer.sni = "one.one.one.one".to_string();
        // make a new connection to https://1.1.1.1
        let stream = connector.new_stream(&peer).await.unwrap();
        let timing = stream.get_timing_digest();
        assert_eq!(timing.len(), 2);
        let l4_timing = timing[0].as_ref().unwrap();
        assert!(l4_timing.establishment_duration.is_some());
        assert!(l4_timing.offload_wait_duration.is_none());
        let tls_timing = timing[1].as_ref().unwrap();
        assert!(tls_timing.establishment_duration.is_some());
        assert!(tls_timing.offload_wait_duration.is_none());
        connector.release_stream(stream, peer.reuse_hash(), None);

        let (_, reused) = connector.get_stream(&peer).await.unwrap();
        assert!(reused);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(unix)]
    async fn test_connect_uds() {
        let socket_path = test_utils::unique_uds_path("transport_connector");
        let (ready_rx, shutdown_tx, server_handle) =
            test_utils::spawn_mock_uds_server(socket_path.clone(), b"it works!");

        // Wait for the server to be ready before connecting
        ready_rx.await.unwrap();

        // create a new service at /tmp
        let connector = TransportConnector::new(None);
        let peer = BasicPeer::new_uds(&socket_path).unwrap();
        // make a new connection to mock uds
        let mut stream = connector.new_stream(&peer).await.unwrap();
        let mut buf = [0; 9];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"it works!");

        // Test connection reuse by releasing and getting the stream back
        connector.release_stream(stream, peer.reuse_hash(), None);
        let (stream, reused) = connector.get_stream(&peer).await.unwrap();
        assert!(reused);

        // Clean up: drop the stream, tell server to shutdown, and wait for it
        drop(stream);
        let _ = shutdown_tx.send(());
        server_handle.await.unwrap();
    }

    /// Wakes the test when the idle watcher's unlock wakes the pickup, then blocks the
    /// watcher's thread until the test has polled the pickup again.
    struct StallingWaker {
        woken: std::sync::mpsc::SyncSender<()>,
        resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl std::task::Wake for StallingWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let _ = self.woken.send(());
            let _ = self.resume.lock().unwrap().recv();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reuse_stream_while_idle_watcher_is_unlocking() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        // An upstream that accepts connections and never writes to them, so a pooled
        // connection always stays reusable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = BasicPeer::new(&listener.local_addr().unwrap().to_string());
        tokio::spawn(async move {
            let mut accepted = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                accepted.push(stream);
            }
        });

        let connector = TransportConnector::new(None);
        let mut stream = connector.new_stream(&peer).await.unwrap();
        for _ in 0..100 {
            connector.release_stream(stream, peer.reuse_hash(), None);

            let (woken_tx, woken_rx) = std::sync::mpsc::sync_channel(1);
            let (resume_tx, resume_rx) = std::sync::mpsc::channel();
            let waker = Waker::from(Arc::new(StallingWaker {
                woken: woken_tx,
                resume: std::sync::Mutex::new(resume_rx),
            }));
            let mut cx = Context::from_waker(&waker);
            // Unconstrained, so tokio's coop budget never calls the stalling waker on this thread.
            let mut pickup =
                std::pin::pin!(tokio::task::unconstrained(connector.reused_stream(&peer)));

            // The idle watcher almost always still holds the lock when the pickup first asks
            // for it. When it let go first there is no unlock to poll inside, so try again.
            if let Poll::Ready(reused) = pickup.as_mut().poll(&mut cx) {
                stream = reused.expect("healthy pooled connection was dropped");
                continue;
            }
            woken_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("idle watcher should unlock the stream");
            // The watcher's thread is now stalled inside its unlock: the lock is free, but the
            // watcher has not yet dropped its own handle to the stream.
            let reused = pickup.as_mut().poll(&mut cx);
            resume_tx.send(()).unwrap();
            assert!(
                matches!(reused, Poll::Ready(Some(_))),
                "healthy pooled connection was dropped"
            );
            return;
        }
        panic!("the idle watcher never held the lock when the pickup asked for it");
    }

    // 192.0.2.1 is TEST-NET-1 (RFC 5737) — SYN packets are silently
    // dropped on Linux, producing ConnectTimedout. On macOS the kernel
    // may instead return ENETUNREACH (ConnectNoRoute).
    const BLACKHOLE: &str = "192.0.2.1:79";

    async fn do_test_conn_timeout(conf: Option<ConnectorOptions>) {
        let connector = TransportConnector::new(conf);
        let mut peer = BasicPeer::new(BLACKHOLE);
        peer.options.connection_timeout = Some(Duration::from_millis(1));
        let Err(e) = connector.new_stream(&peer).await else {
            panic!("should throw an error");
        };
        assert!(
            e.etype() == &ConnectTimedout || e.etype() == &ConnectNoRoute,
            "unexpected error type: {:?}",
            e.etype()
        );
    }

    #[tokio::test]
    async fn test_conn_timeout() {
        do_test_conn_timeout(None).await;
    }

    #[tokio::test]
    async fn test_conn_timeout_with_offload() {
        let mut conf = ConnectorOptions::new(8);
        conf.offload_threadpool = Some((2, 2));
        do_test_conn_timeout(Some(conf)).await;
    }

    #[tokio::test]
    async fn test_connector_bind_to() {
        // connect to remote while bind to localhost will fail
        let peer = BasicPeer::new("240.0.0.1:80");
        let mut conf = ConnectorOptions::new(1);
        conf.bind_to_v4.push("127.0.0.1:0".parse().unwrap());
        let connector = TransportConnector::new(Some(conf));

        let stream = connector.new_stream(&peer).await;
        let error = stream.unwrap_err();
        // The exact error varies by platform: Linux may return ConnectError,
        // some systems time out (ConnectTimedout), and macOS/others may
        // return ConnectNoRoute (ENETUNREACH) for unreachable addresses.
        assert!(
            error.etype() == &ConnectError
                || error.etype() == &ConnectTimedout
                || error.etype() == &ConnectNoRoute,
            "unexpected error type: {:?}",
            error.etype()
        )
    }

    /// Helper function for testing error handling in the `do_connect` function.
    /// This assumes that the connection will fail on the peer and returns
    /// the decomposed error type and message.
    async fn get_do_connect_failure_with_peer(peer: &BasicPeer) -> (ErrorType, String) {
        let tls_connector = Connector::new(None);
        let stream = do_connect(peer, None, None, &tls_connector.ctx, None).await;
        match stream {
            Ok(_) => panic!("should throw an error"),
            Err(e) => (
                e.etype().clone(),
                e.context
                    .as_ref()
                    .map(|ctx| ctx.as_str().to_owned())
                    .unwrap_or_default(),
            ),
        }
    }

    #[tokio::test]
    async fn test_do_connect_with_total_timeout() {
        let mut peer = BasicPeer::new(BLACKHOLE);
        peer.options.total_connection_timeout = Some(Duration::from_millis(1));
        let (etype, context) = get_do_connect_failure_with_peer(&peer).await;
        assert!(
            etype == ConnectTimedout || etype == ConnectNoRoute,
            "unexpected error type: {etype:?}"
        );
        if etype == ConnectTimedout {
            assert!(context.contains("total-connection timeout"));
        }
    }

    #[tokio::test]
    async fn test_tls_connect_timeout_supersedes_total() {
        let mut peer = BasicPeer::new(BLACKHOLE);
        peer.options.total_connection_timeout = Some(Duration::from_millis(10));
        peer.options.connection_timeout = Some(Duration::from_millis(1));
        let (etype, context) = get_do_connect_failure_with_peer(&peer).await;
        assert!(
            etype == ConnectTimedout || etype == ConnectNoRoute,
            "unexpected error type: {etype:?}"
        );
        if etype == ConnectTimedout {
            assert!(!context.contains("total-connection timeout"));
        }
    }

    #[tokio::test]
    async fn test_do_connect_without_total_timeout() {
        let peer = BasicPeer::new(BLACKHOLE);
        let (etype, context) = get_do_connect_failure_with_peer(&peer).await;
        assert!(etype != ConnectTimedout || !context.contains("total-connection timeout"));
    }

    #[tokio::test]
    async fn test_tls_handshake_failure_records_local_addr() {
        use crate::connectors::l4::ConnectErrorExt;

        // A plaintext listener that closes each connection immediately, so the TLS handshake fails
        // after the TCP connection is established.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });

        // Non-empty SNI makes BasicPeer request TLS against the plaintext listener.
        let mut peer = BasicPeer::new(&server_addr.to_string());
        peer.sni = "openrusty.org".to_string();
        // Safety net so the test fails fast rather than hanging if a platform does not surface the
        // handshake failure immediately; a handshake timeout still exercises the same code path.
        peer.options.connection_timeout = Some(Duration::from_secs(5));

        let tls_connector = Connector::new(None);
        let err = do_connect(&peer, None, None, &tls_connector.ctx, None)
            .await
            .unwrap_err();

        let local_addr = err
            .connect_local_addr()
            .expect("TLS handshake failure should retain the assigned local address");
        assert_ne!(local_addr.port(), 0);
    }

    #[tokio::test]
    async fn test_unexpected_data_connection_count_increments() {
        // Create a duplex stream where we control both ends
        let (mut server, client) = tokio::io::duplex(64);

        let counter = AtomicU64::new(0);
        let mut stream: Stream = Box::new(client);

        // With no data available, the stream should be considered reusable
        assert!(test_reusable_stream(&mut stream, &counter));
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        // Write unexpected data from the server side
        use tokio::io::AsyncWriteExt;
        server.write_all(b"unexpected").await.unwrap();

        // Give the data a moment to be buffered
        tokio::task::yield_now().await;

        // Now test_reusable_stream should detect the unexpected data
        assert!(!test_reusable_stream(&mut stream, &counter));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "unexpected_data_connection_count should have incremented"
        );
    }

    #[test]
    fn released_idle_watcher_runs_on_the_releasing_thread() {
        use std::sync::Mutex as StdMutex;

        const WORKERS: usize = 4;
        const EVICTIONS: usize = 32;

        let runtime = pingora_runtime::Runtime::new_no_steal(WORKERS, "test-idle-watcher");
        let (done, wait) = std::sync::mpsc::channel();
        runtime.get_handle().spawn(async move {
            let releasing = std::thread::current().id();
            let callback_threads = Arc::new(StdMutex::new(Vec::new()));
            let recorded = callback_threads.clone();
            let mut options = ConnectorOptions::new(1);
            options.keepalive_pool_callback = Some(Arc::new(move |_elapsed| {
                recorded
                    .lock()
                    .expect("callback threads")
                    .push(std::thread::current().id());
            }));
            let connector = TransportConnector::new(Some(options));

            // Keep the listener (and its backlog) alive so the released streams stay
            // open and reusable; never accept, so no peer FIN arrives.
            let _listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = _listener.local_addr().unwrap();
            let peer = BasicPeer::new(&addr.to_string());

            // A one-slot pool: every release after the first evicts its predecessor
            // and fires that predecessor's callback.
            for _ in 0..=EVICTIONS {
                let stream = connector.new_stream(&peer).await.unwrap();
                connector.release_stream(stream, peer.reuse_hash(), None);
            }

            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while callback_threads.lock().unwrap().len() < EVICTIONS
                && std::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let callbacks = callback_threads.lock().unwrap().clone();
            let _ = done.send((releasing, callbacks));
        });

        let (releasing, callbacks) = wait
            .recv_timeout(Duration::from_secs(30))
            .expect("the idle-watcher task did not finish");
        runtime.shutdown_timeout(Duration::from_secs(1));
        assert_eq!(
            callbacks.len(),
            EVICTIONS,
            "every eviction must fire its keepalive callback"
        );
        assert!(
            callbacks.iter().all(|thread| *thread == releasing),
            "every idle watcher must run on the releasing thread: {callbacks:?} vs {releasing:?}"
        );
    }

    async fn idle_echo_peer() -> (BasicPeer, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = BasicPeer::new(&listener.local_addr().unwrap().to_string());
        let handle = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        (peer, handle)
    }

    #[test]
    fn rebind_moves_a_stream_to_another_runtime() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).unwrap();
            socket.write_all(&buf).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let connector = TransportConnector::new(None);
        let peer = BasicPeer::new(&addr.to_string());
        let mut stream = runtime_a.block_on(async { connector.new_stream(&peer).await.unwrap() });

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            Rebind::rebind(&mut *stream).expect("rebind onto the new runtime");
            stream.write_all(b"ping").await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        });
        drop(stream);
        drop(runtime_a);
        drop(runtime_b);
        server.join().unwrap();
    }

    #[test]
    fn an_offloaded_connection_is_owned_by_the_callers_runtime() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 4];
            if socket.read_exact(&mut buf).is_ok() {
                socket.write_all(&buf).unwrap();
            }
            std::thread::sleep(Duration::from_millis(100));
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut options = ConnectorOptions::new(8);
        options.offload_threadpool = Some((1, 1));
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let mut stream = runtime.block_on(async { connector.new_stream(&peer).await.unwrap() });

        // Occupy the single offload worker so its IO driver cannot make progress; a stream
        // still registered there can then neither read nor observe a close.
        let (wedged_tx, wedged_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel::<()>();
        connector
            .offload
            .as_ref()
            .unwrap()
            .get_runtime(peer.reuse_hash())
            .spawn(async move {
                let _ = wedged_tx.send(());
                let _ = released_rx.recv();
            });
        wedged_rx.recv().unwrap();

        runtime.block_on(async {
            use tokio::io::AsyncReadExt;
            let echo = async {
                stream.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            };
            tokio::time::timeout(Duration::from_secs(5), echo)
                .await
                .expect("readiness must not depend on the offload runtime");
        });

        let _ = released_tx.send(());
        drop(connector);
        server.join().unwrap();
    }

    #[test]
    fn an_offloaded_connection_fails_when_its_rebind_fails() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut options = ConnectorOptions::new(8);
        options.offload_threadpool = Some((1, 1));
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        fail_next_rebind();
        let error = runtime.block_on(async { connector.new_stream(&peer).await.unwrap_err() });
        assert_eq!(error.etype(), &InternalError);
        drop(connector);
        drop(runtime);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn l1_hit_skips_the_shared_pool() {
        let (peer, _server) = idle_echo_peer().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        let reused = connector.reused_stream(&peer).await;
        assert!(reused.is_some(), "the connection must come from L1");
        assert_eq!(
            connector.pending_l1_hits(),
            1,
            "the hit is counted per worker"
        );
        assert_eq!(
            connector.pool_counters().l1_hit(),
            0,
            "an L1 hit must not write the shared counter"
        );
        assert_eq!(connector.pool_counters().l2_hit(), 0);
    }

    #[tokio::test]
    async fn l1_hits_reach_the_shared_counter_within_one_window() {
        let (addr, _server) = spawn_holding_listener().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_millis(20);
        options.l1_capacity = 4;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        let stream = connector
            .reused_stream(&peer)
            .await
            .expect("the resident entry must be served from L1");
        assert_eq!(connector.pending_l1_hits(), 1);
        assert_eq!(
            connector.pool_counters().l1_hit(),
            0,
            "the hit itself must not write the shared counter"
        );

        connector.release_stream(stream, peer.reuse_hash(), None);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            connector.pool_counters().l1_hit(),
            1,
            "the per-worker delta must reach the shared counter within one window"
        );
        assert_eq!(connector.pending_l1_hits(), 0);
    }

    /// A worker that goes quiet with its connection held still reaches the shared counter
    /// within a window, with no further release or take.
    #[tokio::test]
    async fn a_quiet_worker_flushes_pending_l1_hits_within_one_window() {
        let (addr, _server) = spawn_holding_listener().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_millis(20);
        options.l1_capacity = 1;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        let stream = connector
            .reused_stream(&peer)
            .await
            .expect("the resident entry must be served from L1");
        assert_eq!(connector.pending_l1_hits(), 1);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            connector.pool_counters().l1_hit(),
            1,
            "nothing released or took, yet the delta must be flushed"
        );
        assert_eq!(connector.pending_l1_hits(), 0);
        drop(stream);
    }

    #[tokio::test]
    async fn l1_expiry_moves_the_connection_to_the_shared_pool() {
        let (peer, _server) = idle_echo_peer().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_millis(1);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(connector.pool_counters().l1_expired(), 1);

        let reused = connector.reused_stream(&peer).await;
        assert!(
            reused.is_some(),
            "the shared pool must serve the expired entry"
        );
        assert_eq!(connector.pool_counters().l1_hit(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 1);
    }

    #[test]
    fn cross_runtime_take_rebinds_to_the_taking_runtime() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4];
                if socket.read_exact(&mut buf).is_ok() {
                    socket.write_all(&buf).unwrap();
                }
                held.push(socket);
            }
        });

        let connector = Arc::new(TransportConnector::new(None));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();

        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let a_connector = Arc::clone(&connector);
        let a_peer = BasicPeer::new(&addr.to_string());
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let thread_a = std::thread::spawn(move || {
            runtime_a.block_on(async move {
                let stream = a_connector.new_stream(&a_peer).await.unwrap();
                a_connector.release_stream(stream, key, None);
                released_tx.send(()).unwrap();
                // Keep polling so the idle watcher can hand the slot over.
                let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
            });
        });

        released_rx.recv().unwrap();
        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let taken = runtime_b.block_on(async {
            use tokio::io::AsyncReadExt;
            let mut stream = connector.reused_stream(&peer).await;
            if let Some(stream) = stream.as_mut() {
                stream.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            }
            stream
        });
        assert!(taken.is_some(), "another runtime must reuse the connection");
        assert_eq!(
            connector.pool_counters().rebind_count(),
            1,
            "the take must rebind the stream to the taking runtime"
        );
        stop_tx.send(()).unwrap();
        thread_a.join().unwrap();
        drop(taken);
        drop(server);
    }

    #[test]
    fn cross_runtime_take_survives_the_releasing_runtime_shutdown() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            while socket.read_exact(&mut buf).is_ok() {
                socket.write_all(&buf).unwrap();
            }
        });

        let connector = Arc::new(TransportConnector::new(None));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        {
            let connector = Arc::clone(&connector);
            let peer = BasicPeer::new(&addr.to_string());
            runtime_a.block_on(async move {
                let stream = connector.new_stream(&peer).await.unwrap();
                connector.release_stream(stream, key, None);
            });
        }
        runtime_a.shutdown_timeout(Duration::from_secs(1));

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            use tokio::io::AsyncWriteExt;
            let mut stream = connector
                .reused_stream(&peer)
                .await
                .expect("the shutdown runtime must not take the connection with it");
            stream.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            connector.release_stream(stream, key, None);

            let mut again = connector
                .reused_stream(&peer)
                .await
                .expect("the connection stays in the pool on the taking runtime");
            again.write_all(b"pong").await.unwrap();
            again.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
        });
        assert_eq!(connector.pool_counters().rebind_count(), 1);
        assert_eq!(connector.pool_counters().l2_hit(), 2);
        drop(server);
    }

    #[test]
    fn l1_take_on_the_same_thread_rebinds_to_the_taking_runtime() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            while socket.read_exact(&mut buf).is_ok() {
                socket.write_all(&buf).unwrap();
            }
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();

        // Both current-thread runtimes live on this thread, so they share the L1
        // bucket. A is left alive but unpolled after the release.
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_a.block_on(async {
            let stream = connector.new_stream(&peer).await.unwrap();
            connector.release_stream(stream, key, None);
        });

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            use tokio::io::AsyncReadExt;
            let mut stream =
                tokio::time::timeout(Duration::from_secs(5), connector.reused_stream(&peer))
                    .await
                    .expect("the L1 take must not wait on the releasing runtime")
                    .expect("the resident entry must be reused");
            tokio::time::timeout(Duration::from_secs(5), async {
                stream.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            })
            .await
            .expect("the taking runtime must drive the reused stream");
        });

        assert_eq!(connector.pool_counters().rebind_count(), 1);
        assert_eq!(connector.pending_l1_hits(), 1);
        runtime_b.shutdown_timeout(Duration::from_secs(1));
        runtime_a.shutdown_timeout(Duration::from_secs(1));
        server.join().unwrap();
    }

    /// A take past the window but inside the idle deadline is served from L1 without
    /// bouncing the stream through L2.
    #[test]
    fn an_l1_entry_past_the_window_is_still_served_from_l1_on_another_runtime() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(b"ready").unwrap();
            let mut buf = [0u8; 4];
            while socket.read_exact(&mut buf).is_ok() {
                socket.write_all(&buf).unwrap();
            }
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_millis(1);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_a.block_on(async {
            let mut stream = connector.new_stream(&peer).await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut ready = [0u8; 5];
            stream.read_exact(&mut ready).await.unwrap();
            connector.release_stream(stream, key, None);
        });

        // A is unpolled, so its sweeper has not moved the entry yet and it is past the window.
        std::thread::sleep(Duration::from_millis(20));

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            use tokio::io::AsyncReadExt;
            let mut stream = connector
                .take_from_l1(&peer)
                .expect("an entry inside its idle deadline must be served from L1");
            tokio::time::timeout(Duration::from_secs(5), async {
                stream.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            })
            .await
            .expect("the taking runtime must drive the stream");
        });

        assert_eq!(connector.pool_counters().l1_expired(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 0);
        assert_eq!(connector.pool_counters().rebind_count(), 1);
        assert_eq!(connector.pending_l1_hits(), 1);
        runtime_b.shutdown_timeout(Duration::from_secs(1));
        runtime_a.shutdown_timeout(Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn l1_capacity_eviction_on_the_same_thread_rebinds_the_evicted_stream() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 4];
                if socket.read_exact(&mut buf).is_ok() {
                    socket.write_all(&buf).unwrap();
                }
                held.push(socket);
            }
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 1;
        let connector = TransportConnector::new(Some(options));
        let peer_a = crate::upstreams::peer::HttpPeer::new(addr, false, "a.example".to_string());
        let peer_b = crate::upstreams::peer::HttpPeer::new(addr, false, "b.example".to_string());
        let key_a = peer_a.reuse_hash();
        let key_b = peer_b.reuse_hash();
        assert_ne!(key_a, key_b);

        // Both current-thread runtimes live on this thread, so they share the L1
        // bucket. A is left alive but unpolled after releasing its entry.
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_a.block_on(async {
            let stream = connector.new_stream(&peer_a).await.unwrap();
            connector.release_stream(stream, key_a, None);
        });

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            let stream = connector.new_stream(&peer_b).await.unwrap();
            // Capacity is one, so this evicts A's entry to the shared pool on B.
            connector.release_stream(stream, key_b, None);
            // Let the L2 idle watcher poll the evicted socket once and park on it.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        // The watcher spawned above lives on B; it must not be driving a socket whose
        // registration dies with A.
        runtime_a.shutdown_timeout(Duration::from_secs(1));

        runtime_b.block_on(async {
            use tokio::io::AsyncReadExt;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut stream =
                tokio::time::timeout(Duration::from_secs(5), connector.reused_stream(&peer_a))
                    .await
                    .expect("the L2 take must not wait on the evicting runtime")
                    .expect("the evicted entry must still be pooled after the releaser exits");
            tokio::time::timeout(Duration::from_secs(5), async {
                stream.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            })
            .await
            .expect("the taking runtime must drive the evicted stream");
        });

        assert_eq!(connector.pool_counters().rebind_count(), 1);
        assert_eq!(connector.pool_counters().l2_hit(), 1);
        runtime_b.shutdown_timeout(Duration::from_secs(1));
        drop(server);
    }

    #[test]
    fn l1_capacity_eviction_with_a_failed_rebind_drops_the_evicted_stream() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept() {
                held.push(socket);
            }
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 1;
        let connector = TransportConnector::new(Some(options));
        let peer_a = crate::upstreams::peer::HttpPeer::new(addr, false, "a.example".to_string());
        let peer_b = crate::upstreams::peer::HttpPeer::new(addr, false, "b.example".to_string());
        let key_a = peer_a.reuse_hash();
        let key_b = peer_b.reuse_hash();
        assert_ne!(key_a, key_b);

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_a.block_on(async {
            let stream = connector.new_stream(&peer_a).await.unwrap();
            connector.release_stream(stream, key_a, None);
        });

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            let stream = connector.new_stream(&peer_b).await.unwrap();
            // The release below evicts A's entry; its rebind must fail and the stream
            // must be dropped rather than handed to B's idle watcher.
            fail_next_rebind();
            connector.release_stream(stream, key_b, None);
            assert!(
                connector.reused_stream(&peer_a).await.is_none(),
                "an evicted entry whose rebind failed must not be pooled"
            );
        });

        assert_eq!(connector.pool_counters().rebind_count(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 0);

        runtime_b.shutdown_timeout(Duration::from_secs(1));
        runtime_a.shutdown_timeout(Duration::from_secs(1));
        drop(server);
    }

    #[test]
    fn l1_take_with_a_failed_rebind_reports_a_miss() {
        use std::io::Read;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            while socket.read_exact(&mut buf).is_ok() {}
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_a.block_on(async {
            let stream = connector.new_stream(&peer).await.unwrap();
            connector.release_stream(stream, key, None);
        });

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        fail_next_rebind();
        let taken = runtime_b.block_on(async { connector.reused_stream(&peer).await });
        assert!(taken.is_none(), "a failed L1 rebind must report a miss");
        assert_eq!(connector.pending_l1_hits(), 0);
        assert_eq!(connector.pool_counters().rebind_count(), 0);
        runtime_b.shutdown_timeout(Duration::from_secs(1));
        runtime_a.shutdown_timeout(Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn failed_rebind_drops_the_stream_and_reports_a_miss() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept() {
                held.push(socket);
            }
        });

        let connector = Arc::new(TransportConnector::new(None));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();

        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let a_connector = Arc::clone(&connector);
        let a_peer = BasicPeer::new(&addr.to_string());
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let thread_a = std::thread::spawn(move || {
            runtime_a.block_on(async move {
                let stream = a_connector.new_stream(&a_peer).await.unwrap();
                a_connector.release_stream(stream, key, None);
                released_tx.send(()).unwrap();
                let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
            });
        });

        released_rx.recv().unwrap();
        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        fail_next_rebind();
        let taken = runtime_b.block_on(async { connector.reused_stream(&peer).await });
        assert!(taken.is_none(), "a failed rebind must report a pool miss");
        assert_eq!(connector.pool_counters().rebind_count(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 0);

        stop_tx.send(()).unwrap();
        thread_a.join().unwrap();
        drop(server);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_connection_closed_while_in_l1_is_not_returned() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            accepted_tx.send(socket).unwrap();
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());
        let stream = connector.new_stream(&peer).await.unwrap();
        let fd = stream.id();
        let accepted = accepted_rx.recv().unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);

        drop(accepted);
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid `pollfd` for the single fd `fd`; `poll` only
        // reads/writes that struct and the kernel's fd table.
        let ready = unsafe { libc::poll(&mut pfd, 1, 5000) };
        assert!(ready > 0, "the client socket must observe the peer FIN");
        // The FIN is queued; give the runtime's I/O driver one turn to cache the
        // readiness for the pooled stream.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let taken = connector.take_from_l1(&peer);
        assert!(
            taken.is_none(),
            "a peer-closed L1 entry must not be returned"
        );
        assert_eq!(connector.pool_counters().l1_hit(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 0);
        drop(server);
    }

    #[test]
    fn a_release_into_a_full_l1_reaches_another_worker() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept() {
                held.push(socket);
            }
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 1;
        let connector = Arc::new(TransportConnector::new(Some(options)));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();

        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let a_connector = Arc::clone(&connector);
        let a_peer = BasicPeer::new(&addr.to_string());
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let thread_a = std::thread::spawn(move || {
            runtime_a.block_on(async move {
                let first = a_connector.new_stream(&a_peer).await.unwrap();
                a_connector.release_stream(first, key, None);
                let second = a_connector.new_stream(&a_peer).await.unwrap();
                // Capacity is one, so this release evicts the first to the shared pool.
                a_connector.release_stream(second, key, None);
                released_tx.send(()).unwrap();
                let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
            });
        });

        released_rx.recv().unwrap();
        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let taken = runtime_b.block_on(async { connector.reused_stream(&peer).await });
        assert!(
            taken.is_some(),
            "the evicted connection must be visible in the shared pool"
        );
        assert_eq!(connector.pool_counters().l1_hit(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 1);

        stop_tx.send(()).unwrap();
        thread_a.join().unwrap();
        drop(taken);
        drop(server);
    }

    #[test]
    fn an_expired_l1_entry_is_taken_by_another_worker() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept() {
                held.push(socket);
            }
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_millis(20);
        options.l1_capacity = 8;
        let connector = Arc::new(TransportConnector::new(Some(options)));
        let peer = BasicPeer::new(&addr.to_string());
        let key = peer.reuse_hash();

        let (released_tx, released_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let a_connector = Arc::clone(&connector);
        let a_peer = BasicPeer::new(&addr.to_string());
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let thread_a = std::thread::spawn(move || {
            runtime_a.block_on(async move {
                let stream = a_connector.new_stream(&a_peer).await.unwrap();
                a_connector.release_stream(stream, key, None);
                released_tx.send(()).unwrap();
                let _ = tokio::task::spawn_blocking(move || stop_rx.recv()).await;
            });
        });

        released_rx.recv().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while connector.pool_counters().l1_expired() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the L1 entry never expired"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let taken = runtime_b.block_on(async { connector.reused_stream(&peer).await });
        assert!(
            taken.is_some(),
            "an expired L1 entry must be taken from the shared pool"
        );
        assert_eq!(connector.pool_counters().l1_hit(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 1);
        assert_eq!(connector.pool_counters().rebind_count(), 1);

        stop_tx.send(()).unwrap();
        thread_a.join().unwrap();
        drop(taken);
        drop(server);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_stealing_runtime_releases_straight_to_the_shared_pool() {
        let (peer, _server) = idle_echo_peer().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        let reused = connector.reused_stream(&peer).await;
        assert!(reused.is_some(), "the shared pool must serve the release");
        assert_eq!(connector.pool_counters().l1_hit(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 1);
    }

    #[tokio::test]
    async fn l1_eviction_releases_under_the_evicted_entrys_key() {
        let (addr, _server) = spawn_holding_listener().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 1;
        let connector = TransportConnector::new(Some(options));

        let peer_a = crate::upstreams::peer::HttpPeer::new(addr, false, "a.example".to_string());
        let peer_b = crate::upstreams::peer::HttpPeer::new(addr, false, "b.example".to_string());
        assert_ne!(
            peer_a.reuse_hash(),
            peer_b.reuse_hash(),
            "peers sharing an address but differing TLS identities must not share a key"
        );

        let first = connector.new_stream(&peer_a).await.unwrap();
        connector.release_stream(first, peer_a.reuse_hash(), None);
        let second = connector.new_stream(&peer_b).await.unwrap();
        // Capacity is one, so this evicts `first` to the shared pool.
        connector.release_stream(second, peer_b.reuse_hash(), None);

        let b = connector.reused_stream(&peer_b).await;
        assert!(b.is_some(), "the resident entry must be served from L1");
        assert_eq!(
            connector.pending_l1_hits(),
            1,
            "the L1 hit is counted on this worker"
        );
        assert_eq!(
            connector.pool_counters().l1_hit(),
            0,
            "an L1 hit must not write the shared counter"
        );

        let a = connector.reused_stream(&peer_a).await;
        assert!(
            a.is_some(),
            "the evicted entry must be reusable only under its own key"
        );
        assert_eq!(connector.pool_counters().l2_hit(), 1);
    }

    #[tokio::test]
    async fn an_l1_entry_past_its_idle_deadline_is_rejected_on_take() {
        let (addr, mut accepted) = spawn_capturing_listener().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));

        let peer = BasicPeer::new(&addr.to_string());
        let stream = connector.new_stream(&peer).await.unwrap();
        let mut accepted = accepted.recv().await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), Some(Duration::ZERO));

        let taken = connector.take_from_l1(&peer);
        assert!(
            taken.is_none(),
            "a take must not hand out a connection past its idle deadline"
        );
        assert_eq!(connector.pool_counters().l1_expired(), 1);

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), accepted.read(&mut buf))
            .await
            .expect("the peer must observe the close at the idle deadline")
            .unwrap();
        assert_eq!(n, 0, "the peer must see EOF");
    }

    #[tokio::test]
    async fn an_idle_timeout_shorter_than_the_l1_window_closes_at_the_deadline() {
        let (addr, mut accepted) = spawn_capturing_listener().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));

        let peer = BasicPeer::new(&addr.to_string());
        let stream = connector.new_stream(&peer).await.unwrap();
        let mut accepted = accepted.recv().await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), Some(Duration::from_millis(30)));

        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), accepted.read(&mut buf))
            .await
            .expect("the idle deadline must close the L1 entry, not wait for the window")
            .unwrap();
        assert_eq!(n, 0, "the peer must see EOF");
        assert!(connector.pool_counters().l1_expired() >= 1);
        assert!(connector.reused_stream(&peer).await.is_none());
        assert!(
            connector.l1_bucket(|bucket| bucket.is_none()),
            "the sweeper must end once nothing is left to expire"
        );
    }

    /// Release on runtime A (into its L1, or straight into the shared pool with no idle
    /// watcher, as when the watcher has handed the slot over on a take), let `peer_action`
    /// act on the accepted socket, let A's driver see it, then take on runtime B.
    #[cfg(unix)]
    fn take_on_another_runtime_after(
        shared_pool: bool,
        peer_action: impl FnOnce(std::net::TcpStream) -> Option<std::net::TcpStream>,
    ) -> (Option<Stream>, TransportConnector) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            accepted_tx.send(listener.accept().unwrap().0).unwrap();
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Held so the slot's channels outlive the take.
        let mut slot_channels = None;
        runtime_a.block_on(async {
            let stream = connector.new_stream(&peer).await.unwrap();
            if shared_pool {
                let owned = OwnerStream {
                    runtime: tokio::runtime::Handle::current().id(),
                    stream,
                };
                let meta = ConnectionMeta::new(peer.reuse_hash(), owned.stream.id());
                let slot: PooledSlot = Arc::new(Mutex::new(Some(owned)));
                slot_channels = Some(connector.pool.pool.put(&meta, slot));
            } else {
                connector.release_stream(stream, peer.reuse_hash(), None);
            }
        });
        let kept = peer_action(accepted_rx.recv().unwrap());
        // A's driver caches the readiness; B's fresh registration would not have it.
        runtime_a.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let taken = runtime_b.block_on(async { connector.reused_stream(&peer).await });
        drop((kept, slot_channels));
        server.join().unwrap();
        (taken, connector)
    }

    #[cfg(unix)]
    fn peer_closes(accepted: std::net::TcpStream) -> Option<std::net::TcpStream> {
        drop(accepted);
        None
    }

    #[cfg(unix)]
    fn peer_sends_unexpected_data(
        mut accepted: std::net::TcpStream,
    ) -> Option<std::net::TcpStream> {
        use std::io::Write;

        accepted.write_all(b"x").unwrap();
        Some(accepted)
    }

    #[cfg(unix)]
    #[test]
    fn a_cross_runtime_take_rejects_a_peer_closed_connection() {
        let (taken, connector) = take_on_another_runtime_after(false, peer_closes);
        assert!(taken.is_none(), "a peer-closed connection must be rejected");
        assert_eq!(connector.pool_counters().rebind_count(), 0);
        assert_eq!(connector.pending_l1_hits(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_cross_runtime_take_rejects_a_connection_with_unexpected_data() {
        let (taken, connector) = take_on_another_runtime_after(false, peer_sends_unexpected_data);
        assert!(taken.is_none(), "unexpected data must make it unusable");
        assert_eq!(connector.unexpected_data_connection_count(), 1);
        assert_eq!(connector.pool_counters().rebind_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_shared_pool_take_rejects_a_peer_closed_connection_before_rebinding() {
        let (taken, connector) = take_on_another_runtime_after(true, peer_closes);
        assert!(taken.is_none(), "a peer-closed connection must be rejected");
        assert_eq!(connector.pool_counters().rebind_count(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_shared_pool_take_rejects_unexpected_data_before_rebinding() {
        let (taken, connector) = take_on_another_runtime_after(true, peer_sends_unexpected_data);
        assert!(taken.is_none(), "unexpected data must make it unusable");
        assert_eq!(connector.unexpected_data_connection_count(), 1);
        assert_eq!(connector.pool_counters().rebind_count(), 0);
        assert_eq!(connector.pool_counters().l2_hit(), 0);
    }

    fn recording_callback() -> (PoolCallback, Arc<std::sync::Mutex<Vec<Duration>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let callback: PoolCallback = Arc::new(move |idle| recorded.lock().unwrap().push(idle));
        (callback, seen)
    }

    /// The callback's idle time covers the time spent in L1, not only in L2.
    #[tokio::test]
    async fn the_keepalive_callback_counts_l1_residency() {
        let (addr, _server) = spawn_holding_listener().await;
        let (callback, seen) = recording_callback();
        // A one-slot shared pool: the second entry reaching it evicts the first.
        let mut options = ConnectorOptions::new(1);
        options.l1_window = Duration::from_millis(50);
        options.l1_capacity = 8;
        options.keepalive_pool_callback = Some(callback);
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let first = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(first, 1, None);
        tokio::time::sleep(Duration::from_millis(120)).await;
        let second = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(second, 2, None);
        tokio::time::sleep(Duration::from_millis(250)).await;

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the eviction must fire the callback");
        // 120ms until the second release plus its 50ms in L1; L2 residency alone is ~50ms less.
        assert!(
            seen[0] >= Duration::from_millis(160),
            "idle time must include the first entry's 50ms in L1: {:?}",
            seen[0]
        );
    }

    /// An entry that hits its idle deadline inside L1 leaves the pool without reuse too.
    #[tokio::test]
    async fn the_keepalive_callback_fires_for_an_l1_idle_deadline_drop() {
        let (addr, _server) = spawn_holding_listener().await;
        let (callback, seen) = recording_callback();
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 8;
        options.keepalive_pool_callback = Some(callback);
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), Some(Duration::from_millis(30)));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(seen.lock().unwrap().len(), 1);

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), Some(Duration::ZERO));
        assert!(connector.take_from_l1(&peer).is_none());
        assert_eq!(
            seen.lock().unwrap().len(),
            2,
            "a take past the idle deadline must fire the callback"
        );
    }

    #[tokio::test]
    async fn dropping_a_connector_flushes_its_hits_and_frees_its_l1_bucket() {
        let (addr, _server) = spawn_holding_listener().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_millis(20);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        let stream = connector.reused_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        let (id, counters) = (connector.id, connector.pool_counters());
        drop(connector);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counters.l1_hit(),
            1,
            "the dropped connector's hit is flushed"
        );
        assert!(
            L1.with(|cache| !cache.borrow().contains_key(&id)),
            "the dropped connector's L1 bucket must be freed"
        );
    }

    /// Two runtimes on one thread share the bucket; the sweeper must run on the releaser's.
    #[test]
    fn the_l1_sweeper_follows_the_runtime_that_releases() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept() {
                held.push(socket);
            }
        });

        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_millis(20);
        options.l1_capacity = 8;
        let connector = TransportConnector::new(Some(options));
        let peer_a = crate::upstreams::peer::HttpPeer::new(addr, false, "a.example".to_string());
        let peer_b = crate::upstreams::peer::HttpPeer::new(addr, false, "b.example".to_string());

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_a.block_on(async {
            let stream = connector.new_stream(&peer_a).await.unwrap();
            connector.release_stream(stream, peer_a.reuse_hash(), None);
        });
        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            let stream = connector.new_stream(&peer_b).await.unwrap();
            connector.release_stream(stream, peer_b.reuse_hash(), None);
            // A is never polled again, so only a sweeper on B can expire A's entry.
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        assert_eq!(connector.pool_counters().l1_expired(), 2);
        assert_eq!(connector.pool_counters().rebind_count(), 1);
        runtime_b.shutdown_timeout(Duration::from_secs(1));
        runtime_a.shutdown_timeout(Duration::from_secs(1));
        drop(server);
    }

    fn alive_tasks() -> usize {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    }

    /// Releases past capacity evict to L2, one idle watcher each; L1 itself adds one sweeper.
    #[tokio::test]
    async fn l1_residency_is_bounded_by_capacity_and_one_sweeper() {
        let (addr, _server) = spawn_holding_listener().await;
        let mut options = ConnectorOptions::new(64);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 4;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());
        let baseline = alive_tasks();

        for key in 0..64u64 {
            let stream = connector.new_stream(&peer).await.unwrap();
            connector.release_stream(stream, key, None);
        }
        assert_eq!(
            connector.l1_bucket(|bucket| bucket.map(|bucket| bucket.entries.len())),
            Some(4),
            "L1 must hold exactly its capacity"
        );
        let evicted_watchers = 60;
        assert_eq!(
            alive_tasks() - baseline,
            evicted_watchers + 1,
            "L1 must add one sweeper task, not one task per release"
        );
    }

    /// Repeated hits must not spawn tasks.
    #[tokio::test]
    async fn l1_hits_do_not_spawn_tasks() {
        let (addr, _server) = spawn_holding_listener().await;
        let mut options = ConnectorOptions::new(8);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 4;
        let connector = TransportConnector::new(Some(options));
        let peer = BasicPeer::new(&addr.to_string());

        let stream = connector.new_stream(&peer).await.unwrap();
        connector.release_stream(stream, peer.reuse_hash(), None);
        let baseline = alive_tasks();
        for _ in 0..64 {
            let stream = connector
                .reused_stream(&peer)
                .await
                .expect("the resident entry must be served from L1");
            connector.release_stream(stream, peer.reuse_hash(), None);
        }
        assert_eq!(alive_tasks(), baseline, "a hit must not spawn a task");
        assert_eq!(
            connector.pending_l1_hits(),
            64,
            "every hit is counted on this worker before the window flushes"
        );
        assert_eq!(
            connector.pool_counters().l1_hit(),
            0,
            "hits inside the window must not write the shared counter"
        );
    }

    /// Takes drain L1 without leaving anything behind that grows with traffic.
    #[tokio::test]
    async fn l1_takes_outnumbering_capacity_leave_no_residents() {
        let (addr, _server) = spawn_holding_listener().await;
        let mut options = ConnectorOptions::new(16);
        options.l1_window = Duration::from_secs(60);
        options.l1_capacity = 4;
        let capacity = options.l1_capacity;
        let connector = TransportConnector::new(Some(options));
        let peers: Vec<_> = (0..capacity + 4)
            .map(|i| {
                crate::upstreams::peer::HttpPeer::new(addr, false, format!("take-{i}.example"))
            })
            .collect();

        for peer in &peers {
            let stream = connector.new_stream(peer).await.unwrap();
            connector.release_stream(stream, peer.reuse_hash(), None);
        }
        for peer in &peers {
            let taken = connector.reused_stream(peer).await;
            assert!(taken.is_some(), "every released stream must be reusable");
        }
        assert_eq!(
            connector.l1_bucket(|bucket| bucket.map(|bucket| bucket.entries.len())),
            Some(0)
        );
    }

    async fn spawn_holding_listener() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        (addr, handle)
    }

    async fn spawn_capturing_listener() -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::Receiver<tokio::net::TcpStream>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = tx.send(stream).await;
            }
        });
        (addr, rx)
    }
}
