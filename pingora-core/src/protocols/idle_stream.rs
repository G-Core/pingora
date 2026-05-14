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
//! Per-poll hot path is a single `AtomicWaker::register` (a CAS) plus an
//! atomic load of the abort flag. There is no per-stream `tokio::time::Sleep`.
//!
//! Timeouts are driven by per-worker, **per-timeout-class** sweeper tasks.
//! Connections sharing the same `idle_timeout` are registered into one
//! bucket; each bucket has its own sweeper that walks its registry at a
//! cadence derived from that bucket's timeout. This avoids "scan
//! amplification": one short-timeout connection on a worker no longer
//! forces all long-timeout connections on the same worker to be scanned
//! at the short cadence.
//!
//! Aborted tasks are actively woken by the sweeper via per-direction
//! `AtomicWaker`s (read and write get distinct wakers so
//! `tokio::io::split`-style callers don't lose a wake when an operation
//! in the other direction is polled in between).
//!
//! The (`aborted`, `last_activity`) pair lives in a single `AtomicU64`
//! so the sweeper can CAS-set the abort flag only while `last_activity`
//! is unchanged. This closes a TOCTOU race where the sweeper would
//! otherwise abort a connection that received bytes between the
//! sweeper's load of `last_activity` and its store of `aborted`
//! (possible on tokio multi-thread / work-stealing).

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures::task::{noop_waker, AtomicWaker};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::protocols::{
    raw_connect::ProxyDigest,
    tls::{digest::SslDigest, TlsRef},
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl, Stream,
    TimingDigest, UniqueID, UniqueIDType, ALPN,
};

/// Lower bound on the sweeper sleep duration. Prevents a pathologically
/// small `idle_timeout` (e.g. microseconds) from spinning the sweeper.
const MIN_SWEEP_INTERVAL: Duration = Duration::from_millis(10);

/// Upper bound on the sweeper sleep duration. Bounds the worst-case
/// timeout overshoot regardless of how large the configured
/// `idle_timeout` is: for a 90 s timeout this caps overshoot at 5 s
/// (5.5 %) rather than the 22.5 s (25 %) that `idle_timeout / 4` would
/// otherwise yield. An idle worker pays one no-op sweep tick per
/// `MAX_SWEEP_INTERVAL` (~µs of CPU work).
const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Opportunistic prune cadence within a bucket: after this many
/// registrations into the bucket, the prune walks the registry once
/// and drops dead `Weak`s. Bounds inter-sweep memory at roughly
/// `live_count + REGISTRATIONS_PER_PRUNE` even under high connection
/// churn between sweeps (which can be up to `MAX_SWEEP_INTERVAL` apart).
const REGISTRATIONS_PER_PRUNE: u64 = 4096;

const TIMED_OUT_MSG: &str = "downstream idle timeout";

/// High bit of `IdleConnState::state`: aborted flag.
const ABORTED_BIT: u64 = 1u64 << 63;
/// Low 63 bits of `IdleConnState::state`: `last_activity` micros since `ORIGIN`.
/// 63 bits give ~292,471 years of headroom at microsecond resolution.
const ACTIVITY_MASK: u64 = !ABORTED_BIT;

/// Monotonic clock origin. Using `tokio::time::Instant` makes the wrapper
/// honour `tokio::test(start_paused = true)` in unit tests, and is identical
/// to `std::time::Instant` in production.
static ORIGIN: Lazy<Instant> = Lazy::new(Instant::now);

#[inline]
fn monotonic_micros() -> u64 {
    let micros = Instant::now()
        .saturating_duration_since(*ORIGIN)
        .as_micros();
    // Saturate to 63 bits so the high bit of `state` is never accidentally
    // set by the activity timestamp (the high bit is reserved for ABORTED).
    let v = u64::try_from(micros).unwrap_or(u64::MAX);
    v & ACTIVITY_MASK
}

/// Convert a `Duration` to microseconds. Sub-microsecond values
/// (`Duration::from_nanos(n)` with `n < 1000`) truncate to 0 — the
/// resulting timeout is "abort on next sweep tick", bounded by
/// `MIN_SWEEP_INTERVAL`. Saturates to `u64::MAX` for impractically
/// large durations.
#[inline]
fn duration_to_micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

#[inline]
fn sweep_interval_for(idle_timeout_micros: u64) -> Duration {
    Duration::from_micros(idle_timeout_micros / 4)
        .max(MIN_SWEEP_INTERVAL)
        .min(MAX_SWEEP_INTERVAL)
}

/// Per-connection state shared between the wrapped stream and the sweeper.
///
/// `(aborted, last_activity)` are packed into a single `AtomicU64` so the
/// sweeper can atomically CAS-set the abort flag only when
/// `last_activity` has not changed since its read. Without this packing,
/// a sweeper running on a different worker thread could abort a
/// connection that received bytes between the load of `last_activity`
/// and the store of `aborted` (a TOCTOU race possible on tokio
/// multi-thread / work-stealing runtimes).
///
/// `read_waker` and `write_waker` are kept distinct so that a caller
/// using `tokio::io::split` (independent tasks driving read and write)
/// has both halves correctly woken on abort. For pingora's standard
/// single-task drivers, both wakers refer to the same task and
/// `AtomicWaker::register` deduplicates via `Waker::will_wake`.
struct IdleConnState {
    /// High bit `ABORTED_BIT`: aborted flag. Low 63 bits: `last_activity`
    /// in micros since `ORIGIN`. Always accessed via CAS so the two
    /// quantities update atomically together.
    state: AtomicU64,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
    idle_timeout_micros: u64,
}

impl IdleConnState {
    fn new(idle_timeout: Duration) -> Self {
        // `monotonic_micros` masks the timestamp to 63 bits so the
        // high bit (ABORTED_BIT) is never accidentally set here. If a
        // future refactor removes that mask, this assert will catch it.
        let now = monotonic_micros();
        debug_assert_eq!(
            now & ABORTED_BIT,
            0,
            "monotonic_micros leaked the abort bit into last_activity",
        );
        Self {
            state: AtomicU64::new(now),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
            idle_timeout_micros: duration_to_micros(idle_timeout),
        }
    }

    /// Update `last_activity` to "now" while preserving the abort flag.
    /// If already aborted, this is a no-op (no point recording activity
    /// on a connection that's about to close).
    ///
    /// Initial load is `Acquire` to synchronize with the sweeper's
    /// `Release` CAS in `try_mark_aborted_if_stale`; on retry, the CAS
    /// itself provides the synchronization.
    #[inline]
    fn note_activity(&self) {
        let now = monotonic_micros();
        let mut cur = self.state.load(Ordering::Acquire);
        loop {
            if cur & ABORTED_BIT != 0 {
                return;
            }
            // High bit clear (we just verified), so `cur | now` is the
            // same as `now` after masking. Keep as explicit OR for clarity.
            let new = (cur & ABORTED_BIT) | now;
            match self
                .state
                .compare_exchange_weak(cur, new, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    #[inline]
    fn is_aborted(&self) -> bool {
        self.state.load(Ordering::Acquire) & ABORTED_BIT != 0
    }

    /// Try to set the abort flag iff `last_activity` is at least
    /// `idle_timeout` stale relative to `now_micros`. Uses CAS so a
    /// concurrent `note_activity()` racing with the sweeper either:
    ///   (a) wins, updates `last_activity`, our CAS fails, we re-read
    ///       and observe the connection is no longer stale → skip; or
    ///   (b) loses, our CAS succeeds, the conn task's next CAS sees
    ///       ABORTED_BIT and bails (note_activity becomes a no-op).
    /// Returns `true` if we newly marked the connection aborted.
    ///
    /// Initial load is `Acquire` to synchronize with `note_activity`'s
    /// `Release` CAS.
    fn try_mark_aborted_if_stale(&self, now_micros: u64) -> bool {
        let mut cur = self.state.load(Ordering::Acquire);
        loop {
            if cur & ABORTED_BIT != 0 {
                return false; // already aborted by a previous sweep
            }
            let last = cur & ACTIVITY_MASK;
            if now_micros.saturating_sub(last) < self.idle_timeout_micros {
                return false; // not stale
            }
            let new = cur | ABORTED_BIT;
            match self
                .state
                .compare_exchange_weak(cur, new, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Per-timeout-class registry. All connections in this bucket share the
/// same `idle_timeout`, so the sweep cadence is fixed and no shared-min
/// recomputation / `Notify` kick is needed.
struct RegistryInner {
    conns: Mutex<Vec<Weak<IdleConnState>>>,
    registrations_since_prune: AtomicU64,
    /// The shared `idle_timeout` of every connection in this bucket;
    /// drives the sweeper's sleep cadence.
    idle_timeout_micros: u64,
    /// Set to `true` by the sweeper, **under the `conns` lock**,
    /// immediately before it exits because `conns` is empty. Register
    /// must also check this under the `conns` lock before pushing a
    /// new `Weak`: it is not enough to inspect `JoinHandle::is_finished`
    /// because tokio marks the handle finished slightly after the task
    /// function returns, leaving a brief window where register would
    /// otherwise see "sweeper alive" and push into a dying bucket.
    retired: AtomicBool,
}

type Registry = Arc<RegistryInner>;

struct BucketState {
    registry: Registry,
    /// Held to detect a dropped runtime (e.g. between unit tests on the
    /// same worker thread). Not awaited. The `is_finished()` check is
    /// load-bearing for test isolation: `#[tokio::test]` builds a new
    /// runtime per test, which cancels the previous test's sweeper and
    /// flips this handle to "finished" so the next register respawns.
    join: JoinHandle<()>,
}

thread_local! {
    /// Map of `idle_timeout_micros` → bucket. One sweeper per bucket.
    /// New conns either land in an existing bucket (matching timeout)
    /// or spawn a new bucket with a fresh sweeper.
    static SWEEPER: RefCell<HashMap<u64, BucketState>> = RefCell::new(HashMap::new());
}

/// Probe that the current tokio runtime has the time driver enabled.
/// Polls a `tokio::time::sleep` with a no-op waker; if the time driver
/// is absent, the poll panics with tokio's standard message, surfacing
/// from `IdleStream::new` synchronously instead of from inside the
/// spawned sweeper task (where it would be invisible to the caller).
fn probe_time_driver() {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut sleep = std::pin::pin!(tokio::time::sleep(Duration::from_secs(0)));
    let _ = sleep.as_mut().poll(&mut cx);
}

fn register_in_local_sweeper(state: &Arc<IdleConnState>) {
    SWEEPER.with(|cell| {
        let mut buckets = cell.borrow_mut();
        let key = state.idle_timeout_micros;

        // Prune any bucket whose sweeper task has finished (runtime
        // dropped between tests, or natural retirement via empty
        // sweep). Walks all buckets so retired entries at non-`key`
        // keys are also reclaimed. O(n_buckets) per register, but
        // bucket count is bounded by the number of distinct
        // `idle_timeout` values ever observed on this worker — small.
        buckets.retain(|_, b| !b.join.is_finished());

        // Find or create the bucket for this timeout. If we find one,
        // the sweeper might retire it between our entry-lookup and our
        // `conns.lock()` (a brief window where retired=true but the
        // task hasn't fully terminated yet). The retry loop closes that
        // race: if we observe `retired` after taking the lock, we
        // remove the bucket and try again, guaranteed to land in a
        // fresh bucket on the next iteration. Bounded to one retry in
        // practice (the fresh bucket has retired=false and we hold its
        // lock, so the sweeper can't retire it before our push).
        loop {
            // `entry().or_insert_with(...)` returns &mut BucketState;
            // we immediately clone the registry Arc so we can release
            // the &mut borrow on the HashMap and take it back on the
            // retry path if needed.
            let registry_arc = {
                let entry = buckets.entry(key).or_insert_with(|| {
                    let handle = Handle::try_current().unwrap_or_else(|_| {
                        panic!(
                            "IdleStream::new must be called from within a tokio runtime; \
                             no runtime detected via Handle::try_current()"
                        );
                    });
                    // Fail fast if the runtime has no time driver.
                    // tokio::time::sleep panics on first poll without it; we
                    // surface that here in IdleStream::new rather than inside
                    // the spawned task.
                    probe_time_driver();
                    let registry = Arc::new(RegistryInner {
                        conns: Mutex::new(Vec::new()),
                        registrations_since_prune: AtomicU64::new(0),
                        idle_timeout_micros: key,
                        retired: AtomicBool::new(false),
                    });
                    let join = handle.spawn(sweeper_loop(Arc::clone(&registry)));
                    BucketState { registry, join }
                });
                Arc::clone(&entry.registry)
            };

            let mut conns = registry_arc.conns.lock();
            if registry_arc.retired.load(Ordering::Acquire) {
                // Sweeper marked the bucket retired between our entry
                // lookup and our lock acquire. Drop the lock, remove
                // the stale bucket, retry. The next iteration's
                // `or_insert_with` will spawn a fresh bucket.
                drop(conns);
                buckets.remove(&key);
                continue;
            }

            // Sweeper can't retire while we hold the conns lock, so
            // the push is safe.
            let prev = registry_arc
                .registrations_since_prune
                .fetch_add(1, Ordering::Relaxed);
            if prev.saturating_add(1) >= REGISTRATIONS_PER_PRUNE {
                registry_arc
                    .registrations_since_prune
                    .store(0, Ordering::Relaxed);
                conns.retain(|w| w.strong_count() > 0);
            }
            conns.push(Arc::downgrade(state));
            return;
        }
    });
}

async fn sweeper_loop(registry: Registry) {
    let interval = sweep_interval_for(registry.idle_timeout_micros);
    loop {
        tokio::time::sleep(interval).await;
        if sweep_and_maybe_retire(&registry) {
            return;
        }
    }
}

/// Walk the bucket's registry, abort stale conns, prune dead Weaks. If
/// the registry is now empty, mark the bucket retired (under the lock)
/// and return `true` so the sweeper can exit.
fn sweep_and_maybe_retire(registry: &RegistryInner) -> bool {
    let now = monotonic_micros();
    let mut conns = registry.conns.lock();
    conns.retain(|w| {
        let Some(state) = w.upgrade() else {
            return false;
        };
        if state.try_mark_aborted_if_stale(now) {
            // Newly aborted: wake parked tasks so they re-poll and
            // observe the abort. The CAS returned false if the conn
            // task raced us with note_activity, in which case we leave
            // the conn alone (its `last_activity` is fresh now).
            state.read_waker.wake();
            state.write_waker.wake();
        }
        true
    });
    if conns.is_empty() {
        // Mark retired BEFORE dropping the lock so a concurrent
        // register acquiring the lock right after us sees retired=true
        // and recreates the bucket instead of stranding a Weak in a
        // dying registry.
        registry.retired.store(true, Ordering::Release);
        true
    } else {
        false
    }
}

/// Downstream-stream wrapper enforcing a peer-inactivity timeout.
/// Per-byte hot path is two atomic ops; the timer logic lives in a
/// shared sweeper task.
pub struct IdleStream {
    inner: Stream,
    state: Arc<IdleConnState>,
}

impl IdleStream {
    /// Wrap `inner` with a peer-inactivity timeout.
    ///
    /// Each wrapped connection is registered with a per-worker,
    /// per-timeout-class sweeper task that periodically marks it
    /// aborted if no bytes have flowed in either direction for
    /// `idle_timeout`. The next poll observes the abort and returns
    /// `io::ErrorKind::TimedOut`, causing the transport to close.
    ///
    /// Connections with different `idle_timeout` values on the same
    /// worker land in different buckets, so a short-timeout connection
    /// does not force long-timeout connections to be scanned at the
    /// short cadence.
    ///
    /// # Sweep cadence
    ///
    /// Each bucket's sweeper sleeps for
    /// `clamp(idle_timeout / 4, MIN_SWEEP_INTERVAL, MAX_SWEEP_INTERVAL)`.
    /// Concretely: a 90 s timeout sweeps every 5 s (clamped); a 50 ms
    /// timeout sweeps every 12.5 ms. Buckets are independent — one
    /// short-timeout conn does not affect the cadence of a 90 s bucket.
    ///
    /// # Granularity
    ///
    /// The actual timeout fires no earlier than `idle_timeout` and no
    /// later than `idle_timeout + sweep_interval` for the bucket. For
    /// small timeouts where `idle_timeout / 4 < MIN_SWEEP_INTERVAL`,
    /// the floor (`MIN_SWEEP_INTERVAL = 10 ms`) dominates — e.g. a 5
    /// ms timeout can overshoot by up to 10 ms.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime context, or if the
    /// runtime is missing the **time driver**. The wrapper requires
    /// `Handle::try_current()` to spawn the per-bucket sweeper task,
    /// and `tokio::time::sleep` to drive its cadence. `IdleStream::new`
    /// synchronously probes both before returning, so misconfigured
    /// runtimes fail fast at construction rather than producing a
    /// silently-disabled timeout via a late panic inside the spawned
    /// sweeper task. Pingora's server runtime always enables both
    /// drivers.
    pub fn new(inner: Stream, idle_timeout: Duration) -> Self {
        let state = Arc::new(IdleConnState::new(idle_timeout));
        register_in_local_sweeper(&state);
        Self { inner, state }
    }
}

#[inline]
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, TIMED_OUT_MSG)
}

impl AsyncRead for IdleStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Register before reading abort: a sweeper wake between the two
        // is observed by the load; a sweeper write before register is
        // observed too because the load is Acquire.
        self.state.read_waker.register(cx.waker());
        if self.state.is_aborted() {
            return Poll::Ready(Err(timed_out()));
        }
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.state.note_activity();
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
        self.state.write_waker.register(cx.waker());
        if self.state.is_aborted() {
            return Poll::Ready(Err(timed_out()));
        }
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.state.note_activity();
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.write_waker.register(cx.waker());
        if self.state.is_aborted() {
            return Poll::Ready(Err(timed_out()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.write_waker.register(cx.waker());
        if self.state.is_aborted() {
            return Poll::Ready(Err(timed_out()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.state.write_waker.register(cx.waker());
        if self.state.is_aborted() {
            return Poll::Ready(Err(timed_out()));
        }
        let res = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.state.note_activity();
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
        if self.state.is_aborted() {
            return Err(timed_out());
        }
        // try_peek bypasses poll_read, so the abort flag would never be
        // checked here. Race the peek against a poll_fn that registers
        // our read waker and resolves on abort, so the sweeper can
        // interrupt h2c-preface stalls and slow clients.
        let state = Arc::clone(&self.state);
        let abort_fut = poll_fn(move |cx| {
            state.read_waker.register(cx.waker());
            if state.is_aborted() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        let peek_fut = self.inner.try_peek(buf);
        tokio::pin!(peek_fut, abort_fut);
        let res = tokio::select! {
            biased;
            _ = &mut abort_fut => Err(timed_out()),
            res = &mut peek_fut => res,
        };
        if matches!(res, Ok(true)) {
            self.state.note_activity();
        }
        res
    }
}

impl Debug for IdleStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdleStream")
            .field("idle_timeout_micros", &self.state.idle_timeout_micros)
            .finish()
    }
}

/// Snapshot of the current thread's sweeper-bucket count. Used in
/// tests to assert that empty buckets retire (and that a register on
/// a different timeout doesn't accidentally leak a stale bucket).
#[cfg(test)]
fn current_sweeper_bucket_count() -> usize {
    SWEEPER.with(|cell| cell.borrow().len())
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
    //
    // All tests run under `start_paused = true`. Auto-advance fires the
    // sweeper ticks promptly, so test wall time stays in the ms range while
    // virtual time still reflects the configured idle_timeout cadence.
    //
    // Tests assert virtual elapsed time inside the band
    // `[idle_timeout, idle_timeout + sweep_interval]`, where
    // `sweep_interval = clamp(idle_timeout / 4, 10 ms, 5 s)`.

    fn expected_sweep_interval(idle: Duration) -> Duration {
        sweep_interval_for(duration_to_micros(idle))
    }

    #[tokio::test(start_paused = true)]
    async fn timer_fires_on_no_reads() {
        // Hold the writer half alive so the read side stays open (not EOF)
        // but never write anything; the IdleStream's read should time out
        // at idle_timeout.
        let idle = Duration::from_millis(50);
        let (_keep_writer_alive, reader_half) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(reader_half), idle);
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed = Instant::now().saturating_duration_since(start);
        let upper = idle + expected_sweep_interval(idle);
        assert!(elapsed >= idle, "fired too early: {elapsed:?} < {idle:?}");
        assert!(elapsed <= upper, "fired too late: {elapsed:?} > {upper:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn timer_resets_on_successful_read() {
        // Bytes arrive at t≈30ms, then a long quiet stretch. With
        // idle_timeout = 50ms, the first read succeeds and the next read
        // times out ~50ms after the previous read — not 50ms after
        // construction.
        let idle = Duration::from_millis(50);
        let (mut writer, reader_half) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(reader_half), idle);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            writer.write_all(b"hello").await.unwrap();
            // Keep the writer half alive — closing would EOF the reader
            // and the subsequent read would return Ok(0) instead of
            // timing out.
            std::future::pending::<()>().await;
        });

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        let after_first_read = Instant::now();
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed_since_read = Instant::now().saturating_duration_since(after_first_read);
        let upper = idle + expected_sweep_interval(idle);
        assert!(
            elapsed_since_read >= idle,
            "second read fired too early: {elapsed_since_read:?} < {idle:?}"
        );
        assert!(
            elapsed_since_read <= upper,
            "second read fired too late: {elapsed_since_read:?} > {upper:?}"
        );
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
        let idle = Duration::from_millis(50);
        let (our_half, _peer_kept_alive) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(our_half), idle);
        stream.write_all(b"out").await.unwrap();
        let after_write = Instant::now();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let mut buf = [0u8; 16];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed = Instant::now().saturating_duration_since(after_write);
        let upper = idle + expected_sweep_interval(idle);
        assert!(elapsed >= idle, "fired too early: {elapsed:?} < {idle:?}");
        assert!(elapsed <= upper, "fired too late: {elapsed:?} > {upper:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_write_times_out() {
        // duplex(16) << payload (1024) and the peer never drains: the first
        // ~16 bytes succeed and bump last_activity, the rest block. Sweeper
        // tick observes idle_timeout exceeded and aborts.
        let idle = Duration::from_millis(50);
        let (our_half, _peer_kept_alive) = tokio::io::duplex(16);
        let mut stream = IdleStream::new(Box::new(our_half), idle);
        let big = [0u8; 1024];
        let start = Instant::now();
        let err = stream.write_all(&big).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed = Instant::now().saturating_duration_since(start);
        let upper = idle + expected_sweep_interval(idle);
        assert!(elapsed >= idle, "fired too early: {elapsed:?} < {idle:?}");
        assert!(elapsed <= upper, "fired too late: {elapsed:?} > {upper:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn sweeper_wakes_parked_task() {
        // Explicit: a task parked inside inner.poll_read is woken by the
        // sweeper. The inner duplex would otherwise block forever (peer
        // never writes), so this can only succeed via waker.wake() from
        // the sweeper after it sets aborted = true.
        let idle = Duration::from_millis(100);
        let (_keep_alive, reader_half) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(reader_half), idle);
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed = Instant::now().saturating_duration_since(start);
        let upper = idle + expected_sweep_interval(idle);
        assert!(elapsed >= idle, "fired too early: {elapsed:?} < {idle:?}");
        assert!(elapsed <= upper, "fired too late: {elapsed:?} > {upper:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn split_style_wakes_both_directions() {
        // Real split-style: `tokio::io::split` gives independent ReadHalf
        // and WriteHalf, each driven by a separate spawned task with its
        // own waker. Reader parks in `poll_read` (inner duplex has no
        // bytes to deliver) and registers the reader-task's waker on
        // `read_waker`. Writer fills the 16-byte duplex, then parks in
        // `poll_write` and registers the writer-task's waker on
        // `write_waker`. On sweeper abort, BOTH wakers must fire — if
        // `write_waker.wake()` were removed, the writer task would hang
        // forever (its waker is held only by us and by the inner duplex,
        // which never delivers a buffer-drained event) and `writer.await`
        // would never resolve.
        let idle = Duration::from_millis(50);
        let (our_half, _peer_kept_alive) = tokio::io::duplex(16);
        let idle_stream = IdleStream::new(Box::new(our_half), idle);
        let (mut rd, mut wr) = tokio::io::split(idle_stream);

        let writer = tokio::spawn(async move {
            let big = [0u8; 1024];
            wr.write_all(&big).await
        });
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            rd.read(&mut buf).await
        });

        let reader_res = reader.await.unwrap();
        let writer_res = writer.await.unwrap();
        assert_eq!(
            reader_res.unwrap_err().kind(),
            io::ErrorKind::TimedOut,
            "reader half did not time out"
        );
        assert_eq!(
            writer_res.unwrap_err().kind(),
            io::ErrorKind::TimedOut,
            "writer half did not time out (write_waker.wake() likely missing)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_idle_timeout_aborts_within_one_sweep_tick() {
        // Documents the edge: `Duration::ZERO` means "abort on next
        // sweep tick" — bounded by `MIN_SWEEP_INTERVAL`. The wrapper
        // must not UB, hang, or spin on this degenerate config.
        let (_keep_writer, reader_half) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(reader_half), Duration::ZERO);
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed = Instant::now().saturating_duration_since(start);
        // Lower bound: 0 (configured). Upper bound: one full sweep tick
        // at the floor (`MIN_SWEEP_INTERVAL`), plus 1ms of paused-time
        // auto-advance slack.
        assert!(
            elapsed <= MIN_SWEEP_INTERVAL + Duration::from_millis(1),
            "Duration::ZERO timeout overshot the sweep floor: {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sub_floor_idle_timeout_aborts_at_floor() {
        // `idle_timeout` < `MIN_SWEEP_INTERVAL` (10 ms): the floor
        // dominates. A 1 ms timeout should still abort, but within one
        // floor's worth of overshoot.
        let idle = Duration::from_millis(1);
        let (_keep_writer, reader_half) = tokio::io::duplex(1024);
        let mut stream = IdleStream::new(Box::new(reader_half), idle);
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let elapsed = Instant::now().saturating_duration_since(start);
        assert!(elapsed >= idle, "fired too early: {elapsed:?} < {idle:?}");
        assert!(
            elapsed <= idle + MIN_SWEEP_INTERVAL + Duration::from_millis(1),
            "sub-floor timeout overshot the bound: {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn empty_bucket_retires_and_is_pruned_on_next_register() {
        // After the only conn in a bucket drops, the sweeper's next
        // sweep finds conns empty, sets retired=true, and exits. A
        // subsequent register (on a different key) walks the HashMap
        // with `retain(|_, b| !b.join.is_finished())` and prunes the
        // dead bucket. Without retirement, the bucket and its sleeping
        // task would leak for the worker's lifetime.
        let short = Duration::from_millis(50);
        let other = Duration::from_secs(10);

        {
            let (_keep, half) = tokio::io::duplex(1024);
            let _stream = IdleStream::new(Box::new(half), short);
            assert_eq!(current_sweeper_bucket_count(), 1);
        }
        // _stream drops. The bucket's sweeper sleeps `short / 4 = 12.5
        // ms`; we wait long enough that it has run at least once with
        // empty conns, set retired=true, and exited the loop.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Trigger the HashMap retain via a register on a different key.
        let (_keep2, half2) = tokio::io::duplex(1024);
        let _stream2 = IdleStream::new(Box::new(half2), other);

        // Only the new bucket should remain; the retired short bucket
        // was pruned by the retain at the top of register.
        assert_eq!(
            current_sweeper_bucket_count(),
            1,
            "retired bucket leaked: HashMap still contains the dead short-timeout entry"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mixed_timeouts_each_aborted_at_own_deadline() {
        // Two live conns with different timeouts go to different
        // buckets. Each is aborted at its own deadline; the short
        // conn's bucket does NOT force the long conn's bucket to
        // scan at the short cadence. Lock in: long conn survives
        // past short conn's idle_timeout.
        let short = Duration::from_millis(50);
        let long = Duration::from_secs(5);
        let (_keep_a, half_a) = tokio::io::duplex(1024);
        let mut short_stream = IdleStream::new(Box::new(half_a), short);
        let (_keep_b, half_b) = tokio::io::duplex(1024);
        let mut long_stream = IdleStream::new(Box::new(half_b), long);

        // Short conn aborts within short + sweep_interval.
        let mut buf = [0u8; 16];
        let short_err = short_stream.read(&mut buf).await.unwrap_err();
        assert_eq!(short_err.kind(), io::ErrorKind::TimedOut);

        // Long conn must NOT be aborted within short + slack — its
        // bucket sweeps at long/4, not at short/4.
        let long_outcome = tokio::time::timeout(
            short + Duration::from_millis(100),
            long_stream.read(&mut buf),
        )
        .await;
        assert!(
            long_outcome.is_err(),
            "long-timeout stream was aborted by the short bucket's cadence: {long_outcome:?}"
        );
    }

    #[test]
    #[should_panic(expected = "IdleStream::new must be called from within a tokio runtime")]
    fn panics_outside_tokio_runtime() {
        // No `#[tokio::test]` here — bare `#[test]` runs without a
        // tokio runtime, so `Handle::try_current()` inside
        // `register_in_local_sweeper` returns `Err` and IdleStream::new
        // panics. This locks in the fail-fast API contract documented
        // in `IdleStream::new` (silent timeout disablement is a
        // footgun for a public-facing wrapper).
        let (our_half, _peer) = tokio::io::duplex(16);
        let _ = IdleStream::new(Box::new(our_half), Duration::from_millis(50));
    }

    #[test]
    #[should_panic]
    fn panics_without_time_driver() {
        // Build a tokio runtime WITHOUT the time driver (no
        // `enable_time`, no `enable_all`). `IdleStream::new`'s
        // synchronous `probe_time_driver` call must surface the panic
        // here — at construction — rather than letting it explode
        // later inside the spawned sweeper task where the caller would
        // never see it (and the timeout would silently never fire).
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let (our_half, _peer) = tokio::io::duplex(16);
            let _ = IdleStream::new(Box::new(our_half), Duration::from_millis(50));
        });
    }

    #[tokio::test(start_paused = true)]
    async fn note_activity_after_abort_is_noop() {
        // Pure unit test of IdleConnState CAS semantics; intentionally
        // bypasses registration / sweeper. Once aborted, note_activity
        // must not clear the abort bit.
        let state = Arc::new(IdleConnState::new(Duration::from_millis(50)));
        let stale_time = monotonic_micros() + duration_to_micros(Duration::from_secs(1));
        assert!(state.try_mark_aborted_if_stale(stale_time));
        assert!(state.is_aborted());
        state.note_activity();
        assert!(
            state.is_aborted(),
            "note_activity cleared the abort bit, breaking abort-stickiness"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn try_mark_aborted_is_idempotent() {
        // Pure unit test of IdleConnState CAS semantics; intentionally
        // bypasses registration / sweeper. Second attempt on an
        // already-aborted state returns false (no new transition), so
        // sweep_once won't double-wake.
        let state = Arc::new(IdleConnState::new(Duration::from_millis(50)));
        let stale_time = monotonic_micros() + duration_to_micros(Duration::from_secs(1));
        assert!(state.try_mark_aborted_if_stale(stale_time));
        assert!(
            !state.try_mark_aborted_if_stale(stale_time),
            "second try_mark_aborted_if_stale on an aborted state should return false"
        );
    }
}
