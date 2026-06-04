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

#[cfg(target_os = "linux")]
use log::{debug, error, warn};
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::socket::{self, AddressFamily, Backlog, RecvMsg, SockFlag, SockType, UnixAddr};
#[cfg(target_os = "linux")]
use nix::sys::stat;
use nix::{Error, NixPath};
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::io::{IoSlice, IoSliceMut};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::io::RawFd;
#[cfg(target_os = "linux")]
use std::{thread, time};

// Utilities to transfer file descriptors between sockets, e.g. during graceful upgrades.

/// Container for open file descriptors and their associated bind addresses.
pub struct Fds {
    /// Actively used file descriptors, keyed by bind address.
    /// Populated by `add()` and by listener setup via `mark_used()`.
    map: HashMap<String, RawFd>,
    /// Inherited FDs not yet claimed by a listener.
    /// Populated exclusively by `deserialize()`. When a listener claims an inherited
    /// FD via `add()` or `mark_used()`, the entry is moved from here to `map`.
    /// Any entries remaining at `close_unused_inherited()` time are stale (the
    /// port was removed from the current config) and will be closed.
    inherited_pending: HashMap<String, RawFd>,
}

impl Fds {
    pub fn new() -> Self {
        Fds {
            map: HashMap::new(),
            inherited_pending: HashMap::new(),
        }
    }

    pub fn add(&mut self, bind: String, fd: RawFd) {
        // If this key arrived via deserialize(), move it out of inherited_pending
        // so close_unused_inherited() doesn't treat it as stale.
        self.inherited_pending.remove(&bind);
        self.map.insert(bind, fd);
    }

    pub fn get(&self, bind: &str) -> Option<&RawFd> {
        // Claimed FDs live in map; inherited-but-not-yet-claimed ones live in
        // inherited_pending. Check map first so post-claim lookups are fast.
        self.map
            .get(bind)
            .or_else(|| self.inherited_pending.get(bind))
    }

    pub fn remove(&mut self, bind: &str) {
        self.inherited_pending.remove(bind);
        self.map.remove(bind);
    }

    /// Mark a key as actively used.
    ///
    /// When an inherited FD is reused directly under its existing key (without going
    /// through `add()`), call this to move the entry from `inherited_pending` to `map`
    /// so that `close_unused_inherited()` does not treat it as stale.
    pub fn mark_used(&mut self, key: &str) {
        if let Some(fd) = self.inherited_pending.remove(key) {
            self.map.insert(key.to_string(), fd);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn serialize(&self) -> (Vec<String>, Vec<RawFd>) {
        // `inherited_pending` must be empty here — call `close_unused_inherited()` before
        // `send_to_sock()` to ensure stale inherited FDs are not forwarded.
        self.map.iter().map(|(key, val)| (key.clone(), val)).unzip()
    }

    pub fn deserialize(&mut self, binds: Vec<String>, fds: Vec<RawFd>) {
        assert_eq!(binds.len(), fds.len());
        for (bind, fd) in binds.into_iter().zip(fds) {
            // Inherited FDs live in inherited_pending until a listener claims them.
            // They are NOT inserted into map until claimed via add() or mark_used().
            self.inherited_pending.insert(bind, fd);
        }
    }

    /// Close and remove all inherited FDs that were never claimed by a listener.
    ///
    /// Call this before `send_to_sock()` during a graceful upgrade so that stale FDs
    /// (ports removed from the current config) are neither kept open nor forwarded to
    /// the next process generation.
    pub fn close_unused_inherited(&mut self) {
        for (key, fd) in self.inherited_pending.drain() {
            log::info!("Closing unclaimed inherited fd {} for {}", fd, key);
            let _ = nix::unistd::close(fd);
        }
    }

    pub fn send_to_sock<P>(&self, path: &P) -> Result<usize, Error>
    where
        P: ?Sized + NixPath + std::fmt::Display,
    {
        let (vec_key, vec_fds) = self.serialize();
        send_fds_chunked_to(&vec_key, &vec_fds, path, None)
    }

    pub fn get_from_sock<P>(&mut self, path: &P) -> Result<(), Error>
    where
        P: ?Sized + NixPath + std::fmt::Display,
    {
        let (fds, keys) = recv_fds_chunked_from(path, None)?;
        self.deserialize(keys, fds);
        Ok(())
    }
}

impl Drop for Fds {
    fn drop(&mut self) {
        // Safety net: close any unclaimed inherited FDs remaining in inherited_pending.
        // FDs in map are owned by their respective listeners and must NOT be closed here.
        self.close_unused_inherited();
    }
}

fn serialize_vec_string(vec_string: &[String]) -> Vec<u8> {
    // Space-separated serialization. Uses dynamic allocation to avoid silent truncation.
    vec_string.join(" ").into_bytes()
}

fn deserialize_vec_string(buf: &[u8]) -> Result<Vec<String>, Error> {
    let joined = std::str::from_utf8(buf).map_err(|_| Error::EINVAL)?;
    Ok(joined.split_ascii_whitespace().map(String::from).collect())
}

// Kept for backward compatibility and unit tests; production code uses recv_fds_chunked_from.
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(target_os = "linux")]
pub fn get_fds_from<P>(
    path: &P,
    payload: &mut [u8],
    max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    let max_retry = max_retry.unwrap_or(MAX_RETRY);
    const MAX_FDS: usize = 1024;

    let listen_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let unix_addr = UnixAddr::new(path).unwrap();
    // clean up old sock
    match nix::unistd::unlink(path) {
        Ok(()) => {
            debug!("unlink {} done", path);
        }
        Err(e) => {
            // Normal if file does not exist
            debug!("unlink {} failed: {}", path, e);
            // TODO: warn if exist but not able to unlink
        }
    };
    socket::bind(listen_fd.as_raw_fd(), &unix_addr).unwrap();

    /* sock is created before we change user, need to give permission */
    stat::fchmodat(
        // SAFETY: AT_FDCWD is a well-defined POSIX sentinel constant used by *at() syscalls
        // to indicate the current working directory. It is not a real file descriptor and does
        // not require ownership or lifetime guarantees.
        unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
        path,
        stat::Mode::from_bits_truncate(0o666),
        stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();

    socket::listen(
        &listen_fd,
        Backlog::new(8).expect("8 is well within SOMAXCONN"),
    )
    .unwrap();

    let fd = match accept_with_retry_timeout(listen_fd.as_raw_fd(), max_retry) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Giving up reading socket from: {path}, error: {e:?}");
            //cleanup
            if nix::unistd::close(listen_fd).is_ok() {
                nix::unistd::unlink(path).unwrap();
            }
            return Err(e);
        }
    };

    let mut io_vec = [IoSliceMut::new(payload); 1];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS]);
    let msg: RecvMsg<UnixAddr> = socket::recvmsg(
        fd,
        &mut io_vec,
        Some(&mut cmsg_buf),
        socket::MsgFlags::empty(),
    )
    .unwrap();

    let mut fds: Vec<RawFd> = Vec::new();
    for cmsg in msg.cmsgs()? {
        if let socket::ControlMessageOwned::ScmRights(mut vec_fds) = cmsg {
            fds.append(&mut vec_fds)
        } else {
            warn!("Unexpected control messages: {cmsg:?}")
        }
    }

    //cleanup
    if nix::unistd::close(listen_fd).is_ok() {
        nix::unistd::unlink(path).unwrap();
    }

    Ok((fds, msg.bytes))
}

#[cfg(not(target_os = "linux"))]
pub fn get_fds_from<P>(
    _path: &P,
    _payload: &mut [u8],
    _max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, usize), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    log::error!("Upgrade is not currently supported outside of Linux platforms");
    Err(Errno::ECONNREFUSED)
}

#[cfg(target_os = "linux")]
const MAX_RETRY: usize = 5;
#[cfg(target_os = "linux")]
const RETRY_INTERVAL: time::Duration = time::Duration::from_secs(1);
/// Linux kernel limit (`SCM_MAX_FD`): maximum FDs per `SCM_RIGHTS` control message.
const MAX_FDS_PER_MSG: usize = 253;

#[cfg(target_os = "linux")]
fn accept_with_retry_timeout(listen_fd: i32, max_retry: usize) -> Result<i32, Error> {
    let mut retried = 0;
    loop {
        match socket::accept(listen_fd) {
            Ok(fd) => return Ok(fd),
            Err(e) => {
                if retried > max_retry {
                    return Err(e);
                }
                match e {
                    Errno::EAGAIN => {
                        error!(
                            "No incoming socket transfer, sleep {RETRY_INTERVAL:?} and try again"
                        );
                        retried += 1;
                        thread::sleep(RETRY_INTERVAL);
                    }
                    _ => {
                        error!("Error accepting socket transfer: {e}");
                        return Err(e);
                    }
                }
            }
        }
    }
}

// Kept for backward compatibility and unit tests; production code uses send_fds_chunked_to.
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(target_os = "linux")]
pub fn send_fds_to<P>(
    fds: Vec<RawFd>,
    payload: &[u8],
    path: &P,
    max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    let max_retry = max_retry.unwrap_or(MAX_RETRY);
    const MAX_NONBLOCKING_POLLS: usize = 20;
    const NONBLOCKING_POLL_INTERVAL: time::Duration = time::Duration::from_millis(500);

    let send_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    let unix_addr = UnixAddr::new(path)?;
    let mut retried = 0;
    let mut nonblocking_polls = 0;

    let conn_result: Result<usize, Error> = loop {
        match socket::connect(send_fd.as_raw_fd(), &unix_addr) {
            Ok(_) => break Ok(0),
            Err(e) => match e {
                /* If the new process hasn't created the upgrade sock we'll get an ENOENT.
                ECONNREFUSED may happen if the sock wasn't cleaned up
                and the old process tries sending before the new one is listening.
                EACCES may happen if connect() happen before the correct permission is set */
                Errno::ENOENT | Errno::ECONNREFUSED | Errno::EACCES => {
                    /*the server is not ready yet*/
                    retried += 1;
                    if retried > max_retry {
                        error!(
                            "Max retry: {} reached. Giving up sending socket to: {}, error: {:?}",
                            max_retry, path, e
                        );
                        break Err(e);
                    }
                    warn!("server not ready, will try again in {RETRY_INTERVAL:?}");
                    thread::sleep(RETRY_INTERVAL);
                }
                /* handle nonblocking IO */
                Errno::EINPROGRESS => {
                    nonblocking_polls += 1;
                    if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                        error!("Connect() not ready after retries when sending socket to: {path}",);
                        break Err(e);
                    }
                    warn!("Connect() not ready, will try again in {NONBLOCKING_POLL_INTERVAL:?}",);
                    thread::sleep(NONBLOCKING_POLL_INTERVAL);
                }
                _ => {
                    error!("Error sending socket to: {path}, error: {e:?}");
                    break Err(e);
                }
            },
        }
    };

    let result = match conn_result {
        Ok(_) => {
            let io_vec = [IoSlice::new(payload); 1];
            let scm = socket::ControlMessage::ScmRights(fds.as_slice());
            let cmsg = [scm; 1];
            loop {
                match socket::sendmsg(
                    send_fd.as_raw_fd(),
                    &io_vec,
                    &cmsg,
                    socket::MsgFlags::empty(),
                    None::<&UnixAddr>,
                ) {
                    Ok(result) => break Ok(result),
                    Err(e) => match e {
                        /* handle nonblocking IO */
                        Errno::EAGAIN => {
                            nonblocking_polls += 1;
                            if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                                error!(
                                    "Sendmsg() not ready after retries when sending socket to: {}",
                                    path
                                );
                                break Err(e);
                            }
                            warn!(
                                "Sendmsg() not ready, will try again in {:?}",
                                NONBLOCKING_POLL_INTERVAL
                            );
                            thread::sleep(NONBLOCKING_POLL_INTERVAL);
                        }
                        _ => break Err(e),
                    },
                }
            }
        }
        Err(_) => conn_result,
    };

    nix::unistd::close(send_fd).unwrap();
    result
}

#[cfg(not(target_os = "linux"))]
pub fn send_fds_to<P>(
    _fds: Vec<RawFd>,
    _payload: &[u8],
    _path: &P,
    _max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    Ok(0)
}

/// Like [`send_fds_to`] but sends FDs in chunks of at most [`MAX_FDS_PER_MSG`] per message,
/// staying within the Linux `SCM_RIGHTS` (`SCM_MAX_FD = 253`) limit.
///
/// Each message carries a key-subset in the iov payload and the matching FDs in `SCM_RIGHTS`.
/// The receiver detects end-of-stream when the sender closes the connection (bytes == 0 in
/// `recvmsg`). Old receivers that call `get_fds_from` only once will still work: they receive
/// the first chunk and see EOF on the next call, which is indistinguishable from the old
/// single-message protocol.
#[cfg(target_os = "linux")]
fn send_fds_chunked_to<P>(
    keys: &[String],
    fds: &[RawFd],
    path: &P,
    max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    debug_assert_eq!(keys.len(), fds.len());
    let max_retry = max_retry.unwrap_or(MAX_RETRY);
    const MAX_NONBLOCKING_POLLS: usize = 20;
    const NONBLOCKING_POLL_INTERVAL: time::Duration = time::Duration::from_millis(500);

    let send_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )?;
    let unix_addr = UnixAddr::new(path)?;
    let mut retried = 0;
    let mut nonblocking_polls = 0;

    // Connect with the same retry logic as send_fds_to.
    let conn_result: Result<(), Error> = loop {
        match socket::connect(send_fd, &unix_addr) {
            Ok(_) => break Ok(()),
            Err(e) => match e {
                Errno::ENOENT | Errno::ECONNREFUSED | Errno::EACCES => {
                    retried += 1;
                    if retried > max_retry {
                        error!(
                            "Max retry: {} reached. Giving up sending socket to: {}, error: {:?}",
                            max_retry, path, e
                        );
                        break Err(e);
                    }
                    warn!("server not ready, will try again in {RETRY_INTERVAL:?}");
                    thread::sleep(RETRY_INTERVAL);
                }
                Errno::EINPROGRESS => {
                    nonblocking_polls += 1;
                    if nonblocking_polls >= MAX_NONBLOCKING_POLLS {
                        error!("Connect() not ready after retries when sending socket to: {path}");
                        break Err(e);
                    }
                    warn!("Connect() not ready, will try again in {NONBLOCKING_POLL_INTERVAL:?}");
                    thread::sleep(NONBLOCKING_POLL_INTERVAL);
                }
                _ => {
                    error!("Error sending socket to: {path}, error: {e:?}");
                    break Err(e);
                }
            },
        }
    };

    let result = match conn_result {
        Ok(()) => {
            let mut total_sent = 0;
            let mut send_err: Option<Error> = None;
            // If fds is empty we send no messages; closing the connection is sufficient for
            // the receiver to see EOF and return an empty result.
            for (key_chunk, fd_chunk) in keys
                .chunks(MAX_FDS_PER_MSG)
                .zip(fds.chunks(MAX_FDS_PER_MSG))
            {
                let payload = serialize_vec_string(key_chunk);
                let io_vec = [IoSlice::new(&payload); 1];
                let scm = socket::ControlMessage::ScmRights(fd_chunk);
                let cmsg = [scm; 1];
                let mut nb_polls = nonblocking_polls;
                let sent = loop {
                    match socket::sendmsg(
                        send_fd,
                        &io_vec,
                        &cmsg,
                        socket::MsgFlags::empty(),
                        None::<&UnixAddr>,
                    ) {
                        Ok(n) => break Ok(n),
                        Err(Errno::EAGAIN) => {
                            nb_polls += 1;
                            if nb_polls >= MAX_NONBLOCKING_POLLS {
                                error!("Sendmsg() not ready after retries when sending socket to: {path}");
                                break Err(Errno::EAGAIN);
                            }
                            warn!("Sendmsg() not ready, will try again in {NONBLOCKING_POLL_INTERVAL:?}");
                            thread::sleep(NONBLOCKING_POLL_INTERVAL);
                        }
                        Err(e) => break Err(e),
                    }
                };
                match sent {
                    Ok(n) => total_sent += n,
                    Err(e) => {
                        send_err = Some(e);
                        break;
                    }
                }
            }
            match send_err {
                None => Ok(total_sent),
                Some(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    };

    nix::unistd::close(send_fd).unwrap();
    result
}

#[cfg(not(target_os = "linux"))]
fn send_fds_chunked_to<P>(
    _keys: &[String],
    _fds: &[RawFd],
    _path: &P,
    _max_retry: Option<usize>,
) -> Result<usize, Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    Ok(0)
}

/// Counterpart to [`send_fds_chunked_to`]: receives all chunks until EOF (sender closed),
/// accumulating keys and FDs across messages.
///
/// Also compatible with old senders using a single `send_fds_to` call: they send one message
/// then close, which from the receiver's perspective is identical to a one-chunk protocol.
#[cfg(target_os = "linux")]
fn recv_fds_chunked_from<P>(
    path: &P,
    max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, Vec<String>), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    let max_retry = max_retry.unwrap_or(MAX_RETRY);

    let listen_fd = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_NONBLOCK,
        None,
    )
    .unwrap();
    let unix_addr = UnixAddr::new(path).unwrap();
    match nix::unistd::unlink(path) {
        Ok(()) => debug!("unlink {} done", path),
        Err(e) => debug!("unlink {} failed: {}", path, e),
    }
    socket::bind(listen_fd, &unix_addr).unwrap();
    stat::fchmodat(
        None,
        path,
        stat::Mode::all(),
        stat::FchmodatFlags::FollowSymlink,
    )
    .unwrap();
    socket::listen(listen_fd, 8).unwrap();

    let conn_fd = match accept_with_retry_timeout(listen_fd, max_retry) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Giving up reading socket from: {path}, error: {e:?}");
            if nix::unistd::close(listen_fd).is_ok() {
                nix::unistd::unlink(path).unwrap();
            }
            return Err(e);
        }
    };

    let mut all_fds: Vec<RawFd> = Vec::new();
    let mut all_keys: Vec<String> = Vec::new();

    // The accepted socket is blocking (standard accept() does not inherit SOCK_NONBLOCK).
    // We loop recvmsg until bytes == 0, which signals EOF (sender closed the connection).
    loop {
        let mut payload_buf = [0u8; 32768];
        let mut io_vec = [IoSliceMut::new(&mut payload_buf); 1];
        let mut cmsg_buf = nix::cmsg_space!([RawFd; MAX_FDS_PER_MSG]);
        let msg: RecvMsg<UnixAddr> = socket::recvmsg(
            conn_fd,
            &mut io_vec,
            Some(&mut cmsg_buf),
            socket::MsgFlags::empty(),
        )
        .unwrap();

        if msg.bytes == 0 {
            // EOF: sender closed the connection.
            break;
        }

        match deserialize_vec_string(&payload_buf[..msg.bytes]) {
            Ok(keys) => {
                all_keys.extend(keys);
                for cmsg in msg.cmsgs() {
                    if let socket::ControlMessageOwned::ScmRights(mut chunk_fds) = cmsg {
                        all_fds.append(&mut chunk_fds);
                    } else {
                        warn!("Unexpected control message: {cmsg:?}");
                    }
                }
            }
            Err(e) => {
                // Deserialization failed: skip this chunk entirely so keys and FDs stay
                // in sync. Drain and close any kernel-duped FDs to avoid leaking them.
                warn!("Failed to deserialize keys in chunk — skipping chunk FDs: {e:?}");
                for cmsg in msg.cmsgs() {
                    if let socket::ControlMessageOwned::ScmRights(chunk_fds) = cmsg {
                        for fd in chunk_fds {
                            let _ = nix::unistd::close(fd);
                        }
                    }
                }
            }
        }
    }

    let _ = nix::unistd::close(conn_fd);
    if nix::unistd::close(listen_fd).is_ok() {
        nix::unistd::unlink(path).unwrap();
    }
    Ok((all_fds, all_keys))
}

#[cfg(not(target_os = "linux"))]
fn recv_fds_chunked_from<P>(
    _path: &P,
    _max_retry: Option<usize>,
) -> Result<(Vec<RawFd>, Vec<String>), Error>
where
    P: ?Sized + NixPath + std::fmt::Display,
{
    log::error!("Upgrade is not currently supported outside of Linux platforms");
    Err(Errno::ECONNREFUSED)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;
    use log::{debug, error};

    fn init_log() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_add_get() {
        init_log();
        let mut fds = Fds::new();
        let key = "1.1.1.1:80".to_string();
        fds.add(key.clone(), 128);
        assert_eq!(128, *fds.get(&key).unwrap());
    }

    #[test]
    fn test_table_serde() {
        init_log();
        let fd1 = make_pipe_fd();
        let fd2 = make_pipe_fd();
        let key1 = "1.1.1.1:80".to_string();
        let key2 = "1.1.1.1:443".to_string();
        let mut fds = Fds::new();
        fds.add(key1.clone(), fd1);
        fds.add(key2.clone(), fd2);

        let (k, v) = fds.serialize();
        let mut fds2 = Fds::new();
        fds2.deserialize(k, v);

        assert_eq!(fd1, *fds2.get(&key1).unwrap());
        assert_eq!(fd2, *fds2.get(&key2).unwrap());
        // fds2 drops here: close_unused_inherited() closes fd1 and fd2 (inherited, unclaimed).
        // fds drops here: its map entries are NOT closed (add()-owned fds, correct).
    }

    #[test]
    fn test_vec_string_serde() {
        init_log();
        let vec_str: Vec<String> = vec!["aaaa".to_string(), "bbb".to_string()];
        let ser_bytes = serialize_vec_string(&vec_str);
        let de_vec_string = deserialize_vec_string(&ser_bytes).unwrap();
        assert_eq!(de_vec_string.len(), 2);
        assert_eq!(de_vec_string[0], "aaaa");
        assert_eq!(de_vec_string[1], "bbb");
    }

    #[test]
    fn test_send_receive_fds() {
        init_log();
        let dumb_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        // receiver need to start in another thread since it is blocking
        let child = thread::spawn(move || {
            let mut buf: [u8; 32] = [0; 32];
            let (fds, bytes) =
                get_fds_from("/tmp/pingora_fds_receive.sock", &mut buf, None).unwrap();
            debug!("{:?}", fds);
            assert_eq!(1, fds.len());
            assert_eq!(32, bytes);
            assert_eq!(1, buf[0]);
            assert_eq!(1, buf[31]);
        });

        let fds = vec![dumb_fd.as_raw_fd()];
        let buf: [u8; 128] = [1; 128];
        match send_fds_to(fds, &buf, "/tmp/pingora_fds_receive.sock", None) {
            Ok(sent) => {
                assert!(sent > 0);
            }
            Err(e) => {
                error!("{:?}", e);
                panic!()
            }
        }

        child.join().unwrap();
    }

    #[test]
    fn test_serde_via_socket() {
        init_log();
        let mut fds = Fds::new();
        let key1 = "1.1.1.1:80".to_string();
        let dumb_fd1 = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        fds.add(key1.clone(), dumb_fd1.as_raw_fd());
        let key2 = "1.1.1.1:443".to_string();
        let dumb_fd2 = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        fds.add(key2.clone(), dumb_fd2.as_raw_fd());

        let child = thread::spawn(move || {
            let mut fds2 = Fds::new();
            fds2.get_from_sock("/tmp/pingora_fds_receive2.sock")
                .unwrap();
            assert!(*fds2.get(&key1).unwrap() > 0);
            assert!(*fds2.get(&key2).unwrap() > 0);
        });

        fds.send_to_sock("/tmp/pingora_fds_receive2.sock").unwrap();
        child.join().unwrap();
    }

    #[test]
    fn test_send_fds_to_respects_configurable_timeout() {
        init_log();
        use std::time::Instant;

        let dumb_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();

        let fds = vec![dumb_fd.as_raw_fd()];
        let buf: [u8; 32] = [1; 32];

        // Try to send with a custom max_retries of 2
        let start = Instant::now();
        let result = send_fds_to(fds, &buf, "/tmp/pingora_test_config_send.sock", Some(2));
        let elapsed = start.elapsed();

        // Should fail after 2 retries with RETRY_INTERVAL (1 second) between each
        // Total time should be approximately 2 seconds
        assert!(result.is_err());
        assert!(
            elapsed.as_secs() >= 2,
            "Expected at least 2 seconds, got {:?}",
            elapsed
        );
        assert!(
            elapsed.as_secs() < 4,
            "Expected less than 4 seconds, got {:?}",
            elapsed
        );
    }

    #[test]
    fn test_get_fds_from_respects_configurable_timeout() {
        init_log();
        use std::time::Instant;

        let mut buf: [u8; 32] = [0; 32];

        // Try to receive with a custom max_retries of 2
        let start = Instant::now();
        let result = get_fds_from("/tmp/pingora_test_config_receive.sock", &mut buf, Some(2));
        let elapsed = start.elapsed();

        // Should fail after 2 retries with RETRY_INTERVAL (1 second) between each
        // Total time should be approximately 2 seconds
        assert!(result.is_err());
        assert!(
            elapsed.as_secs() >= 2,
            "Expected at least 2 seconds, got {:?}",
            elapsed
        );
        assert!(
            elapsed.as_secs() < 4,
            "Expected less than 4 seconds, got {:?}",
            elapsed
        );
    }

    // ── inherited_pending / close_unused_inherited tests ───────────────────
    //
    // These tests use real pipe fds (via nix::unistd::pipe()) as the "inherited" fds
    // so that close_unused_inherited() operates on fds we actually own, not arbitrary
    // integers that might alias open fds belonging to other test threads.
    // Each test only checks map state — not fd liveness — to avoid races between
    // close() and the OS reusing the fd number.

    fn make_pipe_fd() -> RawFd {
        let (read_end, write_end) = nix::unistd::pipe().expect("pipe()");
        // Close the read end immediately; we only need a single real fd for tests.
        let _ = nix::unistd::close(read_end);
        write_end
    }

    #[test]
    fn test_close_unused_inherited_removes_unclaimed() {
        init_log();
        let fd_stale = make_pipe_fd();
        let fd_active = make_pipe_fd();
        let mut fds = Fds::new();
        fds.deserialize(
            vec!["0.0.0.0:8080".to_string(), "0.0.0.0:9090".to_string()],
            vec![fd_stale, fd_active],
        );
        // Claim one via add() so it is moved from inherited_pending to map.
        fds.add("0.0.0.0:9090".to_string(), fd_active);

        fds.close_unused_inherited(); // closes fd_stale, keeps fd_active

        assert!(
            fds.get("0.0.0.0:8080").is_none(),
            "unclaimed key should not be accessible after close_unused_inherited()"
        );
        assert_eq!(
            *fds.get("0.0.0.0:9090").unwrap(),
            fd_active,
            "claimed key should remain in map"
        );
        // fd_active is still open — close it to avoid a resource leak.
        let _ = nix::unistd::close(fd_active);
    }

    #[test]
    fn test_serialize_after_cleanup_excludes_stale_fds() {
        init_log();
        let fd_stale = make_pipe_fd();
        let fd_active = make_pipe_fd();
        let mut fds = Fds::new();
        fds.deserialize(
            vec!["0.0.0.0:1111".to_string(), "0.0.0.0:2222".to_string()],
            vec![fd_stale, fd_active],
        );
        fds.add("0.0.0.0:2222".to_string(), fd_active);

        fds.close_unused_inherited(); // closes fd_stale

        let (keys, raw_fds) = fds.serialize();
        assert_eq!(keys.len(), 1, "only the active FD should remain");
        assert_eq!(keys[0], "0.0.0.0:2222");
        assert_eq!(raw_fds[0], fd_active);
        let _ = nix::unistd::close(fd_active);
    }

    #[test]
    fn test_mark_used_prevents_removal() {
        init_log();
        let fd = make_pipe_fd();
        let mut fds = Fds::new();
        fds.deserialize(vec!["0.0.0.0:3333".to_string()], vec![fd]);

        fds.mark_used("0.0.0.0:3333");
        fds.close_unused_inherited(); // should NOT close fd (was marked used)

        assert_eq!(
            *fds.get("0.0.0.0:3333").unwrap(),
            fd,
            "mark_used() key should remain in map after close_unused_inherited()"
        );
        let _ = nix::unistd::close(fd);
    }

    #[test]
    fn test_remove_clears_inherited_pending() {
        init_log();
        let fd = make_pipe_fd();
        let mut fds = Fds::new();
        fds.deserialize(vec!["0.0.0.0:4444".to_string()], vec![fd]);

        fds.remove("0.0.0.0:4444");
        // Should be a no-op — no panics, no double-close.
        fds.close_unused_inherited();

        assert!(fds.get("0.0.0.0:4444").is_none());
        // In production, remove() is called to clean up old-style addr keys after the
        // fd was already re-registered under a new per-thread key via add().
        // Here we close the fd directly to avoid a resource leak in the test.
        let _ = nix::unistd::close(fd);
    }

    #[test]
    fn test_add_removes_from_inherited_pending() {
        init_log();
        let fd = make_pipe_fd();
        let mut fds = Fds::new();
        fds.deserialize(vec!["0.0.0.0:5555".to_string()], vec![fd]);

        fds.add("0.0.0.0:5555".to_string(), fd);
        fds.close_unused_inherited(); // should NOT close fd

        assert_eq!(
            *fds.get("0.0.0.0:5555").unwrap(),
            fd,
            "add()-claimed key should not be removed from map"
        );
        let _ = nix::unistd::close(fd);
    }

    #[test]
    fn test_close_unused_inherited_idempotent() {
        init_log();
        let fd = make_pipe_fd();
        let mut fds = Fds::new();
        fds.deserialize(vec!["0.0.0.0:6666".to_string()], vec![fd]);
        fds.close_unused_inherited(); // closes fd
        fds.close_unused_inherited(); // second call must be a no-op, no EBADF abort
        assert!(fds.get("0.0.0.0:6666").is_none());
    }
}
