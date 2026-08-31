//! SO_PEERCRED-based authentication for the gRPC-over-Unix-socket IPC.
//!
//! Defense-in-depth model:
//!
//! 1. The socket file already lives in `/run/vpnd/` with mode `0660` and an
//!    owner-only parent directory (filesystem ACL).
//! 2. On each accepted connection the kernel reports the peer's UID/GID/PID
//!    via `SO_PEERCRED`. We capture those credentials *before* any byte is
//!    read from the wire.
//! 3. A tonic interceptor checks the captured UID/GID against an allow-list
//!    from `[ipc] allowed_uids = […]` / `allowed_gids = […]`.  Root (UID 0)
//!    and the daemon's own UID are always implicitly trusted.
//!
//! Steps 2-3 close the gap when filesystem permissions are misconfigured (eg.
//! a `chmod 0666 /run/vpnd/control.sock` would otherwise expose every RPC).

use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tonic::transport::server::Connected;
use tracing::{debug, warn};

/// Credentials reported by the kernel via `SO_PEERCRED` for a Unix-domain
/// socket peer.  These values are trustworthy: they are filled in by the
/// kernel and cannot be spoofed by the peer process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

impl PeerCred {
    /// Query `SO_PEERCRED` on a connected `UnixStream`.
    pub fn from_stream(stream: &UnixStream) -> std::io::Result<Self> {
        let fd = stream.as_raw_fd();
        // SAFETY: `getsockopt` with `SO_PEERCRED` writes a `struct ucred`
        // (uid, gid, pid) into the provided buffer.  `fd` is owned by `stream`
        // for the lifetime of this call, so the FD is valid.
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let rc = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(PeerCred {
                uid: cred.uid,
                gid: cred.gid,
                pid: cred.pid,
            })
        }
    }
}

// ── A `UnixStream` wrapper that exposes peer credentials to tonic ─────────

/// `UnixStream` augmented with the peer credentials that were captured at
/// accept time.  Implements [`tonic::transport::server::Connected`] so the
/// credentials are placed in every request's extensions.
#[derive(Debug)]
pub struct AuthenticatedUnixStream {
    inner: UnixStream,
    peer: PeerCred,
}

impl AuthenticatedUnixStream {
    pub fn peer(&self) -> PeerCred {
        self.peer
    }
}

impl Connected for AuthenticatedUnixStream {
    type ConnectInfo = PeerCred;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer
    }
}

impl AsyncRead for AuthenticatedUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthenticatedUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── A `Stream` of authenticated connections suitable for `serve_with_incoming` ─

/// Adapts a [`UnixListener`] into a `Stream<Item = io::Result<AuthenticatedUnixStream>>`.
///
/// The stream silently drops connections whose credentials cannot be queried
/// (which would only happen on a kernel that does not support `SO_PEERCRED` —
/// not a thing on modern Linux).  An audit log entry is produced for each
/// successful accept.
pub struct AuthenticatedListener {
    listener: UnixListener,
    audit: bool,
}

impl AuthenticatedListener {
    pub fn new(listener: UnixListener, audit: bool) -> Self {
        Self { listener, audit }
    }
}

impl Stream for AuthenticatedListener {
    type Item = std::io::Result<AuthenticatedUnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _addr))) => match PeerCred::from_stream(&stream) {
                    Ok(peer) => {
                        if this.audit {
                            debug!(
                                uid = peer.uid,
                                gid = peer.gid,
                                pid = peer.pid,
                                "IPC connection accepted"
                            );
                        }
                        return Poll::Ready(Some(Ok(AuthenticatedUnixStream {
                            inner: stream,
                            peer,
                        })));
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to read SO_PEERCRED — dropping connection");
                        // Loop and accept the next connection rather than
                        // bubbling the error up (which would tear down the server).
                        continue;
                    }
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ── Authorization policy ──────────────────────────────────────────────────

/// Decision returned by [`is_authorized`].  Carries a human-readable reason
/// so it can be logged when access is denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Allowed,
    Denied(String),
}

/// Decide whether a peer with `cred` may use the IPC channel.
///
/// Always-allowed:
/// - UID 0 (root)
/// - The daemon's own UID (so the daemon can talk to itself for self-tests)
///
/// Otherwise the UID/GID must appear in `allowed_uids` / `allowed_gids`.
pub fn is_authorized(
    cred: &PeerCred,
    daemon_uid: u32,
    allowed_uids: &[u32],
    allowed_gids: &[u32],
) -> AuthDecision {
    if cred.uid == 0 {
        return AuthDecision::Allowed;
    }
    if cred.uid == daemon_uid {
        return AuthDecision::Allowed;
    }
    if allowed_uids.contains(&cred.uid) {
        return AuthDecision::Allowed;
    }
    if allowed_gids.contains(&cred.gid) {
        return AuthDecision::Allowed;
    }
    AuthDecision::Denied(format!(
        "uid={} gid={} not in allow-list (allowed_uids={:?}, allowed_gids={:?})",
        cred.uid, cred.gid, allowed_uids, allowed_gids
    ))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_always_allowed() {
        let cred = PeerCred { uid: 0, gid: 0, pid: 1 };
        assert_eq!(
            is_authorized(&cred, 998, &[], &[]),
            AuthDecision::Allowed
        );
    }

    #[test]
    fn daemon_uid_is_always_allowed() {
        let cred = PeerCred { uid: 998, gid: 998, pid: 42 };
        assert_eq!(
            is_authorized(&cred, 998, &[], &[]),
            AuthDecision::Allowed
        );
    }

    #[test]
    fn allowed_uid_passes() {
        let cred = PeerCred { uid: 1000, gid: 1000, pid: 100 };
        assert_eq!(
            is_authorized(&cred, 998, &[1000], &[]),
            AuthDecision::Allowed
        );
    }

    #[test]
    fn allowed_gid_passes() {
        let cred = PeerCred { uid: 1000, gid: 27, pid: 100 };
        assert_eq!(
            is_authorized(&cred, 998, &[], &[27]),
            AuthDecision::Allowed
        );
    }

    #[test]
    fn unknown_uid_denied() {
        let cred = PeerCred { uid: 1234, gid: 1234, pid: 100 };
        match is_authorized(&cred, 998, &[1000], &[27]) {
            AuthDecision::Denied(_) => {}
            other => panic!("expected denial, got {:?}", other),
        }
    }
}
