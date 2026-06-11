// sentinel-core::ebpf::auth — socket authentication via eBPF-backed identity.
//
// The Unix socket at /tmp/sentinel.sock currently accepts any connection. This
// gate authenticates the *connecting process* by its on-disk binary hash before
// the daemon will speak to it.
//
// Silent-drop contract (Agent 4 prompt): an unauthenticated peer NEVER receives
// an explicit rejection. `authenticate` returns `Err`; the caller drops the
// connection without writing a response, so the peer simply times out. This
// denies an adversary the signal that an auth gate even exists.

use super::{Allowlist, ProcessIdentity, SentinelError};
use std::sync::Arc;

/// Authenticates processes connecting to the sentinel socket against the
/// allowlist. Holds only the allowlist (per the Agent 4 interface); logging of
/// dropped attempts is the caller's responsibility so this stays pure/testable.
pub struct SocketAuth {
    allowlist: Arc<Allowlist>,
}

impl SocketAuth {
    pub fn new(allowlist: Arc<Allowlist>) -> Self {
        SocketAuth { allowlist }
    }

    /// Authenticate a peer by its pid (obtained from `SO_PEERCRED`).
    ///
    /// Flow:
    ///   1. Resolve the binary path from `/proc/<pid>/exe`.
    ///   2. Compute SHA-256 of the binary on disk.
    ///   3. Check the hash against the allowlist.
    ///   4. Match  → `Ok(ProcessIdentity)`.
    ///   5. No match → `Err` — the caller logs the attempt and drops the
    ///      connection silently (the peer times out; no rejection is sent).
    ///
    /// On non-Linux platforms identity cannot be resolved from a pid, so this
    /// returns `UnsupportedPlatform` (a form of `Err`, i.e. also a silent drop).
    pub fn authenticate(&self, peer_pid: u32) -> Result<ProcessIdentity, SentinelError> {
        let identity = ProcessIdentity::resolve(peer_pid)?;
        self.authenticate_identity(identity)
    }

    /// The pure allowlist check, separated so it can be exercised
    /// cross-platform (the `/proc` resolution in `authenticate` is Linux-only).
    /// Returns the identity on success; `NotAllowlisted` otherwise.
    pub fn authenticate_identity(
        &self,
        identity: ProcessIdentity,
    ) -> Result<ProcessIdentity, SentinelError> {
        if self.allowlist.contains(&identity.binary_hash) {
            Ok(identity)
        } else {
            // Caller logs + drops silently. The error carries enough context for
            // the audit log without ever being sent back to the peer.
            Err(SentinelError::IdentityUnresolved(format!(
                "pid {} (binary {}) is not allowlisted — connection dropped silently",
                identity.pid,
                identity.binary_path.display()
            )))
        }
    }
}

/// Extract the peer pid from a connected Unix stream via `SO_PEERCRED`. The
/// daemon calls this on each accepted connection, then passes the pid to
/// `SocketAuth::authenticate`. Returns an error if the kernel does not expose a
/// peer pid (e.g. macOS `LOCAL_PEERCRED` provides uid/gid but not pid).
#[cfg(unix)]
pub fn peer_pid(stream: &tokio::net::UnixStream) -> Result<u32, SentinelError> {
    let cred = stream
        .peer_cred()
        .map_err(|e| SentinelError::Io(format!("peer_cred: {e}")))?;
    match cred.pid() {
        Some(pid) if pid > 0 => Ok(pid as u32),
        _ => Err(SentinelError::IdentityUnresolved(
            "SO_PEERCRED did not yield a peer pid on this platform".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::{AllowlistEntry, ProcessIdentity};
    use std::path::PathBuf;

    fn temp_binary(name: &str, contents: &[u8]) -> (PathBuf, ProcessIdentity) {
        let dir = std::env::temp_dir().join("sentinel-auth-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        let id = ProcessIdentity::from_path(1234, path.clone()).unwrap();
        (path, id)
    }

    #[test]
    fn allowlisted_process_authenticates() {
        let (path, id) = temp_binary("auth-good", b"\x7fELF authorized client");
        let entry = AllowlistEntry {
            binary_hash: id.binary_hash,
            binary_path: path.clone(),
            parent_hash: [0u8; 32],
            description: "authorized integrator".into(),
        };
        let auth = SocketAuth::new(Arc::new(Allowlist::from_entries(vec![entry])));

        let result = auth.authenticate_identity(id.clone());
        assert!(result.is_ok());
        let returned = result.unwrap();
        assert_eq!(returned.pid, id.pid);
        assert_eq!(returned.binary_hash, id.binary_hash);
        assert_eq!(returned.binary_path, path);
    }

    #[test]
    fn unallowlisted_process_is_dropped_silently() {
        // Empty allowlist → no process authenticates. Caller gets Err (drop),
        // never a rejection payload.
        let (_path, id) = temp_binary("auth-bad", b"\x7fELF unauthorized client");
        let auth = SocketAuth::new(Arc::new(Allowlist::empty()));

        let result = auth.authenticate_identity(id);
        assert!(result.is_err());
        // The error is for the audit log only; it is never written to the peer.
        match result {
            Err(SentinelError::IdentityUnresolved(msg)) => {
                assert!(msg.contains("not allowlisted"));
            }
            other => panic!("expected silent-drop error, got {other:?}"),
        }
    }

    #[test]
    fn authenticate_by_pid_resolves_current_exe_on_linux() {
        // Allowlist this test binary's own executable and authenticate by our
        // own pid end-to-end. Linux-only (needs /proc); a no-op assertion off
        // Linux keeps the test green cross-platform.
        if !cfg!(target_os = "linux") {
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let self_id = ProcessIdentity::from_path(std::process::id(), exe.clone()).unwrap();
        let entry = AllowlistEntry {
            binary_hash: self_id.binary_hash,
            binary_path: exe,
            parent_hash: [0u8; 32],
            description: "test runner".into(),
        };
        let auth = SocketAuth::new(Arc::new(Allowlist::from_entries(vec![entry])));

        let result = auth.authenticate(std::process::id());
        assert!(result.is_ok(), "self should authenticate: {result:?}");
    }
}
