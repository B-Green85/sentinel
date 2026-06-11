// sentinel-core::ebpf::interceptor — interception decision logic.
//
// This is the pure, platform-independent core of Agent 4. `intercept()` is the
// seam the eBPF event loop (or a ptrace `PTRACE_SYSCALL` loop) drives: it
// resolves the calling process, renders a decision, emits an audit event, and
// returns the decision for the caller to enforce.

use super::{
    DenyReason, EbpfInterceptor, InterceptionDecision, InterceptionEvent, InterceptorMode,
    ProcessIdentity, SyscallId,
};
use crate::types::now_timestamp;

impl EbpfInterceptor {
    /// Process a single interception event. Called from the eBPF/userspace event
    /// loop with the syscall id, its raw argument bytes, and the calling pid.
    ///
    /// Returns the decision; the caller is responsible for allowing or blocking.
    /// Every call emits an `InterceptionEvent` on the audit channel.
    ///
    /// Latency: in this userspace-simulation build the hot path is dominated by
    /// the `/proc/<pid>/exe` read + SHA-256 in `ProcessIdentity::resolve` (tens
    /// of microseconds for a small binary, scaling with binary size). A real
    /// eBPF backend hits the 100–500 ns target because the calling binary's hash
    /// is resolved in-kernel and cached per-pid rather than re-hashed per call.
    pub fn intercept(&self, syscall: SyscallId, args: &[u8], pid: u32) -> InterceptionDecision {
        // `args` carries the raw syscall arguments. The decision in this build is
        // identity/allowlist-based and does not inspect argument contents; the
        // parameter is retained for interface fidelity and future arg-aware
        // policy (e.g. path-scoped open/openat rules).
        let _ = args;

        // Resolve the caller's identity. Best-effort: a failure to resolve is
        // fatal to "Allow" (fail-closed) but never blocks in Observe mode.
        let identity = ProcessIdentity::resolve(pid).ok();

        let decision = match (&self.mode, &identity) {
            // Observe mode never blocks, regardless of identity resolution.
            (InterceptorMode::Observe, _) => InterceptionDecision::Log,
            // Enforce mode with a resolved identity: run the full policy.
            (InterceptorMode::Enforce, Some(id)) => self.make_decision(syscall, args, id),
            // Enforce mode but identity could not be resolved: cannot prove the
            // caller is allowlisted → deny, fail-closed.
            (InterceptorMode::Enforce, None) => {
                InterceptionDecision::Deny(DenyReason::NotAllowlisted)
            }
        };

        // Emit the audit event. A full channel must never wedge the hot path, so
        // a send failure (receiver dropped) is ignored.
        let event = InterceptionEvent {
            pid,
            syscall,
            decision: decision.clone(),
            binary_path: identity.as_ref().map(|i| i.binary_path.clone()),
            binary_hash: identity.as_ref().map(|i| i.binary_hash),
            timestamp: now_timestamp(),
        };
        let _ = self.audit_tx.send(event);

        decision
    }

    /// The core policy. Mirrors the Agent 4 prompt:
    ///   1. Observe mode → always Log.
    ///   2. Not allowlisted → Deny(NotAllowlisted).
    ///   3. Binary changed since registration → Deny(TamperedBinary).
    ///   4. Otherwise → Allow.
    pub(crate) fn make_decision(
        &self,
        syscall: SyscallId,
        args: &[u8],
        identity: &ProcessIdentity,
    ) -> InterceptionDecision {
        let _ = (syscall, args); // not consulted by the current policy

        // 1. Observe mode: log and pass through, unconditionally.
        if self.mode == InterceptorMode::Observe {
            return InterceptionDecision::Log;
        }

        // 2. Process binary must be allowlisted.
        if !self.allowlist.contains(&identity.binary_hash) {
            return InterceptionDecision::Deny(DenyReason::NotAllowlisted);
        }

        // 3. The on-disk binary must not have changed since the identity was
        //    captured (TOCTOU / live-tamper guard).
        if self.binary_hash_changed(identity) {
            return InterceptionDecision::Deny(DenyReason::TamperedBinary);
        }

        // 4. Allow.
        InterceptionDecision::Allow
    }

    /// True if the binary on disk no longer hashes to the value captured in
    /// `identity` — i.e. it was swapped or modified after the identity was
    /// resolved. An unreadable/removed binary is treated as changed (fail-closed).
    pub(crate) fn binary_hash_changed(&self, identity: &ProcessIdentity) -> bool {
        match std::fs::read(&identity.binary_path) {
            Ok(bytes) => super::sha256_bytes(&bytes) != identity.binary_hash,
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::{
        Allowlist, AllowlistEntry, EbpfInterceptor, InterceptorMode, ProcessIdentity,
    };
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::sync::Arc;

    fn interceptor_with(
        mode: InterceptorMode,
        allowlist: Allowlist,
    ) -> (EbpfInterceptor, mpsc::Receiver<super::InterceptionEvent>) {
        let (tx, rx) = mpsc::channel();
        let i = EbpfInterceptor::new(mode, Arc::new(allowlist), tx).unwrap();
        (i, rx)
    }

    /// Write a temp file, return (path, its identity).
    fn temp_binary(name: &str, contents: &[u8]) -> (PathBuf, ProcessIdentity) {
        let dir = std::env::temp_dir().join("sentinel-interceptor-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        let id = ProcessIdentity::from_path(4242, path.clone()).unwrap();
        (path, id)
    }

    #[test]
    fn observe_mode_always_logs() {
        let (i, _rx) = interceptor_with(InterceptorMode::Observe, Allowlist::empty());
        let (_p, id) = temp_binary("observe-bin", b"\x7fELF observe");
        // Even though the allowlist is empty, Observe never denies.
        let d = i.make_decision(SyscallId::Execve, &[], &id);
        assert_eq!(d, InterceptionDecision::Log);
    }

    #[test]
    fn enforce_denies_unallowlisted() {
        let (i, _rx) = interceptor_with(InterceptorMode::Enforce, Allowlist::empty());
        let (_p, id) = temp_binary("unlisted-bin", b"\x7fELF unlisted");
        let d = i.make_decision(SyscallId::Openat, &[], &id);
        assert_eq!(d, InterceptionDecision::Deny(DenyReason::NotAllowlisted));
    }

    #[test]
    fn enforce_allows_allowlisted_unchanged() {
        let (path, id) = temp_binary("good-bin", b"\x7fELF good agent");
        let entry = AllowlistEntry {
            binary_hash: id.binary_hash,
            binary_path: path.clone(),
            parent_hash: [0u8; 32],
            description: "test agent".into(),
        };
        let (i, _rx) =
            interceptor_with(InterceptorMode::Enforce, Allowlist::from_entries(vec![entry]));
        let d = i.make_decision(SyscallId::Connect, &[], &id);
        assert_eq!(d, InterceptionDecision::Allow);
    }

    #[test]
    fn enforce_denies_tampered_binary() {
        let (path, id) = temp_binary("tamper-bin", b"\x7fELF original");
        // Allowlist the ORIGINAL hash.
        let entry = AllowlistEntry {
            binary_hash: id.binary_hash,
            binary_path: path.clone(),
            parent_hash: [0u8; 32],
            description: "tamper test".into(),
        };
        let (i, _rx) =
            interceptor_with(InterceptorMode::Enforce, Allowlist::from_entries(vec![entry]));

        // Now modify the on-disk binary after the identity was captured.
        std::fs::write(&path, b"\x7fELF MODIFIED PAYLOAD").unwrap();

        let d = i.make_decision(SyscallId::Execve, &[], &id);
        assert_eq!(d, InterceptionDecision::Deny(DenyReason::TamperedBinary));
    }

    #[test]
    fn binary_hash_changed_detects_removal() {
        let (path, id) = temp_binary("removed-bin", b"\x7fELF transient");
        let (i, _rx) = interceptor_with(InterceptorMode::Enforce, Allowlist::empty());
        assert!(!i.binary_hash_changed(&id)); // unchanged so far
        std::fs::remove_file(&path).unwrap();
        assert!(i.binary_hash_changed(&id)); // removed → treated as changed
    }

    #[test]
    fn intercept_emits_audit_event() {
        // Observe mode + a real, resolvable-or-not pid: the decision is Log and
        // exactly one event is emitted regardless of identity resolution.
        let (i, rx) = interceptor_with(InterceptorMode::Observe, Allowlist::empty());
        let d = i.intercept(SyscallId::Write, b"payload", std::process::id());
        assert_eq!(d, InterceptionDecision::Log);
        let ev = rx.recv().unwrap();
        assert_eq!(ev.pid, std::process::id());
        assert_eq!(ev.syscall, SyscallId::Write);
        assert_eq!(ev.decision, InterceptionDecision::Log);
    }
}
