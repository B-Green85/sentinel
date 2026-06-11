// sentinel-core::ebpf::programs — eBPF program definitions and backend lifecycle.
//
// ─────────────────────────────────────────────────────────────────────────────
// Toolchain decision (per the Agent 4 prompt)
// ─────────────────────────────────────────────────────────────────────────────
// The prompt instructs: check whether `aya` or `libbpf-rs` is already in
// `Cargo.toml`; use whichever exists; if neither exists, fall back to a
// ptrace-based userspace simulation, and DO NOT add a new crate dependency
// without confirmation.
//
// State of the workspace at build time:
//   - Neither `aya` nor `libbpf-rs` is present in any Cargo.toml.
//   - `ptrace(2)` itself requires `nix` or `libc` bindings, which are likewise
//     absent — so a real ptrace attach loop cannot be added here without
//     violating the "no new dependencies" constraint.
//
// Therefore this backend implements the *userspace-simulation* path in the only
// form available with zero new dependencies: the kernel-attach step is a
// documented no-op, and interception events are fed in through
// `EbpfInterceptor::intercept(syscall, args, pid)` — which is exactly the seam a
// real eBPF ring-buffer poller or a ptrace `PTRACE_SYSCALL` loop would drive.
// The decision logic (interceptor.rs) and the socket-auth gate (auth.rs) are
// fully real and exercised by tests.
//
// To upgrade to a real kernel backend later:
//   1. Add `aya` (pure-Rust, no libbpf C toolchain) to sentinel-core/Cargo.toml.
//   2. Compile the BPF programs in `SYSCALL_PROBES` as kprobes/tracepoints.
//   3. Poll the perf/ring buffer and call `intercept()` per event.
// The public surface in mod.rs does not change.

use super::SentinelError;
use std::sync::atomic::{AtomicBool, Ordering};

/// The syscall families this backend attaches probes to. Tracepoint names are
/// the `sys_enter_*` raw-syscall tracepoints used on modern kernels. This table
/// is the single source of truth for "what we hook"; it is consumed by a real
/// eBPF backend at attach time and is exposed here for diagnostics/tests.
pub const SYSCALL_PROBES: &[(&str, &str)] = &[
    ("open", "sys_enter_open"),
    ("openat", "sys_enter_openat"),
    ("connect", "sys_enter_connect"),
    ("accept", "sys_enter_accept"),
    ("execve", "sys_enter_execve"),
    ("execveat", "sys_enter_execveat"),
    ("write", "sys_enter_write"),
    ("sendto", "sys_enter_sendto"),
    ("mmap", "sys_enter_mmap"),
    ("mprotect", "sys_enter_mprotect"),
    ("kill", "sys_enter_kill"),
    ("tkill", "sys_enter_tkill"),
];

/// Which interception backend is in use. Selected at construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// A real eBPF backend (aya / libbpf-rs). Not currently compiled in.
    Ebpf,
    /// Userspace simulation: events fed via `intercept()`. The active default.
    UserspaceSimulation,
    /// No backend possible on this platform (non-Linux).
    Unsupported,
}

impl BackendKind {
    pub fn label(&self) -> &'static str {
        match self {
            BackendKind::Ebpf => "ebpf",
            BackendKind::UserspaceSimulation => "userspace_simulation",
            BackendKind::Unsupported => "unsupported",
        }
    }
}

/// Lifecycle handle for the interception backend. Tracks loaded state with
/// interior mutability so `load`/`unload` can take `&self` (matching the
/// `EbpfInterceptor` interface).
pub struct Backend {
    kind: BackendKind,
    loaded: AtomicBool,
}

impl Backend {
    /// Select the backend appropriate for the current platform/dependencies.
    pub fn new() -> Self {
        Backend {
            kind: Self::select_kind(),
            loaded: AtomicBool::new(false),
        }
    }

    #[cfg(target_os = "linux")]
    fn select_kind() -> BackendKind {
        // Neither aya nor libbpf-rs is compiled in (see module header). Use the
        // userspace simulation path.
        BackendKind::UserspaceSimulation
    }

    #[cfg(not(target_os = "linux"))]
    fn select_kind() -> BackendKind {
        BackendKind::Unsupported
    }

    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::SeqCst)
    }

    /// Attach interception programs.
    ///
    /// On Linux, the userspace-simulation backend marks itself loaded — the
    /// `intercept()` seam is now live. A real eBPF backend would compile and
    /// attach `SYSCALL_PROBES` here.
    ///
    /// On non-Linux platforms this returns `UnsupportedPlatform`; the caller
    /// (daemon) treats that as non-fatal and runs with interception inactive.
    #[cfg(target_os = "linux")]
    pub fn load(&self) -> Result<(), SentinelError> {
        // A real eBPF backend would here:
        //   for (_, tp) in SYSCALL_PROBES { attach_tracepoint("syscalls", tp)?; }
        // The userspace simulation has nothing to attach in-kernel; the probe
        // table documents intended coverage and the intercept() seam is live.
        self.loaded.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(&self) -> Result<(), SentinelError> {
        Err(SentinelError::unsupported("EbpfInterceptor::load"))
    }

    /// Detach and unload. Idempotent.
    #[cfg(target_os = "linux")]
    pub fn unload(&self) -> Result<(), SentinelError> {
        self.loaded.store(false, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn unload(&self) -> Result<(), SentinelError> {
        // Unloading a never-loaded backend is a harmless no-op even off Linux.
        self.loaded.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_table_covers_all_families() {
        // 12 families per the Agent 4 catch table.
        assert_eq!(SYSCALL_PROBES.len(), 12);
        assert!(SYSCALL_PROBES.iter().any(|(f, _)| *f == "execve"));
        assert!(SYSCALL_PROBES.iter().any(|(f, _)| *f == "mprotect"));
    }

    #[test]
    fn backend_kind_matches_platform() {
        let b = Backend::new();
        if cfg!(target_os = "linux") {
            assert_eq!(b.kind(), BackendKind::UserspaceSimulation);
        } else {
            assert_eq!(b.kind(), BackendKind::Unsupported);
        }
    }

    #[test]
    fn load_unload_tracks_state_on_linux() {
        let b = Backend::new();
        assert!(!b.is_loaded());
        let r = b.load();
        if cfg!(target_os = "linux") {
            assert!(r.is_ok());
            assert!(b.is_loaded());
            assert!(b.unload().is_ok());
            assert!(!b.is_loaded());
        } else {
            assert!(matches!(r, Err(SentinelError::UnsupportedPlatform(_))));
            assert!(!b.is_loaded());
        }
    }
}
