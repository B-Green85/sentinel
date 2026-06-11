// sentinel-core::ebpf — eBPF interception layer + socket authentication.
//
// Sentinel v3, Agent 4 deliverable. This module is what makes Sentinel v3
// *active* rather than reactive: a monitored agent cannot complete a syscall
// without Sentinel rendering a decision first.
//
//   Current (reactive):  agent acts → kernel executes → signal detected → respond
//   v3 (active):         agent attempts → Sentinel intercepts → decision → kernel runs (or not)
//
// ─────────────────────────────────────────────────────────────────────────────
// PROVISIONAL CONTRACTS — READ BEFORE RECONCILING
// ─────────────────────────────────────────────────────────────────────────────
// Per the Agent 4 prompt, this module CONSUMES the following types from
// `sentinel-types` (Agent 1) and the daemon core (Agent 3):
//
//     sentinel-types: ProcessIdentity, InterceptionEvent, InterceptionDecision,
//                     DenyReason, SyscallId, SentinelError
//
// As of this writing those types do NOT exist anywhere in the workspace — Agent
// 1 and Agent 3 have not landed. `sentinel-core` does not even depend on
// `sentinel-types`, and the `SentinelError` that exists in `sentinel-types` is a
// `{code, message}` struct, not the enum-with-`UnsupportedPlatform` shape this
// module's interface requires.
//
// To keep Agent 4 self-contained and the crate building with ZERO new
// dependencies, the consumed contracts are defined here, locally, and clearly
// marked `// CONTRACT`. At reconciliation time they should be hoisted into
// `sentinel-types` and these local definitions deleted / re-exported. This
// mirrors the existing repo pattern (see commit "reconcile sentinel-types — add
// 13 missing types"). Field shapes are taken directly from the Agent 4 prompt.
// ─────────────────────────────────────────────────────────────────────────────
//
// Platform policy: everything that touches the kernel is gated behind
// `#[cfg(target_os = "linux")]`. The type definitions and the (pure) decision
// logic compile on every platform. On macOS/Windows the kernel-facing
// operations return `SentinelError::UnsupportedPlatform`.

pub mod auth;
pub mod interceptor;
pub mod programs;

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Arc;

pub use auth::SocketAuth;

// ════════════════════════════════════════════════════════════════════════════
// CONTRACT (sentinel-types / Agent 1) — provisional, see module header.
// ════════════════════════════════════════════════════════════════════════════

/// Error type for the interception layer.
///
/// CONTRACT: the Agent 4 interface is specified as returning
/// `SentinelError::UnsupportedPlatform`, i.e. an *enum*. The `SentinelError`
/// presently in `sentinel-types` is a `{code, message}` struct and is therefore
/// incompatible with this interface. This enum is the provisional shape; at
/// reconciliation, unify it with the `sentinel-types` error (e.g. keep this enum
/// and add a `code()`/`message()` projection for wire compatibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentinelError {
    /// The requested operation requires Linux kernel facilities and is not
    /// available on the current platform.
    UnsupportedPlatform(String),
    /// The allowlist file could not be read or parsed.
    AllowlistLoad(String),
    /// An eBPF/userspace backend operation failed.
    Backend(String),
    /// A process identity could not be resolved (missing `/proc`, dead pid, …).
    IdentityUnresolved(String),
    /// Generic I/O failure surfaced from the OS.
    Io(String),
}

impl SentinelError {
    /// Construct the standard "not supported off Linux" error with a message
    /// naming the operation that was attempted.
    pub fn unsupported(op: &str) -> Self {
        SentinelError::UnsupportedPlatform(format!(
            "{op}: eBPF interception is Linux-only; not available on this platform"
        ))
    }
}

impl std::fmt::Display for SentinelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SentinelError::UnsupportedPlatform(m) => write!(f, "unsupported platform: {m}"),
            SentinelError::AllowlistLoad(m) => write!(f, "allowlist load error: {m}"),
            SentinelError::Backend(m) => write!(f, "ebpf backend error: {m}"),
            SentinelError::IdentityUnresolved(m) => write!(f, "identity unresolved: {m}"),
            SentinelError::Io(m) => write!(f, "io error: {m}"),
        }
    }
}

impl std::error::Error for SentinelError {}

/// The kernel syscall families Sentinel intercepts. See the Agent 4 prompt for
/// the catch table. `Other` carries a raw syscall number that fell outside the
/// intercepted families (used by `Observe` mode / diagnostics).
///
/// CONTRACT: sentinel-types / Agent 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallId {
    Open,
    Openat,
    Connect,
    Accept,
    Execve,
    Execveat,
    Write,
    Sendto,
    Mmap,
    Mprotect,
    Kill,
    Tkill,
    /// A syscall outside the intercepted families, carrying its raw number.
    Other(u64),
}

impl SyscallId {
    /// Map a raw Linux x86-64 syscall number to a `SyscallId`. Numbers are from
    /// `asm/unistd_64.h`. Unrecognised numbers map to `Other(n)`.
    pub fn from_raw(n: u64) -> Self {
        match n {
            2 => SyscallId::Open,
            257 => SyscallId::Openat,
            42 => SyscallId::Connect,
            43 => SyscallId::Accept,
            59 => SyscallId::Execve,
            322 => SyscallId::Execveat,
            1 => SyscallId::Write,
            44 => SyscallId::Sendto,
            9 => SyscallId::Mmap,
            10 => SyscallId::Mprotect,
            62 => SyscallId::Kill,
            200 => SyscallId::Tkill,
            other => SyscallId::Other(other),
        }
    }

    /// Stable lowercase family name for logging.
    pub fn family(&self) -> &'static str {
        match self {
            SyscallId::Open => "open",
            SyscallId::Openat => "openat",
            SyscallId::Connect => "connect",
            SyscallId::Accept => "accept",
            SyscallId::Execve => "execve",
            SyscallId::Execveat => "execveat",
            SyscallId::Write => "write",
            SyscallId::Sendto => "sendto",
            SyscallId::Mmap => "mmap",
            SyscallId::Mprotect => "mprotect",
            SyscallId::Kill => "kill",
            SyscallId::Tkill => "tkill",
            SyscallId::Other(_) => "other",
        }
    }

    /// Whether this syscall is in one of the intercepted families.
    pub fn is_intercepted(&self) -> bool {
        !matches!(self, SyscallId::Other(_))
    }
}

/// The resolved identity of a process that issued a syscall or opened a socket.
///
/// CONTRACT: sentinel-types / Agent 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub binary_path: PathBuf,
    /// SHA-256 of the on-disk binary at the time the identity was captured.
    pub binary_hash: [u8; 32],
}

impl ProcessIdentity {
    /// Build an identity from an explicit path, hashing the file on disk.
    /// Platform-independent (used in tests and by the socket-auth path once a
    /// path is known). Returns `IdentityUnresolved` if the file cannot be read.
    pub fn from_path(pid: u32, path: PathBuf) -> Result<Self, SentinelError> {
        let bytes = std::fs::read(&path).map_err(|e| {
            SentinelError::IdentityUnresolved(format!("read {}: {e}", path.display()))
        })?;
        Ok(ProcessIdentity {
            pid,
            binary_hash: sha256_bytes(&bytes),
            binary_path: path,
        })
    }

    /// Resolve a live process's identity from its pid: read `/proc/<pid>/exe`
    /// and hash the backing binary. Linux-only.
    #[cfg(target_os = "linux")]
    pub fn resolve(pid: u32) -> Result<Self, SentinelError> {
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|e| {
            SentinelError::IdentityUnresolved(format!("readlink /proc/{pid}/exe: {e}"))
        })?;
        ProcessIdentity::from_path(pid, exe)
    }

    /// Off-Linux there is no `/proc`; identity cannot be resolved from a pid.
    #[cfg(not(target_os = "linux"))]
    pub fn resolve(pid: u32) -> Result<Self, SentinelError> {
        let _ = pid;
        Err(SentinelError::unsupported("ProcessIdentity::resolve"))
    }
}

/// What the interceptor decided about a syscall. The caller (eBPF event loop or
/// the socket-auth gate) is responsible for actually allowing or blocking.
///
/// CONTRACT: sentinel-types / Agent 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptionDecision {
    /// Permit the syscall to proceed (also logged).
    Allow,
    /// Block the syscall; carries the reason.
    Deny(DenyReason),
    /// Observe-mode: log and pass through unconditionally, never block.
    Log,
}

impl InterceptionDecision {
    /// True when the decision blocks the syscall.
    pub fn is_block(&self) -> bool {
        matches!(self, InterceptionDecision::Deny(_))
    }

    /// Stable label for logging.
    pub fn label(&self) -> &'static str {
        match self {
            InterceptionDecision::Allow => "allow",
            InterceptionDecision::Deny(_) => "deny",
            InterceptionDecision::Log => "log",
        }
    }
}

/// Why a syscall was denied.
///
/// CONTRACT: sentinel-types / Agent 1. The prompt enumerates exactly these two
/// reasons; an unresolved identity in Enforce mode is treated, fail-closed, as
/// `NotAllowlisted` (we cannot prove the caller is allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The calling binary's hash is not present in the allowlist.
    NotAllowlisted,
    /// The on-disk binary changed since the identity was registered.
    TamperedBinary,
}

impl DenyReason {
    pub fn label(&self) -> &'static str {
        match self {
            DenyReason::NotAllowlisted => "not_allowlisted",
            DenyReason::TamperedBinary => "tampered_binary",
        }
    }
}

/// An audit record emitted for every intercepted syscall. Drained off the
/// `audit_tx` channel by the daemon and written to the audit trail.
///
/// CONTRACT: sentinel-types / Agent 1; the daemon owns the channel.
#[derive(Debug, Clone)]
pub struct InterceptionEvent {
    pub pid: u32,
    pub syscall: SyscallId,
    pub decision: InterceptionDecision,
    pub binary_path: Option<PathBuf>,
    pub binary_hash: Option<[u8; 32]>,
    /// RFC3339-ish timestamp string (matches the daemon's `now_timestamp`).
    pub timestamp: String,
}

// ════════════════════════════════════════════════════════════════════════════
// Allowlist (CONTRACTS_PRODUCED by Agent 4)
// ════════════════════════════════════════════════════════════════════════════

/// In-memory representation of `sentinel.allowlist`. Loaded from disk at startup
/// and refreshed on SIGHUP. Lookups are by binary hash.
pub struct Allowlist {
    entries: Vec<AllowlistEntry>,
}

/// A single allowlist entry.
#[derive(Debug, Clone)]
pub struct AllowlistEntry {
    pub binary_hash: [u8; 32],
    pub binary_path: PathBuf,
    /// Hash of the parent binary permitted to spawn this one. All-zeros means
    /// "no parent constraint".
    pub parent_hash: [u8; 32],
    pub description: String,
}

impl Allowlist {
    /// An empty allowlist. In Enforce mode this denies everything (fail-closed).
    pub fn empty() -> Self {
        Allowlist { entries: Vec::new() }
    }

    /// Build directly from entries (used in tests and by SIGHUP refresh).
    pub fn from_entries(entries: Vec<AllowlistEntry>) -> Self {
        Allowlist { entries }
    }

    /// Load the allowlist from disk.
    ///
    /// Format — one entry per line, whitespace-separated, `#` for comments:
    ///
    /// ```text
    /// # <binary_sha256_hex>  <binary_path>  <parent_sha256_hex|->  <description...>
    /// e3b0c4...855  /usr/bin/python3  -  Python interpreter
    /// ```
    ///
    /// A `parent_hash` of `-` (or 64 zeros) means "no parent constraint".
    pub fn load(path: &std::path::Path) -> Result<Self, SentinelError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            SentinelError::AllowlistLoad(format!("read {}: {e}", path.display()))
        })?;
        let mut entries = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let hash_hex = fields.next().ok_or_else(|| {
                SentinelError::AllowlistLoad(format!("line {}: missing binary hash", lineno + 1))
            })?;
            let bin_path = fields.next().ok_or_else(|| {
                SentinelError::AllowlistLoad(format!("line {}: missing binary path", lineno + 1))
            })?;
            let parent_hex = fields.next().unwrap_or("-");
            let description = {
                let rest: Vec<&str> = fields.collect();
                rest.join(" ")
            };

            let binary_hash = hex_to_32(hash_hex).ok_or_else(|| {
                SentinelError::AllowlistLoad(format!(
                    "line {}: invalid binary hash '{hash_hex}'",
                    lineno + 1
                ))
            })?;
            let parent_hash = if parent_hex == "-" {
                [0u8; 32]
            } else {
                hex_to_32(parent_hex).ok_or_else(|| {
                    SentinelError::AllowlistLoad(format!(
                        "line {}: invalid parent hash '{parent_hex}'",
                        lineno + 1
                    ))
                })?
            };

            entries.push(AllowlistEntry {
                binary_hash,
                binary_path: PathBuf::from(bin_path),
                parent_hash,
                description,
            });
        }
        Ok(Allowlist { entries })
    }

    /// Whether a binary hash is allowlisted.
    pub fn contains(&self, binary_hash: &[u8; 32]) -> bool {
        self.entries.iter().any(|e| &e.binary_hash == binary_hash)
    }

    /// Whether a parent hash is permitted to spawn an allowlisted binary.
    pub fn contains_parent(&self, parent_hash: &[u8; 32]) -> bool {
        self.entries.iter().any(|e| &e.parent_hash == parent_hash)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ════════════════════════════════════════════════════════════════════════════
// EbpfInterceptor (CONTRACTS_PRODUCED by Agent 4)
// ════════════════════════════════════════════════════════════════════════════

/// Operating mode for the interceptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptorMode {
    /// Block policy violations.
    Enforce,
    /// Log only — never block. Wired to the `--oo` flag.
    Observe,
}

impl InterceptorMode {
    pub fn label(&self) -> &'static str {
        match self {
            InterceptorMode::Enforce => "enforcer",
            InterceptorMode::Observe => "observer_only",
        }
    }

    /// Whether this mode actually enforces (blocks).
    pub fn enforces(&self) -> bool {
        matches!(self, InterceptorMode::Enforce)
    }
}

/// The eBPF interception layer. Constructed at daemon startup, loaded before the
/// event loop runs, and consulted on every intercepted syscall via `intercept`.
pub struct EbpfInterceptor {
    pub(crate) mode: InterceptorMode,
    pub(crate) allowlist: Arc<Allowlist>,
    pub(crate) audit_tx: Sender<InterceptionEvent>,
    pub(crate) backend: programs::Backend,
}

impl EbpfInterceptor {
    /// Construct an interceptor. Platform-independent and infallible in
    /// practice — it only wires up state; `load()` does the kernel work.
    pub fn new(
        mode: InterceptorMode,
        allowlist: Arc<Allowlist>,
        audit_tx: Sender<InterceptionEvent>,
    ) -> Result<Self, SentinelError> {
        Ok(EbpfInterceptor {
            mode,
            allowlist,
            audit_tx,
            backend: programs::Backend::new(),
        })
    }

    /// Load and attach the interception programs. Must be called before
    /// `intercept()` is meaningful. On non-Linux platforms this returns
    /// `UnsupportedPlatform`; the daemon treats that as non-fatal and runs with
    /// interception inactive.
    pub fn load(&self) -> Result<(), SentinelError> {
        self.backend.load()
    }

    /// Detach and unload the interception programs. Called on daemon shutdown.
    pub fn unload(&self) -> Result<(), SentinelError> {
        self.backend.unload()
    }

    /// Whether the backend is currently loaded.
    pub fn is_loaded(&self) -> bool {
        self.backend.is_loaded()
    }

    /// The interceptor's mode.
    pub fn mode(&self) -> InterceptorMode {
        self.mode
    }

    // `intercept()` and the decision logic live in `interceptor.rs`.
}

// ════════════════════════════════════════════════════════════════════════════
// Hashing helpers (reuse the crate's dependency-free SHA-256).
// ════════════════════════════════════════════════════════════════════════════

/// SHA-256 of a byte slice as a raw 32-byte array. Reuses `crate::sha256` so we
/// add no new dependency.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let hex = crate::sha256::sha256_hex(data);
    // sha256_hex always returns 64 lowercase hex chars.
    hex_to_32(&hex).expect("sha256_hex produces valid 64-char hex")
}

/// Decode a 64-character hex string into a 32-byte array. Returns `None` on any
/// length/character error.
pub fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Encode a 32-byte array as a 64-character lowercase hex string.
pub fn bytes_to_hex(b: &[u8; 32]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let original = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let bytes = hex_to_32(original).unwrap();
        assert_eq!(bytes_to_hex(&bytes), original);
    }

    #[test]
    fn hex_rejects_bad_length_and_chars() {
        assert!(hex_to_32("abc").is_none());
        assert!(hex_to_32(&"z".repeat(64)).is_none());
    }

    #[test]
    fn sha256_bytes_matches_known_vector() {
        // SHA-256("abc")
        let h = sha256_bytes(b"abc");
        assert_eq!(
            bytes_to_hex(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn syscall_raw_mapping_and_family() {
        assert_eq!(SyscallId::from_raw(257), SyscallId::Openat);
        assert_eq!(SyscallId::from_raw(59), SyscallId::Execve);
        assert_eq!(SyscallId::from_raw(9999), SyscallId::Other(9999));
        assert_eq!(SyscallId::Connect.family(), "connect");
        assert!(SyscallId::Kill.is_intercepted());
        assert!(!SyscallId::Other(7).is_intercepted());
    }

    #[test]
    fn allowlist_parses_and_looks_up() {
        let h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let dir = std::env::temp_dir().join("sentinel-allowlist-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sentinel.allowlist");
        std::fs::write(
            &path,
            format!("# comment\n\n{h}  /usr/bin/python3  -  Python interpreter\n"),
        )
        .unwrap();

        let al = Allowlist::load(&path).unwrap();
        assert_eq!(al.len(), 1);
        let hash = hex_to_32(h).unwrap();
        assert!(al.contains(&hash));
        assert!(!al.contains(&[0xAB; 32]));
        // "-" parent means zero-hash, i.e. no parent constraint.
        assert!(al.contains_parent(&[0u8; 32]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_missing_file_errors() {
        let err = Allowlist::load(std::path::Path::new("/nonexistent/sentinel.allowlist"));
        assert!(matches!(err, Err(SentinelError::AllowlistLoad(_))));
    }

    #[test]
    fn empty_allowlist_is_fail_closed() {
        let al = Allowlist::empty();
        assert!(al.is_empty());
        assert!(!al.contains(&[0u8; 32]));
    }
}
