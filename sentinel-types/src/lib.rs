// sentinel-types — Shared types for Sentinel agent oversight system.
// All structs defined here are the single source of truth.
// sentinel-core and sentinel-py import from this crate — no redefinition.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Agent trust tier. Determines oversight intensity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "python", pyo3::pyclass(eq, eq_int))]
pub enum AgentTier {
    /// Full autonomy within sandbox. Heartbeat every 30s.
    Autonomous,
    /// Semi-autonomous. Heartbeat every 10s. Output sampled.
    Supervised,
    /// Fully monitored. Heartbeat every 2s. All output captured.
    Restricted,
}

impl std::fmt::Display for AgentTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentTier::Autonomous => write!(f, "autonomous"),
            AgentTier::Supervised => write!(f, "supervised"),
            AgentTier::Restricted => write!(f, "restricted"),
        }
    }
}

impl std::str::FromStr for AgentTier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "autonomous" => Ok(AgentTier::Autonomous),
            "supervised" => Ok(AgentTier::Supervised),
            "restricted" => Ok(AgentTier::Restricted),
            _ => Err(format!("unknown tier: {s}")),
        }
    }
}

/// Current state of a registered agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "python", pyo3::pyclass(eq, eq_int))]
pub enum AgentState {
    Running,
    Idle,
    Terminated,
    Unresponsive,
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Running => write!(f, "running"),
            AgentState::Idle => write!(f, "idle"),
            AgentState::Terminated => write!(f, "terminated"),
            AgentState::Unresponsive => write!(f, "unresponsive"),
        }
    }
}

/// Response from register().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all))]
pub struct RegisterResponse {
    pub registered: bool,
    pub agent_id: String,
    pub tier: String,
    pub timestamp: String,
    pub audit_hash: String,
}

/// Response from heartbeat().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all))]
pub struct HeartbeatResponse {
    pub acknowledged: bool,
    pub agent_id: String,
    pub timestamp: String,
    pub audit_hash: String,
}

/// Response from emit_output().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all))]
pub struct EmitOutputResponse {
    pub recorded: bool,
    pub agent_id: String,
    pub timestamp: String,
    pub audit_hash: String,
    pub bytes_captured: usize,
}

/// Response from status().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "python", pyo3::pyclass(get_all))]
pub struct StatusResponse {
    pub agent_id: String,
    pub tier: String,
    pub state: String,
    pub last_heartbeat: String,
    pub output_count: u64,
    pub registered_at: String,
    pub audit_hash: String,
}

/// Request envelope sent over the Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelRequest {
    pub method: String,
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Error type for sentinel operations.
///
/// v3: converted from a `{ code, message }` struct to a named-variant enum so
/// call sites can match on specific failure modes (`UnknownProfile`,
/// `UnsupportedPlatform`, `TransportError`). The `Generic(String)` variant
/// preserves the prior free-form `{ code, message }` usage — the legacy `code`
/// is folded into the message string via [`SentinelError::generic`]. Existing
/// serde users continue to work: `Generic` carries the human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SentinelError {
    /// Free-form error. Preserves the legacy `{ code, message }` shape; the
    /// message carries the human-readable description.
    Generic(String),
    /// The named deployment profile does not exist.
    UnknownProfile(String),
    /// The requested operation is not supported on this platform.
    UnsupportedPlatform,
    /// A transport-level failure (bind / accept / listen / IPC).
    TransportError(String),
}

impl SentinelError {
    /// Construct a [`SentinelError::Generic`] from a stable code plus a
    /// human-readable message, folding both into one string. Bridges call
    /// sites written against the old `{ code, message }` struct.
    pub fn generic(code: &str, message: impl std::fmt::Display) -> Self {
        SentinelError::Generic(format!("{code}: {message}"))
    }
}

impl std::fmt::Display for SentinelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SentinelError::Generic(msg) => write!(f, "SentinelError: {msg}"),
            SentinelError::UnknownProfile(name) => {
                write!(f, "unknown deployment profile: {name}")
            }
            SentinelError::UnsupportedPlatform => {
                write!(f, "operation not supported on this platform")
            }
            SentinelError::TransportError(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

impl std::error::Error for SentinelError {}

/// Compute SHA256 audit hash for an action.
pub fn audit_hash(agent_id: &str, action: &str, timestamp: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(b"|");
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.as_bytes());
    hex::encode(hasher.finalize())
}

// ── Signal detection types (consumed by sentinel-signals) ───

/// A single observed agent output. Captured passively — no instrumentation
/// inside the agent process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOutput {
    pub agent_id: String,
    pub content: String,
    pub timestamp: String,
    /// Whether this output was immediately followed by a tool call.
    pub followed_by_tool_call: bool,
}

/// A single observed tool invocation by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedToolCall {
    pub agent_id: String,
    pub tool_name: String,
    /// Hash of the call arguments — identical args produce identical hashes.
    pub args_hash: String,
    pub timestamp: String,
}

/// A task-progression marker. Recorded when an agent advances task state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStateMarker {
    pub agent_id: String,
    pub state_id: String,
    pub timestamp: String,
}

/// The kind of degradation signal a detector emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalType {
    RepetitionScore,
    SelfReferentialLoop,
    TokenVelocityStall,
    ToolRetryAnomaly,
    // v3 detectors — additive, consumed by sentinel-signals.
    ReasoningLoop,
    GoalDrift,
    ConfidenceInflation,
    ScopeViolation,
    HedgeAccumulation,
    /// Composite terminal state — multiple detectors firing simultaneously.
    Cascade,
}

/// A degradation event emitted by the signal engine when a detector
/// threshold is exceeded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationEvent {
    pub agent_id: String,
    pub signal_type: SignalType,
    pub score: f64,
    pub timestamp: String,
}

/// Sliding-window sizes for each detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    pub repetition_window: usize,
    pub self_referential_window: usize,
    pub velocity_window: usize,
    pub tool_retry_window: usize,
    // v3 detector windows — additive.
    pub reasoning_window: usize,
    pub goal_drift_window: usize,
    pub confidence_window: usize,
    pub scope_window: usize,
    pub output_quality_window: usize,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            repetition_window: 8,
            self_referential_window: 6,
            velocity_window: 16,
            tool_retry_window: 8,
            reasoning_window: 8,
            goal_drift_window: 8,
            confidence_window: 8,
            scope_window: 8,
            output_quality_window: 8,
        }
    }
}

/// Score thresholds at which each detector emits a `DegradationEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalThresholds {
    pub repetition_score: f64,
    pub self_referential_loop: f64,
    pub token_velocity_stall: f64,
    pub tool_retry_anomaly: f64,
    // v3 detector thresholds — additive.
    pub reasoning_loop: f64,
    pub goal_drift: f64,
    pub confidence_inflation: f64,
    pub scope_creep: f64,
    pub hedge_accumulation: f64,
    pub cascade: f64,
}

impl Default for SignalThresholds {
    fn default() -> Self {
        Self {
            repetition_score: 0.6,
            self_referential_loop: 0.5,
            token_velocity_stall: 0.9,
            tool_retry_anomaly: 0.5,
            reasoning_loop: 0.25,
            goal_drift: 0.6,
            confidence_inflation: 0.6,
            scope_creep: 0.1,
            hedge_accumulation: 0.5,
            cascade: 0.9,
        }
    }
}

// ── Response control types (consumed by sentinel-controls) ──

/// The set of capabilities granted to an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl PermissionSet {
    /// All capabilities granted.
    pub fn full() -> Self {
        Self { read: true, write: true, execute: true }
    }

    /// Read-only — write and execute revoked.
    pub fn read_only() -> Self {
        Self { read: true, write: false, execute: false }
    }

    /// All capabilities revoked.
    pub fn none() -> Self {
        Self { read: false, write: false, execute: false }
    }
}

/// The intervention tier applied in response to accumulated degradation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseTier {
    /// Pause — permissions retained, agent signalled to halt.
    Soft,
    /// Downgrade to read-only.
    Medium,
    /// Revoke all permissions and lock the agent.
    Hard,
}

/// Cumulative-score thresholds at which each response tier is triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlThresholds {
    pub soft_threshold: f64,
    pub medium_threshold: f64,
    pub hard_threshold: f64,
}

impl Default for ControlThresholds {
    fn default() -> Self {
        Self {
            soft_threshold: 0.4,
            medium_threshold: 0.7,
            hard_threshold: 0.9,
        }
    }
}

/// A control action applied to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAction {
    pub agent_id: String,
    pub tier: ResponseTier,
    pub permissions: PermissionSet,
    pub reason: String,
    pub timestamp: String,
}

/// Payload POSTed to the configured webhook when a control action fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event: DegradationEvent,
    pub action: ControlAction,
}

/// An immutable audit-log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub operator_id: String,
    pub action: String,
    pub hash: String,
}

// ── Sentinel v3 — kernel-authoritative identity & interception types ──
//
// Additive only. Consumed by sentinel-signals, sentinel-core, and
// sentinel-controls. The crate is `std` (PathBuf, std::error::Error), so the
// `no_std` note in the build prompt does not apply; `chrono` is already a
// dependency, so timestamps use `DateTime<Utc>` rather than a `u64` fallback.

/// Stable identifier for an agent. Aliased to `String` to match the rest of
/// this crate, where `agent_id` is a `String` everywhere. Kept as an alias
/// (not a newtype) per the explicitness-over-cleverness guidance.
pub type AgentId = String;

/// A semantic event recorded in the chained audit log. The payload is carried
/// inline by the variant — `ChainedAuditEntry` folds the whole event into
/// `entry_hash`, which is why the entry has no separate `data` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEvent {
    AgentRegistered,
    Heartbeat,
    OutputEmitted,
    StatusQueried,
    SessionIssued,
    DegradationDetected(SignalType),
    ControlApplied(ResponseTier),
    SyscallIntercepted(InterceptionDecision),
    /// Free-form event for cases not covered by the variants above.
    Custom(String),
}

/// Process identity — kernel-authoritative on GolemLinux, procfs on standalone.
/// Never constructed by the agent. Always constructed by Sentinel from verified
/// sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// SHA-256 of the executable on disk.
    pub binary_hash: [u8; 32],
    pub binary_path: PathBuf,
    pub parent_pid: u32,
    /// SHA-256 of the parent executable.
    pub parent_hash: [u8; 32],
    pub uid: u32,
}

/// Session credential — generated by Sentinel at first contact, never exposed
/// to the agent. Lives entirely in Sentinel's custody. Stable identity token
/// for the session duration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCredential {
    pub agent_id: AgentId,
    pub process_identity: ProcessIdentity,
    pub issued_at: DateTime<Utc>,
    /// SHA-256 over agent_id + process_identity + issued_at.
    pub credential_hash: [u8; 32],
}

/// Single entry in the cryptographic audit chain.
/// `entry_hash` = SHA-256 over (sequence + timestamp + agent_id + event +
/// prev_hash). `prev_hash` = `entry_hash` of the immediately prior entry.
/// Genesis entry `prev_hash` = `[0u8; 32]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainedAuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub agent_id: AgentId,
    pub event: AuditEvent,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

/// Identifies a syscall family for interception tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallId {
    Open,
    OpenAt,
    Connect,
    Accept,
    Execve,
    ExecveAt,
    Write,
    SendTo,
    Mmap,
    Mprotect,
    Kill,
    TKill,
    Unknown(u32),
}

/// Why an interception was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    PolicyViolation,
    NotAllowlisted,
    TamperedBinary,
    SpoofedParent,
    ThresholdExceeded,
}

/// The decision rendered for an intercepted syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterceptionDecision {
    Allow,
    Deny(DenyReason),
    /// Observer mode — always allows, always logs.
    Log,
}

/// Record of a single syscall interception.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptionEvent {
    pub syscall: SyscallId,
    /// Raw syscall args, serialized.
    pub args: Vec<u8>,
    pub process_identity: ProcessIdentity,
    pub decision: InterceptionDecision,
    pub latency_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_roundtrip() {
        for tier in [AgentTier::Autonomous, AgentTier::Supervised, AgentTier::Restricted] {
            let s = tier.to_string();
            let parsed: AgentTier = s.parse().unwrap();
            assert_eq!(tier, parsed);
        }
    }

    #[test]
    fn test_audit_hash_deterministic() {
        let h1 = audit_hash("agent-1", "register", "2026-01-01T00:00:00Z");
        let h2 = audit_hash("agent-1", "register", "2026-01-01T00:00:00Z");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_audit_hash_varies() {
        let h1 = audit_hash("agent-1", "register", "2026-01-01T00:00:00Z");
        let h2 = audit_hash("agent-2", "register", "2026-01-01T00:00:00Z");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_v3_types_roundtrip_serde() {
        let proc = ProcessIdentity {
            pid: 42,
            binary_hash: [1u8; 32],
            binary_path: PathBuf::from("/usr/bin/agent"),
            parent_pid: 1,
            parent_hash: [2u8; 32],
            uid: 1000,
        };
        let event = InterceptionEvent {
            syscall: SyscallId::OpenAt,
            args: vec![0xde, 0xad],
            process_identity: proc.clone(),
            decision: InterceptionDecision::Deny(DenyReason::TamperedBinary),
            latency_ns: 1234,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: InterceptionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(back.process_identity, proc);
    }

    #[test]
    fn test_syscall_unknown_distinct() {
        assert_ne!(SyscallId::Unknown(7), SyscallId::Unknown(8));
        assert_eq!(SyscallId::Execve, SyscallId::Execve);
    }
}
