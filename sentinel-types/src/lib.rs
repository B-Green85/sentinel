// sentinel-types — Shared types for Sentinel agent oversight system.
// All structs defined here are the single source of truth.
// sentinel-core and sentinel-py import from this crate — no redefinition.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for SentinelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SentinelError({}): {}", self.code, self.message)
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
}
