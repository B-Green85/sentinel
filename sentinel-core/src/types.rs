use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Permission tiers for registered agents.
/// Ordered by privilege: READ_ONLY < WRITE < EXECUTE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionTier {
    ReadOnly,
    Write,
    Execute,
}

impl PermissionTier {
    /// Return the next lower tier, or None if already at minimum.
    pub fn downgrade(self) -> Option<Self> {
        match self {
            Self::Execute => Some(Self::Write),
            Self::Write => Some(Self::ReadOnly),
            Self::ReadOnly => None,
        }
    }
}

impl std::fmt::Display for PermissionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "READ_ONLY"),
            Self::Write => write!(f, "WRITE"),
            Self::Execute => write!(f, "EXECUTE"),
        }
    }
}

impl std::str::FromStr for PermissionTier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "READ_ONLY" | "READONLY" => Ok(Self::ReadOnly),
            "WRITE" => Ok(Self::Write),
            "EXECUTE" => Ok(Self::Execute),
            _ => Err(format!("unknown permission tier: {s}")),
        }
    }
}

/// Registration request sent over the Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub agent_id: String,
    pub permission_tier: PermissionTier,
    pub heartbeat_interval: u64, // seconds
}

/// Heartbeat sent by infrastructure (not the agent — agent is blind).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_id: String,
}

/// Envelope for all requests over the Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    Register(RegisterRequest),
    Heartbeat(HeartbeatRequest),
    Status { agent_id: String },
    Deregister { agent_id: String },
}

/// Generic response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    pub agent_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub timestamp: String,
    pub audit_hash: String,
}

/// Internal record for a registered agent.
#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub agent_id: String,
    pub tier: PermissionTier,
    pub original_tier: PermissionTier,
    pub heartbeat_interval: u64,
    pub last_heartbeat: SystemTime,
    pub registered_at: SystemTime,
    pub downgraded: bool,
}

impl AgentRecord {
    pub fn new(req: &RegisterRequest) -> Self {
        let now = SystemTime::now();
        Self {
            agent_id: req.agent_id.clone(),
            tier: req.permission_tier,
            original_tier: req.permission_tier,
            heartbeat_interval: req.heartbeat_interval,
            last_heartbeat: now,
            registered_at: now,
            downgraded: false,
        }
    }
}

/// Events published on the internal event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum Event {
    AgentRegistered {
        agent_id: String,
        tier: String,
        timestamp: String,
    },
    HeartbeatReceived {
        agent_id: String,
        timestamp: String,
    },
    HeartbeatMissed {
        agent_id: String,
        missed_by_secs: u64,
        timestamp: String,
    },
    TierDowngraded {
        agent_id: String,
        from_tier: String,
        to_tier: String,
        reason: String,
        timestamp: String,
    },
    AgentDeregistered {
        agent_id: String,
        timestamp: String,
    },
    SignalDetected {
        detector_id: String,
        signal: String,
        severity: String,
        timestamp: String,
    },
}

/// Format a SystemTime as ISO 8601 UTC string.
pub fn format_timestamp(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    // Manual UTC datetime formatting
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Days since epoch to Y-M-D (simplified Gregorian)
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's date library
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Return current time as ISO 8601 string.
pub fn now_timestamp() -> String {
    format_timestamp(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_ordering() {
        assert!(PermissionTier::ReadOnly < PermissionTier::Write);
        assert!(PermissionTier::Write < PermissionTier::Execute);
    }

    #[test]
    fn test_tier_downgrade() {
        assert_eq!(PermissionTier::Execute.downgrade(), Some(PermissionTier::Write));
        assert_eq!(PermissionTier::Write.downgrade(), Some(PermissionTier::ReadOnly));
        assert_eq!(PermissionTier::ReadOnly.downgrade(), None);
    }

    #[test]
    fn test_tier_parse() {
        assert_eq!("READ_ONLY".parse::<PermissionTier>().unwrap(), PermissionTier::ReadOnly);
        assert_eq!("WRITE".parse::<PermissionTier>().unwrap(), PermissionTier::Write);
        assert_eq!("EXECUTE".parse::<PermissionTier>().unwrap(), PermissionTier::Execute);
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(PermissionTier::ReadOnly.to_string(), "READ_ONLY");
        assert_eq!(PermissionTier::Write.to_string(), "WRITE");
        assert_eq!(PermissionTier::Execute.to_string(), "EXECUTE");
    }

    #[test]
    fn test_epoch_timestamp() {
        let t = UNIX_EPOCH;
        assert_eq!(format_timestamp(t), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_request_serde() {
        let req = Request::Register(RegisterRequest {
            agent_id: "test-agent".into(),
            permission_tier: PermissionTier::Write,
            heartbeat_interval: 30,
        });
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        match parsed {
            Request::Register(r) => {
                assert_eq!(r.agent_id, "test-agent");
                assert_eq!(r.permission_tier, PermissionTier::Write);
                assert_eq!(r.heartbeat_interval, 30);
            }
            _ => panic!("wrong variant"),
        }
    }
}
