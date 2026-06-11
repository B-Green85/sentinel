//! Observation-only capability.
//!
//! Every enforcement method is a no-op. This is the *complete* implementation —
//! there is no hidden enforcement path. A third-party auditor receiving an
//! observer build can verify, by inspection of this file and the resulting
//! binary, that it contains:
//!
//!   * no SIGTERM / `libc::kill` call,
//!   * no permission-revocation code path,
//!   * no tier-escalation logic.
//!
//! Degradation events are logged upstream in `sentinel-signals`; the observer's
//! `on_signal` deliberately does nothing here beyond returning `Ok`.

use sentinel_types::{AgentId, DegradationEvent, SentinelError};

use crate::capability::SentinelCapability;

/// The no-op capability. Carries no state.
pub struct Observer;

impl SentinelCapability for Observer {
    fn on_signal(&self, _event: &DegradationEvent) -> Result<(), SentinelError> {
        Ok(()) // log only — handled upstream in sentinel-signals
    }

    fn pause_agent(&self, _id: &AgentId) -> Result<(), SentinelError> {
        Ok(()) // no-op
    }

    fn restrict_agent(&self, _id: &AgentId) -> Result<(), SentinelError> {
        Ok(()) // no-op
    }

    fn terminate_agent(&self, _id: &AgentId) -> Result<(), SentinelError> {
        Ok(()) // no-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::SignalType;

    #[test]
    fn all_methods_are_noops_and_succeed() {
        let obs = Observer;
        let event = DegradationEvent {
            agent_id: "agent-1".to_string(),
            signal_type: SignalType::RepetitionScore,
            score: 0.99,
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        };
        let id = "agent-1".to_string();
        assert!(obs.on_signal(&event).is_ok());
        assert!(obs.pause_agent(&id).is_ok());
        assert!(obs.restrict_agent(&id).is_ok());
        assert!(obs.terminate_agent(&id).is_ok());
    }
}
