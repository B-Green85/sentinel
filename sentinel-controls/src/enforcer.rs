//! Full enforcement capability — the v2 tier logic, exposed through
//! [`SentinelCapability`].
//!
//! The enforcement tiers are unchanged from v2. They live in
//! [`ControlEngine`](crate::controller::ControlEngine):
//!
//! | Cumulative score | Response                                              |
//! |------------------|-------------------------------------------------------|
//! | > 0.4            | Pause agent, request human confirmation               |
//! | > 0.7            | Downgrade to READ only, suspend WRITE and EXECUTE     |
//! | > 0.9            | SIGTERM, revoke all permissions, permanently lock id  |
//!
//! `Enforcer` is a thin wrapper that adapts the existing `&mut self` engine to
//! the shared `&self` trait via interior mutability. No tier thresholds or
//! behaviour change here.

use std::sync::Mutex;

use sentinel_types::{AgentId, DegradationEvent, SentinelError};

use crate::capability::SentinelCapability;
use crate::controller::ControlEngine;
use crate::util::now_utc;

/// The full-enforcement capability. Wraps a [`ControlEngine`] behind a `Mutex`
/// so the engine's `&mut self` operations satisfy the `&self` trait interface.
pub struct Enforcer {
    engine: Mutex<ControlEngine>,
    operator_id: String,
}

impl Enforcer {
    /// Build an enforcer around an existing engine. Audit entries produced by
    /// the enforcer itself are attributed to `operator_id` `"enforcer"`.
    pub fn new(engine: ControlEngine) -> Self {
        Self::with_operator(engine, "enforcer")
    }

    /// Build an enforcer with an explicit operator id for self-originated audit
    /// entries (the synthetic actor recorded when the enforcer, not a human,
    /// applies a tier).
    pub fn with_operator(engine: ControlEngine, operator_id: impl Into<String>) -> Self {
        Self {
            engine: Mutex::new(engine),
            operator_id: operator_id.into(),
        }
    }

    fn lock_engine(&self) -> Result<std::sync::MutexGuard<'_, ControlEngine>, SentinelError> {
        self.engine
            .lock()
            .map_err(|_| SentinelError::generic("EnginePoisoned", "control engine mutex poisoned"))
    }

    fn audit_err(action: &str) -> SentinelError {
        SentinelError::generic(
            "AuditWriteFailed",
            format!("failed to write audit entry for {}", action),
        )
    }
}

impl SentinelCapability for Enforcer {
    fn on_signal(&self, event: &DegradationEvent) -> Result<(), SentinelError> {
        let mut engine = self.lock_engine()?;
        // The event carries its own timestamp; use it so the audit trail matches
        // the originating signal.
        engine.process_event(event, &event.timestamp, &self.operator_id);
        Ok(())
    }

    fn pause_agent(&self, id: &AgentId) -> Result<(), SentinelError> {
        let ts = now_utc();
        let mut engine = self.lock_engine()?;
        if engine.force_pause(id, &ts, &self.operator_id) {
            Ok(())
        } else {
            Err(Self::audit_err("pause_agent"))
        }
    }

    fn restrict_agent(&self, id: &AgentId) -> Result<(), SentinelError> {
        let ts = now_utc();
        let mut engine = self.lock_engine()?;
        if engine.force_restrict(id, &ts, &self.operator_id) {
            Ok(())
        } else {
            Err(Self::audit_err("restrict_agent"))
        }
    }

    fn terminate_agent(&self, id: &AgentId) -> Result<(), SentinelError> {
        let ts = now_utc();
        let mut engine = self.lock_engine()?;
        if engine.force_terminate(id, &ts, &self.operator_id) {
            Ok(())
        } else {
            Err(Self::audit_err("terminate_agent"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::{ControlThresholds, SignalType};
    use std::fs;

    fn test_engine() -> (Enforcer, std::path::PathBuf) {
        let dir = std::env::temp_dir().join("sentinel_enforcer_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(format!(
            "enf_{}_{}.log",
            std::process::id(),
            // disambiguate parallel tests without Date/random
            dir.as_os_str().len()
        ));
        let _ = fs::remove_file(&path);
        let engine = ControlEngine::new(ControlThresholds::default(), None, &path);
        (Enforcer::new(engine), path)
    }

    #[test]
    fn terminate_locks_agent() {
        let (enf, path) = test_engine();
        enf.terminate_agent(&"agent-1".to_string()).unwrap();
        let engine = enf.engine.lock().unwrap();
        assert!(engine.is_locked("agent-1"));
        let perms = engine.get_permissions("agent-1");
        assert!(!perms.read && !perms.write && !perms.execute);
        drop(engine);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn restrict_downgrades_to_read_only() {
        let (enf, path) = test_engine();
        enf.restrict_agent(&"agent-2".to_string()).unwrap();
        let engine = enf.engine.lock().unwrap();
        let perms = engine.get_permissions("agent-2");
        assert!(perms.read && !perms.write && !perms.execute);
        drop(engine);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn on_signal_accumulates_through_engine() {
        let (enf, path) = test_engine();
        let event = DegradationEvent {
            agent_id: "agent-3".to_string(),
            signal_type: SignalType::RepetitionScore,
            score: 0.95,
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        };
        enf.on_signal(&event).unwrap();
        let engine = enf.engine.lock().unwrap();
        // 0.95 cumulative crosses the Hard threshold → locked.
        assert!(engine.is_locked("agent-3"));
        drop(engine);
        let _ = fs::remove_file(&path);
    }
}
