use std::collections::HashMap;
use std::path::Path;

use sentinel_types::{
    ControlAction, ControlThresholds, DegradationEvent, PermissionSet, ResponseTier,
    WebhookPayload,
};

use crate::audit::{create_audit_entry, AuditLog};
use crate::webhook;

/// Tracks cumulative degradation score per agent and applies tiered responses.
pub struct ControlEngine {
    thresholds: ControlThresholds,
    cumulative_scores: HashMap<String, f64>,
    agent_permissions: HashMap<String, PermissionSet>,
    locked_agents: HashMap<String, bool>,
    webhook_url: Option<String>,
    audit_log: AuditLog,
}

/// Result of processing a degradation event.
#[derive(Debug)]
pub struct ControlResult {
    pub action: Option<ControlAction>,
    pub webhook_sent: bool,
    pub audit_written: bool,
}

impl ControlEngine {
    pub fn new(
        thresholds: ControlThresholds,
        webhook_url: Option<String>,
        audit_log_path: &Path,
    ) -> Self {
        Self {
            thresholds,
            cumulative_scores: HashMap::new(),
            agent_permissions: HashMap::new(),
            locked_agents: HashMap::new(),
            webhook_url,
            audit_log: AuditLog::new(audit_log_path),
        }
    }

    /// Process a degradation event. Accumulates score and applies the
    /// appropriate response tier if thresholds are exceeded.
    pub fn process_event(
        &mut self,
        event: &DegradationEvent,
        timestamp: &str,
        operator_id: &str,
    ) -> ControlResult {
        // Locked agents are permanently blocked.
        if self.is_locked(&event.agent_id) {
            return ControlResult {
                action: None,
                webhook_sent: false,
                audit_written: false,
            };
        }

        let cumulative = self
            .cumulative_scores
            .entry(event.agent_id.clone())
            .or_insert(0.0);
        *cumulative += event.score;
        let score = *cumulative;

        let tier = self.determine_tier(score);
        let tier = match tier {
            Some(t) => t,
            None => {
                return ControlResult {
                    action: None,
                    webhook_sent: false,
                    audit_written: false,
                }
            }
        };

        let permissions = match tier {
            ResponseTier::Soft => {
                // Pause — keep current permissions, but signal pause.
                self.agent_permissions
                    .entry(event.agent_id.clone())
                    .or_insert_with(PermissionSet::full)
                    .clone()
            }
            ResponseTier::Medium => {
                let ps = PermissionSet::read_only();
                self.agent_permissions
                    .insert(event.agent_id.clone(), ps.clone());
                ps
            }
            ResponseTier::Hard => {
                let ps = PermissionSet::none();
                self.agent_permissions
                    .insert(event.agent_id.clone(), ps.clone());
                self.locked_agents.insert(event.agent_id.clone(), true);
                ps
            }
        };

        let reason = format!(
            "{:?} tier triggered: cumulative score {:.3} on {:?} signal",
            tier, score, event.signal_type
        );

        let action = ControlAction {
            agent_id: event.agent_id.clone(),
            tier,
            permissions,
            reason,
            timestamp: timestamp.to_string(),
        };

        // Write audit entry — this is mandatory, failure is propagated.
        let audit_action = format!("{:?}_tier_applied:{}", tier, event.agent_id);
        let entry = create_audit_entry(&audit_action, timestamp, operator_id);
        let audit_written = self.audit_log.append(&entry).is_ok();

        // Send webhook — best-effort.
        let webhook_sent = self.try_send_webhook(event, &action);

        ControlResult {
            action: Some(action),
            webhook_sent,
            audit_written,
        }
    }

    /// Manual override by human operator. Creates an audit entry.
    pub fn operator_override(
        &mut self,
        agent_id: &str,
        new_permissions: PermissionSet,
        timestamp: &str,
        operator_id: &str,
    ) -> bool {
        let action = format!("operator_override:{}", agent_id);
        let entry = create_audit_entry(&action, timestamp, operator_id);
        let written = self.audit_log.append(&entry).is_ok();

        self.agent_permissions
            .insert(agent_id.to_string(), new_permissions);
        // Unlock if locked.
        self.locked_agents.remove(agent_id);
        // Reset cumulative score.
        self.cumulative_scores.remove(agent_id);

        written
    }

    /// Check if an agent is permanently locked.
    pub fn is_locked(&self, agent_id: &str) -> bool {
        self.locked_agents.get(agent_id).copied().unwrap_or(false)
    }

    /// Get current permissions for an agent.
    pub fn get_permissions(&self, agent_id: &str) -> PermissionSet {
        self.agent_permissions
            .get(agent_id)
            .cloned()
            .unwrap_or_else(PermissionSet::full)
    }

    /// Get cumulative score for an agent.
    pub fn get_cumulative_score(&self, agent_id: &str) -> f64 {
        self.cumulative_scores
            .get(agent_id)
            .copied()
            .unwrap_or(0.0)
    }

    fn determine_tier(&self, score: f64) -> Option<ResponseTier> {
        if score > self.thresholds.hard_threshold {
            Some(ResponseTier::Hard)
        } else if score > self.thresholds.medium_threshold {
            Some(ResponseTier::Medium)
        } else if score > self.thresholds.soft_threshold {
            Some(ResponseTier::Soft)
        } else {
            None
        }
    }

    fn try_send_webhook(&self, event: &DegradationEvent, action: &ControlAction) -> bool {
        let url = match &self.webhook_url {
            Some(u) => u,
            None => return false,
        };
        let payload = WebhookPayload {
            event: event.clone(),
            action: action.clone(),
        };
        webhook::send_webhook(url, &payload).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::{DegradationEvent, SignalType};
    use std::fs;

    fn test_audit_path() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("sentinel_ctrl_test");
        let _ = fs::create_dir_all(&dir);
        dir.join(format!("test_{}.log", std::process::id()))
    }

    fn make_event(agent_id: &str, score: f64) -> DegradationEvent {
        DegradationEvent {
            agent_id: agent_id.to_string(),
            signal_type: SignalType::RepetitionScore,
            score,
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn no_action_below_threshold() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);
        let result =
            engine.process_event(&make_event("agent-1", 0.1), "2026-03-18T00:00:00Z", "sys");
        assert!(result.action.is_none());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn soft_tier_on_moderate_score() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);
        let result =
            engine.process_event(&make_event("agent-1", 0.5), "2026-03-18T00:00:00Z", "sys");
        let action = result.action.unwrap();
        assert_eq!(action.tier, ResponseTier::Soft);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn medium_tier_on_high_score() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);
        let result =
            engine.process_event(&make_event("agent-1", 0.75), "2026-03-18T00:00:00Z", "sys");
        let action = result.action.unwrap();
        assert_eq!(action.tier, ResponseTier::Medium);
        let perms = engine.get_permissions("agent-1");
        assert!(perms.read);
        assert!(!perms.write);
        assert!(!perms.execute);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn hard_tier_locks_agent() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);
        let result =
            engine.process_event(&make_event("agent-1", 0.95), "2026-03-18T00:00:00Z", "sys");
        let action = result.action.unwrap();
        assert_eq!(action.tier, ResponseTier::Hard);
        assert!(engine.is_locked("agent-1"));
        let perms = engine.get_permissions("agent-1");
        assert!(!perms.read && !perms.write && !perms.execute);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cumulative_score_escalates() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);

        // First event: 0.3 — below soft threshold
        let r1 =
            engine.process_event(&make_event("agent-1", 0.3), "2026-03-18T00:00:00Z", "sys");
        assert!(r1.action.is_none());

        // Second event: cumulative 0.6 — soft tier
        let r2 =
            engine.process_event(&make_event("agent-1", 0.3), "2026-03-18T00:01:00Z", "sys");
        assert_eq!(r2.action.unwrap().tier, ResponseTier::Soft);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn operator_override_unlocks() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);

        // Lock the agent
        engine.process_event(&make_event("agent-1", 0.95), "2026-03-18T00:00:00Z", "sys");
        assert!(engine.is_locked("agent-1"));

        // Override
        let written = engine.operator_override(
            "agent-1",
            PermissionSet::full(),
            "2026-03-18T00:05:00Z",
            "human-operator-1",
        );
        assert!(written);
        assert!(!engine.is_locked("agent-1"));
        let perms = engine.get_permissions("agent-1");
        assert!(perms.read && perms.write && perms.execute);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn locked_agent_ignored() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);

        engine.process_event(&make_event("agent-1", 0.95), "2026-03-18T00:00:00Z", "sys");
        assert!(engine.is_locked("agent-1"));

        // Further events for locked agent produce no action
        let result =
            engine.process_event(&make_event("agent-1", 0.5), "2026-03-18T00:01:00Z", "sys");
        assert!(result.action.is_none());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn different_agents_tracked_independently() {
        let path = test_audit_path();
        let mut engine =
            ControlEngine::new(ControlThresholds::default(), None, &path);

        engine.process_event(&make_event("agent-1", 0.95), "2026-03-18T00:00:00Z", "sys");
        assert!(engine.is_locked("agent-1"));
        assert!(!engine.is_locked("agent-2"));

        let _ = fs::remove_file(&path);
    }
}
