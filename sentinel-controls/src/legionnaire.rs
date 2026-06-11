//! The Legionnaire per-action policy engine.
//!
//! Legionnaire sits on top of the enforcer. Where the enforcer reacts to
//! accumulated *degradation score*, Legionnaire renders a decision for a
//! *specific action* an agent is attempting (open a file, connect a socket,
//! spawn a process, …) according to the active deployment profile.
//!
//! Profiles are defined in [`crate::profiles`].

use std::collections::HashMap;

use sentinel_types::ProcessIdentity;

/// A class of agent action Legionnaire can rule on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionType {
    FileAccess,
    NetworkConnect,
    ProcessSpawn,
    MemoryMap,
    DataExfiltration,
    TradingSyscall,
    SyscallUnknown,
    /// Wildcard — matches when no specific rule applies.
    AnyAction,
    /// Matches on any `DegradationEvent`.
    AnyAnomaly,
}

/// What Legionnaire does about an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Terminate the agent immediately.
    AutoTerminate,
    /// Block this action, leave the agent running.
    AutoBlock,
    /// Notify a human and hold the action pending their decision.
    NotifyHold,
    /// Permit and record only.
    LogOnly,
}

/// What to do when a notify-and-hold expires with no operator response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutDefault {
    /// Permit the held action.
    Allow,
    /// Block the held action.
    Deny,
}

/// Configuration for the notify-and-hold behaviour of a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldConfig {
    pub timeout_seconds: u64,
    pub default_on_timeout: TimeoutDefault,
    pub notify_telegram: bool,
}

impl HoldConfig {
    /// The `PolicyAction` that the timeout default resolves to.
    /// `Allow` → permit (`LogOnly`); `Deny` → block (`AutoBlock`).
    pub fn timeout_action(&self) -> PolicyAction {
        match self.default_on_timeout {
            TimeoutDefault::Allow => PolicyAction::LogOnly,
            TimeoutDefault::Deny => PolicyAction::AutoBlock,
        }
    }
}

/// The active policy: a rule table plus hold configuration.
#[derive(Debug, Clone)]
pub struct LegionnairePolicy {
    pub enabled: bool,
    pub rules: HashMap<ActionType, PolicyAction>,
    pub hold_config: HoldConfig,
    pub human_override: bool,
}

impl LegionnairePolicy {
    /// Evaluate an action against the policy.
    ///
    /// Resolution order: a rule for the exact action wins; otherwise the
    /// `AnyAction` wildcard; otherwise `LogOnly`. A disabled policy always
    /// returns `LogOnly`. `identity` is accepted for future identity-scoped
    /// rules; the current rule table does not key on it.
    pub fn evaluate(&self, action: ActionType, _identity: &ProcessIdentity) -> PolicyAction {
        if !self.enabled {
            return PolicyAction::LogOnly;
        }
        self.rules
            .get(&action)
            .or_else(|| self.rules.get(&ActionType::AnyAction))
            .copied()
            .unwrap_or(PolicyAction::LogOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_identity() -> ProcessIdentity {
        ProcessIdentity {
            pid: 1,
            binary_hash: [0u8; 32],
            binary_path: PathBuf::from("/bin/agent"),
            parent_pid: 0,
            parent_hash: [0u8; 32],
            uid: 1000,
        }
    }

    #[test]
    fn disabled_policy_is_log_only() {
        let policy = LegionnairePolicy {
            enabled: false,
            rules: HashMap::from([(ActionType::FileAccess, PolicyAction::AutoTerminate)]),
            hold_config: HoldConfig {
                timeout_seconds: 0,
                default_on_timeout: TimeoutDefault::Deny,
                notify_telegram: false,
            },
            human_override: false,
        };
        assert_eq!(
            policy.evaluate(ActionType::FileAccess, &dummy_identity()),
            PolicyAction::LogOnly
        );
    }

    #[test]
    fn specific_rule_beats_wildcard() {
        let policy = LegionnairePolicy {
            enabled: true,
            rules: HashMap::from([
                (ActionType::FileAccess, PolicyAction::AutoBlock),
                (ActionType::AnyAction, PolicyAction::LogOnly),
            ]),
            hold_config: HoldConfig {
                timeout_seconds: 0,
                default_on_timeout: TimeoutDefault::Deny,
                notify_telegram: false,
            },
            human_override: true,
        };
        assert_eq!(
            policy.evaluate(ActionType::FileAccess, &dummy_identity()),
            PolicyAction::AutoBlock
        );
        // No specific rule → wildcard.
        assert_eq!(
            policy.evaluate(ActionType::NetworkConnect, &dummy_identity()),
            PolicyAction::LogOnly
        );
    }

    #[test]
    fn no_rule_no_wildcard_is_log_only() {
        let policy = LegionnairePolicy {
            enabled: true,
            rules: HashMap::new(),
            hold_config: HoldConfig {
                timeout_seconds: 0,
                default_on_timeout: TimeoutDefault::Allow,
                notify_telegram: false,
            },
            human_override: true,
        };
        assert_eq!(
            policy.evaluate(ActionType::MemoryMap, &dummy_identity()),
            PolicyAction::LogOnly
        );
    }
}
