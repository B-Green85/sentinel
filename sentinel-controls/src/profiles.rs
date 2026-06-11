//! The five named deployment profiles, plus the startup ("genesis") audit entry
//! that records which profile is active.
//!
//! A profile is just a fully-populated [`LegionnairePolicy`]. `from_name` is the
//! single entry point used at daemon startup — unknown names are rejected, never
//! silently defaulted.

use std::collections::HashMap;

use sentinel_types::SentinelError;

use crate::legionnaire::{
    ActionType, HoldConfig, LegionnairePolicy, PolicyAction, TimeoutDefault,
};

impl LegionnairePolicy {
    /// `critical-infrastructure` — terminate on any anomaly or sensitive action.
    /// No holds (timeout 0), no human override.
    pub fn critical_infrastructure() -> Self {
        let rules = HashMap::from([
            (ActionType::AnyAnomaly, PolicyAction::AutoTerminate),
            (ActionType::FileAccess, PolicyAction::AutoTerminate),
            (ActionType::NetworkConnect, PolicyAction::AutoTerminate),
            (ActionType::ProcessSpawn, PolicyAction::AutoTerminate),
            (ActionType::MemoryMap, PolicyAction::AutoTerminate),
        ]);
        LegionnairePolicy {
            enabled: true,
            rules,
            hold_config: HoldConfig {
                timeout_seconds: 0,
                default_on_timeout: TimeoutDefault::Deny,
                notify_telegram: false,
            },
            human_override: false,
        }
    }

    /// `financial` — hold on trading and network actions, block file/process.
    pub fn financial() -> Self {
        let rules = HashMap::from([
            (ActionType::TradingSyscall, PolicyAction::NotifyHold),
            (ActionType::FileAccess, PolicyAction::AutoBlock),
            (ActionType::NetworkConnect, PolicyAction::NotifyHold),
            (ActionType::ProcessSpawn, PolicyAction::AutoBlock),
        ]);
        LegionnairePolicy {
            enabled: true,
            rules,
            hold_config: HoldConfig {
                timeout_seconds: 5,
                default_on_timeout: TimeoutDefault::Deny,
                notify_telegram: true,
            },
            human_override: true,
        }
    }

    /// `healthcare` — hold on file/network access, terminate on exfiltration.
    pub fn healthcare() -> Self {
        let rules = HashMap::from([
            (ActionType::FileAccess, PolicyAction::NotifyHold),
            (ActionType::NetworkConnect, PolicyAction::NotifyHold),
            (ActionType::ProcessSpawn, PolicyAction::AutoBlock),
            (ActionType::DataExfiltration, PolicyAction::AutoTerminate),
        ]);
        LegionnairePolicy {
            enabled: true,
            rules,
            hold_config: HoldConfig {
                timeout_seconds: 60,
                default_on_timeout: TimeoutDefault::Deny,
                notify_telegram: true,
            },
            human_override: true,
        }
    }

    /// `enterprise` — block file access, hold network/process, log memory maps.
    pub fn enterprise() -> Self {
        let rules = HashMap::from([
            (ActionType::FileAccess, PolicyAction::AutoBlock),
            (ActionType::NetworkConnect, PolicyAction::NotifyHold),
            (ActionType::ProcessSpawn, PolicyAction::NotifyHold),
            (ActionType::MemoryMap, PolicyAction::LogOnly),
        ]);
        LegionnairePolicy {
            enabled: true,
            rules,
            hold_config: HoldConfig {
                timeout_seconds: 30,
                default_on_timeout: TimeoutDefault::Allow,
                notify_telegram: true,
            },
            human_override: true,
        }
    }

    /// `development` — log everything, intervene in nothing.
    pub fn development() -> Self {
        let rules = HashMap::from([(ActionType::AnyAction, PolicyAction::LogOnly)]);
        LegionnairePolicy {
            enabled: true,
            rules,
            hold_config: HoldConfig {
                timeout_seconds: 0,
                default_on_timeout: TimeoutDefault::Allow,
                notify_telegram: false,
            },
            human_override: true,
        }
    }

    /// Resolve a profile by its kebab-case name. Unknown names are rejected with
    /// a clear error — the daemon must never silently fall back to a profile.
    pub fn from_name(name: &str) -> Result<Self, SentinelError> {
        match name {
            "critical-infrastructure" => Ok(Self::critical_infrastructure()),
            "financial" => Ok(Self::financial()),
            "healthcare" => Ok(Self::healthcare()),
            "enterprise" => Ok(Self::enterprise()),
            "development" => Ok(Self::development()),
            other => Err(unknown_profile(other)),
        }
    }
}

/// Construct the `UnknownProfile` error. `SentinelError` in `sentinel-types` is
/// now a named-variant enum, so the rejection uses the dedicated
/// `SentinelError::UnknownProfile` variant carrying the offending profile name.
fn unknown_profile(name: &str) -> SentinelError {
    SentinelError::UnknownProfile(name.to_string())
}

/// Build the genesis audit entry (`sequence` 0, `event` `sentinel_start`) that
/// records the active deployment profile at startup. Returned as a JSON string
/// for the daemon to write to its audit log.
///
/// `mode` is `"enforcer"` or `"observer"`.
///
/// Integration note: `sentinel-core` currently keeps its own standalone audit
/// chain and does not depend on this crate. Wiring is a one-line call at the
/// point the daemon writes sequence 0 — pass the resolved profile name and mode.
pub fn genesis_audit_json(mode: &str, profile_name: &str, policy: &LegionnairePolicy) -> String {
    format!(
        r#"{{"sequence":0,"event":"sentinel_start","mode":"{}","profile":"{}","legionnaire_enabled":{},"human_override":{},"hold_timeout":{}}}"#,
        escape(mode),
        escape(profile_name),
        policy.enabled,
        policy.human_override,
        policy.hold_config.timeout_seconds,
    )
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legionnaire::PolicyAction;
    use std::path::PathBuf;
    use sentinel_types::ProcessIdentity;

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
    fn from_name_rejects_unknown() {
        let err = LegionnairePolicy::from_name("unknown-profile").unwrap_err();
        match err {
            SentinelError::UnknownProfile(name) => assert!(name.contains("unknown-profile")),
            other => panic!("expected UnknownProfile, got {other:?}"),
        }
    }

    #[test]
    fn from_name_resolves_all_five() {
        for name in [
            "critical-infrastructure",
            "financial",
            "healthcare",
            "enterprise",
            "development",
        ] {
            assert!(LegionnairePolicy::from_name(name).is_ok(), "{}", name);
        }
    }

    #[test]
    fn critical_infrastructure_is_strict() {
        let p = LegionnairePolicy::critical_infrastructure();
        assert_eq!(p.hold_config.timeout_seconds, 0);
        assert!(!p.human_override);
        assert_eq!(
            p.evaluate(ActionType::AnyAnomaly, &dummy_identity()),
            PolicyAction::AutoTerminate
        );
        assert_eq!(
            p.evaluate(ActionType::FileAccess, &dummy_identity()),
            PolicyAction::AutoTerminate
        );
    }

    #[test]
    fn development_logs_any_action() {
        let p = LegionnairePolicy::development();
        for action in [
            ActionType::FileAccess,
            ActionType::NetworkConnect,
            ActionType::ProcessSpawn,
            ActionType::MemoryMap,
            ActionType::SyscallUnknown,
        ] {
            assert_eq!(
                p.evaluate(action, &dummy_identity()),
                PolicyAction::LogOnly,
                "{:?}",
                action
            );
        }
    }

    #[test]
    fn financial_matches_spec() {
        let p = LegionnairePolicy::financial();
        let id = dummy_identity();
        assert_eq!(p.evaluate(ActionType::TradingSyscall, &id), PolicyAction::NotifyHold);
        assert_eq!(p.evaluate(ActionType::FileAccess, &id), PolicyAction::AutoBlock);
        assert_eq!(p.evaluate(ActionType::NetworkConnect, &id), PolicyAction::NotifyHold);
        assert_eq!(p.evaluate(ActionType::ProcessSpawn, &id), PolicyAction::AutoBlock);
        assert_eq!(p.hold_config.timeout_seconds, 5);
        assert_eq!(p.hold_config.default_on_timeout, TimeoutDefault::Deny);
        assert!(p.human_override);
    }

    #[test]
    fn enterprise_matches_spec() {
        let p = LegionnairePolicy::enterprise();
        let id = dummy_identity();
        assert_eq!(p.evaluate(ActionType::FileAccess, &id), PolicyAction::AutoBlock);
        assert_eq!(p.evaluate(ActionType::NetworkConnect, &id), PolicyAction::NotifyHold);
        assert_eq!(p.evaluate(ActionType::ProcessSpawn, &id), PolicyAction::NotifyHold);
        assert_eq!(p.evaluate(ActionType::MemoryMap, &id), PolicyAction::LogOnly);
        assert_eq!(p.hold_config.timeout_seconds, 30);
        assert_eq!(p.hold_config.default_on_timeout, TimeoutDefault::Allow);
    }

    #[test]
    fn healthcare_matches_spec() {
        let p = LegionnairePolicy::healthcare();
        let id = dummy_identity();
        assert_eq!(p.evaluate(ActionType::FileAccess, &id), PolicyAction::NotifyHold);
        assert_eq!(p.evaluate(ActionType::DataExfiltration, &id), PolicyAction::AutoTerminate);
        assert_eq!(p.hold_config.timeout_seconds, 60);
    }

    #[test]
    fn genesis_entry_records_profile() {
        let p = LegionnairePolicy::critical_infrastructure();
        let json = genesis_audit_json("enforcer", "critical-infrastructure", &p);
        assert!(json.contains(r#""sequence":0"#));
        assert!(json.contains(r#""event":"sentinel_start""#));
        assert!(json.contains(r#""mode":"enforcer""#));
        assert!(json.contains(r#""profile":"critical-infrastructure""#));
        assert!(json.contains(r#""legionnaire_enabled":true"#));
        assert!(json.contains(r#""human_override":false"#));
        assert!(json.contains(r#""hold_timeout":0"#));
    }
}
