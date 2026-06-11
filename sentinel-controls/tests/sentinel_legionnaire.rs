// Sentinel v3 — Agent 8 test suite: tests/sentinel_legionnaire
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// Contractual test names from the v3 spec, exercised against the REAL
// Legionnaire policy engine, deployment profiles, and Telegram notify-and-hold
// (Agent 5).

use sentinel_controls::{
    ActionType, HoldConfig, LegionnairePolicy, PolicyAction, TelegramNotifier, TimeoutDefault,
};
use sentinel_types::ProcessIdentity;
use std::path::PathBuf;

fn identity() -> ProcessIdentity {
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
fn test_critical_profile_auto_terminates() {
    let policy = LegionnairePolicy::critical_infrastructure();
    assert_eq!(
        policy.evaluate(ActionType::AnyAnomaly, &identity()),
        PolicyAction::AutoTerminate
    );
}

#[test]
fn test_financial_profile_holds_5s() {
    let policy = LegionnairePolicy::financial();
    assert_eq!(policy.hold_config.timeout_seconds, 5);
    assert_eq!(
        policy.evaluate(ActionType::NetworkConnect, &identity()),
        PolicyAction::NotifyHold
    );
}

#[tokio::test]
async fn test_hold_timeout_applies_default() {
    // NotifyHold with timeout 1s, default_on_timeout = Deny, Telegram enabled and
    // credentials present. With no inbound operator reply, the hold waits the
    // full second and then applies the default → AutoBlock. The notifier logs
    // "operator_timeout" to stderr as it applies the default.
    let notifier = TelegramNotifier::new("bot-token", "chat-id");
    let hold = HoldConfig {
        timeout_seconds: 1,
        default_on_timeout: TimeoutDefault::Deny,
        notify_telegram: true,
    };
    let action = notifier
        .notify_and_hold(
            &"agent-1".to_string(),
            ActionType::NetworkConnect,
            "10.0.0.1:443",
            "financial",
            &hold,
        )
        .await;
    assert_eq!(action, PolicyAction::AutoBlock, "timeout default (Deny) must apply as AutoBlock");
}

// The spec mocks a TelegramNotifier that returns an operator decision (Allow).
// Agent 5's TelegramNotifier has NO inbound operator-reply channel (see
// notify.rs: "There is no inbound operator-reply channel yet") — an operator
// Allow/Deny cannot be injected, so notify_and_hold always resolves to the
// timeout default. Present per contract, ignored until the reply channel lands.
#[test]
#[ignore = "blocked: TelegramNotifier has no inbound operator-reply channel (Agent 5) — operator Allow cannot be injected; notify_and_hold only ever applies the timeout default"]
fn test_operator_allow_releases_syscall() {}

#[test]
#[ignore = "blocked: TelegramNotifier has no inbound operator-reply channel (Agent 5) — operator Deny cannot be injected; notify_and_hold only ever applies the timeout default"]
fn test_operator_deny_blocks_syscall() {}

#[tokio::test]
async fn test_no_hold_when_timeout_zero() {
    // timeout_seconds == 0 → the default is applied immediately, with no wait.
    let notifier = TelegramNotifier::new("bot-token", "chat-id");
    let hold = HoldConfig {
        timeout_seconds: 0,
        default_on_timeout: TimeoutDefault::Deny,
        notify_telegram: true,
    };
    // Default-on-timeout Deny resolves to AutoBlock, and HoldConfig agrees.
    assert_eq!(hold.timeout_action(), PolicyAction::AutoBlock);
    let action = notifier
        .notify_and_hold(
            &"agent-1".to_string(),
            ActionType::FileAccess,
            "/etc/passwd",
            "critical-infrastructure",
            &hold,
        )
        .await;
    assert_eq!(action, PolicyAction::AutoBlock);
}

#[test]
fn test_human_override_disabled_critical() {
    let policy = LegionnairePolicy::critical_infrastructure();
    assert!(!policy.human_override, "critical-infrastructure must disable human override");
}

#[test]
fn test_profile_recorded_in_audit_log() {
    // The genesis audit entry records the active deployment profile name.
    let policy = LegionnairePolicy::enterprise();
    let json = sentinel_controls::genesis_audit_json("enforcer", "enterprise", &policy);
    assert!(json.contains(r#""profile":"enterprise""#), "genesis must record the profile: {json}");
    assert!(json.contains(r#""sequence":0"#));
    assert!(json.contains(r#""event":"sentinel_start""#));
}

#[test]
fn test_unknown_profile_rejected_at_startup() {
    // from_name rejects unknown profiles — never silently defaults.
    let err = LegionnairePolicy::from_name("not-a-real-profile").unwrap_err();
    // `sentinel_types::SentinelError` is now a named-variant enum, matching the
    // v3 spec: unknown profiles reject with `SentinelError::UnknownProfile(name)`.
    match err {
        sentinel_types::SentinelError::UnknownProfile(name) => {
            assert!(name.contains("not-a-real-profile"));
        }
        other => panic!("expected UnknownProfile, got {other:?}"),
    }
}
