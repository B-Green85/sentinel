//! Telegram notify-and-hold interface.
//!
//! When a profile rule resolves to [`NotifyHold`](crate::legionnaire::PolicyAction::NotifyHold),
//! the held action is sent to a human operator over Telegram and the action is
//! held until they respond or the configured timeout expires.
//!
//! Scope note for the initial implementation:
//!   * The outbound Telegram send is a best-effort stub — `sentinel-controls`
//!     has no TLS HTTP client dependency, so [`TelegramNotifier::send_message`]
//!     logs the payload and returns `false`. Wiring a real client is a drop-in
//!     replacement for that one method.
//!   * There is no inbound operator-reply channel yet, so a hold with a non-zero
//!     timeout waits the full duration and then applies `default_on_timeout`,
//!     logged as `operator_timeout`.

use sentinel_types::AgentId;

use crate::legionnaire::{ActionType, HoldConfig, PolicyAction, TimeoutDefault};

/// Sends hold notifications to a Telegram chat and waits for an operator
/// decision.
pub struct TelegramNotifier {
    pub bot_token: String,
    pub chat_id: String,
}

impl TelegramNotifier {
    pub fn new(bot_token: impl Into<String>, chat_id: impl Into<String>) -> Self {
        Self {
            bot_token: bot_token.into(),
            chat_id: chat_id.into(),
        }
    }

    /// Whether usable Telegram credentials are configured.
    fn configured(&self) -> bool {
        !self.bot_token.is_empty() && !self.chat_id.is_empty()
    }

    /// Send a hold notification and wait for the operator's decision.
    /// Returns the operator's decision, or the timeout default.
    ///
    /// Rules:
    ///   * `timeout_seconds == 0` → apply the default immediately, no wait.
    ///   * `notify_telegram == false` → skip Telegram, apply the default now.
    ///   * credentials not configured → log a warning, apply the default now.
    ///   * otherwise → send, wait up to the timeout, then apply the default
    ///     (logged as `operator_timeout`).
    pub async fn notify_and_hold(
        &self,
        agent_id: &AgentId,
        action: ActionType,
        target: &str,
        profile: &str,
        hold_config: &HoldConfig,
    ) -> PolicyAction {
        let default = hold_config.timeout_action();

        // No hold permitted (e.g. critical-infrastructure): apply default now.
        if hold_config.timeout_seconds == 0 {
            return default;
        }

        // Profile opted out of Telegram: apply default now.
        if !hold_config.notify_telegram {
            return default;
        }

        // No credentials: warn and fall back, never panic.
        if !self.configured() {
            eprintln!(
                "[sentinel] WARN: Telegram not configured; applying default ({:?}) for {} on {:?}",
                hold_config.default_on_timeout, agent_id, action
            );
            return default;
        }

        let message = format_hold_message(agent_id, action, target, profile, hold_config);
        let _sent = self.send_message(&message).await;

        // No inbound reply channel yet — wait the timeout then apply the default.
        tokio::time::sleep(std::time::Duration::from_secs(hold_config.timeout_seconds)).await;
        eprintln!(
            "[sentinel] operator_timeout: no response for {} on {:?}; applying default ({:?})",
            agent_id, action, hold_config.default_on_timeout
        );
        default
    }

    /// Best-effort outbound send. Stub for the initial implementation: logs the
    /// message and reports failure to deliver. Replace with a real HTTPS client
    /// call to the Telegram Bot API (`sendMessage`) without changing callers.
    async fn send_message(&self, message: &str) -> bool {
        eprintln!(
            "[sentinel] (telegram stub) would send to chat {}:\n{}",
            self.chat_id, message
        );
        false
    }
}

/// Render the operator-facing hold notification exactly as specified.
fn format_hold_message(
    agent_id: &AgentId,
    action: ActionType,
    target: &str,
    profile: &str,
    hold_config: &HoldConfig,
) -> String {
    let default = match hold_config.default_on_timeout {
        TimeoutDefault::Allow => "allow",
        TimeoutDefault::Deny => "deny",
    };
    format!(
        "🔴 SENTINEL HOLD — decision required\n\n\
         Agent:    {agent}\n\
         Action:   {action:?}\n\
         Target:   {target}\n\
         Profile:  {profile}\n\
         Timeout:  {timeout}s (default: {default})\n\n\
         Reply:\n  \
         /allow          — permit this action\n  \
         /deny           — block this action\n  \
         /terminate      — terminate the agent\n  \
         /always_allow   — add to policy (this session)\n  \
         /always_deny    — add to policy (this session)",
        agent = agent_id,
        action = action,
        target = target,
        profile = profile,
        timeout = hold_config.timeout_seconds,
        default = default,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(timeout: u64, default: TimeoutDefault, notify: bool) -> HoldConfig {
        HoldConfig {
            timeout_seconds: timeout,
            default_on_timeout: default,
            notify_telegram: notify,
        }
    }

    #[tokio::test]
    async fn timeout_zero_applies_default_immediately() {
        let n = TelegramNotifier::new("tok", "chat");
        let id = "agent-1".to_string();
        // Deny default → AutoBlock, returned with no wait.
        let action = n
            .notify_and_hold(
                &id,
                ActionType::FileAccess,
                "/etc/passwd",
                "critical-infrastructure",
                &cfg(0, TimeoutDefault::Deny, false),
            )
            .await;
        assert_eq!(action, PolicyAction::AutoBlock);
    }

    #[tokio::test]
    async fn notify_disabled_applies_default() {
        let n = TelegramNotifier::new("tok", "chat");
        let id = "agent-1".to_string();
        let action = n
            .notify_and_hold(
                &id,
                ActionType::NetworkConnect,
                "10.0.0.1",
                "development",
                &cfg(30, TimeoutDefault::Allow, false),
            )
            .await;
        assert_eq!(action, PolicyAction::LogOnly);
    }

    #[tokio::test]
    async fn missing_credentials_falls_back_without_panic() {
        let n = TelegramNotifier::new("", "");
        let id = "agent-1".to_string();
        let action = n
            .notify_and_hold(
                &id,
                ActionType::NetworkConnect,
                "10.0.0.1",
                "financial",
                &cfg(30, TimeoutDefault::Deny, true),
            )
            .await;
        assert_eq!(action, PolicyAction::AutoBlock);
    }

    #[test]
    fn message_format_contains_fields() {
        let id = "agent-7".to_string();
        let msg = format_hold_message(
            &id,
            ActionType::TradingSyscall,
            "NYSE:AAPL",
            "financial",
            &cfg(5, TimeoutDefault::Deny, true),
        );
        assert!(msg.contains("SENTINEL HOLD"));
        assert!(msg.contains("agent-7"));
        assert!(msg.contains("TradingSyscall"));
        assert!(msg.contains("NYSE:AAPL"));
        assert!(msg.contains("financial"));
        assert!(msg.contains("5s (default: deny)"));
        assert!(msg.contains("/always_deny"));
    }
}
