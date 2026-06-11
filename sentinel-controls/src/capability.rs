//! The shared capability interface.
//!
//! Both the full [`Enforcer`](crate::enforcer::Enforcer) and the no-op
//! [`Observer`](crate::observer::Observer) implement this single trait. A build
//! configured with the `Observer` has every enforcement method compiled down to
//! a no-op — a third-party auditor can verify the observer binary contains no
//! SIGTERM call and no permission-revocation path.

use sentinel_types::{AgentId, DegradationEvent, SentinelError};

/// The interface every Sentinel response capability implements.
///
/// `on_signal` reacts to a degradation event; the three `*_agent` methods apply
/// a specific intervention tier directly. The `Enforcer` carries them out; the
/// `Observer` makes all four no-ops.
pub trait SentinelCapability: Send + Sync {
    /// React to a degradation event. The enforcer accumulates score and applies
    /// the appropriate tier; the observer logs only (handled upstream).
    fn on_signal(&self, event: &DegradationEvent) -> Result<(), SentinelError>;

    /// Soft tier — pause the agent, permissions retained.
    fn pause_agent(&self, id: &AgentId) -> Result<(), SentinelError>;

    /// Medium tier — downgrade the agent to read-only.
    fn restrict_agent(&self, id: &AgentId) -> Result<(), SentinelError>;

    /// Hard tier — terminate the agent, revoke all permissions, lock the id.
    fn terminate_agent(&self, id: &AgentId) -> Result<(), SentinelError>;
}
