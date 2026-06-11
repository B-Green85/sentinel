//! Sentinel response controls.
//!
//! v3 splits the response surface into two capabilities behind a single trait:
//!
//!   * [`Enforcer`] — the full v2 tier logic (pause → restrict → terminate),
//!   * [`Observer`] — every enforcement method compiled to a no-op,
//!
//! both implementing [`SentinelCapability`]. On top of the enforcer sits the
//! [`LegionnairePolicy`] per-action engine and its five named deployment
//! [`profiles`], with a Telegram [`notify`]-and-hold path for human-in-the-loop
//! decisions.

pub mod audit;
pub mod capability;
pub mod controller;
pub mod enforcer;
pub mod legionnaire;
pub mod notify;
pub mod observer;
pub mod process;
pub mod profiles;
pub mod socket;
pub mod util;
pub mod webhook;

// v2 surface — unchanged.
pub use controller::ControlEngine;
pub use process::{hard_terminate, sigterm_agent};
pub use socket::OverrideSocket;

// v3 surface.
pub use capability::SentinelCapability;
pub use enforcer::Enforcer;
pub use legionnaire::{
    ActionType, HoldConfig, LegionnairePolicy, PolicyAction, TimeoutDefault,
};
pub use notify::TelegramNotifier;
pub use observer::Observer;
pub use profiles::genesis_audit_json;
