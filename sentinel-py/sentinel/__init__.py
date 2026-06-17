"""Sentinel — Python bindings for the Sentinel agent-oversight daemon.

The compiled PyO3 extension is exposed as ``sentinel._sentinel_core``. This
package re-exports its public surface so operators can ``import sentinel`` and
reach both the existing client functions and the v3 operator-only additions
(ProcessIdentity, SessionCredentialSummary, AuditEntry, get_process_identity,
read_audit_chain, verify_audit_chain, get_profile, is_observer_mode).

Build with: ``maturin develop`` (needs a PyO3-supported CPython, ≤ 3.13, or set
``PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1``).
"""

from __future__ import annotations

from ._sentinel_core import (  # noqa: F401
    # v2 client surface (unchanged)
    register,
    heartbeat,
    emit_output,
    status,
    # detector inputs for the WS plane (GoalDrift / Scope / ToolRetry)
    observe_tool_call,
    set_agent_goal,
    set_agent_scope,
    AgentTier,
    AgentState,
    RegisterResponse,
    HeartbeatResponse,
    EmitOutputResponse,
    StatusResponse,
    # v3 operator-only surface (Agent 8)
    ProcessIdentity,
    SessionCredentialSummary,
    AuditEntry,
    get_process_identity,
    read_audit_chain,
    verify_audit_chain,
    get_profile,
    is_observer_mode,
)

__all__ = [
    "register",
    "heartbeat",
    "emit_output",
    "status",
    "observe_tool_call",
    "set_agent_goal",
    "set_agent_scope",
    "AgentTier",
    "AgentState",
    "RegisterResponse",
    "HeartbeatResponse",
    "EmitOutputResponse",
    "StatusResponse",
    "ProcessIdentity",
    "SessionCredentialSummary",
    "AuditEntry",
    "get_process_identity",
    "read_audit_chain",
    "verify_audit_chain",
    "get_profile",
    "is_observer_mode",
]
