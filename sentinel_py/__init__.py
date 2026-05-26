"""Sentinel Python client package.

Public API for operators and external integrators to talk to the Sentinel
oversight daemon. Prefers the compiled PyO3 extension
(``_sentinel_core``) when available and transparently falls back to the
pure-Python Unix-socket implementation in :mod:`._client` otherwise. The
:class:`Watch` context manager and the :func:`watch` factory are always
provided by :mod:`.watch`.

Exported symbols:
    register, heartbeat, emit_output, status, watch,
    AgentTier, AgentState,
    RegisterResponse, HeartbeatResponse, EmitOutputResponse, StatusResponse

OPERATIONAL SECURITY NOTE:
    Every symbol exported here is for HUMAN OPERATORS and EXTERNAL
    INTEGRATORS ONLY. Do not import this package — or any of its
    submodules — into the runtime environment of an agent under
    oversight. Doing so would let the agent forge, suppress, or
    deregister its own audit trail.
"""

from ._types import (
    AgentState,
    AgentTier,
    EmitOutputResponse,
    HeartbeatResponse,
    RegisterResponse,
    StatusResponse,
)

try:
    from _sentinel_core import (  # type: ignore[import-not-found]
        deregister,
        emit_output,
        heartbeat,
        register,
        status,
    )
except ImportError:
    from ._client import (
        deregister,
        emit_output,
        heartbeat,
        register,
        status,
    )

from .watch import Watch


def watch(
    agent_id: str,
    tier: str = "supervised",
    heartbeat_interval: float = 5.0,
) -> Watch:
    """Construct a :class:`Watch` context manager for ``agent_id``.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    return Watch(agent_id=agent_id, tier=tier, heartbeat_interval=heartbeat_interval)


__all__ = [
    "register",
    "heartbeat",
    "emit_output",
    "status",
    "deregister",
    "watch",
    "Watch",
    "AgentTier",
    "AgentState",
    "RegisterResponse",
    "HeartbeatResponse",
    "EmitOutputResponse",
    "StatusResponse",
]
