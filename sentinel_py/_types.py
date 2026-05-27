"""Sentinel response and enum types.

Mirrors the Rust ``Request``/``Response`` types in
``sentinel-core/src/types.rs`` exactly. Field names, enum variants, and
value strings round-trip through JSON without renaming.

The daemon uses a single ``Response`` shape with optional ``tier`` and
``state`` fields (elided when absent). The dataclasses here are split per
method to document which fields each response actually carries.

OPERATIONAL SECURITY NOTE:
    These types are part of the operator/integrator surface of Sentinel.
    They must never be imported into or made accessible from the runtime
    environment of an agent under oversight.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AgentTier(Enum):
    """Permission tier assigned to an agent at registration.

    Ordered by privilege: READ_ONLY < WRITE < EXECUTE.
    """

    READ_ONLY = "READ_ONLY"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"


class AgentState(Enum):
    """Lifecycle state of a registered agent as reported by the daemon."""

    ACTIVE = "active"
    DOWNGRADED = "downgraded"


@dataclass(frozen=True)
class RegisterResponse:
    success: bool
    agent_id: str
    message: str
    tier: Optional[str]
    timestamp: str
    audit_hash: str


@dataclass(frozen=True)
class HeartbeatResponse:
    success: bool
    agent_id: str
    message: str
    timestamp: str
    audit_hash: str


@dataclass(frozen=True)
class StatusResponse:
    success: bool
    agent_id: str
    message: str
    tier: Optional[str]
    state: Optional[str]
    timestamp: str
    audit_hash: str


@dataclass(frozen=True)
class DeregisterResponse:
    success: bool
    agent_id: str
    message: str
    timestamp: str
    audit_hash: str
