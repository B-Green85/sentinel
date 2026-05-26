"""Sentinel response and enum types.

Mirrors the Rust types defined in the sentinel-types crate exactly: field
names, enum variants, and value strings are kept in sync so that JSON
payloads round-trip without renaming.

OPERATIONAL SECURITY NOTE:
    These types are part of the operator/integrator surface of Sentinel.
    They must never be imported into or made accessible from the runtime
    environment of an agent under oversight.
"""

from dataclasses import dataclass
from enum import Enum


class AgentTier(Enum):
    """Privilege tier assigned to an agent at registration."""

    AUTONOMOUS = "autonomous"
    SUPERVISED = "supervised"
    RESTRICTED = "restricted"


class AgentState(Enum):
    """Lifecycle state of a registered agent."""

    RUNNING = "running"
    IDLE = "idle"
    TERMINATED = "terminated"
    UNRESPONSIVE = "unresponsive"


@dataclass(frozen=True)
class RegisterResponse:
    registered: bool
    agent_id: str
    tier: str
    timestamp: str
    audit_hash: str


@dataclass(frozen=True)
class HeartbeatResponse:
    acknowledged: bool
    agent_id: str
    timestamp: str
    audit_hash: str


@dataclass(frozen=True)
class EmitOutputResponse:
    recorded: bool
    agent_id: str
    timestamp: str
    audit_hash: str
    bytes_captured: int


@dataclass(frozen=True)
class StatusResponse:
    agent_id: str
    tier: str
    state: str
    last_heartbeat: str
    output_count: int
    registered_at: str
    audit_hash: str
