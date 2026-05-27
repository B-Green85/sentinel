"""Pure-Python Unix-socket client for the Sentinel daemon.

Speaks the JSON request envelope defined in
``sentinel-core/src/types.rs`` over the Unix socket at
``/tmp/sentinel.sock`` (overridable via ``SENTINEL_SOCKET_PATH``). Each
call opens a fresh connection, writes one JSON request, half-closes the
write side, and reads the full response until EOF.

The daemon recognizes four methods only — ``register``, ``heartbeat``,
``status``, ``deregister``. Agent output is NOT ingested over this
socket; the daemon captures stdout/stderr out-of-band through its
process harness, so there is no ``emit_output`` RPC.

Request envelope::

    {"method": "register",   "agent_id": "...", "permission_tier": "READ_ONLY"|"WRITE"|"EXECUTE", "heartbeat_interval": <u64 seconds>}
    {"method": "heartbeat",  "agent_id": "..."}
    {"method": "status",     "agent_id": "..."}
    {"method": "deregister", "agent_id": "..."}

Response envelope (fields with ``Option`` semantics on the Rust side are
elided when null)::

    {"success": bool, "agent_id": str, "message": str,
     "tier": str?, "state": str?, "timestamp": str, "audit_hash": str}

OPERATIONAL SECURITY NOTE:
    This client is for HUMAN OPERATORS and EXTERNAL INTEGRATORS ONLY. It
    must never be imported into or made accessible from the agent's
    runtime environment — doing so would let the agent under oversight
    forge, suppress, or deregister its own audit trail.
"""

import json
import os
import socket
from typing import Any, Dict

from ._types import (
    DeregisterResponse,
    HeartbeatResponse,
    RegisterResponse,
    StatusResponse,
)


_DEFAULT_SOCKET_PATH = "/tmp/sentinel.sock"
_READ_CHUNK_BYTES = 4096


class SentinelError(Exception):
    """Raised when the Sentinel daemon returns ``success=false``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _get_socket_path() -> str:
    """Return the configured Sentinel Unix socket path."""
    return os.environ.get("SENTINEL_SOCKET_PATH", _DEFAULT_SOCKET_PATH)


def _send_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Send one JSON request to the daemon and return the parsed response.

    Opens a fresh AF_UNIX/SOCK_STREAM connection, writes the encoded
    payload, half-closes with ``SHUT_WR`` so the daemon sees EOF, then
    reads in 4096-byte chunks until the peer closes.
    """
    encoded = json.dumps(payload).encode("utf-8")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(_get_socket_path())
        sock.sendall(encoded)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = sock.recv(_READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()

    raw = b"".join(chunks)
    return json.loads(raw.decode("utf-8"))


def _check(response: Dict[str, Any]) -> Dict[str, Any]:
    """Raise SentinelError if the daemon reports failure, else return response."""
    if not response.get("success", False):
        raise SentinelError(
            code=str(response.get("agent_id") or "unknown"),
            message=str(response.get("message", "")),
        )
    return response


def register(
    agent_id: str, permission_tier: str, heartbeat_interval: int = 5
) -> RegisterResponse:
    """Register an agent with the daemon at the given permission tier.

    ``permission_tier`` must be one of ``READ_ONLY``, ``WRITE``,
    ``EXECUTE``. ``heartbeat_interval`` is an integer number of seconds
    (the daemon deserializes it as ``u64``).

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _check(
        _send_request(
            {
                "method": "register",
                "agent_id": agent_id,
                "permission_tier": permission_tier,
                "heartbeat_interval": int(heartbeat_interval),
            }
        )
    )
    return RegisterResponse(
        success=response["success"],
        agent_id=response["agent_id"],
        message=response["message"],
        tier=response.get("tier"),
        timestamp=response["timestamp"],
        audit_hash=response["audit_hash"],
    )


def heartbeat(agent_id: str) -> HeartbeatResponse:
    """Send a liveness heartbeat for ``agent_id``.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _check(
        _send_request({"method": "heartbeat", "agent_id": agent_id})
    )
    return HeartbeatResponse(
        success=response["success"],
        agent_id=response["agent_id"],
        message=response["message"],
        timestamp=response["timestamp"],
        audit_hash=response["audit_hash"],
    )


def status(agent_id: str) -> StatusResponse:
    """Fetch the current oversight status for ``agent_id``.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _check(
        _send_request({"method": "status", "agent_id": agent_id})
    )
    return StatusResponse(
        success=response["success"],
        agent_id=response["agent_id"],
        message=response["message"],
        tier=response.get("tier"),
        state=response.get("state"),
        timestamp=response["timestamp"],
        audit_hash=response["audit_hash"],
    )


def deregister(agent_id: str) -> DeregisterResponse:
    """Tear down oversight state for ``agent_id``.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _check(
        _send_request({"method": "deregister", "agent_id": agent_id})
    )
    return DeregisterResponse(
        success=response["success"],
        agent_id=response["agent_id"],
        message=response["message"],
        timestamp=response["timestamp"],
        audit_hash=response["audit_hash"],
    )
