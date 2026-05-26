"""Pure-Python Unix-socket client for the Sentinel daemon.

Speaks the line-oriented JSON request protocol exposed by the Rust core on
the Unix socket at ``/tmp/sentinel.sock`` (overridable via the
``SENTINEL_SOCKET_PATH`` environment variable). Each call opens a fresh
connection, writes one JSON request, half-closes the write side, and reads
the full response until EOF.

OPERATIONAL SECURITY NOTE:
    This client is for HUMAN OPERATORS and EXTERNAL INTEGRATORS ONLY. It
    must never be imported into or made accessible from the agent's runtime
    environment — doing so would let the agent under oversight forge,
    suppress, or deregister its own audit trail.
"""

import json
import os
import socket
from typing import Any, Dict

from ._types import (
    EmitOutputResponse,
    HeartbeatResponse,
    RegisterResponse,
    StatusResponse,
)


_DEFAULT_SOCKET_PATH = "/tmp/sentinel.sock"
_READ_CHUNK_BYTES = 4096


class SentinelError(Exception):
    """Raised when the Sentinel daemon returns an error response."""

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
    reads in 4096-byte chunks until the peer closes. Raises
    :class:`SentinelError` if the response carries an ``error`` field.
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
    response = json.loads(raw.decode("utf-8"))
    if isinstance(response, dict) and "error" in response:
        err = response["error"]
        if isinstance(err, dict):
            code = str(err.get("code", "unknown"))
            message = str(err.get("message", ""))
        else:
            code = "unknown"
            message = str(err)
        raise SentinelError(code, message)
    return response


def register(agent_id: str, tier: str) -> RegisterResponse:
    """Register an agent with the daemon at the given tier.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _send_request(
        {"method": "register", "agent_id": agent_id, "tier": tier, "text": None}
    )
    return RegisterResponse(
        registered=response["registered"],
        agent_id=response["agent_id"],
        tier=response["tier"],
        timestamp=response["timestamp"],
        audit_hash=response["audit_hash"],
    )


def heartbeat(agent_id: str) -> HeartbeatResponse:
    """Send a liveness heartbeat for ``agent_id``.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _send_request(
        {"method": "heartbeat", "agent_id": agent_id, "tier": None, "text": None}
    )
    return HeartbeatResponse(
        acknowledged=response["acknowledged"],
        agent_id=response["agent_id"],
        timestamp=response["timestamp"],
        audit_hash=response["audit_hash"],
    )


def emit_output(agent_id: str, text: str) -> EmitOutputResponse:
    """Record a chunk of agent output to the audit log.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _send_request(
        {"method": "emit_output", "agent_id": agent_id, "tier": None, "text": text}
    )
    return EmitOutputResponse(
        recorded=response["recorded"],
        agent_id=response["agent_id"],
        timestamp=response["timestamp"],
        audit_hash=response["audit_hash"],
        bytes_captured=response["bytes_captured"],
    )


def status(agent_id: str) -> StatusResponse:
    """Fetch the current oversight status for ``agent_id``.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    response = _send_request(
        {"method": "status", "agent_id": agent_id, "tier": None, "text": None}
    )
    return StatusResponse(
        agent_id=response["agent_id"],
        tier=response["tier"],
        state=response["state"],
        last_heartbeat=response["last_heartbeat"],
        output_count=response["output_count"],
        registered_at=response["registered_at"],
        audit_hash=response["audit_hash"],
    )


def deregister(agent_id: str) -> None:
    """Tear down oversight state for ``agent_id``.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """
    _send_request(
        {"method": "deregister", "agent_id": agent_id, "tier": None, "text": None}
    )
