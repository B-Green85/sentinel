"""Tests for sentinel_py._client — Unix socket client for sentinel-core.

Uses a real Unix socket server to test the full request/response cycle.
This validates that method signatures match exactly what sentinel-core exposes.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import pytest

from sentinel_py._client import (
    SentinelError,
    deregister,
    emit_output,
    heartbeat,
    register,
    status,
)
from sentinel_py._types import (
    EmitOutputResponse,
    HeartbeatResponse,
    RegisterResponse,
    StatusResponse,
)


def _audit_hash(agent_id: str, action: str, timestamp: str) -> str:
    """Mirror of sentinel-types audit_hash for test assertions."""
    return sha256(f"{agent_id}|{action}|{timestamp}".encode()).hexdigest()


class MockSentinelDaemon:
    """Minimal mock of sentinel-core daemon for testing the client protocol."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.agents: dict[str, dict[str, Any]] = {}
        self._server_socket: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        thread = threading.Thread(target=self._serve, daemon=True)
        thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._server_socket:
            self._server_socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server_socket.accept()  # type: ignore[union-attr]
            except (TimeoutError, OSError):
                continue

            try:
                data = b""
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk

                req = json.loads(data.decode())
                resp = self._handle(req)
                conn.sendall(json.dumps(resp).encode())
            except Exception:  # noqa: S110
                pass
            finally:
                conn.close()

    def _handle(self, req: dict[str, Any]) -> dict[str, Any]:
        method = req.get("method", "")
        agent_id = req.get("agent_id", "")
        now = datetime.now(tz=UTC).isoformat()

        if method == "register":
            tier = req.get("tier", "supervised")
            self.agents[agent_id] = {
                "tier": tier, "state": "running",
                "registered_at": now, "last_heartbeat": now,
                "output_count": 0,
            }
            return {
                "registered": True,
                "agent_id": agent_id,
                "tier": tier,
                "timestamp": now,
                "audit_hash": _audit_hash(agent_id, "register", now),
            }
        elif method == "heartbeat":
            if agent_id in self.agents:
                self.agents[agent_id]["last_heartbeat"] = now
            return {
                "acknowledged": True,
                "agent_id": agent_id,
                "timestamp": now,
                "audit_hash": _audit_hash(agent_id, "heartbeat", now),
            }
        elif method == "emit_output":
            text = req.get("text", "")
            if agent_id in self.agents:
                self.agents[agent_id]["output_count"] += 1
            return {
                "recorded": True,
                "agent_id": agent_id,
                "timestamp": now,
                "audit_hash": _audit_hash(agent_id, "emit_output", now),
                "bytes_captured": len(text),
            }
        elif method == "status":
            if agent_id not in self.agents:
                return {"code": "AGENT_NOT_FOUND", "message": f"agent not registered: {agent_id}"}
            rec = self.agents[agent_id]
            return {
                "agent_id": agent_id,
                "tier": rec["tier"],
                "state": rec["state"],
                "last_heartbeat": rec["last_heartbeat"],
                "output_count": rec["output_count"],
                "registered_at": rec["registered_at"],
                "audit_hash": _audit_hash(agent_id, "status", now),
            }
        elif method == "deregister":
            if agent_id in self.agents:
                self.agents[agent_id]["state"] = "terminated"
            return {
                "deregistered": True,
                "agent_id": agent_id,
                "timestamp": now,
                "audit_hash": _audit_hash(agent_id, "deregister", now),
            }
        return {"code": "UNKNOWN_METHOD", "message": f"unknown method: {method}"}


@pytest.fixture()
def sentinel_daemon() -> Any:
    """Start a mock sentinel-core daemon on a temp Unix socket."""
    import tempfile
    sock_path = os.path.join(tempfile.gettempdir(), f"sentinel-test-{os.getpid()}.sock")
    daemon = MockSentinelDaemon(sock_path)
    daemon.start()

    old_env = os.environ.get("SENTINEL_SOCKET_PATH")
    os.environ["SENTINEL_SOCKET_PATH"] = sock_path

    yield daemon

    daemon.stop()
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    if old_env is not None:
        os.environ["SENTINEL_SOCKET_PATH"] = old_env
    else:
        os.environ.pop("SENTINEL_SOCKET_PATH", None)


class TestRegister:
    def test_register_success(self, sentinel_daemon: MockSentinelDaemon) -> None:
        resp = register("test-agent-001", "supervised")
        assert isinstance(resp, RegisterResponse)
        assert resp.registered is True
        assert resp.agent_id == "test-agent-001"
        assert resp.tier == "supervised"
        assert len(resp.audit_hash) == 64  # SHA256 hex

    def test_register_restricted(self, sentinel_daemon: MockSentinelDaemon) -> None:
        resp = register("test-agent-002", "restricted")
        assert resp.tier == "restricted"

    def test_register_autonomous(self, sentinel_daemon: MockSentinelDaemon) -> None:
        resp = register("test-agent-003", "autonomous")
        assert resp.tier == "autonomous"


class TestHeartbeat:
    def test_heartbeat_success(self, sentinel_daemon: MockSentinelDaemon) -> None:
        register("test-agent-hb", "supervised")
        resp = heartbeat("test-agent-hb")
        assert isinstance(resp, HeartbeatResponse)
        assert resp.acknowledged is True
        assert resp.agent_id == "test-agent-hb"
        assert len(resp.audit_hash) == 64


class TestEmitOutput:
    def test_emit_output_success(self, sentinel_daemon: MockSentinelDaemon) -> None:
        register("test-agent-emit", "supervised")
        resp = emit_output("test-agent-emit", "hello world")
        assert isinstance(resp, EmitOutputResponse)
        assert resp.recorded is True
        assert resp.bytes_captured == len("hello world")
        assert len(resp.audit_hash) == 64

    def test_emit_empty_output(self, sentinel_daemon: MockSentinelDaemon) -> None:
        register("test-agent-emit-empty", "supervised")
        resp = emit_output("test-agent-emit-empty", "")
        assert resp.bytes_captured == 0


class TestStatus:
    def test_status_registered_agent(self, sentinel_daemon: MockSentinelDaemon) -> None:
        register("test-agent-status", "restricted")
        resp = status("test-agent-status")
        assert isinstance(resp, StatusResponse)
        assert resp.agent_id == "test-agent-status"
        assert resp.tier == "restricted"
        assert resp.state == "running"
        assert resp.output_count == 0

    def test_status_unregistered_agent(self, sentinel_daemon: MockSentinelDaemon) -> None:
        with pytest.raises(SentinelError, match="AGENT_NOT_FOUND"):
            status("nonexistent-agent")

    def test_status_after_output(self, sentinel_daemon: MockSentinelDaemon) -> None:
        register("test-agent-count", "supervised")
        emit_output("test-agent-count", "output 1")
        emit_output("test-agent-count", "output 2")
        resp = status("test-agent-count")
        assert resp.output_count == 2


class TestDeregister:
    def test_deregister_success(self, sentinel_daemon: MockSentinelDaemon) -> None:
        register("test-agent-dereg", "supervised")
        resp = deregister("test-agent-dereg")
        assert resp["deregistered"] is True
        assert resp["agent_id"] == "test-agent-dereg"

    def test_deregister_sets_terminated(self, sentinel_daemon: MockSentinelDaemon) -> None:
        register("test-agent-term", "supervised")
        deregister("test-agent-term")
        resp = status("test-agent-term")
        assert resp.state == "terminated"


class TestConnectionError:
    def test_connection_refused(self) -> None:
        """Client raises when sentinel-core is not running."""
        old_env = os.environ.get("SENTINEL_SOCKET_PATH")
        os.environ["SENTINEL_SOCKET_PATH"] = "/tmp/nonexistent-sentinel-test.sock"  # nosec  # noqa: S108
        try:
            with pytest.raises(OSError):
                register("agent", "supervised")
        finally:
            if old_env is not None:
                os.environ["SENTINEL_SOCKET_PATH"] = old_env
            else:
                os.environ.pop("SENTINEL_SOCKET_PATH", None)
