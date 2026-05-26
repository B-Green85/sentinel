"""Context manager that registers an agent and heartbeats in the background.

:class:`Watch` is the high-level operator entry point. Entering the
context registers the agent with the Sentinel daemon and spawns a daemon
thread that sends heartbeats at a fixed interval; exiting stops the
thread and deregisters the agent.

OPERATIONAL SECURITY NOTE:
    This module — like the underlying client — is for HUMAN OPERATORS and
    EXTERNAL INTEGRATORS ONLY. It must never be imported into or made
    accessible from the runtime environment of an agent under oversight.
"""

import threading
from typing import Optional

from . import _client
from ._types import StatusResponse


class Watch:
    """Register an agent for the lifetime of a ``with`` block.

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """

    def __init__(
        self,
        agent_id: str,
        tier: str = "supervised",
        heartbeat_interval: float = 5.0,
    ) -> None:
        self.agent_id = agent_id
        self.tier = tier
        self.heartbeat_interval = heartbeat_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "Watch":
        _client.register(self.agent_id, self.tier)
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"sentinel-heartbeat-{self.agent_id}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.heartbeat_interval + 1)
            self._thread = None
        try:
            _client.deregister(self.agent_id)
        except Exception:
            pass

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.wait(self.heartbeat_interval):
            try:
                _client.heartbeat(self.agent_id)
            except Exception:
                pass

    def emit(self, text: str):
        """Record a chunk of agent output to the audit log."""
        return _client.emit_output(self.agent_id, text)

    def check_status(self) -> StatusResponse:
        """Fetch the current oversight status for this watch."""
        return _client.status(self.agent_id)
