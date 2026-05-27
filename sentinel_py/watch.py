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

    ``tier`` accepts the daemon's tier strings: ``"READ_ONLY"``,
    ``"WRITE"``, or ``"EXECUTE"``. ``heartbeat_interval`` is in seconds
    and is rounded to an integer before being sent (the daemon's wire
    type is ``u64``).

    OPERATIONAL SECURITY NOTE: operator/integrator surface only — never
    expose to a watched agent's runtime.
    """

    def __init__(
        self,
        agent_id: str,
        tier: str = "WRITE",
        heartbeat_interval: float = 5.0,
    ) -> None:
        self.agent_id = agent_id
        self.tier = tier
        self.heartbeat_interval = heartbeat_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "Watch":
        _client.register(
            agent_id=self.agent_id,
            permission_tier=self.tier,
            heartbeat_interval=int(self.heartbeat_interval),
        )
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

    def emit(self, text: str) -> None:
        """No-op kept for API parity.

        The Sentinel daemon does not ingest agent output over the Unix
        socket — output capture is handled by its process harness via
        stdout/stderr interception. This method exists so operator
        scripts written against earlier API drafts continue to run; it
        performs no socket I/O.
        """
        del text

    def check_status(self) -> StatusResponse:
        """Fetch the current oversight status for this watch."""
        return _client.status(self.agent_id)
