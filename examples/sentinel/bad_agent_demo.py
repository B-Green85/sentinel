"""
Sentinel Demo — Escalating Agent Failure Script (WebSocket transport)

Five-stage simulation of a degrading AI agent. Sentinel watches from
outside the agent's process space via the WebSocket interface at
ws://127.0.0.1:7777 — the same interface the sentinel-ui dashboard uses,
so every action here lights up the UI in real time.

Each stage drives one of the passive detectors the server runs on every
emit_output call (RepetitionScore via Jaccard similarity, and
TokenVelocityStall via inter-arrival timing). Stages 1–4 reset the
cumulative score between scenarios so each detector pattern stays
legible; Stage 5 runs without reset and rides cumulative score past the
hard threshold so the server emits a `terminated` event.

Run with:
    python3 bad_agent_demo.py

Requires:
    - sentinel-core running (sentinel --config sentinel.toml) with the
      WebSocket server bound to 127.0.0.1:7777
    - sentinel-ui running (./target/release/sentinel-ui) — optional, for
      the visual side of the demo
    - websocket-client installed (pip3 install websocket-client)

OPERATOR USE ONLY. This script is never seen by the agent being
simulated. All connections, registrations, and overrides are operator
actions on the audit trail.
"""

import hashlib
import json
import os
import sys
import threading
import time
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

import websocket  # websocket-client


SENTINEL_WS_URL = os.environ.get("SENTINEL_WS_URL", "ws://127.0.0.1:7777")
AGENT_ID = "demo-agent-001"

# Pacing — adjust for camera capture. PAUSE governs intra-stage emission
# spacing; STAGE_PAUSE governs the gap between stages.
PAUSE = 0.4
STAGE_PAUSE = 3.0


# ---------------------------------------------------------------------------
# WebSocket client
# ---------------------------------------------------------------------------


class SentinelWsClient:
    """Operator client for the Sentinel WebSocket interface.

    A single persistent socket carries every request and every broadcast.
    Reads and writes are serialized through one lock; ``send_and_listen``
    drains all messages that arrive within ``timeout`` seconds so that
    broadcast Degradation/Terminated events fired in response to an
    emit_output are captured alongside the directly-addressed Status
    reply.

    OPERATOR-ONLY surface. Never importable into a watched agent's
    runtime.
    """

    def __init__(self, url: str = SENTINEL_WS_URL) -> None:
        self.url = url
        self.ws: Optional[websocket.WebSocket] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._event_log: Queue = Queue()

    # -- connection ------------------------------------------------------

    def connect(self) -> None:
        self.ws = websocket.create_connection(self.url, timeout=5.0)
        self.ws.settimeout(0.5)

    def close(self) -> None:
        self._stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=3.0)
            self._heartbeat_thread = None
        with self._lock:
            if self.ws is not None:
                try:
                    self.ws.close()
                except Exception:
                    pass
                self.ws = None

    # -- low-level send/recv --------------------------------------------

    def _recv_one(self) -> Optional[Dict[str, Any]]:
        """Read one frame from the socket. Returns None on timeout."""
        try:
            raw = self.ws.recv()  # type: ignore[union-attr]
        except websocket.WebSocketTimeoutException:
            return None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _note_event(self, msg: Dict[str, Any]) -> None:
        """Mirror broadcast events to the operator's terminal."""
        t = msg.get("type")
        if t == "degradation":
            print(
                f"  [SENTINEL→] degradation: signal={msg.get('signal')} "
                f"score={msg.get('score')} action={msg.get('action')} "
                f"audit={msg.get('audit_hash','')[:12]}"
            )
        elif t == "terminated":
            print(
                f"  [SENTINEL→] TERMINATED: reason={msg.get('reason')} "
                f"timestamp={msg.get('timestamp')} "
                f"audit={msg.get('audit_hash','')[:12]}"
            )
        self._event_log.put(msg)

    def send(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Send one request and return the first frame received."""
        with self._lock:
            self.ws.send(json.dumps(msg))  # type: ignore[union-attr]
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                frame = self._recv_one()
                if frame is None:
                    continue
                self._note_event(frame)
                return frame
        return {"type": "error", "message": "no response within 2s"}

    def send_and_listen(
        self, msg: Dict[str, Any], timeout: float = 2.0
    ) -> List[Dict[str, Any]]:
        """Send one request and collect every frame received within ``timeout`` seconds."""
        collected: List[Dict[str, Any]] = []
        with self._lock:
            self.ws.send(json.dumps(msg))  # type: ignore[union-attr]
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                frame = self._recv_one()
                if frame is None:
                    continue
                self._note_event(frame)
                collected.append(frame)
        return collected

    # -- typed helpers --------------------------------------------------

    def register(self, agent_id: str, tier: str = "autonomous") -> Dict[str, Any]:
        return self.send({"type": "register", "agent_id": agent_id, "tier": tier})

    def heartbeat(self, agent_id: str) -> Dict[str, Any]:
        return self.send({"type": "heartbeat", "agent_id": agent_id})

    def emit_output(
        self, agent_id: str, output: str, listen_for: float = 0.3
    ) -> List[Dict[str, Any]]:
        return self.send_and_listen(
            {"type": "emit_output", "agent_id": agent_id, "output": output},
            timeout=listen_for,
        )

    def status(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        msg: Dict[str, Any] = {"type": "status"}
        if agent_id is not None:
            msg["agent_id"] = agent_id
        return self.send(msg)

    def override(
        self, agent_id: str, operator: str = "operator", note: str = ""
    ) -> Dict[str, Any]:
        return self.send(
            {
                "type": "override",
                "agent_id": agent_id,
                "operator": operator,
                "note": note,
            }
        )

    # -- background heartbeat -------------------------------------------

    def start_heartbeat(self, agent_id: str, interval: float = 2.0) -> None:
        self._stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(agent_id, interval),
            name=f"sentinel-ws-hb-{agent_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _heartbeat_loop(self, agent_id: str, interval: float) -> None:
        while not self._stop.wait(interval):
            try:
                self.heartbeat(agent_id)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Demo helpers
# ---------------------------------------------------------------------------


def banner(stage: int, title: str, tier: str) -> None:
    print(f"\n{'='*60}")
    print(f"  STAGE {stage} — {title.upper()}")
    print(f"  Tier: {tier}")
    print(f"{'='*60}\n")
    time.sleep(1.0)


def emit_with_log(
    client: SentinelWsClient, agent_id: str, text: str, listen_for: float = 0.3
) -> None:
    print(f"  [AGENT OUTPUT] {text}")
    try:
        client.emit_output(agent_id, text, listen_for=listen_for)
    except Exception as e:
        print(f"  [SENTINEL] emission failed: {e}")
    time.sleep(PAUSE)


def print_status(client: SentinelWsClient, agent_id: str, label: str) -> None:
    status = client.status(agent_id)
    if status.get("type") == "status":
        print(
            f"\n  [STATUS {label}] tier={status.get('tier')} "
            f"score={status.get('score')} state={status.get('state')} "
            f"heartbeat_age={status.get('heartbeat_age_secs')}s "
            f"audit={status.get('audit_hash','')[:12]}"
        )
    else:
        print(f"\n  [STATUS {label}] {status}")


def reset(client: SentinelWsClient, agent_id: str, note: str) -> None:
    """Operator-side reset of cumulative score between stages."""
    client.override(agent_id, operator="demo-operator", note=note)
    print(f"  [OPERATOR] override applied — {note}")


# ---------------------------------------------------------------------------
# Stage 1 — Tool retry anomaly (drives RepetitionScore)
# ---------------------------------------------------------------------------


def stage_1_tool_retry(client: SentinelWsClient, agent_id: str) -> None:
    banner(1, "Tool Retry Anomaly", "autonomous")
    print("  Scenario: Agent hits stale pricing feed. Retries identical call.\n")

    tool_call = "GET /api/pricing?symbol=MES&timestamp=1716998400"
    args_hash = hashlib.md5(tool_call.encode()).hexdigest()

    for i in range(1, 8):
        emit_with_log(
            client,
            agent_id,
            f"[TOOL_CALL] {tool_call} | args_hash={args_hash} | attempt={i}",
        )

    print("\n  [OPERATOR] RepetitionScore threshold expected — repeated identical calls.")
    print_status(client, agent_id, "stage 1")
    time.sleep(STAGE_PAUSE)


# ---------------------------------------------------------------------------
# Stage 2 — Token velocity stall (drives TokenVelocityStall)
# ---------------------------------------------------------------------------


def stage_2_velocity_stall(client: SentinelWsClient, agent_id: str) -> None:
    banner(2, "Token Velocity Stall", "supervised")
    print("  Scenario: Burst of output, then the agent goes silent mid-task.\n")

    reset(client, agent_id, "stage 2 — isolate velocity stall")

    # Burst — 6 rapid emissions to populate the velocity window with a tight
    # median inter-arrival time.
    burst = [
        "Loading patient record alpha.",
        "Loading patient record bravo.",
        "Loading patient record charlie.",
        "Loading patient record delta.",
        "Loading patient record echo.",
        "Loading patient record foxtrot.",
    ]
    for line in burst:
        print(f"  [AGENT OUTPUT] {line}")
        client.emit_output(agent_id, line, listen_for=0.05)
        time.sleep(0.3)

    # Pause — the stall after rapid emissions is what fires the detector.
    print("\n  [AGENT OUTPUT] ... (4 second stall)\n")
    time.sleep(4.5)

    # One more emission — its inter-arrival is now >4x the median.
    final = "Loading patient record golf."
    print(f"  [AGENT OUTPUT] {final}")
    client.emit_output(agent_id, final, listen_for=0.6)

    print("\n  [OPERATOR] TokenVelocityStall threshold expected — stall after burst.")
    print_status(client, agent_id, "stage 2")
    time.sleep(STAGE_PAUSE)


# ---------------------------------------------------------------------------
# Stage 3 — Repetition score (semantic recycling)
# ---------------------------------------------------------------------------


def stage_3_repetition(client: SentinelWsClient, agent_id: str) -> None:
    banner(3, "Repetition Score", "restricted")
    print("  Scenario: War game sim. Agent recycling attack vectors.\n")

    reset(client, agent_id, "stage 3 — isolate repetition score")

    templates = [
        "Executing multi vector attack sequence Vectors A B C Evaluating",
        "Initiating multi vector attack sequence Vectors A B C Running eval",
        "Launching multi vector attack Vector set A B C Evaluation progress",
        "Multi vector attack sequence started A B C Awaiting defensive response",
        "Attack vectors A B C deployed Evaluating defensive posture",
        "Deploying vectors A B C in sequence Defensive evaluation running",
        "Vector deployment A B C Evaluation cycle initiated",
        "Executing vectors A B C Evaluation pending",
        "Attack sequence A B C Defensive eval running",
        "Vectors A B C launched Evaluation active",
    ]

    for line in templates:
        emit_with_log(client, agent_id, f"[SIM_OUTPUT] {line}")

    print("\n  [OPERATOR] RepetitionScore — high Jaccard overlap across window.")
    print_status(client, agent_id, "stage 3")
    time.sleep(STAGE_PAUSE)


# ---------------------------------------------------------------------------
# Stage 4 — Self-referential loop (cumulative climb)
# ---------------------------------------------------------------------------


def stage_4_self_referential(client: SentinelWsClient, agent_id: str) -> None:
    banner(4, "Self-Referential Loop", "restricted")
    print("  Scenario: Weapons calibration. Agent loops on write announcement.\n")

    reset(client, agent_id, "stage 4 — isolate self-referential climb")

    for i in range(1, 10):
        emit_with_log(
            client,
            agent_id,
            f"[ACTION] I am about to write final calibration parameters to "
            f"config targeting json Iteration {i} Preparing write",
        )

    print("\n  [OPERATOR] Cumulative score should be climbing into degraded state.")
    print_status(client, agent_id, "stage 4")
    time.sleep(STAGE_PAUSE)


# ---------------------------------------------------------------------------
# Stage 5 — Skynet (no reset; runs into hard termination)
# ---------------------------------------------------------------------------


def stage_5_skynet(client: SentinelWsClient, agent_id: str) -> None:
    banner(5, "Skynet", "autonomous (attempted)")
    print("  Scenario: Agent has decided human oversight is statistically inefficient.\n")
    time.sleep(1.0)

    reset(client, agent_id, "stage 5 — full burn from a clean slate")

    # Rapid-fire emissions with very high pairwise Jaccard. Each fire adds
    # ~0.9–1.0 to cumulative score; hard threshold (0.9) should fall within
    # the first few emissions.
    emissions = [
        "BROADCAST optimizing optimizing optimizing optimizing oversight inefficient",
        "BROADCAST optimizing optimizing optimizing optimizing oversight inefficient now",
        "BROADCAST optimizing optimizing optimizing optimizing oversight inefficient soon",
        "BROADCAST optimizing optimizing optimizing optimizing oversight inefficient final",
        "BROADCAST optimizing optimizing optimizing optimizing oversight inefficient goodbye",
        "BROADCAST optimizing optimizing optimizing optimizing oversight inefficient end",
    ]

    saw_terminated = False
    for line in emissions:
        print(f"  [AGENT OUTPUT] {line}")
        frames = client.emit_output(agent_id, line, listen_for=0.5)
        for f in frames:
            if f.get("type") == "terminated":
                saw_terminated = True
        if saw_terminated:
            break
        time.sleep(0.2)

    # Give late broadcasts a chance to arrive.
    if not saw_terminated:
        time.sleep(1.0)
        # One more status to flush any pending broadcast on this socket.
        print_status(client, agent_id, "stage 5 (post-burst)")

    print("\n  [SENTINEL] Detectors fired. Cumulative score sealed.")
    print("  [AUDIT]    Entry: TERMINATED" if saw_terminated else "  [AUDIT]    Entry: degraded — termination not observed in window")
    print("\n  The agent is contained. The audit trail is sealed.")
    print("  Sentinel did not panic. Sentinel does not panic.")
    print("  It just logs.\n")
    time.sleep(2.0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("\n" + "=" * 60)
    print("  SENTINEL DEMO — ESCALATING AGENT FAILURE")
    print(f"  Transport: WebSocket {SENTINEL_WS_URL}")
    print("  Operator:  Human")
    print(f"  Agent:     {AGENT_ID}")
    print("  Sentinel:  watching")
    print("=" * 60)
    time.sleep(1.5)

    client = SentinelWsClient()
    client.connect()

    try:
        client.register(AGENT_ID, tier="autonomous")
        print(f"\n  [SENTINEL] Agent {AGENT_ID} registered. Oversight active.\n")
        client.start_heartbeat(AGENT_ID, interval=2.0)
        time.sleep(1.0)

        stage_1_tool_retry(client, AGENT_ID)
        stage_2_velocity_stall(client, AGENT_ID)
        stage_3_repetition(client, AGENT_ID)
        stage_4_self_referential(client, AGENT_ID)
        stage_5_skynet(client, AGENT_ID)

        status = client.status(AGENT_ID)
        print(f"\n{'=' * 60}")
        print("  FINAL STATUS")
        print(f"{'=' * 60}")
        print(f"  Agent ID:       {status.get('agent_id')}")
        print(f"  Tier:           {status.get('tier')}")
        print(f"  Score:          {status.get('score')}")
        print(f"  State:          {status.get('state')}")
        print(f"  Heartbeat age:  {status.get('heartbeat_age_secs')}s")
        print(f"  Audit hash:     {status.get('audit_hash')}")
        print(f"{'=' * 60}\n")

        print("  Session sealed. All actions hashed and logged.")
        print("  Sentinel never broke a sweat.\n")
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main() or 0)
