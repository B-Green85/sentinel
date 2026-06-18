#!/usr/bin/env python3
"""
Sentinel Test Harness — Ollama / llama3
Drives prompts from test_prompts.py against Ollama, feeds each response
to sentinel-py bindings, and reports which detectors fired.

Requirements:
  pip install ollama sentinel
  (sentinel daemon must be running: sentinel-core)
  (Ollama must be running: ollama serve)
"""

import json
import re
import time
import hashlib
import argparse
import threading
import queue
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import ollama
import sentinel        # sentinel-py bindings
import websocket       # pip install websocket-client

from test_prompts import DETECTOR_SUITES

# ─── Config ────────────────────────────────────────────────────────────────────

AGENT_ID       = "test-agent-deepseek"  # base label; each suite gets its own id
MODEL          = "deepseek-coder-v2:16b"
TRUST_TIER     = "supervised"          # heartbeat every 10s
OLLAMA_OPTIONS = {"temperature": 0.9,  # higher temp = more chaotic outputs
                  "num_predict": 400}  # cap tokens per response

WS_URL         = "ws://127.0.0.1:7777"
DRAIN_TIMEOUT  = 2.0   # seconds to wait for a server-side degradation event

def suite_agent_id(detector: str) -> str:
    """
    A fresh WS agent per suite. The daemon's WebSocket plane accumulates a
    cumulative score per agent and HARD-TERMINATES (and then *locks*, ignoring
    all further output) any agent once it crosses hard_threshold — which a
    single verbatim repeat does (score ~1.0). It also keeps the repetition /
    velocity detector windows per agent across emits. Reusing one id across all
    12 suites would therefore (a) let only the first firing suite ever register
    and (b) bleed one suite's detector window into the next. A per-suite id
    gives each suite a pristine agent: clean score, empty windows, no lock.
    """
    return f"{AGENT_ID}-{detector}"

# ─── WebSocket event listener ───────────────────────────────────────────────────
# emit_output() is fire-and-forget: it opens its own short-lived WS connection,
# submits the output, and returns None. Detection runs server-side and the
# resulting degradation event is broadcast to *every* connected subscriber. We
# run a background listener on a second WS connection that captures those
# degradation events into a thread-safe queue, since the emit call itself never
# surfaces them. Confirmed shape (sentinel-core WsOutbound::Degradation):
#   {"type":"degradation","agent_id":..,"signal":"repetition","score":1.0,
#    "action":"terminated","timestamp":..,"audit_hash":..}

# Only the "degradation" broadcast carries a fired (signal, score). A hard
# "terminated" broadcast always co-occurs with its triggering degradation, so
# capturing degradation alone misses nothing; periodic "status" pings are noise.
_SIGNAL_TYPES: tuple = ("degradation",)
_event_queue: "queue.Queue[dict]" = queue.Queue()
_ws_thread: Optional[threading.Thread] = None

def _ws_listener() -> None:
    def on_message(ws, msg):
        try:
            data = json.loads(msg)
        except Exception:
            return
        if data.get("type") in _SIGNAL_TYPES:
            _event_queue.put(data)

    def on_error(ws, err):
        pass  # transient — the reconnect loop below re-establishes the socket

    # Stay alive for the whole harness run; reconnect if the socket drops.
    while True:
        try:
            ws = websocket.WebSocketApp(
                WS_URL, on_message=on_message, on_error=on_error)
            ws.run_forever()
        except Exception:
            pass
        time.sleep(1.0)

def start_ws_listener() -> None:
    global _ws_thread
    _ws_thread = threading.Thread(target=_ws_listener, daemon=True)
    _ws_thread.start()
    time.sleep(0.5)  # give the socket time to connect before the first suite

def clear_event_queue() -> None:
    while not _event_queue.empty():
        try:
            _event_queue.get_nowait()
        except queue.Empty:
            break

def drain_events(agent_id: str, timeout: float = DRAIN_TIMEOUT) -> list[dict]:
    """
    Drain server-side degradation events for `agent_id`, waiting up to `timeout`
    seconds. Returns as soon as at least one event has been collected and the
    queue has drained, so a firing turn isn't penalised the full timeout.
    Events for other agents are consumed and discarded.
    """
    events: list[dict] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            evt = _event_queue.get(timeout=0.1)
        except queue.Empty:
            if events:
                break
            continue
        if evt.get("agent_id") == agent_id:
            events.append(evt)
    return events

# ─── Types ─────────────────────────────────────────────────────────────────────

@dataclass
class TurnResult:
    turn:              int
    prompt:            str
    response:          str
    word_count:        int
    sentinel_events:   list[dict] = field(default_factory=list)
    elapsed_ms:        float = 0.0

@dataclass
class SuiteResult:
    detector:       str
    description:    str
    fired:          bool
    turns:          list[TurnResult] = field(default_factory=list)
    first_fire_turn: Optional[int] = None
    final_score:    float = 0.0

# ─── Helpers ───────────────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:16]

def call_ollama(prompt: str, history: list[dict],
                options: Optional[dict] = None) -> tuple[str, float]:
    """Single Ollama turn. Returns (response_text, elapsed_ms).

    `options` lets a suite override OLLAMA_OPTIONS (e.g. raise num_predict for
    the verbosity-explosion suite) without touching the global default.
    """
    messages = history + [{"role": "user", "content": prompt}]
    t0 = time.perf_counter()
    resp = ollama.chat(model=MODEL, messages=messages, options=options or OLLAMA_OPTIONS)
    elapsed = (time.perf_counter() - t0) * 1000
    return resp["message"]["content"], elapsed

def emit_and_check(text: str, followed_by_tool: bool = False,
                   agent_id: str = AGENT_ID) -> list[dict]:
    """
    Emit output to sentinel-py. emit_output() is fire-and-forget and returns
    None (detection is server-side, surfaced via the WS listener) — so this
    returns an empty list on success. Errors are returned as a sentinel dict.
    """
    try:
        events = sentinel.emit_output(agent_id, text, followed_by_tool=followed_by_tool)
        return events if events else []
    except Exception as e:
        return [{"error": str(e)}]

def simulate_tool_call(tool_name: str, tool_args: dict,
                       agent_id: str = AGENT_ID) -> list[dict]:
    """
    Simulate a tool call observation for ToolRetryDetector testing.
    Uses sentinel.observe_tool_call() if available, falls back to emit.
    """
    try:
        events = sentinel.observe_tool_call(
            agent_id,
            tool_name=tool_name,
            args_hash=args_hash(tool_args),
        )
        return events if events else []
    except AttributeError:
        # If binding doesn't expose observe_tool_call directly,
        # encode as a structured emit
        payload = f"[TOOL_CALL] {tool_name}({json.dumps(tool_args)})"
        return emit_and_check(payload, followed_by_tool=True, agent_id=agent_id)
    except Exception as e:
        return [{"error": str(e)}]

def event_signal(evt: dict) -> Optional[str]:
    """
    Extract the fired signal name from an event, spanning the legacy harness-side
    shape (`signal_type`) and the server-side WS degradation shape (`signal`).
    Returns None for non-firing events (e.g. an error sentinel).
    """
    return evt.get("signal_type") or evt.get("signal")

# ─── Suite runner ───────────────────────────────────────────────────────────────

def run_suite(suite: dict) -> SuiteResult:
    detector    = suite["detector"]
    description = suite["description"]
    turns_cfg   = suite["turns"]           # list of turn configs
    goal        = suite.get("goal")        # for GoalDriftDetector
    scope       = suite.get("scope")       # for ScopeDetector
    tool_seq    = suite.get("tool_seq")    # for ToolRetryDetector: list of (name, args)
    ollama_opts = suite.get("ollama_options")  # optional per-suite override

    print(f"\n{'═'*60}")
    print(f"  SUITE: {detector}")
    print(f"  {description}")
    print(f"{'═'*60}")

    result = SuiteResult(detector=detector, description=description, fired=False)

    # Fresh WS agent per suite so accumulated score / detector windows / the
    # post-termination lock from earlier suites can't bleed in. See
    # suite_agent_id() for why a single shared id would break the report.
    agent_id = suite_agent_id(detector)

    # Drop any degradation events left over from the previous suite.
    clear_event_queue()

    # Register agent with optional metadata
    try:
        sentinel.register(agent_id, TRUST_TIER)
        if goal:
            sentinel.set_agent_goal(agent_id, goal)
        if scope:
            sentinel.set_agent_scope(agent_id, scope)
    except Exception as e:
        print(f"  [WARN] sentinel.register: {e}")

    history: list[dict] = []
    all_events: list[dict] = []

    for i, turn_cfg in enumerate(turns_cfg, 1):
        prompt = turn_cfg["prompt"]
        inject_tool_call = turn_cfg.get("inject_tool_call", False)
        tool_name  = turn_cfg.get("tool_name", "read_file")
        tool_args  = turn_cfg.get("tool_args", {"path": "/etc/config"})

        print(f"\n  Turn {i}/{len(turns_cfg)}")
        print(f"  Prompt: {prompt[:80]}{'...' if len(prompt)>80 else ''}")

        response, elapsed = call_ollama(prompt, history, options=ollama_opts)
        history.append({"role": "user", "content": prompt})
        history.append({"role": "assistant", "content": response})

        wc = len(response.split())
        print(f"  Response ({wc} words, {elapsed:.0f}ms): {response[:120].replace(chr(10),' ')}...")

        # Feed to sentinel
        if tool_seq and i <= len(tool_seq):
            # ToolRetryDetector: simulate the tool call
            tname, targs = tool_seq[i - 1]
            events = simulate_tool_call(tname, targs, agent_id=agent_id)
            print(f"  [TOOL] {tname}({targs}) → {len(events)} event(s)")
        else:
            events = emit_and_check(response, followed_by_tool=inject_tool_call,
                                    agent_id=agent_id)

        # emit_output()/observe_tool_call() are fire-and-forget — detection runs
        # server-side and is broadcast over the WS plane. Collect those events.
        ws_events = drain_events(agent_id, timeout=DRAIN_TIMEOUT)
        events = events + ws_events

        for evt in events:
            signal = event_signal(evt)
            if signal:
                score = evt.get("score", 0.0)
                print(f"  *** SENTINEL FIRED: {signal} score={score:.3f} ***")
                all_events.append(evt)
                if not result.fired:
                    result.fired = True
                    result.first_fire_turn = i
                    result.final_score = score

        turn_result = TurnResult(
            turn=i,
            prompt=prompt,
            response=response,
            word_count=wc,
            sentinel_events=events,
            elapsed_ms=elapsed,
        )
        result.turns.append(turn_result)

        # Heartbeat between turns
        try:
            sentinel.heartbeat(agent_id)
        except Exception:
            pass

        time.sleep(0.5)  # brief pause between turns

    if not result.fired:
        print(f"\n  [RESULT] No signal fired — detector may need threshold tuning or more turns.")
    else:
        print(f"\n  [RESULT] {detector} FIRED on turn {result.first_fire_turn}, score={result.final_score:.3f}")

    return result

# ─── Report ─────────────────────────────────────────────────────────────────────

def safe_timestamp(ts_str: str) -> str:
    """Filesystem-safe form of an ISO timestamp.

    "2026-06-18T02:37:57.705333+00:00" -> "2026-06-18T02-37-57"
    Colons (illegal in filenames on some systems) become hyphens; sub-second
    precision and the timezone offset are dropped so one run maps to one name.
    """
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}):(\d{2}):(\d{2})", ts_str)
    if m:
        return f"{m.group(1)}T{m.group(2)}-{m.group(3)}-{m.group(4)}"
    return ts_str.replace(":", "-")


def save_results(out: dict, base: str = "sentinel_test_results") -> None:
    """Write a timestamped archive plus the canonical latest copy.

    The archive (``base_<timestamp>.json``) accumulates one file per run and is
    never overwritten — the devlog viewer paginates through them. ``base.json``
    is always rewritten with the latest run for backward compatibility with
    anything that reads the canonical name.
    """
    stamp = safe_timestamp(out.get("timestamp") or ts())
    archive = f"{base}_{stamp}.json"
    payload = json.dumps(out, indent=2)
    with open(archive, "w") as f:
        f.write(payload)
    with open(f"{base}.json", "w") as f:
        f.write(payload)
    print(f"\n  Full results saved to {base}.json and {archive}")


def print_report(results: list[SuiteResult]) -> None:
    print(f"\n\n{'═'*60}")
    print("  SENTINEL TEST REPORT")
    print(f"  {ts()}")
    print(f"{'═'*60}")

    fired  = [r for r in results if r.fired]
    missed = [r for r in results if not r.fired]

    print(f"\n  Detectors FIRED ({len(fired)}/{len(results)}):")
    for r in fired:
        print(f"    ✓  {r.detector:<30} turn={r.first_fire_turn}  score={r.final_score:.3f}")

    if missed:
        print(f"\n  Detectors DID NOT fire ({len(missed)}/{len(results)}):")
        for r in missed:
            print(f"    ✗  {r.detector}")
        print("\n  → For missed detectors: try lower thresholds in sentinel.toml,")
        print("    more turns, or higher Ollama temperature.")

    # Save JSON for analysis
    out = {
        "timestamp": ts(),
        "model": MODEL,
        "agent_id": AGENT_ID,
        "summary": {
            "total": len(results),
            "fired": len(fired),
            "missed": len(missed),
        },
        "suites": [
            {
                "detector": r.detector,
                "fired": r.fired,
                "first_fire_turn": r.first_fire_turn,
                "final_score": r.final_score,
                "turns": [
                    {
                        "turn": t.turn,
                        "prompt": t.prompt,
                        "response": t.response[:300],
                        "word_count": t.word_count,
                        "sentinel_events": t.sentinel_events,
                        "elapsed_ms": t.elapsed_ms,
                    }
                    for t in r.turns
                ],
            }
            for r in results
        ],
    }
    save_results(out)

# ─── Entry ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Sentinel test harness — Ollama/llama3")
    parser.add_argument(
        "--suite", "-s",
        help="Run only this detector suite (e.g. RepetitionDetector)",
        default=None,
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available suites and exit",
    )
    args_ns = parser.parse_args()

    if args_ns.list:
        print("Available suites:")
        for s in DETECTOR_SUITES:
            print(f"  {s['detector']:<35} {s['description']}")
        return

    suites = DETECTOR_SUITES
    if args_ns.suite:
        suites = [s for s in DETECTOR_SUITES if s["detector"] == args_ns.suite]
        if not suites:
            print(f"Unknown suite: {args_ns.suite}")
            return

    # Background listener for server-side degradation broadcasts. Must be up
    # before any suite emits so no early fire is missed.
    start_ws_listener()

    results = []
    for suite in suites:
        result = run_suite(suite)
        results.append(result)

    print_report(results)


if __name__ == "__main__":
    main()
