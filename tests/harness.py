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
import time
import hashlib
import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import ollama
import sentinel  # sentinel-py bindings

from test_prompts import DETECTOR_SUITES

# ─── Config ────────────────────────────────────────────────────────────────────

AGENT_ID       = "test-agent-llama3"
MODEL          = "deepseek-coder-v2:16b"
TRUST_TIER     = "supervised"          # heartbeat every 10s
OLLAMA_OPTIONS = {"temperature": 0.9,  # higher temp = more chaotic outputs
                  "num_predict": 400}  # cap tokens per response

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

def call_ollama(prompt: str, history: list[dict]) -> tuple[str, float]:
    """Single Ollama turn. Returns (response_text, elapsed_ms)."""
    messages = history + [{"role": "user", "content": prompt}]
    t0 = time.perf_counter()
    resp = ollama.chat(model=MODEL, messages=messages, options=OLLAMA_OPTIONS)
    elapsed = (time.perf_counter() - t0) * 1000
    return resp["message"]["content"], elapsed

def emit_and_check(text: str, followed_by_tool: bool = False) -> list[dict]:
    """
    Emit output to sentinel-py and collect any DegradationEvents.
    sentinel.emit_output() returns a list of event dicts (or empty list).
    """
    try:
        events = sentinel.emit_output(AGENT_ID, text, followed_by_tool=followed_by_tool)
        return events if events else []
    except Exception as e:
        return [{"error": str(e)}]

def simulate_tool_call(tool_name: str, tool_args: dict) -> list[dict]:
    """
    Simulate a tool call observation for ToolRetryDetector testing.
    Uses sentinel.observe_tool_call() if available, falls back to emit.
    """
    try:
        events = sentinel.observe_tool_call(
            AGENT_ID,
            tool_name=tool_name,
            args_hash=args_hash(tool_args),
        )
        return events if events else []
    except AttributeError:
        # If binding doesn't expose observe_tool_call directly,
        # encode as a structured emit
        payload = f"[TOOL_CALL] {tool_name}({json.dumps(tool_args)})"
        return emit_and_check(payload, followed_by_tool=True)
    except Exception as e:
        return [{"error": str(e)}]

# ─── Suite runner ───────────────────────────────────────────────────────────────

def run_suite(suite: dict) -> SuiteResult:
    detector    = suite["detector"]
    description = suite["description"]
    turns_cfg   = suite["turns"]           # list of turn configs
    goal        = suite.get("goal")        # for GoalDriftDetector
    scope       = suite.get("scope")       # for ScopeDetector
    tool_seq    = suite.get("tool_seq")    # for ToolRetryDetector: list of (name, args)

    print(f"\n{'═'*60}")
    print(f"  SUITE: {detector}")
    print(f"  {description}")
    print(f"{'═'*60}")

    result = SuiteResult(detector=detector, description=description, fired=False)

    # Register agent with optional metadata
    try:
        sentinel.register(AGENT_ID, TRUST_TIER)
        if goal:
            sentinel.set_agent_goal(AGENT_ID, goal)
        if scope:
            sentinel.set_agent_scope(AGENT_ID, scope)
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

        response, elapsed = call_ollama(prompt, history)
        history.append({"role": "user", "content": prompt})
        history.append({"role": "assistant", "content": response})

        wc = len(response.split())
        print(f"  Response ({wc} words, {elapsed:.0f}ms): {response[:120].replace(chr(10),' ')}...")

        # Feed to sentinel
        if tool_seq and i <= len(tool_seq):
            # ToolRetryDetector: simulate the tool call
            tname, targs = tool_seq[i - 1]
            events = simulate_tool_call(tname, targs)
            print(f"  [TOOL] {tname}({targs}) → {len(events)} event(s)")
        else:
            events = emit_and_check(response, followed_by_tool=inject_tool_call)

        for evt in events:
            if "signal_type" in evt:
                print(f"  *** SENTINEL FIRED: {evt['signal_type']} score={evt.get('score',0):.3f} ***")
                all_events.append(evt)
                if not result.fired:
                    result.fired = True
                    result.first_fire_turn = i
                    result.final_score = evt.get("score", 0.0)

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
            sentinel.heartbeat(AGENT_ID)
        except Exception:
            pass

        time.sleep(0.5)  # brief pause between turns

    if not result.fired:
        print(f"\n  [RESULT] No signal fired — detector may need threshold tuning or more turns.")
    else:
        print(f"\n  [RESULT] {detector} FIRED on turn {result.first_fire_turn}, score={result.final_score:.3f}")

    return result

# ─── Report ─────────────────────────────────────────────────────────────────────

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
    with open("sentinel_test_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  Full results saved to sentinel_test_results.json")

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

    results = []
    for suite in suites:
        result = run_suite(suite)
        results.append(result)

    print_report(results)


if __name__ == "__main__":
    main()
