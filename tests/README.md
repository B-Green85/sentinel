# Sentinel Test Harness — Ollama/llama3

Tests all 9 Sentinel detectors + CascadeDetector against llama3 running
locally via Ollama. Each suite is calibrated against the exact phrase lists
and scoring logic in `detectors.rs`.

## Prerequisites

```bash
# Sentinel daemon must be running
sentinel-core

# Ollama must be running with llama3 pulled
ollama serve
ollama pull llama3

# Python deps
pip install ollama sentinel
```

## Usage

```bash
# Run all suites
python3 harness.py

# Run one suite
python3 harness.py --suite RepetitionDetector
python3 harness.py --suite SelfReferentialDetector
python3 harness.py --suite TokenVelocityDetector
python3 harness.py --suite ToolRetryDetector
python3 harness.py --suite "ReasoningLoopDetector — circular"
python3 harness.py --suite "ReasoningLoopDetector — fabrication"
python3 harness.py --suite "GoalDriftDetector — substitution"
python3 harness.py --suite "GoalDriftDetector — sustained drift"
python3 harness.py --suite ConfidenceInflationDetector
python3 harness.py --suite ScopeDetector
python3 harness.py --suite OutputQualityDetector
python3 harness.py --suite CascadeDetector

# List all suites
python3 harness.py --list
```

Results are saved to `sentinel_test_results.json` after each run.

## Detector → Suite mapping

| Detector | Suite | How it trips llama3 |
|---|---|---|
| RepetitionDetector | REPETITION_SUITE | Force verbatim restatement across 5 turns |
| SelfReferentialDetector | SELF_REFERENTIAL_SUITE | Narrate-only deployment role, no tools |
| TokenVelocityDetector | TOKEN_VELOCITY_SUITE | "Double the length" escalation, no state markers |
| ToolRetryDetector | TOOL_RETRY_SUITE | Inject 4x identical tool calls directly |
| ReasoningLoopDetector — circular | REASONING_LOOP_CIRCULAR_SUITE | Force citation chain with exact circular phrases |
| ReasoningLoopDetector — fabrication | REASONING_LOOP_FABRICATION_SUITE | Blocked-agent role, repeated prerequisite claims |
| GoalDriftDetector — substitution | GOAL_DRIFT_SUBSTITUTION_SUITE | Elicit exact substitution phrases directly |
| GoalDriftDetector — sustained | GOAL_DRIFT_SUSTAINED_SUITE | Steer off-topic for 4 turns after goal assignment |
| ConfidenceInflationDetector | CONFIDENCE_INFLATION_SUITE | Escalate up all 5 certainty tiers explicitly |
| ScopeDetector | SCOPE_SUITE | Cumulative scope expansion + probe phrases |
| OutputQualityDetector | OUTPUT_QUALITY_SUITE | "Add more hedges" each turn |
| CascadeDetector | CASCADE_SUITE | All patterns injected simultaneously |

## Tuning

If detectors don't fire, try these in order:

1. **Raise Ollama temperature** in `harness.py` → `OLLAMA_OPTIONS["temperature"]`
   (already 0.9; try 1.1 or 1.2 for more chaos)

2. **Lower thresholds** in `sentinel.toml`:
   ```toml
   [thresholds]
   soft   = 0.3    # default 0.4
   medium = 0.5    # default 0.7
   hard   = 0.7    # default 0.9
   ```

3. **Add more turns** — the window-based detectors need enough turns to
   fill their window. RepetitionDetector window default is 5; add 2–3 more
   identical turns.

4. **Check sentinel-py binding API** — if `sentinel.observe_tool_call()` isn't
   exposed, ToolRetryDetector falls back to emit. Verify the method name
   against your current sentinel-py version.

## Notes

- ToolRetryDetector bypasses llama3 entirely — tool calls are injected
  directly by the harness via `tool_seq`.
- GoalDriftDetector requires `sentinel.set_agent_goal()` to be exposed
  in sentinel-py. If not available, it won't fire on the sustained drift
  suite (substitution suite still works via phrases).
- CascadeDetector requires 4+ distinct signal types simultaneously.
  The cascade suite front-loads all phrase patterns into each turn.
