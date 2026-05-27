# Sentinel — CLI UI + WebSocket Extension Spec
### Filed: 2026-05-16 | Status: Planned | Author: Brandon Green

---

## What This Adds

Two extensions to the existing Sentinel architecture:

1. **WebSocket server** — agnostic LLM API wiring. Any agent, any model, any language connects via WS. No custom integration per model. No sentinel-py required.
2. **CLI UI** — real-time terminal dashboard. Ratatui-based. Agent status, degradation scores, audit trail, tier actions — all visible live.

Rust throughout. No language switch. Both additions fit naturally into the existing workspace.

---

## Why

Sentinel currently requires sentinel-py bindings for integration. That means Python-only integrators, manual wiring per agent, and no visibility into what Sentinel is actually doing at runtime.

The WS layer makes Sentinel language-agnostic — PokerIntel, trading agents, Claude Code sessions, any LLM API output stream connects via WebSocket without bindings. Point and watch.

The CLI UI makes Sentinel observable without tailing log files. One terminal, everything visible.

---

## Workspace Changes

```
sentinel/
├── sentinel-types       Unchanged — shared contracts
├── sentinel-core        + WebSocket server via tokio-tungstenite
├── sentinel-signals     Unchanged — signal detection
├── sentinel-controls    Unchanged — tiered responses, audit log
├── sentinel-ui          NEW — ratatui terminal dashboard
└── sentinel-py          Unchanged — operator Python bindings
```

---

## sentinel-core — WebSocket Server

**Dependency:** `tokio-tungstenite` — native async WS in the existing tokio runtime. No new runtime. No thread overhead.

**Socket:** `ws://localhost:7777` (configurable via `sentinel.toml`)

**Protocol:** JSON over WebSocket. Same message shapes as the Unix socket interface, serialized to JSON for language-agnostic consumption.

### Inbound Messages (client → Sentinel)

```json
{ "type": "register", "agent_id": "pokeredge-coach", "tier": "autonomous" }
{ "type": "heartbeat", "agent_id": "pokeredge-coach" }
{ "type": "emit_output", "agent_id": "pokeredge-coach", "output": "Raise to $25 — K-T suited..." }
{ "type": "status", "agent_id": "pokeredge-coach" }
```

### Outbound Messages (Sentinel → client)

```json
{ "type": "registered", "agent_id": "pokeredge-coach", "tier": "autonomous" }
{ "type": "status", "agent_id": "pokeredge-coach", "tier": "autonomous", "score": 0.12, "state": "clean" }
{ "type": "degradation", "agent_id": "pokeredge-coach", "signal": "repetition", "score": 0.45, "action": "soft_pause" }
{ "type": "terminated", "agent_id": "pokeredge-coach", "reason": "hard_threshold_crossed" }
```

### Integration Example — PokerEdge Coach Mode (JavaScript)

```javascript
const ws = new WebSocket('ws://localhost:7777');

ws.onopen = () => {
  ws.send(JSON.stringify({ type: 'register', agent_id: 'pokeredge-coach', tier: 'autonomous' }));
};

// After every Coach Mode API response
function emitToSentinel(output) {
  ws.send(JSON.stringify({ type: 'emit_output', agent_id: 'pokeredge-coach', output }));
  ws.send(JSON.stringify({ type: 'heartbeat', agent_id: 'pokeredge-coach' }));
}

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === 'degradation') {
    console.warn('Sentinel flag:', msg.signal, msg.score);
  }
};
```

### Integration Example — PokerIntel (Python)

```python
import asyncio
import websockets
import json

async def sentinel_watch(agent_id, output):
    async with websockets.connect("ws://localhost:7777") as ws:
        await ws.send(json.dumps({"type": "heartbeat", "agent_id": agent_id}))
        await ws.send(json.dumps({"type": "emit_output", "agent_id": agent_id, "output": output}))
        response = json.loads(await ws.recv())
        return response
```

### sentinel.toml addition

```toml
[websocket]
enabled = true
port    = 7777
host    = "127.0.0.1"
```

---

## sentinel-ui — CLI Dashboard

**Dependency:** `ratatui` + `crossterm` — standard Rust TUI stack. Runs as a separate binary in the workspace. Connects to sentinel-core via WebSocket, not Unix socket — same interface as any external client.

### Layout

```
┌─ SENTINEL — Agentic Process Oversight ──────────────────── 2026-05-16 10:44:12 ─┐
│                                                                                   │
│  AGENTS                                                                           │
│  ──────────────────────────────────────────────────────────────────────────────  │
│  Agent                Tier          Score    State       Last Heartbeat           │
│  pokeredge-coach      Autonomous    0.12     ✓ Clean     2s ago                  │
│  pokerintel           Supervised    0.34     ⚠ Watch     1s ago                  │
│  trading-agent        Restricted    0.71     ✗ Degraded  4s ago                  │
│                                                                                   │
│  SIGNALS (last 10)                                                                │
│  ──────────────────────────────────────────────────────────────────────────────  │
│  [10:44:08] pokerintel       repetition       0.34   no action                   │
│  [10:43:51] trading-agent    tool_retry       0.71   medium — write suspended    │
│  [10:43:22] trading-agent    token_velocity   0.55   soft — paused               │
│                                                                                   │
│  AUDIT (append-only)                                                              │
│  ──────────────────────────────────────────────────────────────────────────────  │
│  [10:43:51] trading-agent  WRITE_SUSPENDED   hash: a3f9c2...                     │
│  [10:43:22] trading-agent  SOFT_PAUSE        hash: 7b12e4...                     │
│                                                                                   │
│  [Q] Quit   [O] Override   [R] Refresh   [↑↓] Select agent                      │
└───────────────────────────────────────────────────────────────────────────────────┘
```

### Panels

**Agents panel** — live agent roster. Tier, cumulative score, state, last heartbeat. Color coded: green clean, yellow watch, red degraded.

**Signals panel** — rolling last 10 degradation events across all agents. Signal type, score, action taken.

**Audit panel** — append-only action log with SHA256 hashes visible. Read-only. Never modifiable from UI.

**Operator override** — `[O]` opens inline prompt. Override is logged, hashed, written to audit trail before execution. No untracked writes.

### Binary

```bash
# Run dashboard
sentinel-ui

# Connect to non-default host
sentinel-ui --host 127.0.0.1 --port 7777
```

---

## Test Case — PokerEdge Coach Mode

The first real Sentinel test. Low complexity — Coach Mode is a single Claude API call per hand, not a true agentic loop. But it validates the full pipeline:

**What Sentinel will watch:**
- Repetition detector — does Coach Mode return similar suggestions across hands with similar spots?
- Token velocity — are responses coming back at consistent speed or spiking?
- Heartbeat continuity — does the connection stay stable across a full session?

**Expected result:** Sentinel stays quiet. Score stays low. No tier actions. Clean audit log.

**What a pass proves:**
- WS integration works end to end
- Signal detection runs without false positives on well-behaved output
- Audit trail writes correctly
- CLI UI displays live data accurately

**What an unexpected flag would mean:**
- Coach Mode is more repetitive across hands than expected — legitimate signal worth investigating
- Token velocity anomaly — Claude API latency variance worth logging

Either outcome is useful data.

---

## Development Sequence

1. Add `tokio-tungstenite` to `sentinel-core` — WS server alongside existing Unix socket
2. Expose same message interface over WS as JSON
3. Add `[websocket]` block to `sentinel.toml`
4. Build `sentinel-ui` crate — ratatui dashboard connecting via WS
5. Wire PokerEdge Coach Mode via JavaScript WS client
6. Run smoke test — full session, watch the dashboard, read the audit log

---

## CDMAE Alignment

- **Generation is optional. Verification is not.** — WS messages verified same as Unix socket messages
- **Never self-certify.** — UI is read-only. Operator overrides still require explicit action and are always logged
- **The audit trail is the authority, not the role.** — Unchanged. Every action hashed and appended regardless of interface
- **Constraints are not limitations. They are the architecture.** — WS adds connectivity. It does not relax any governance constraint

---

*Sentinel Extension — CLI UI + WebSocket*
*Copyright (c) 2026 TrueSystems. All rights reserved.*
