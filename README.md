# Sentinel

### Agentic Process Oversight Daemon

**Copyright (c) 2026 TrueSystems. All rights reserved.**

---

## The Problem

Agentic AI systems can degrade mid-session. They loop. They retry the same failing operation. They produce plausible-looking output that signals nothing is wrong while the process has already become unreliable. Existing frameworks have no mechanism to detect this. They treat the agent as a reliable function call. They do not treat it as a process that can fail while still running.

Sentinel is the layer that watches while everything else assumes.

---

## What It Is

Sentinel is a Rust-based watchdog daemon that governs agentic AI processes at the infrastructure level. It runs as a persistent background service, entirely outside the agent's process space. The agent has no awareness of its existence. There are no hooks inside the agent. There is no instrumentation. Sentinel observes passively and acts externally.

When a degradation threshold is crossed, Sentinel responds in tiers — pause, restrict, or terminate — and every action taken by any party, human or system, is timestamped, SHA256 hashed, and written to an immutable append-only audit trail.

---

## Architecture

Sentinel is a four-component Rust workspace with shared types as the single source of truth.

```
sentinel/
├── sentinel-types       Shared contracts — all structs defined once, imported everywhere
├── sentinel-core        Persistent daemon — Unix socket server, heartbeat monitor, event bus
├── sentinel-signals     Signal detection engine — passive, deterministic, no ML
├── sentinel-controls    Response engine — tiered actions, audit log, webhook, operator override
└── sentinel-py          PyO3 bindings — operator and integrator access only
```

### sentinel-types

The single source of truth for all shared contracts across the system. No component redefines a struct that lives here.

Defines: `AgentTier`, `AgentState`, `RegisterResponse`, `HeartbeatResponse`, `EmitOutputResponse`, `StatusResponse`, `SentinelRequest`, `SentinelError`, `DegradationEvent`, `SignalType`, `ControlAction`, `ControlThresholds`, `PermissionSet`, `ResponseTier`, `WebhookPayload`, and the `audit_hash` function.

Every audit hash is computed as SHA256 over `agent_id | action | timestamp` — deterministic, verifiable, tamper-evident.

### sentinel-core

A `tokio`-based daemon that runs as a persistent background process. Systemd-compatible out of the box.

Agents register via Unix socket at `/tmp/sentinel.sock` (configurable). The daemon tracks heartbeat timestamps per agent and monitors them on a one-second tick. A missed heartbeat downgrades the agent's trust tier automatically — no human intervention required.

Three trust tiers govern oversight intensity:

| Tier | Heartbeat Interval | Behavior |
|------|--------------------|----------|
| Autonomous | 30s | Full autonomy within sandbox |
| Supervised | 10s | Output sampled |
| Restricted | 2s | All output captured |

Structured logs are written to `/var/log/sentinel/agents.log` in JSON format.

### sentinel-signals

The passive signal detection engine. Accepts external observations of agent output and tool calls. Returns `DegradationEvent` structs scored 0.0–1.0. No instrumentation inside the agent process. No ML. No inference. Pure deterministic logic.

Four detectors run per agent, isolated by `agent_id`:

| Detector | Signal |
|----------|--------|
| `RepetitionDetector` | Semantic similarity score across last N outputs |
| `SelfReferentialDetector` | "I'm about to..." patterns without a following tool call |
| `TokenVelocityDetector` | Token output rate without task state progression |
| `ToolRetryDetector` | Same tool, same args hash, more than 2 consecutive calls |

All thresholds are configurable via `sentinel.toml`. Agent state is fully isolated — one agent's degradation signals never affect another's.

### sentinel-controls

Consumes `DegradationEvent` structs from the signal engine. Accumulates cumulative scores per agent and applies tiered responses when thresholds are crossed.

| Tier | Threshold | Response |
|------|-----------|----------|
| Soft | > 0.4 | Pause agent, signal for human confirmation |
| Medium | > 0.7 | Downgrade to READ only, suspend WRITE and EXECUTE |
| Hard | > 0.9 | SIGTERM agent process, revoke all permissions, lock agent_id permanently |

Once an agent is locked it is permanently ignored until a human operator explicitly overrides. Cumulative scores escalate across events — a sequence of moderate signals will eventually cross a hard threshold.

Every response tier action is written to `/var/log/sentinel/actions.log` — append-only, never modified, never deleted. Webhook notification is sent on every tier trigger.

Human operator overrides are fully supported via Unix socket. Every override — every write, every permission change, every unlock — is timestamped, SHA256 hashed, and written to the same immutable audit log. No untracked writes. Ever. Not even from the operator.

### sentinel-py

PyO3 bindings that expose sentinel-core's Unix socket interface to Python. For human operators and external integrators only. Never exposed to or callable by the agent being watched.

All types are imported from `sentinel-types` via PyO3. Nothing is redefined.

```python
import sentinel

# Register an agent for oversight
sentinel.register("my-agent", "autonomous")

# Send a heartbeat
sentinel.heartbeat("my-agent")

# Emit captured output for signal analysis
sentinel.emit_output("my-agent", output_text)

# Query agent status
sentinel.status("my-agent")

# Context manager — auto-registers, heartbeats on background thread, deregisters on exit
with sentinel.watch("my-agent"):
    # your operator code here
```

Socket path defaults to `/tmp/sentinel.sock`. Override with `SENTINEL_SOCKET_PATH` environment variable.

---

## Permission Model

```
Agent process        RWE within generation sandbox only. Blind to Sentinel's existence.
Sentinel daemon      READ + EXECUTE. Never writes. Observes and acts externally.
Human operator       WRITE + EXECUTE. Every action timestamped, SHA256 hashed, immutable.
```

The agent cannot see the leash. Sentinel cannot modify what it watches. The audit trail is the authority — not the role.

---

## Setup

### 1. Build

```bash
cargo build --release
```

### 2. Install the daemon

```bash
sudo cp target/release/sentinel-core /usr/local/bin/sentinel-core
```

### 3. Configure systemd

```ini
[Unit]
Description=Sentinel Agent Oversight Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel-core
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable sentinel
sudo systemctl start sentinel
```

### 4. Configure thresholds

```toml
# sentinel.toml

[thresholds]
soft   = 0.4
medium = 0.7
hard   = 0.9

[webhook]
url = "https://your-endpoint/sentinel-alert"

[window]
size = 5   # number of outputs to hold in detection window
```

### 5. Set socket path (optional)

```bash
export SENTINEL_SOCKET_PATH=/tmp/sentinel.sock
```

---

## Operating Sentinel

### Check daemon status

```bash
systemctl status sentinel
```

### Read agent log

```bash
tail -f /var/log/sentinel/agents.log
```

### Read action audit log

```bash
tail -f /var/log/sentinel/actions.log
```

### Connect via Python bindings

```bash
pip install sentinel-py
```

```python
import sentinel
sentinel.register("agent-id", "supervised")
```

---

## How It Was Built

Sentinel was built by four Claude Code agents running simultaneously across four terminals, each responsible for one component. Every commit made by every agent was governed autonomously by the [CI Gate Wrapper](https://github.com/B-Green85/ci-wrapper) — a seven-gate enforcement chain that issues cryptographic merge tokens as the only valid exit condition.

No agent could self-certify. No commit could merge without a token. The memory gate enforced architectural contract continuity across all four agents in parallel — catching drift between components without any explicit cross-agent coordination.

The tool that governs agents was built under agent governance. That is not a coincidence. It is a proof of concept.

---

## CDMAD Principles

1. **Generation is optional. Verification is not.**
2. **Never self-certify.**
3. **The audit trail is the authority, not the role.**
4. **Constraints are not limitations. They are the architecture.**

---

*Sentinel — Agentic Process Oversight*
*Copyright (c) 2026 TrueSystems. All rights reserved.*# test
