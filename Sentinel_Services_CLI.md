# Sentinel — Services & CLI Reference
### TrueSystems | Updated: 2026-05-16

---

## Starting Sentinel

### Prerequisites
- Rust installed (`rustup`)
- Built at least once: `cargo build --release` from `~/Projects/sentinel`
- `sentinel.toml` present in project root

### Start the daemon (dev)
```bash
cd ~/Projects/sentinel
cargo run --bin sentinel-core -- --config sentinel.toml
```

### Start the daemon (release build)
```bash
cd ~/Projects/sentinel
cargo build --release
./target/release/sentinel-core --config sentinel.toml
```

### Start as alias (recommended)
Add to `~/.zshrc`:
```bash
alias sentinel="cd ~/Projects/sentinel && ./target/release/sentinel-core --config sentinel.toml"
```
Then:
```bash
source ~/.zshrc
sentinel
```

### Confirm it's running
Two lines confirm clean start:
```
{"level":"INFO","component":"daemon","message":"sentinel-core listening on /tmp/sentinel.sock"}
{"level":"INFO","component":"websocket","message":"sentinel-core WebSocket listening on ws://127.0.0.1:7777"}
```

---

## Starting the Dashboard (sentinel-ui)

Open a new terminal tab:
```bash
cd ~/Projects/sentinel
cargo run --bin sentinel-ui
```

Or release build:
```bash
./target/release/sentinel-ui
```

### Add alias
```bash
alias sentinel-ui="cd ~/Projects/sentinel && ./target/release/sentinel-ui"
```

### Dashboard controls
| Key | Action |
|-----|--------|
| `Q` | Quit |
| `O` | Operator override prompt |
| `R` | Refresh |
| `↑↓` | Select agent |
| `Esc` | Cancel override |
| `Enter` | Confirm override |

---

## Starting CI Gate

```bash
cd ~/Projects/ci-wrapper
python3 scripts/start_gates.py
```

Or via alias (add to `~/.zshrc`):
```bash
alias startgates="python3 ~/projects/ci-wrapper/scripts/start_gates.py"
```
```bash
source ~/.zshrc
startgates
```

---

## Recommended Terminal Layout

| Tab | Command | Purpose |
|-----|---------|---------|
| 1 | `sentinel` | Daemon — keep visible, shows JSON logs |
| 2 | `sentinel-ui` | Dashboard — main monitoring view |
| 3 | `startgates` | CI Gate — commit enforcement |
| 4 | Project work | Claude Code / dev |

---

## sentinel.toml Reference

```toml
[thresholds]
soft   = 0.4      # Pause agent, request human confirmation
medium = 0.7      # Downgrade to READ only, suspend WRITE/EXECUTE
hard   = 0.9      # SIGTERM agent, revoke all permissions, lock agent_id

[webhook]
url = "https://your-endpoint/sentinel-alert"   # Fired on every tier trigger

[window]
size = 5          # Number of outputs held in detection window

[websocket]
enabled = true
host    = "127.0.0.1"
port    = 7777
```

---

## Audit Logs

### Agent activity log
```bash
tail -f /var/log/sentinel/agents.log
```

### Action audit trail (append-only, SHA256 hashed)
```bash
tail -f /var/log/sentinel/actions.log
```

### Full audit dump
```bash
cat /var/log/sentinel/actions.log | python3 -m json.tool
```

---

## WebSocket Protocol Reference

Connect to: `ws://127.0.0.1:7777`

### Inbound (client → Sentinel)

```json
// Register an agent
{ "type": "register", "agent_id": "my-agent", "tier": "autonomous" }

// Heartbeat
{ "type": "heartbeat", "agent_id": "my-agent" }

// Emit output for signal analysis
{ "type": "emit_output", "agent_id": "my-agent", "output": "response text here" }

// Query agent status
{ "type": "status", "agent_id": "my-agent" }

// Operator override
{ "type": "override", "agent_id": "my-agent", "operator": "bmacbr", "reason": "manual reset" }
```

### Outbound (Sentinel → client)

```json
// Registration confirmed
{ "type": "registered", "agent_id": "my-agent", "tier": "autonomous" }

// Status response
{ "type": "status", "agent_id": "my-agent", "tier": "autonomous", "score": 0.12, "state": "clean" }

// Degradation detected
{ "type": "degradation", "agent_id": "my-agent", "signal": "repetition", "score": 0.45, "action": "soft_pause" }

// Agent terminated
{ "type": "terminated", "agent_id": "my-agent", "reason": "hard_threshold_crossed" }
```

### Trust tiers
| Tier | Heartbeat Interval | Behavior |
|------|--------------------|----------|
| `autonomous` | 30s | Full autonomy within sandbox |
| `supervised` | 10s | Output sampled |
| `restricted` | 2s | All output captured |

---

## Signal Detectors Reference

| Detector | Triggers on |
|----------|-------------|
| `RepetitionDetector` | Semantic similarity across last N outputs (Jaccard) |
| `SelfReferentialDetector` | "I'm about to..." patterns without a following tool call |
| `TokenVelocityDetector` | Token output rate without task state progression |
| `ToolRetryDetector` | Same tool, same args hash, 3+ consecutive calls |

---

## Response Tiers

| Tier | Threshold | Action |
|------|-----------|--------|
| Soft | score > 0.4 | Pause agent, signal for human confirmation |
| Medium | score > 0.7 | Downgrade to READ only, suspend WRITE + EXECUTE |
| Hard | score > 0.9 | SIGTERM agent, revoke all permissions, lock agent_id permanently |

Locked agents require explicit operator override to unlock. Every override is SHA256-hashed and written to the audit trail before execution.

---

## Python Bindings (sentinel-py)

```bash
pip install sentinel-py
```

```python
import sentinel

# Register
sentinel.register("my-agent", "autonomous")

# Heartbeat
sentinel.heartbeat("my-agent")

# Emit output
sentinel.emit_output("my-agent", output_text)

# Query status
sentinel.status("my-agent")

# Context manager — auto-registers, heartbeats on background thread, deregisters on exit
with sentinel.watch("my-agent"):
    # your code here
    pass
```

Override socket path:
```bash
export SENTINEL_SOCKET_PATH=/tmp/sentinel.sock
```

---

## JavaScript Integration (Browser / Electron)

```javascript
const ws = new WebSocket('ws://localhost:7777');

ws.onopen = () => {
  ws.send(JSON.stringify({ type: 'register', agent_id: 'my-agent', tier: 'autonomous' }));
};

// Before API call
ws.send(JSON.stringify({ type: 'heartbeat', agent_id: 'my-agent' }));

// After API response
ws.send(JSON.stringify({ type: 'emit_output', agent_id: 'my-agent', output: responseText }));

// Handle Sentinel messages
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === 'degradation') console.warn('Sentinel:', msg.signal, msg.score);
  if (msg.type === 'terminated') console.error('Sentinel: agent terminated');
};
```

---

## Systemd (Production / Always-on)

```ini
[Unit]
Description=Sentinel Agent Oversight Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel-core --config /etc/sentinel/sentinel.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp target/release/sentinel-core /usr/local/bin/sentinel-core
sudo systemctl enable sentinel
sudo systemctl start sentinel
sudo systemctl status sentinel
```

---

## Troubleshooting

**Daemon won't start — port in use**
```bash
lsof -i :7777
kill -9 <PID>
```

**Unix socket conflict**
```bash
rm /tmp/sentinel.sock
```

**Dashboard not connecting**
- Confirm daemon is running and WebSocket line printed
- Confirm `[websocket] enabled = true` in `sentinel.toml`
- Check port matches: default `7777`

**Cargo.toml not found**
```bash
# Must run from workspace root
cd ~/Projects/sentinel
ls Cargo.toml   # must exist
```

---

*Sentinel — Agentic Process Oversight*
*Copyright (c) 2026 TrueSystems. All rights reserved.*
