// sentinel-ui — dashboard application state.
//
// All state the UI renders lives here. Inbound WebSocket messages are applied
// via `apply`; keyboard input is handled by `handle_key`. The dashboard is
// strictly read-only with one exception: the operator override, which is
// sent to sentinel-core where it is hashed and audited before execution.

use std::collections::{BTreeMap, VecDeque};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use serde::Deserialize;
use tokio::sync::mpsc::UnboundedSender;

/// Signals retained for the rolling history panel.
const SIGNAL_CAP: usize = 50;
/// Audit entries retained for the audit panel.
const AUDIT_CAP: usize = 50;

// ---------------------------------------------------------------------------
// Wire messages (Sentinel → dashboard)
// ---------------------------------------------------------------------------

/// A message from sentinel-core, or a synthetic connection event.
#[derive(Debug, Clone)]
pub enum AppEvent {
    Connected,
    Disconnected,
    Server(ServerMsg),
}

/// Outbound messages from sentinel-core's WebSocket interface.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Registered {
        agent_id: String,
        tier: String,
        audit_hash: String,
    },
    Status {
        agent_id: String,
        tier: String,
        score: f64,
        state: String,
        heartbeat_age_secs: u64,
    },
    Degradation {
        agent_id: String,
        signal: String,
        score: f64,
        action: String,
        timestamp: String,
        #[serde(default)]
        audit_hash: String,
    },
    Terminated {
        agent_id: String,
        reason: String,
        timestamp: String,
        #[serde(default)]
        audit_hash: String,
    },
    Snapshot {
        agents: Vec<AgentSnap>,
        signals: Vec<SignalRec>,
        audit: Vec<AuditRec>,
    },
    OverrideApplied {
        agent_id: String,
        operator: String,
        note: String,
        timestamp: String,
        audit_hash: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentSnap {
    pub agent_id: String,
    pub tier: String,
    pub score: f64,
    pub state: String,
    pub heartbeat_age_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignalRec {
    pub timestamp: String,
    pub agent_id: String,
    pub signal: String,
    pub score: f64,
    pub action: String,
}

/// Audit entry as carried in a snapshot. Extra fields (sequence, actor,
/// prev_hash) are present on the wire but not rendered — serde ignores them.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditRec {
    pub timestamp: String,
    pub action: String,
    pub target: String,
    pub hash: String,
}

// ---------------------------------------------------------------------------
// Dashboard state
// ---------------------------------------------------------------------------

/// One agent's row in the agents panel.
#[derive(Debug, Clone)]
pub struct AgentView {
    pub tier: String,
    pub score: f64,
    pub state: String,
    pub heartbeat_age_secs: u64,
}

/// Input mode — Normal, or the inline operator-override prompt.
#[derive(Debug, Clone)]
pub enum Mode {
    Normal,
    Override { agent_id: String, input: String },
}

pub struct App {
    pub operator: String,
    pub connected: bool,
    pub agents: BTreeMap<String, AgentView>,
    pub order: Vec<String>,
    pub selected: usize,
    pub signals: VecDeque<SignalRec>,
    pub audit: VecDeque<AuditRec>,
    pub mode: Mode,
    pub status_line: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(operator: String) -> Self {
        Self {
            operator,
            connected: false,
            agents: BTreeMap::new(),
            order: Vec::new(),
            selected: 0,
            signals: VecDeque::new(),
            audit: VecDeque::new(),
            mode: Mode::Normal,
            status_line: "connecting…".to_string(),
            should_quit: false,
        }
    }

    /// The agent currently highlighted in the agents panel.
    pub fn selected_agent(&self) -> Option<&String> {
        self.order.get(self.selected)
    }

    fn sync_order(&mut self) {
        self.order = self.agents.keys().cloned().collect();
        if self.selected >= self.order.len() {
            self.selected = self.order.len().saturating_sub(1);
        }
    }

    fn push_audit(&mut self, action: &str, target: &str, hash: &str, timestamp: &str) {
        if hash.is_empty() {
            return;
        }
        self.audit.push_front(AuditRec {
            timestamp: timestamp.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            hash: hash.to_string(),
        });
        while self.audit.len() > AUDIT_CAP {
            self.audit.pop_back();
        }
    }

    fn push_signal(&mut self, rec: SignalRec) {
        self.signals.push_front(rec);
        while self.signals.len() > SIGNAL_CAP {
            self.signals.pop_back();
        }
    }

    /// Apply an inbound event to dashboard state.
    pub fn apply(&mut self, event: AppEvent) {
        match event {
            AppEvent::Connected => {
                self.connected = true;
                self.status_line = "connected to sentinel-core".to_string();
            }
            AppEvent::Disconnected => {
                self.connected = false;
                self.status_line = "disconnected — reconnecting…".to_string();
            }
            AppEvent::Server(msg) => self.apply_server(msg),
        }
    }

    fn apply_server(&mut self, msg: ServerMsg) {
        match msg {
            ServerMsg::Registered {
                agent_id,
                tier,
                audit_hash,
            } => {
                self.agents.entry(agent_id.clone()).or_insert(AgentView {
                    tier,
                    score: 0.0,
                    state: "clean".to_string(),
                    heartbeat_age_secs: 0,
                });
                self.sync_order();
                self.push_audit("REGISTER", &agent_id, &audit_hash, "");
            }
            ServerMsg::Status {
                agent_id,
                tier,
                score,
                state,
                heartbeat_age_secs,
                ..
            } => {
                let is_new = !self.agents.contains_key(&agent_id);
                self.agents.insert(
                    agent_id,
                    AgentView {
                        tier,
                        score,
                        state,
                        heartbeat_age_secs,
                    },
                );
                if is_new {
                    self.sync_order();
                }
            }
            ServerMsg::Degradation {
                agent_id,
                signal,
                score,
                action,
                timestamp,
                audit_hash,
            } => {
                self.push_audit(&action.to_uppercase(), &agent_id, &audit_hash, &timestamp);
                self.push_signal(SignalRec {
                    timestamp,
                    agent_id,
                    signal,
                    score,
                    action,
                });
            }
            ServerMsg::Terminated {
                agent_id,
                reason,
                timestamp,
                audit_hash,
            } => {
                self.push_audit("HARD_TERMINATE", &agent_id, &audit_hash, &timestamp);
                if let Some(a) = self.agents.get_mut(&agent_id) {
                    a.state = "degraded".to_string();
                }
                self.status_line = format!("{agent_id} terminated — {reason}");
            }
            ServerMsg::Snapshot {
                agents,
                signals,
                audit,
            } => {
                self.agents = agents
                    .into_iter()
                    .map(|a| {
                        (
                            a.agent_id,
                            AgentView {
                                tier: a.tier,
                                score: a.score,
                                state: a.state,
                                heartbeat_age_secs: a.heartbeat_age_secs,
                            },
                        )
                    })
                    .collect();
                self.signals = signals.into_iter().collect();
                // Snapshot audit arrives oldest-first; the panel is newest-first.
                self.audit = audit.into_iter().rev().collect();
                while self.audit.len() > AUDIT_CAP {
                    self.audit.pop_back();
                }
                self.sync_order();
            }
            ServerMsg::OverrideApplied {
                agent_id,
                operator,
                note,
                timestamp,
                audit_hash,
            } => {
                self.push_audit("OPERATOR_OVERRIDE", &agent_id, &audit_hash, &timestamp);
                let short = short_hash(&audit_hash);
                self.status_line =
                    format!("override on {agent_id} by {operator} applied — audit {short} ({note})");
            }
            ServerMsg::Error { message } => {
                self.status_line = format!("sentinel: {message}");
            }
        }
    }

    /// Handle a keypress. `out` carries client messages to sentinel-core.
    pub fn handle_key(&mut self, key: KeyEvent, out: &UnboundedSender<String>) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        match &self.mode {
            Mode::Normal => self.handle_normal_key(key, out),
            Mode::Override { .. } => self.handle_override_key(key, out),
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent, out: &UnboundedSender<String>) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => self.should_quit = true,
            KeyCode::Char('r') | KeyCode::Char('R') => {
                let _ = out.send(r#"{"type":"status"}"#.to_string());
                self.status_line = "refresh requested".to_string();
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                if let Some(agent_id) = self.selected_agent().cloned() {
                    self.mode = Mode::Override {
                        agent_id,
                        input: String::new(),
                    };
                } else {
                    self.status_line = "no agent selected".to_string();
                }
            }
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                if self.selected + 1 < self.order.len() {
                    self.selected += 1;
                }
            }
            _ => {}
        }
    }

    fn handle_override_key(&mut self, key: KeyEvent, out: &UnboundedSender<String>) {
        // Take ownership of the mode so we can mutate input freely.
        let (agent_id, mut input) = match std::mem::replace(&mut self.mode, Mode::Normal) {
            Mode::Override { agent_id, input } => (agent_id, input),
            Mode::Normal => return,
        };
        match key.code {
            KeyCode::Esc => {
                self.status_line = "override cancelled".to_string();
            }
            KeyCode::Enter => {
                let note = if input.trim().is_empty() {
                    "manual operator override".to_string()
                } else {
                    input.trim().to_string()
                };
                // The dashboard never writes the audit trail itself — it asks
                // sentinel-core, which hashes and records the override before
                // applying it.
                let payload = serde_json::json!({
                    "type": "override",
                    "agent_id": agent_id,
                    "operator": self.operator,
                    "note": note,
                })
                .to_string();
                let _ = out.send(payload);
                self.status_line =
                    format!("override sent for {agent_id} — awaiting audit hash");
            }
            KeyCode::Backspace => {
                input.pop();
                self.mode = Mode::Override { agent_id, input };
            }
            KeyCode::Char(c) => {
                input.push(c);
                self.mode = Mode::Override { agent_id, input };
            }
            _ => {
                self.mode = Mode::Override { agent_id, input };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// First 6 hex chars of an audit hash, with an ellipsis — matching the spec
/// dashboard ("hash: a3f9c2…").
pub fn short_hash(hash: &str) -> String {
    if hash.is_empty() {
        "—".to_string()
    } else {
        let head: String = hash.chars().take(6).collect();
        format!("{head}…")
    }
}

/// Extract `HH:MM:SS` from an ISO-8601 timestamp; fall back to the raw value.
pub fn hms(ts: &str) -> String {
    if ts.len() >= 19 && ts.as_bytes().get(10) == Some(&b'T') {
        ts[11..19].to_string()
    } else {
        ts.to_string()
    }
}

/// Title-case a tier name ("autonomous" → "Autonomous").
pub fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Current UTC wall-clock as `YYYY-MM-DD HH:MM:SS`.
pub fn now_clock() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let tod = secs % 86400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Howard Hinnant's days-from-civil, inverted.
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_truncates() {
        assert_eq!(short_hash("a3f9c2deadbeef"), "a3f9c2…");
        assert_eq!(short_hash(""), "—");
    }

    #[test]
    fn hms_extracts_time() {
        assert_eq!(hms("2026-05-16T10:44:08Z"), "10:44:08");
        assert_eq!(hms("garbage"), "garbage");
    }

    #[test]
    fn title_case_capitalizes() {
        assert_eq!(title_case("autonomous"), "Autonomous");
    }

    #[test]
    fn snapshot_replaces_state() {
        let mut app = App::new("op".into());
        let msg: ServerMsg = serde_json::from_str(
            r#"{"type":"snapshot","agents":[{"agent_id":"a","tier":"autonomous","score":0.1,"state":"clean","heartbeat_age_secs":2}],"signals":[],"audit":[]}"#,
        )
        .unwrap();
        app.apply(AppEvent::Server(msg));
        assert_eq!(app.order, vec!["a".to_string()]);
        assert_eq!(app.agents["a"].tier, "autonomous");
    }

    #[test]
    fn degradation_feeds_signals_and_audit() {
        let mut app = App::new("op".into());
        let msg: ServerMsg = serde_json::from_str(
            r#"{"type":"degradation","agent_id":"a","signal":"repetition","score":0.45,"action":"soft_pause","timestamp":"2026-05-16T10:44:08Z","audit_hash":"abcdef123456"}"#,
        )
        .unwrap();
        app.apply(AppEvent::Server(msg));
        assert_eq!(app.signals.len(), 1);
        assert_eq!(app.audit.len(), 1);
        assert_eq!(app.audit[0].action, "SOFT_PAUSE");
    }

    #[test]
    fn no_action_signal_writes_no_audit() {
        let mut app = App::new("op".into());
        let msg: ServerMsg = serde_json::from_str(
            r#"{"type":"degradation","agent_id":"a","signal":"repetition","score":0.34,"action":"no_action","timestamp":"2026-05-16T10:44:08Z","audit_hash":""}"#,
        )
        .unwrap();
        app.apply(AppEvent::Server(msg));
        assert_eq!(app.signals.len(), 1);
        assert_eq!(app.audit.len(), 0, "no-action signals must not forge audit rows");
    }
}
