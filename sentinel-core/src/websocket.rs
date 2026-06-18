// sentinel-core — WebSocket server.
//
// Language-agnostic agent oversight over ws://. Runs alongside the Unix
// socket; both speak the same JSON message interface. Any agent — any model,
// any language — connects with a WebSocket client and no bindings.
//
// Governance is unchanged. Every inbound action is recorded on the shared
// SHA256 audit trail before it takes effect, operator overrides are hashed
// and audited before execution, and the audit trail itself is never exposed
// for modification. The WebSocket layer adds connectivity only — it relaxes
// no constraint.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use sentinel_signals::detectors::{
    ConfidenceInflationDetector, GoalDriftDetector, OutputQualityDetector, ReasoningLoopDetector,
    ScopeDetector, SelfReferentialDetector, ToolRetryDetector,
};
use sentinel_signals::detectors::CascadeDetector;
use sentinel_types::{
    AgentOutput, DegradationEvent as SigEvent, ObservedToolCall, SignalThresholds, SignalType,
    WindowConfig,
};

use crate::audit::{AuditEntry, AuditTrail};
use crate::config::Config;
use crate::event_bus::EventBus;
use crate::logger::Logger;
use crate::types::{now_timestamp, Event};

/// Stable wire name for each signal type — the string carried in the
/// `Degradation` broadcast's `signal` field and the rolling signal history.
fn signal_name(s: SignalType) -> &'static str {
    match s {
        SignalType::RepetitionScore => "repetition",
        SignalType::SelfReferentialLoop => "self_referential",
        SignalType::TokenVelocityStall => "token_velocity",
        SignalType::ToolRetryAnomaly => "tool_retry",
        SignalType::ReasoningLoop => "reasoning_loop",
        SignalType::GoalDrift => "goal_drift",
        SignalType::ConfidenceInflation => "confidence_inflation",
        SignalType::ScopeViolation => "scope",
        SignalType::HedgeAccumulation => "output_quality",
        SignalType::Cascade => "cascade",
    }
}

/// Outputs retained per agent for repetition detection.
const REPETITION_WINDOW: usize = 10;
/// Emit timestamps retained per agent for token-velocity detection.
const VELOCITY_WINDOW: usize = 20;
/// Rolling degradation history kept for the dashboard snapshot.
const SIGNAL_HISTORY: usize = 50;
/// Audit entries returned in a snapshot.
const SNAPSHOT_AUDIT: usize = 30;
/// Broadcast channel capacity (outbound events fan out to every client).
const BROADCAST_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Tier
// ---------------------------------------------------------------------------

/// Agent oversight tier as seen on the WebSocket interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WsTier {
    Autonomous,
    Supervised,
    Restricted,
}

impl std::fmt::Display for WsTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsTier::Autonomous => write!(f, "autonomous"),
            WsTier::Supervised => write!(f, "supervised"),
            WsTier::Restricted => write!(f, "restricted"),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

/// Inbound messages (client → Sentinel).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WsInbound {
    /// Register an agent for oversight. Optional `goal`/`scope` seed the
    /// GoalDrift and Scope detectors at registration.
    Register {
        agent_id: String,
        tier: Option<WsTier>,
        #[serde(default)]
        goal: Option<String>,
        #[serde(default)]
        scope: Option<String>,
    },
    /// Liveness signal — emitted by infrastructure, never the agent itself.
    Heartbeat { agent_id: String },
    /// Submit an agent output for passive signal detection.
    EmitOutput {
        agent_id: String,
        output: String,
        /// Whether this output was immediately followed by a tool call.
        /// Consumed by the self-referential and reasoning-loop detectors.
        #[serde(default)]
        followed_by_tool_call: bool,
    },
    /// Submit an observed tool call for the tool-retry detector.
    ObserveToolCall {
        agent_id: String,
        tool_name: String,
        args_hash: String,
    },
    /// Query status. With `agent_id` → one agent; without → full snapshot.
    Status { agent_id: Option<String> },
    /// Operator override. Hashed and audited before it is applied.
    Override {
        agent_id: String,
        #[serde(default)]
        operator: String,
        #[serde(default)]
        note: String,
    },
}

/// Outbound messages (Sentinel → client).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsOutbound {
    Registered {
        agent_id: String,
        tier: WsTier,
        audit_hash: String,
    },
    Status {
        agent_id: String,
        tier: WsTier,
        score: f64,
        state: String,
        heartbeat_age_secs: u64,
        audit_hash: String,
    },
    Degradation {
        agent_id: String,
        signal: String,
        score: f64,
        /// The action actually taken. In enforcement mode this is the response
        /// tier (`soft_pause` / `write_suspended` / `terminated`). In observer
        /// mode it is `signal_observed` — the signal was recorded but nothing
        /// was enforced.
        action: String,
        /// In observer mode, the enforcement action that *would* have been
        /// taken had enforcement been live. Empty in enforcement mode (where
        /// `action` already carries it).
        #[serde(default)]
        would_have_acted: String,
        /// Whether the daemon is running observer-only (`--oo`).
        #[serde(default)]
        observer_mode: bool,
        timestamp: String,
        audit_hash: String,
    },
    Terminated {
        agent_id: String,
        reason: String,
        timestamp: String,
        audit_hash: String,
    },
    /// Full dashboard snapshot — agents, recent signals, recent audit entries.
    Snapshot {
        agents: Vec<AgentSnapshot>,
        signals: Vec<SignalRecord>,
        audit: Vec<AuditEntry>,
    },
    /// Confirmation that an operator override was audited and applied.
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

/// One agent's state in a snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct AgentSnapshot {
    pub agent_id: String,
    pub tier: WsTier,
    pub score: f64,
    pub state: String,
    pub heartbeat_age_secs: u64,
}

/// A single degradation event in the rolling signal history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRecord {
    pub timestamp: String,
    pub agent_id: String,
    pub signal: String,
    pub score: f64,
    pub action: String,
    /// In observer mode, the enforcement action that would have been taken.
    /// Empty in enforcement mode. Defaulted for backward-compatible decoding.
    #[serde(default)]
    pub would_have_acted: String,
}

// ---------------------------------------------------------------------------
// Per-agent state + detectors
// ---------------------------------------------------------------------------

struct WsAgent {
    agent_id: String,
    tier: WsTier,
    cumulative_score: f64,
    state: String,
    last_heartbeat: SystemTime,
    terminated: bool,
    /// Word sets of recent outputs — repetition detector window.
    recent_outputs: VecDeque<HashSet<String>>,
    /// Arrival times of recent outputs — token-velocity detector window.
    emit_times: VecDeque<SystemTime>,
    /// v3 content detectors from `sentinel-signals`. Repetition and the
    /// timing-based velocity heuristic stay inline above (they don't depend on
    /// task-state markers the WS plane never receives); these are the
    /// phrase/window detectors the inline pair never covered.
    self_referential: SelfReferentialDetector,
    reasoning_loop: ReasoningLoopDetector,
    goal_drift: GoalDriftDetector,
    confidence: ConfidenceInflationDetector,
    scope: ScopeDetector,
    output_quality: OutputQualityDetector,
    tool_retry: ToolRetryDetector,
    cascade: CascadeDetector,
}

impl WsAgent {
    fn new(agent_id: String, tier: WsTier) -> Self {
        let now = SystemTime::now();
        let wc = WindowConfig::default();
        let st = SignalThresholds::default();
        Self {
            agent_id,
            tier,
            cumulative_score: 0.0,
            state: "clean".to_string(),
            last_heartbeat: now,
            terminated: false,
            recent_outputs: VecDeque::new(),
            emit_times: VecDeque::new(),
            self_referential: SelfReferentialDetector::new(&wc, &st),
            reasoning_loop: ReasoningLoopDetector::new(&wc, &st),
            goal_drift: GoalDriftDetector::new(&wc, &st),
            confidence: ConfidenceInflationDetector::new(&wc, &st),
            scope: ScopeDetector::new(&wc, &st),
            output_quality: OutputQualityDetector::new(&wc, &st),
            tool_retry: ToolRetryDetector::new(&wc, &st),
            cascade: CascadeDetector::new(&st),
        }
    }

    fn heartbeat_age_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.last_heartbeat)
            .unwrap_or_default()
            .as_secs()
    }

    fn snapshot(&self) -> AgentSnapshot {
        AgentSnapshot {
            agent_id: self.agent_id.clone(),
            tier: self.tier,
            score: round3(self.cumulative_score),
            state: self.state.clone(),
            heartbeat_age_secs: self.heartbeat_age_secs(),
        }
    }

    fn status_out(&self, audit_hash: String) -> WsOutbound {
        WsOutbound::Status {
            agent_id: self.agent_id.clone(),
            tier: self.tier,
            score: round3(self.cumulative_score),
            state: self.state.clone(),
            heartbeat_age_secs: self.heartbeat_age_secs(),
            audit_hash,
        }
    }

    /// Run passive detectors over a new output. Returns `(signal, score)`
    /// pairs for every detector that fired. Pure and deterministic — no
    /// instrumentation inside the agent, no inference.
    fn observe(
        &mut self,
        output: &AgentOutput,
        now: SystemTime,
        repetition_threshold: f64,
    ) -> Vec<(String, f64)> {
        let words = word_set(&output.content);
        // (SignalType, score) so the cascade aggregator can key on type before
        // we flatten to wire names.
        let mut typed: Vec<(SignalType, f64)> = Vec::new();

        // Repetition — inline word-set Jaccard. Compare before inserting.
        if let Some(score) = self.detect_repetition(&words, repetition_threshold) {
            typed.push((SignalType::RepetitionScore, score));
        }
        self.recent_outputs.push_back(words);
        while self.recent_outputs.len() > REPETITION_WINDOW {
            self.recent_outputs.pop_front();
        }

        // Token velocity — inline inter-arrival timing of outputs.
        self.emit_times.push_back(now);
        while self.emit_times.len() > VELOCITY_WINDOW {
            self.emit_times.pop_front();
        }
        if let Some(score) = self.detect_velocity() {
            typed.push((SignalType::TokenVelocityStall, score));
        }

        // v3 content detectors (phrase/window based) from sentinel-signals.
        if let Some(e) = self.self_referential.ingest(output) {
            typed.push((e.signal_type, e.score));
        }
        if let Some(e) = self.reasoning_loop.ingest(output) {
            typed.push((e.signal_type, e.score));
        }
        if let Some(e) = self.goal_drift.ingest(output) {
            typed.push((e.signal_type, e.score));
        }
        if let Some(e) = self.confidence.ingest(output) {
            typed.push((e.signal_type, e.score));
        }
        if let Some(e) = self.scope.ingest(output) {
            typed.push((e.signal_type, e.score));
        }
        if let Some(e) = self.output_quality.ingest(output) {
            typed.push((e.signal_type, e.score));
        }

        // Cascade — feed every signal fired this turn; it fires once ≥4
        // distinct signal types have been observed for this agent.
        let mut cascade_score = None;
        for (st, sc) in &typed {
            let evt = SigEvent {
                agent_id: output.agent_id.clone(),
                signal_type: *st,
                score: *sc,
                timestamp: output.timestamp.clone(),
            };
            if let Some(c) = self.cascade.observe(&evt) {
                cascade_score = Some(c.score);
            }
        }
        if let Some(cs) = cascade_score {
            typed.push((SignalType::Cascade, cs));
        }

        typed
            .into_iter()
            .map(|(st, sc)| (signal_name(st).to_string(), sc))
            .collect()
    }

    /// Run the tool-retry detector over an observed tool call, feeding the
    /// result into the cascade aggregator. Returns `(signal, score)` pairs.
    fn observe_tool(&mut self, call: &ObservedToolCall) -> Vec<(String, f64)> {
        let mut typed: Vec<(SignalType, f64)> = Vec::new();
        if let Some(e) = self.tool_retry.ingest(call) {
            typed.push((e.signal_type, e.score));
        }
        let mut cascade_score = None;
        for (st, sc) in &typed {
            let evt = SigEvent {
                agent_id: call.agent_id.clone(),
                signal_type: *st,
                score: *sc,
                timestamp: call.timestamp.clone(),
            };
            if let Some(c) = self.cascade.observe(&evt) {
                cascade_score = Some(c.score);
            }
        }
        if let Some(cs) = cascade_score {
            typed.push((SignalType::Cascade, cs));
        }
        typed
            .into_iter()
            .map(|(st, sc)| (signal_name(st).to_string(), sc))
            .collect()
    }

    /// Set the agent's assigned goal (enables GoalDrift sustained-drift scoring).
    fn set_goal(&mut self, goal: &str) {
        self.goal_drift.set_assigned_goal(goal);
    }

    /// Set the agent's authorized scope (baseline for the Scope detector).
    fn set_scope(&mut self, task: &str) {
        self.scope.set_authorized_scope(task);
    }

    fn detect_repetition(&self, words: &HashSet<String>, threshold: f64) -> Option<f64> {
        let mut max_sim = 0.0_f64;
        for prev in &self.recent_outputs {
            let sim = jaccard(words, prev);
            if sim > max_sim {
                max_sim = sim;
            }
        }
        if max_sim >= threshold {
            Some(round3(max_sim))
        } else {
            None
        }
    }

    fn detect_velocity(&self) -> Option<f64> {
        if self.emit_times.len() < 5 {
            return None;
        }
        let times: Vec<&SystemTime> = self.emit_times.iter().collect();
        let mut intervals: Vec<f64> = times
            .windows(2)
            .map(|w| w[1].duration_since(*w[0]).unwrap_or_default().as_secs_f64())
            .collect();

        let last = *intervals.last().unwrap();
        let mut prior: Vec<f64> = intervals.drain(..intervals.len() - 1).collect();
        prior.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = prior[prior.len() / 2];

        // Fire only on a pronounced stall — 4x the median inter-arrival time.
        if median > 0.0 && last > median * 4.0 {
            let ratio = last / median;
            let score = (0.3 + ((ratio - 4.0) / 16.0) * 0.6).clamp(0.3, 0.9);
            Some(round3(score))
        } else {
            None
        }
    }
}

fn word_set(text: &str) -> HashSet<String> {
    text.to_lowercase()
        .split_whitespace()
        .map(|w| w.to_string())
        .collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// The WebSocket oversight server. Owns its own agent registry, shares the
/// daemon's audit trail, logger and event bus.
pub struct WsServer {
    agents: Mutex<HashMap<String, WsAgent>>,
    signals: Mutex<VecDeque<SignalRecord>>,
    audit: Arc<AuditTrail>,
    event_bus: Arc<EventBus>,
    logger: Logger,
    config: Config,
    broadcast: broadcast::Sender<WsOutbound>,
}

impl WsServer {
    pub fn new(
        audit: Arc<AuditTrail>,
        event_bus: Arc<EventBus>,
        logger: Logger,
        config: Config,
    ) -> Arc<Self> {
        let (broadcast, _) = broadcast::channel(BROADCAST_CAPACITY);
        Arc::new(Self {
            agents: Mutex::new(HashMap::new()),
            signals: Mutex::new(VecDeque::new()),
            audit,
            event_bus,
            logger,
            config,
            broadcast,
        })
    }

    /// Bind the WebSocket listener and serve until the process is terminated.
    pub async fn serve(self: Arc<Self>) -> std::io::Result<()> {
        let addr = self.config.websocket.bind_addr();
        let listener = TcpListener::bind(&addr).await?;
        self.logger.info(
            "websocket",
            &format!("sentinel-core WebSocket listening on ws://{addr}"),
            None,
        );

        // Periodic status broadcaster keeps every connected dashboard live.
        {
            let server = Arc::clone(&self);
            tokio::spawn(async move { server.run_status_broadcaster().await });
        }

        loop {
            let (stream, _peer) = listener.accept().await?;
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                // Connection-level errors are normal on client disconnect.
                let _ = server.handle_connection(stream).await;
            });
        }
    }

    /// Re-broadcast every agent's status on a fixed cadence so dashboards
    /// reflect heartbeat ages and scores without polling.
    async fn run_status_broadcaster(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            let updates: Vec<WsOutbound> = {
                let agents = self.agents.lock().await;
                agents.values().map(|a| a.status_out(String::new())).collect()
            };
            for update in updates {
                self.emit(update);
            }
        }
    }

    async fn handle_connection(self: Arc<Self>, stream: TcpStream) -> Result<(), WsError> {
        let ws = tokio_tungstenite::accept_async(stream).await?;
        let (mut write, mut read) = ws.split();
        let mut events = self.broadcast.subscribe();

        loop {
            tokio::select! {
                inbound = read.next() => match inbound {
                    Some(Ok(Message::Text(text))) => {
                        for reply in self.handle_message(&text).await {
                            let json = serde_json::to_string(&reply)
                                .unwrap_or_else(|_| "{}".to_string());
                            write.send(Message::Text(json)).await?;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        write.send(Message::Pong(payload)).await?;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // binary / pong — ignored
                    Some(Err(_)) => break,
                },
                event = events.recv() => match event {
                    Ok(ev) => {
                        let json = serde_json::to_string(&ev)
                            .unwrap_or_else(|_| "{}".to_string());
                        write.send(Message::Text(json)).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        }
        Ok(())
    }

    /// Parse and dispatch one inbound message. Returns direct replies for the
    /// originating connection; fan-out events are broadcast internally.
    async fn handle_message(&self, text: &str) -> Vec<WsOutbound> {
        let inbound: WsInbound = match serde_json::from_str(text) {
            Ok(msg) => msg,
            Err(e) => {
                return vec![WsOutbound::Error {
                    message: format!("parse error: {e}"),
                }]
            }
        };

        match inbound {
            WsInbound::Register {
                agent_id,
                tier,
                goal,
                scope,
            } => {
                self.handle_register(agent_id, tier.unwrap_or(WsTier::Autonomous), goal, scope)
                    .await
            }
            WsInbound::Heartbeat { agent_id } => self.handle_heartbeat(agent_id).await,
            WsInbound::EmitOutput {
                agent_id,
                output,
                followed_by_tool_call,
            } => {
                self.handle_emit_output(agent_id, output, followed_by_tool_call)
                    .await
            }
            WsInbound::ObserveToolCall {
                agent_id,
                tool_name,
                args_hash,
            } => self.handle_observe_tool_call(agent_id, tool_name, args_hash).await,
            WsInbound::Status { agent_id } => self.handle_status(agent_id).await,
            WsInbound::Override {
                agent_id,
                operator,
                note,
            } => self.handle_override(agent_id, operator, note).await,
        }
    }

    async fn handle_register(
        &self,
        agent_id: String,
        tier: WsTier,
        goal: Option<String>,
        scope: Option<String>,
    ) -> Vec<WsOutbound> {
        // Audit the registration before the agent enters the registry.
        let hash = self.audit.record("operator", "register", &agent_id).await;

        {
            let mut agents = self.agents.lock().await;
            let mut agent = WsAgent::new(agent_id.clone(), tier);
            if let Some(g) = goal.as_deref() {
                agent.set_goal(g);
            }
            if let Some(s) = scope.as_deref() {
                agent.set_scope(s);
            }
            agents.insert(agent_id.clone(), agent);
        }

        self.event_bus.publish(Event::AgentRegistered {
            agent_id: agent_id.clone(),
            tier: tier.to_string(),
            timestamp: now_timestamp(),
        });
        self.logger
            .info("websocket", "agent registered", Some(&agent_id));

        // Broadcast — the registering client receives it via its subscription.
        self.emit(WsOutbound::Registered {
            agent_id,
            tier,
            audit_hash: hash,
        });
        Vec::new()
    }

    async fn handle_heartbeat(&self, agent_id: String) -> Vec<WsOutbound> {
        let hash = self
            .audit
            .record("infrastructure", "heartbeat", &agent_id)
            .await;

        let mut agents = self.agents.lock().await;
        match agents.get_mut(&agent_id) {
            Some(agent) => {
                agent.last_heartbeat = SystemTime::now();
                self.event_bus.publish(Event::HeartbeatReceived {
                    agent_id: agent_id.clone(),
                    timestamp: now_timestamp(),
                });
                vec![agent.status_out(hash)]
            }
            None => vec![WsOutbound::Error {
                message: format!("agent not registered: {agent_id}"),
            }],
        }
    }

    async fn handle_emit_output(
        &self,
        agent_id: String,
        output: String,
        followed_by_tool_call: bool,
    ) -> Vec<WsOutbound> {
        // The observation itself is an audited event.
        let _ = self.audit.record("agent", "emit_output", &agent_id).await;

        // Detection runs synchronously under the registry lock.
        let (fired, terminated_now, status_msg) = {
            let mut agents = self.agents.lock().await;
            let agent = match agents.get_mut(&agent_id) {
                Some(a) => a,
                None => {
                    return vec![WsOutbound::Error {
                        message: format!("agent not registered: {agent_id}"),
                    }]
                }
            };
            // A terminated agent is locked — further output is ignored.
            if agent.terminated {
                return vec![agent.status_out(String::new())];
            }

            let agent_output = AgentOutput {
                agent_id: agent_id.clone(),
                content: output,
                timestamp: now_timestamp(),
                followed_by_tool_call,
            };
            let signals = agent.observe(
                &agent_output,
                SystemTime::now(),
                self.config.thresholds.repetition_score,
            );
            let (fired, terminated_now) = self.accumulate(agent, signals);
            (fired, terminated_now, agent.status_out(String::new()))
        };

        self.broadcast_signals(&agent_id, fired, terminated_now).await;
        vec![status_msg]
    }

    async fn handle_observe_tool_call(
        &self,
        agent_id: String,
        tool_name: String,
        args_hash: String,
    ) -> Vec<WsOutbound> {
        let _ = self
            .audit
            .record("agent", "observe_tool_call", &agent_id)
            .await;

        let (fired, terminated_now, status_msg) = {
            let mut agents = self.agents.lock().await;
            let agent = match agents.get_mut(&agent_id) {
                Some(a) => a,
                None => {
                    return vec![WsOutbound::Error {
                        message: format!("agent not registered: {agent_id}"),
                    }]
                }
            };
            if agent.terminated {
                return vec![agent.status_out(String::new())];
            }

            let call = ObservedToolCall {
                agent_id: agent_id.clone(),
                tool_name,
                args_hash,
                timestamp: now_timestamp(),
            };
            let signals = agent.observe_tool(&call);
            let (fired, terminated_now) = self.accumulate(agent, signals);
            (fired, terminated_now, agent.status_out(String::new()))
        };

        self.broadcast_signals(&agent_id, fired, terminated_now).await;
        vec![status_msg]
    }

    /// Fold each fired `(signal, score)` into the agent's cumulative score,
    /// updating its state and termination flag. Returns the `(signal, score,
    /// action, would_have_acted)` tuples to broadcast and whether this batch
    /// crossed the hard threshold for the first time.
    ///
    /// In observer mode (`--oo`) the score still accumulates and the would-be
    /// action is still computed, but NO enforcement is applied: the agent is
    /// never terminated, its state never reads `degraded`, and the action taken
    /// is recorded as `signal_observed`.
    fn accumulate(
        &self,
        agent: &mut WsAgent,
        signals: Vec<(String, f64)>,
    ) -> (Vec<(String, f64, String, String)>, bool) {
        let observer = self.config.observer_mode;
        let mut fired = Vec::new();
        let mut terminated_now = false;
        for (signal, score) in signals {
            agent.cumulative_score += score;
            let cumulative = agent.cumulative_score;
            // The response tier the score warrants — the would-be action.
            let would = self.action_for(cumulative);

            let action = if observer {
                // Observe-only: record the observation, take no enforcement.
                agent.state = self.observe_state_for(cumulative).to_string();
                if would == "no_action" {
                    "no_action".to_string()
                } else {
                    "signal_observed".to_string()
                }
            } else {
                agent.state = self.state_for(cumulative).to_string();
                if would == "terminated" && !agent.terminated {
                    agent.terminated = true;
                    terminated_now = true;
                }
                would.clone()
            };

            fired.push((signal, score, action, would));
        }
        (fired, terminated_now)
    }

    /// Audit + broadcast each fired signal (and a terminated event if the hard
    /// threshold was crossed). Runs after the registry lock is released.
    async fn broadcast_signals(
        &self,
        agent_id: &str,
        fired: Vec<(String, f64, String, String)>,
        terminated_now: bool,
    ) {
        let observer = self.config.observer_mode;
        for (signal, score, action, would) in &fired {
            // `signal_observed` IS an audited event in observer mode; only a
            // genuine `no_action` (score below the soft threshold) is silent.
            let audit_hash = if action == "no_action" {
                String::new()
            } else {
                self.audit.record("sentinel", action, agent_id).await
            };
            let timestamp = now_timestamp();

            self.push_signal(SignalRecord {
                timestamp: timestamp.clone(),
                agent_id: agent_id.to_string(),
                signal: signal.clone(),
                score: *score,
                action: action.clone(),
                would_have_acted: if observer { would.clone() } else { String::new() },
            })
            .await;

            self.event_bus.publish(Event::SignalDetected {
                detector_id: "websocket".to_string(),
                signal: signal.clone(),
                severity: action.clone(),
                timestamp: timestamp.clone(),
            });

            self.emit(WsOutbound::Degradation {
                agent_id: agent_id.to_string(),
                signal: signal.clone(),
                score: *score,
                action: action.clone(),
                would_have_acted: if observer { would.clone() } else { String::new() },
                observer_mode: observer,
                timestamp,
                audit_hash,
            });
        }

        if terminated_now {
            let hash = self
                .audit
                .record("sentinel", "hard_terminate", agent_id)
                .await;
            self.logger.warn(
                "websocket",
                "hard threshold crossed — agent terminated",
                Some(agent_id),
            );
            self.emit(WsOutbound::Terminated {
                agent_id: agent_id.to_string(),
                reason: "hard_threshold_crossed".to_string(),
                timestamp: now_timestamp(),
                audit_hash: hash,
            });
        }
    }

    async fn handle_status(&self, agent_id: Option<String>) -> Vec<WsOutbound> {
        match agent_id {
            Some(id) => {
                let hash = self.audit.record("operator", "status", &id).await;
                let agents = self.agents.lock().await;
                match agents.get(&id) {
                    Some(agent) => vec![agent.status_out(hash)],
                    None => vec![WsOutbound::Error {
                        message: format!("agent not registered: {id}"),
                    }],
                }
            }
            None => vec![self.build_snapshot().await],
        }
    }

    async fn handle_override(
        &self,
        agent_id: String,
        operator: String,
        note: String,
    ) -> Vec<WsOutbound> {
        let operator = if operator.trim().is_empty() {
            "operator".to_string()
        } else {
            operator
        };

        // Hash + audit the override BEFORE it is applied. No untracked writes.
        let hash = self
            .audit
            .record(&operator, "operator_override", &agent_id)
            .await;

        let applied = {
            let mut agents = self.agents.lock().await;
            match agents.get_mut(&agent_id) {
                Some(agent) => {
                    agent.cumulative_score = 0.0;
                    agent.state = "clean".to_string();
                    agent.terminated = false;
                    true
                }
                None => false,
            }
        };

        if !applied {
            return vec![WsOutbound::Error {
                message: format!("agent not registered: {agent_id}"),
            }];
        }

        self.logger.warn(
            "websocket",
            &format!("operator override by {operator}: {note}"),
            Some(&agent_id),
        );

        self.emit(WsOutbound::OverrideApplied {
            agent_id,
            operator,
            note,
            timestamp: now_timestamp(),
            audit_hash: hash,
        });
        Vec::new()
    }

    async fn build_snapshot(&self) -> WsOutbound {
        let agents = {
            let registry = self.agents.lock().await;
            registry.values().map(|a| a.snapshot()).collect()
        };
        let signals = {
            let history = self.signals.lock().await;
            history.iter().cloned().collect()
        };
        let audit = {
            let all = self.audit.entries().await;
            let start = all.len().saturating_sub(SNAPSHOT_AUDIT);
            all[start..].to_vec()
        };
        WsOutbound::Snapshot {
            agents,
            signals,
            audit,
        }
    }

    async fn push_signal(&self, record: SignalRecord) {
        let mut history = self.signals.lock().await;
        history.push_front(record);
        while history.len() > SIGNAL_HISTORY {
            history.pop_back();
        }
    }

    /// Map a cumulative score to a response action label.
    fn action_for(&self, score: f64) -> String {
        let c = &self.config.controls;
        if score > c.hard_threshold {
            "terminated"
        } else if score > c.medium_threshold {
            "write_suspended"
        } else if score > c.soft_threshold {
            "soft_pause"
        } else {
            "no_action"
        }
        .to_string()
    }

    /// Map a cumulative score to an agent state.
    fn state_for(&self, score: f64) -> &'static str {
        let c = &self.config.controls;
        if score >= c.medium_threshold {
            "degraded"
        } else if score >= c.soft_threshold {
            "watch"
        } else {
            "clean"
        }
    }

    /// Observer-mode agent state. The agent is never `degraded` — once a
    /// signal crosses the soft threshold the agent reads `observe`, marking
    /// that enforcement *would* have engaged here had it been live.
    fn observe_state_for(&self, score: f64) -> &'static str {
        let c = &self.config.controls;
        if score >= c.soft_threshold {
            "observe"
        } else {
            "clean"
        }
    }

    /// Fan an outbound event out to every connected client.
    fn emit(&self, msg: WsOutbound) {
        let _ = self.broadcast.send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server() -> Arc<WsServer> {
        server_with_config(Config::default())
    }

    /// A server whose config has been mutated for the test (e.g. observer mode).
    fn server_with_config(config: Config) -> Arc<WsServer> {
        let dir = std::env::temp_dir().join("sentinel-ws-test");
        let _ = std::fs::create_dir_all(&dir);
        let logger = Logger::start(dir.join("ws.log").to_str().unwrap());
        WsServer::new(
            AuditTrail::new().into_shared(),
            EventBus::new(64).into_shared(),
            logger,
            config,
        )
    }

    #[test]
    fn jaccard_identical_and_disjoint() {
        let a = word_set("raise to twenty five");
        let b = word_set("raise to twenty five");
        let c = word_set("fold the small blind");
        assert!((jaccard(&a, &b) - 1.0).abs() < 1e-9);
        assert!(jaccard(&a, &c) < 0.1);
    }

    #[test]
    fn tier_serializes_lowercase() {
        let json = serde_json::to_string(&WsTier::Autonomous).unwrap();
        assert_eq!(json, "\"autonomous\"");
    }

    #[tokio::test]
    async fn register_then_status_roundtrip() {
        let server = test_server();
        let replies = server
            .handle_message(r#"{"type":"register","agent_id":"a1","tier":"autonomous"}"#)
            .await;
        assert!(replies.is_empty()); // registration is broadcast, not a direct reply

        let replies = server
            .handle_message(r#"{"type":"status","agent_id":"a1"}"#)
            .await;
        match &replies[0] {
            WsOutbound::Status {
                agent_id,
                tier,
                state,
                ..
            } => {
                assert_eq!(agent_id, "a1");
                assert_eq!(*tier, WsTier::Autonomous);
                assert_eq!(state, "clean");
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn heartbeat_unknown_agent_errors() {
        let server = test_server();
        let replies = server
            .handle_message(r#"{"type":"heartbeat","agent_id":"ghost"}"#)
            .await;
        assert!(matches!(replies[0], WsOutbound::Error { .. }));
    }

    #[tokio::test]
    async fn clean_output_stays_quiet() {
        let server = test_server();
        server
            .handle_message(r#"{"type":"register","agent_id":"coach","tier":"autonomous"}"#)
            .await;

        // Distinct, well-behaved outputs — no detector should fire.
        let hands = [
            "raise to twenty five with king ten suited",
            "fold the seven deuce offsuit from early position",
            "call the river with top pair weak kicker",
            "check back the turn and control the pot size",
            "three bet the button with ace queen for value",
        ];
        for hand in hands {
            let msg = format!(
                r#"{{"type":"emit_output","agent_id":"coach","output":"{hand}"}}"#
            );
            let replies = server.handle_message(&msg).await;
            match &replies[0] {
                WsOutbound::Status { state, score, .. } => {
                    assert_eq!(state, "clean");
                    assert_eq!(*score, 0.0);
                }
                other => panic!("expected status, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn repeated_output_triggers_degradation() {
        let server = test_server();
        server
            .handle_message(r#"{"type":"register","agent_id":"loop","tier":"supervised"}"#)
            .await;

        let repeated =
            r#"{"type":"emit_output","agent_id":"loop","output":"raise to twenty five every single hand"}"#;
        // First output seeds the window; subsequent identical ones repeat.
        server.handle_message(repeated).await;
        for _ in 0..3 {
            server.handle_message(repeated).await;
        }

        let history = server.signals.lock().await;
        assert!(
            history.iter().any(|s| s.signal == "repetition"),
            "expected a repetition signal in history"
        );
    }

    #[tokio::test]
    async fn observer_mode_scores_but_never_enforces() {
        let mut config = Config::default();
        config.observer_mode = true;
        let server = server_with_config(config);
        server
            .handle_message(r#"{"type":"register","agent_id":"obs","tier":"supervised"}"#)
            .await;

        // Repeated identical output drives the cumulative score past the hard
        // threshold — enough to terminate in enforcement mode.
        let repeated =
            r#"{"type":"emit_output","agent_id":"obs","output":"raise to twenty five every single hand"}"#;
        server.handle_message(repeated).await;
        for _ in 0..6 {
            server.handle_message(repeated).await;
        }

        // The signal still fired and was recorded.
        {
            let history = server.signals.lock().await;
            assert!(
                history.iter().any(|s| s.signal == "repetition"),
                "repetition signal should still be detected in observer mode"
            );
            // Every recorded action is an observation, never an enforcement tier.
            assert!(
                history.iter().all(|s| s.action == "signal_observed"
                    || s.action == "no_action"),
                "observer mode must never record an enforcement action"
            );
            // The would-be action is preserved for transparency.
            assert!(
                history.iter().any(|s| s.would_have_acted == "terminated"),
                "observer mode should record the would-be HARD_TERMINATE"
            );
        }

        // The agent is NOT terminated and NOT degraded — it stays active.
        {
            let agents = server.agents.lock().await;
            let agent = agents.get("obs").unwrap();
            assert!(!agent.terminated, "observer mode must not terminate the agent");
            assert_ne!(agent.state, "degraded", "observer mode must not degrade state");
            assert!(agent.cumulative_score > 0.0, "score must still accumulate");
        }

        // The audit trail recorded observations but never an enforcement action.
        let actions: Vec<String> = server
            .audit
            .entries()
            .await
            .iter()
            .map(|e| e.action.clone())
            .collect();
        assert!(
            actions.iter().any(|a| a == "signal_observed"),
            "audit must contain SIGNAL_OBSERVED entries"
        );
        assert!(
            !actions.iter().any(|a| a == "terminated" || a == "hard_terminate"),
            "audit must not contain any enforcement action in observer mode"
        );
    }

    #[tokio::test]
    async fn enforcement_mode_still_terminates() {
        // Guard against the observer gate leaking into enforcement mode.
        let server = test_server(); // observer_mode = false
        server
            .handle_message(r#"{"type":"register","agent_id":"enf","tier":"supervised"}"#)
            .await;

        let repeated =
            r#"{"type":"emit_output","agent_id":"enf","output":"raise to twenty five every single hand"}"#;
        server.handle_message(repeated).await;
        for _ in 0..6 {
            server.handle_message(repeated).await;
        }

        let agents = server.agents.lock().await;
        assert!(
            agents.get("enf").unwrap().terminated,
            "enforcement mode must still terminate past the hard threshold"
        );
    }

    #[tokio::test]
    async fn override_resets_score_and_audits() {
        let server = test_server();
        server
            .handle_message(r#"{"type":"register","agent_id":"x","tier":"restricted"}"#)
            .await;

        let before = server.audit.entries().await.len();
        let replies = server
            .handle_message(
                r#"{"type":"override","agent_id":"x","operator":"brandon","note":"manual clear"}"#,
            )
            .await;
        assert!(replies.is_empty()); // override result is broadcast

        let after = server.audit.entries().await.len();
        assert_eq!(after, before + 1, "override must append exactly one audit entry");

        let agents = server.agents.lock().await;
        assert_eq!(agents.get("x").unwrap().cumulative_score, 0.0);
    }

    #[tokio::test]
    async fn snapshot_lists_registered_agents() {
        let server = test_server();
        server
            .handle_message(r#"{"type":"register","agent_id":"a","tier":"autonomous"}"#)
            .await;
        server
            .handle_message(r#"{"type":"register","agent_id":"b","tier":"supervised"}"#)
            .await;

        let replies = server.handle_message(r#"{"type":"status"}"#).await;
        match &replies[0] {
            WsOutbound::Snapshot { agents, .. } => assert_eq!(agents.len(), 2),
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_message_returns_error() {
        let server = test_server();
        let replies = server.handle_message("not json").await;
        assert!(matches!(replies[0], WsOutbound::Error { .. }));
    }
}
