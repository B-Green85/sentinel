use std::collections::HashMap;

use sentinel_types::{
    AgentOutput, DegradationEvent, ObservedToolCall, SignalThresholds, TaskStateMarker,
    WindowConfig,
};

use crate::detectors::{
    RepetitionDetector, SelfReferentialDetector, TokenVelocityDetector, ToolRetryDetector,
};

/// Per-agent detector state.
struct AgentDetectors {
    repetition: RepetitionDetector,
    self_referential: SelfReferentialDetector,
    velocity: TokenVelocityDetector,
    tool_retry: ToolRetryDetector,
}

impl AgentDetectors {
    fn new(window_config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            repetition: RepetitionDetector::new(window_config, thresholds),
            self_referential: SelfReferentialDetector::new(window_config, thresholds),
            velocity: TokenVelocityDetector::new(window_config, thresholds),
            tool_retry: ToolRetryDetector::new(window_config, thresholds),
        }
    }
}

/// The signal detection engine. Accepts external observations and emits
/// DegradationEvents when thresholds are exceeded.
///
/// All detection is passive — no instrumentation inside the agent process.
/// All logic is pure and deterministic — no ML, no inference.
pub struct SignalEngine {
    agents: HashMap<String, AgentDetectors>,
    window_config: WindowConfig,
    thresholds: SignalThresholds,
}

impl SignalEngine {
    pub fn new(window_config: WindowConfig, thresholds: SignalThresholds) -> Self {
        Self {
            agents: HashMap::new(),
            window_config,
            thresholds,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(WindowConfig::default(), SignalThresholds::default())
    }

    fn get_or_create(&mut self, agent_id: &str) -> &mut AgentDetectors {
        self.agents
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentDetectors::new(&self.window_config, &self.thresholds))
    }

    /// Process an observed agent output. Returns any triggered signals.
    pub fn observe_output(&mut self, output: &AgentOutput) -> Vec<DegradationEvent> {
        let detectors = self.get_or_create(&output.agent_id);
        let mut events = Vec::new();

        if let Some(evt) = detectors.repetition.ingest(output) {
            events.push(evt);
        }
        if let Some(evt) = detectors.self_referential.ingest(output) {
            events.push(evt);
        }
        detectors.velocity.observe_output(output);
        if let Some(evt) =
            detectors
                .velocity
                .evaluate(&output.agent_id, &output.timestamp)
        {
            events.push(evt);
        }

        events
    }

    /// Process an observed tool call. Returns any triggered signals.
    pub fn observe_tool_call(&mut self, call: &ObservedToolCall) -> Vec<DegradationEvent> {
        let detectors = self.get_or_create(&call.agent_id);
        let mut events = Vec::new();

        if let Some(evt) = detectors.tool_retry.ingest(call) {
            events.push(evt);
        }

        events
    }

    /// Record a task state progression marker.
    pub fn observe_state(&mut self, marker: &TaskStateMarker) {
        let detectors = self.get_or_create(&marker.agent_id);
        detectors.velocity.observe_state(marker);
    }

    /// Remove all state for an agent (e.g., after hard termination).
    pub fn remove_agent(&mut self, agent_id: &str) {
        self.agents.remove(agent_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_output(agent_id: &str, content: &str, followed_by_tool: bool) -> AgentOutput {
        AgentOutput {
            agent_id: agent_id.to_string(),
            content: content.to_string(),
            timestamp: "2026-03-18T00:00:00Z".to_string(),
            followed_by_tool_call: followed_by_tool,
        }
    }

    #[test]
    fn engine_isolates_agents() {
        let mut engine = SignalEngine::with_defaults();
        let out_a = make_output("agent-a", "hello world", true);
        let out_b = make_output("agent-b", "different content", true);
        engine.observe_output(&out_a);
        engine.observe_output(&out_b);
        assert_eq!(engine.agents.len(), 2);
    }

    #[test]
    fn engine_detects_repetition() {
        let mut engine = SignalEngine::with_defaults();
        let content = "the quick brown fox jumps over the lazy dog repeatedly";
        for _ in 0..5 {
            engine.observe_output(&make_output("agent-a", content, true));
        }
        let events = engine.observe_output(&make_output("agent-a", content, true));
        assert!(!events.is_empty());
    }

    #[test]
    fn engine_detects_tool_retry() {
        let mut engine = SignalEngine::with_defaults();
        let call = ObservedToolCall {
            agent_id: "agent-a".to_string(),
            tool_name: "bash".to_string(),
            args_hash: "deadbeef".to_string(),
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        };
        engine.observe_tool_call(&call);
        engine.observe_tool_call(&call);
        let events = engine.observe_tool_call(&call);
        assert!(!events.is_empty());
    }

    #[test]
    fn engine_remove_agent() {
        let mut engine = SignalEngine::with_defaults();
        engine.observe_output(&make_output("agent-a", "test", true));
        assert!(engine.agents.contains_key("agent-a"));
        engine.remove_agent("agent-a");
        assert!(!engine.agents.contains_key("agent-a"));
    }

    #[test]
    fn engine_observe_state() {
        let mut engine = SignalEngine::with_defaults();
        engine.observe_state(&TaskStateMarker {
            agent_id: "agent-a".to_string(),
            state_id: "state-1".to_string(),
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        });
        assert!(engine.agents.contains_key("agent-a"));
    }
}
