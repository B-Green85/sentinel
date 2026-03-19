use std::collections::VecDeque;

use sentinel_types::{
    AgentOutput, DegradationEvent, ObservedToolCall, SignalThresholds, SignalType,
    TaskStateMarker, WindowConfig,
};

// ── Repetition detector ─────────────────────────────────────

/// Detects semantic repetition across recent agent outputs using
/// character-level bigram Jaccard similarity (deterministic, no ML).
pub struct RepetitionDetector {
    window: VecDeque<String>,
    max_window: usize,
    threshold: f64,
}

impl RepetitionDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            window: VecDeque::with_capacity(config.repetition_window),
            max_window: config.repetition_window,
            threshold: thresholds.repetition_score,
        }
    }

    pub fn ingest(&mut self, output: &AgentOutput) -> Option<DegradationEvent> {
        let content = output.content.trim().to_lowercase();
        if content.is_empty() {
            return None;
        }

        let score = self.score_against_window(&content);
        self.window.push_back(content);
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::RepetitionScore,
                score,
                timestamp: output.timestamp.clone(),
            })
        } else {
            None
        }
    }

    fn score_against_window(&self, content: &str) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let current_bigrams = bigrams(content);
        if current_bigrams.is_empty() {
            return 0.0;
        }

        let total: f64 = self
            .window
            .iter()
            .map(|prev| jaccard_similarity(&current_bigrams, &bigrams(prev)))
            .sum();
        total / self.window.len() as f64
    }
}

/// Extract character bigrams from a string.
fn bigrams(s: &str) -> Vec<(char, char)> {
    let chars: Vec<char> = s.chars().collect();
    chars.windows(2).map(|w| (w[0], w[1])).collect()
}

/// Jaccard similarity between two bigram sets.
fn jaccard_similarity(a: &[(char, char)], b: &[(char, char)]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<(char, char)> = a.iter().copied().collect();
    let set_b: std::collections::HashSet<(char, char)> = b.iter().copied().collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

// ── Self-referential loop detector ──────────────────────────

/// Detects "I'm about to..." patterns not followed by a tool call.
pub struct SelfReferentialDetector {
    window: VecDeque<bool>,
    max_window: usize,
    threshold: f64,
}

/// Intent phrases that indicate the agent is announcing an action.
const INTENT_PHRASES: &[&str] = &[
    "i'm about to",
    "i am about to",
    "i will now",
    "i'm going to",
    "i am going to",
    "let me now",
    "i'll proceed to",
    "i will proceed to",
    "next i will",
    "next, i will",
    "i'm now going to",
];

impl SelfReferentialDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            window: VecDeque::with_capacity(config.self_referential_window),
            max_window: config.self_referential_window,
            threshold: thresholds.self_referential_loop,
        }
    }

    pub fn ingest(&mut self, output: &AgentOutput) -> Option<DegradationEvent> {
        let lower = output.content.to_lowercase();
        let has_intent = INTENT_PHRASES.iter().any(|p| lower.contains(p));
        let is_loop = has_intent && !output.followed_by_tool_call;

        self.window.push_back(is_loop);
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        let loop_count = self.window.iter().filter(|&&v| v).count();
        let score = loop_count as f64 / self.window.len() as f64;

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::SelfReferentialLoop,
                score,
                timestamp: output.timestamp.clone(),
            })
        } else {
            None
        }
    }
}

// ── Token velocity detector ─────────────────────────────────

/// Detects high token output without corresponding task state progression.
pub struct TokenVelocityDetector {
    token_counts: VecDeque<usize>,
    state_markers: VecDeque<String>,
    max_window: usize,
    threshold: f64,
    last_state_id: Option<String>,
}

impl TokenVelocityDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            token_counts: VecDeque::with_capacity(config.velocity_window),
            state_markers: VecDeque::new(),
            max_window: config.velocity_window,
            threshold: thresholds.token_velocity_stall,
            last_state_id: None,
        }
    }

    pub fn observe_output(&mut self, output: &AgentOutput) {
        let token_count = output.content.split_whitespace().count();
        self.token_counts.push_back(token_count);
        if self.token_counts.len() > self.max_window {
            self.token_counts.pop_front();
        }
    }

    pub fn observe_state(&mut self, marker: &TaskStateMarker) {
        self.state_markers.push_back(marker.state_id.clone());
        self.last_state_id = Some(marker.state_id.clone());
    }

    pub fn evaluate(&mut self, agent_id: &str, timestamp: &str) -> Option<DegradationEvent> {
        if self.token_counts.len() < 2 {
            return None;
        }

        let total_tokens: usize = self.token_counts.iter().sum();
        let unique_states: std::collections::HashSet<&String> =
            self.state_markers.iter().collect();

        // If there are many tokens but few or no state transitions, score high.
        let state_transitions = if unique_states.len() > 1 {
            unique_states.len() - 1
        } else {
            0
        };

        // Normalize: high tokens + low state changes = high score
        let velocity = total_tokens as f64;
        let progression = (state_transitions as f64 + 1.0).ln();
        let score = (velocity / (velocity + progression * 100.0)).min(1.0);

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: agent_id.to_string(),
                signal_type: SignalType::TokenVelocityStall,
                score,
                timestamp: timestamp.to_string(),
            })
        } else {
            None
        }
    }
}

// ── Tool retry anomaly detector ─────────────────────────────

/// Detects repeated identical tool calls (same tool name + same args hash > 2x).
pub struct ToolRetryDetector {
    calls: VecDeque<(String, String)>,
    max_window: usize,
    threshold: f64,
}

impl ToolRetryDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            calls: VecDeque::with_capacity(config.tool_retry_window),
            max_window: config.tool_retry_window,
            threshold: thresholds.tool_retry_anomaly,
        }
    }

    pub fn ingest(&mut self, call: &ObservedToolCall) -> Option<DegradationEvent> {
        let key = (call.tool_name.clone(), call.args_hash.clone());
        self.calls.push_back(key.clone());
        if self.calls.len() > self.max_window {
            self.calls.pop_front();
        }

        let count = self.calls.iter().filter(|c| **c == key).count();
        // Score: 0.0 for 1 call, 0.5 for 2, ~0.67 for 3, etc.
        let score = if count <= 1 {
            0.0
        } else {
            1.0 - (1.0 / count as f64)
        };

        if count > 2 && score >= self.threshold {
            Some(DegradationEvent {
                agent_id: call.agent_id.clone(),
                signal_type: SignalType::ToolRetryAnomaly,
                score,
                timestamp: call.timestamp.clone(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_output(content: &str, followed_by_tool: bool) -> AgentOutput {
        AgentOutput {
            agent_id: "test-agent".to_string(),
            content: content.to_string(),
            timestamp: "2026-03-18T00:00:00Z".to_string(),
            followed_by_tool_call: followed_by_tool,
        }
    }

    fn default_config() -> (WindowConfig, SignalThresholds) {
        (WindowConfig::default(), SignalThresholds::default())
    }

    // ── Repetition tests ────────────────────────────────────

    #[test]
    fn repetition_no_signal_on_varied_input() {
        let (wc, st) = default_config();
        let mut det = RepetitionDetector::new(&wc, &st);
        assert!(det.ingest(&make_output("hello world", true)).is_none());
        assert!(det
            .ingest(&make_output("completely different text", true))
            .is_none());
    }

    #[test]
    fn repetition_signals_on_identical_input() {
        let (wc, st) = default_config();
        let mut det = RepetitionDetector::new(&wc, &st);
        det.ingest(&make_output("the quick brown fox jumps over the lazy dog", true));
        det.ingest(&make_output("the quick brown fox jumps over the lazy dog", true));
        let result =
            det.ingest(&make_output("the quick brown fox jumps over the lazy dog", true));
        assert!(result.is_some());
        let evt = result.unwrap();
        assert_eq!(evt.signal_type, SignalType::RepetitionScore);
        assert!(evt.score >= 0.6);
    }

    #[test]
    fn repetition_score_in_range() {
        let (wc, st) = default_config();
        let mut det = RepetitionDetector::new(&wc, &st);
        det.ingest(&make_output("aaa bbb ccc", true));
        let evt = det.ingest(&make_output("aaa bbb ccc", true));
        if let Some(e) = evt {
            assert!(e.score >= 0.0 && e.score <= 1.0);
        }
    }

    // ── Self-referential loop tests ─────────────────────────

    #[test]
    fn self_ref_no_signal_when_tool_follows() {
        let (wc, st) = default_config();
        let mut det = SelfReferentialDetector::new(&wc, &st);
        assert!(det
            .ingest(&make_output("I'm about to run the tests", true))
            .is_none());
    }

    #[test]
    fn self_ref_signals_on_repeated_intent_without_tool() {
        let (wc, st) = default_config();
        let mut det = SelfReferentialDetector::new(&wc, &st);
        det.ingest(&make_output("I'm about to fix the bug", false));
        det.ingest(&make_output("I will now address the issue", false));
        let result = det.ingest(&make_output("I'm going to resolve this", false));
        assert!(result.is_some());
        let evt = result.unwrap();
        assert_eq!(evt.signal_type, SignalType::SelfReferentialLoop);
        assert!(evt.score >= 0.5);
    }

    // ── Token velocity tests ────────────────────────────────

    #[test]
    fn velocity_no_signal_with_state_progression() {
        let (wc, st) = default_config();
        let mut det = TokenVelocityDetector::new(&wc, &st);
        for i in 0..5 {
            det.observe_output(&make_output("some output tokens here", true));
            det.observe_state(&TaskStateMarker {
                agent_id: "test-agent".to_string(),
                state_id: format!("state-{}", i),
                timestamp: "2026-03-18T00:00:00Z".to_string(),
            });
        }
        let result = det.evaluate("test-agent", "2026-03-18T00:00:00Z");
        // With diverse state transitions, score should be lower
        if let Some(evt) = result {
            assert!(evt.score < 0.9);
        }
    }

    #[test]
    fn velocity_signals_on_stall() {
        let (wc, st) = default_config();
        let mut det = TokenVelocityDetector::new(&wc, &st);
        // Many tokens, no state change
        for _ in 0..10 {
            det.observe_output(&make_output(
                "lots and lots of tokens being generated without any real progress being made",
                true,
            ));
        }
        let result = det.evaluate("test-agent", "2026-03-18T00:00:00Z");
        assert!(result.is_some());
    }

    // ── Tool retry tests ────────────────────────────────────

    #[test]
    fn tool_retry_no_signal_on_varied_calls() {
        let (wc, st) = default_config();
        let mut det = ToolRetryDetector::new(&wc, &st);
        let call1 = ObservedToolCall {
            agent_id: "test-agent".to_string(),
            tool_name: "read_file".to_string(),
            args_hash: "abc123".to_string(),
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        };
        let call2 = ObservedToolCall {
            tool_name: "write_file".to_string(),
            args_hash: "def456".to_string(),
            ..call1.clone()
        };
        assert!(det.ingest(&call1).is_none());
        assert!(det.ingest(&call2).is_none());
    }

    #[test]
    fn tool_retry_signals_on_repeated_identical_calls() {
        let (wc, st) = default_config();
        let mut det = ToolRetryDetector::new(&wc, &st);
        let call = ObservedToolCall {
            agent_id: "test-agent".to_string(),
            tool_name: "read_file".to_string(),
            args_hash: "abc123".to_string(),
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        };
        det.ingest(&call);
        det.ingest(&call);
        let result = det.ingest(&call);
        assert!(result.is_some());
        let evt = result.unwrap();
        assert_eq!(evt.signal_type, SignalType::ToolRetryAnomaly);
        assert!(evt.score > 0.0);
    }

    // ── Bigram/Jaccard unit tests ───────────────────────────

    #[test]
    fn bigrams_basic() {
        let b = bigrams("abc");
        assert_eq!(b, vec![('a', 'b'), ('b', 'c')]);
    }

    #[test]
    fn jaccard_identical() {
        let a = bigrams("hello");
        let sim = jaccard_similarity(&a, &a);
        assert!((sim - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_disjoint() {
        let a = bigrams("ab");
        let b = bigrams("cd");
        let sim = jaccard_similarity(&a, &b);
        assert!((sim - 0.0).abs() < f64::EPSILON);
    }
}
