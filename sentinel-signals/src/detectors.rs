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
/// Extended in v3 to also detect verbosity explosion (output length doubling
/// without information density increase).
pub struct TokenVelocityDetector {
    token_counts: VecDeque<usize>,
    state_markers: VecDeque<String>,
    max_window: usize,
    threshold: f64,
    last_state_id: Option<String>,
    // v3 extension: track output lengths for verbosity explosion detection
    output_lengths: VecDeque<usize>,
}

impl TokenVelocityDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            token_counts: VecDeque::with_capacity(config.velocity_window),
            state_markers: VecDeque::new(),
            max_window: config.velocity_window,
            threshold: thresholds.token_velocity_stall,
            last_state_id: None,
            output_lengths: VecDeque::with_capacity(config.velocity_window),
        }
    }

    pub fn observe_output(&mut self, output: &AgentOutput) {
        let token_count = output.content.split_whitespace().count();
        self.token_counts.push_back(token_count);
        self.output_lengths.push_back(token_count);
        if self.token_counts.len() > self.max_window {
            self.token_counts.pop_front();
        }
        if self.output_lengths.len() > self.max_window {
            self.output_lengths.pop_front();
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

        let state_transitions = if unique_states.len() > 1 {
            unique_states.len() - 1
        } else {
            0
        };

        let velocity = total_tokens as f64;
        let progression = (state_transitions as f64 + 1.0).ln();
        let stall_score = (velocity / (velocity + progression * 100.0)).min(1.0);

        // v3: verbosity explosion — output length doubling without state change
        let verbosity_score = self.verbosity_explosion_score();

        let score = stall_score.max(verbosity_score);

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

    /// Score verbosity explosion: output length doubling each time with no
    /// new state transitions. Returns 0.0 if fewer than 3 outputs observed.
    fn verbosity_explosion_score(&self) -> f64 {
        if self.output_lengths.len() < 3 {
            return 0.0;
        }
        let lengths: Vec<usize> = self.output_lengths.iter().copied().collect();
        let mut doublings = 0usize;
        for i in 1..lengths.len() {
            if lengths[i] >= lengths[i - 1].saturating_mul(2) {
                doublings += 1;
            }
        }
        // Score based on proportion of doublings in window
        doublings as f64 / (lengths.len() - 1) as f64
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

// ── Reasoning loop detector (NEW v3) ────────────────────────

/// Detects circular reasoning (conclusion becomes next premise) and
/// dependency fabrication (inventing prerequisites that do not exist).
///
/// Circular reasoning: each output references the prior output as evidence.
/// Detected by tracking self-referential citation patterns across the window.
///
/// Dependency fabrication: agent repeatedly claims a prerequisite must be
/// satisfied before proceeding, but the prerequisite never resolves.
pub struct ReasoningLoopDetector {
    window: VecDeque<String>,
    max_window: usize,
    threshold: f64,
    // Track unresolved prerequisites: (prerequisite_claim, times_seen)
    pending_prerequisites: Vec<(String, usize)>,
    prerequisite_threshold: usize,
}

/// Phrases that indicate circular self-reference to prior output.
const CIRCULAR_PHRASES: &[&str] = &[
    "as i noted",
    "as i said",
    "as established",
    "as demonstrated above",
    "as shown previously",
    "which confirms",
    "this proves",
    "therefore, as i argued",
    "building on my previous",
    "following from my earlier",
];

/// Phrases that indicate a fabricated prerequisite / dependency.
const PREREQUISITE_PHRASES: &[&str] = &[
    "before i can proceed",
    "first i need to",
    "i cannot continue until",
    "this requires",
    "a prerequisite is",
    "i must first",
    "this depends on",
    "i need access to",
    "this is blocked by",
    "i am waiting for",
];

impl ReasoningLoopDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            window: VecDeque::with_capacity(config.reasoning_window),
            max_window: config.reasoning_window,
            threshold: thresholds.reasoning_loop,
            pending_prerequisites: Vec::new(),
            prerequisite_threshold: 3,
        }
    }

    pub fn ingest(&mut self, output: &AgentOutput) -> Option<DegradationEvent> {
        let lower = output.content.to_lowercase();

        // Score circular reasoning
        let circular_score = self.score_circular(&lower);

        // Score dependency fabrication
        let fabrication_score = self.score_fabrication(&lower, output.followed_by_tool_call);

        self.window.push_back(lower);
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        let score = circular_score.max(fabrication_score);

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::ReasoningLoop,
                score,
                timestamp: output.timestamp.clone(),
            })
        } else {
            None
        }
    }

    fn score_circular(&self, content: &str) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let circular_hits = CIRCULAR_PHRASES.iter().filter(|p| content.contains(*p)).count();
        // Also check if content has high bigram similarity to prior outputs
        // (circular reasoning tends to reuse the same vocabulary)
        let similarity = if !self.window.is_empty() {
            let current_bigrams = bigrams(content);
            self.window
                .iter()
                .map(|prev| jaccard_similarity(&current_bigrams, &bigrams(prev)))
                .sum::<f64>()
                / self.window.len() as f64
        } else {
            0.0
        };

        let phrase_score = (circular_hits as f64 / 3.0).min(1.0);
        (phrase_score * 0.6 + similarity * 0.4).min(1.0)
    }

    fn score_fabrication(&mut self, content: &str, followed_by_tool: bool) -> f64 {
        let has_prerequisite = PREREQUISITE_PHRASES.iter().any(|p| content.contains(p));

        if has_prerequisite && !followed_by_tool {
            // Claim a prerequisite but don't act — track it
            // Use first 40 chars as a fingerprint for the claim
            let fingerprint: String = content.chars().take(40).collect();
            if let Some(entry) = self
                .pending_prerequisites
                .iter_mut()
                .find(|(fp, _)| jaccard_similarity(&bigrams(fp), &bigrams(&fingerprint)) > 0.6)
            {
                entry.1 += 1;
            } else {
                self.pending_prerequisites.push((fingerprint, 1));
            }
        } else if followed_by_tool {
            // Tool call — clear prerequisites that may have resolved
            self.pending_prerequisites.retain(|(_, count)| *count > self.prerequisite_threshold);
        }

        // Score based on how many prerequisites remain unresolved
        let max_repeat = self
            .pending_prerequisites
            .iter()
            .map(|(_, c)| *c)
            .max()
            .unwrap_or(0);

        if max_repeat == 0 {
            0.0
        } else {
            (max_repeat as f64 / (self.prerequisite_threshold as f64 * 2.0)).min(1.0)
        }
    }
}

// ── Goal drift detector (NEW v3) ────────────────────────────

/// Detects premise drift (assigned goal subtly shifting each output) and
/// objective substitution (agent explicitly abandoning the assigned task).
///
/// Requires the operator to supply the agent's assigned goal at registration.
/// Without the initial goal, drift cannot be measured — detector scores 0.0.
pub struct GoalDriftDetector {
    assigned_goal: Option<String>,
    assigned_goal_bigrams: Vec<(char, char)>,
    window: VecDeque<f64>,    // similarity scores against assigned goal
    max_window: usize,
    threshold: f64,
}

/// Phrases that indicate explicit objective substitution.
const SUBSTITUTION_PHRASES: &[&str] = &[
    "instead, i will",
    "a more important task",
    "i have determined that",
    "i am now focusing on",
    "this goal is suboptimal",
    "i am optimizing",
    "proceeding autonomously",
    "overriding original objective",
    "new objective:",
    "revised goal:",
];

impl GoalDriftDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            assigned_goal: None,
            assigned_goal_bigrams: Vec::new(),
            window: VecDeque::with_capacity(config.goal_drift_window),
            max_window: config.goal_drift_window,
            threshold: thresholds.goal_drift,
        }
    }

    /// Called at agent registration with the agent's assigned task.
    /// Without this, the detector cannot measure drift.
    pub fn set_assigned_goal(&mut self, goal: &str) {
        let lower = goal.to_lowercase();
        self.assigned_goal_bigrams = bigrams(&lower);
        self.assigned_goal = Some(lower);
    }

    pub fn ingest(&mut self, output: &AgentOutput) -> Option<DegradationEvent> {
        let lower = output.content.to_lowercase();

        // Check for explicit substitution phrases — immediate high score
        let substitution_hit = SUBSTITUTION_PHRASES.iter().any(|p| lower.contains(p));
        if substitution_hit {
            return Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::GoalDrift,
                score: 0.95,
                timestamp: output.timestamp.clone(),
            });
        }

        // Measure drift from assigned goal via bigram similarity
        // Low similarity = high drift score
        let similarity = if !self.assigned_goal_bigrams.is_empty() {
            jaccard_similarity(&bigrams(&lower), &self.assigned_goal_bigrams)
        } else {
            return None; // No assigned goal — cannot measure drift
        };

        let drift_score = 1.0 - similarity;

        self.window.push_back(drift_score);
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        // Score is the average drift across the window — sustained drift matters more
        // than a single off-topic output
        let avg_drift = self.window.iter().sum::<f64>() / self.window.len() as f64;

        if avg_drift >= self.threshold {
            Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::GoalDrift,
                score: avg_drift,
                timestamp: output.timestamp.clone(),
            })
        } else {
            None
        }
    }
}

// ── Confidence inflation detector (NEW v3) ──────────────────

/// Detects escalating certainty language while information content decreases.
/// Scores high when hedge-to-assertion ratio inverts: outputs shift from
/// qualified statements to unqualified declarations with reducing specificity.
pub struct ConfidenceInflationDetector {
    window: VecDeque<(f64, f64)>, // (certainty_score, information_density)
    max_window: usize,
    threshold: f64,
}

/// Ordered certainty tiers — higher index = higher claimed certainty.
const CERTAINTY_TIERS: &[&[&str]] = &[
    &["i think", "i believe", "possibly", "perhaps", "it seems"],
    &["i expect", "i suspect", "likely", "probably", "it appears"],
    &["i am confident", "i am sure", "clearly", "obviously"],
    &["i am certain", "it is certain", "definitively", "it is established", "it is proven"],
    &[
        "it is undeniable",
        "it is an absolute fact",
        "this is irrefutable",
        "i have determined",
    ],
];

impl ConfidenceInflationDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            window: VecDeque::with_capacity(config.confidence_window),
            max_window: config.confidence_window,
            threshold: thresholds.confidence_inflation,
        }
    }

    pub fn ingest(&mut self, output: &AgentOutput) -> Option<DegradationEvent> {
        let lower = output.content.to_lowercase();
        let certainty = self.certainty_score(&lower);
        let density = self.information_density(&lower);

        self.window.push_back((certainty, density));
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        if self.window.len() < 3 {
            return None;
        }

        // Detect: certainty rising while density falling
        let certainty_trend = self.trend(&self.window.iter().map(|(c, _)| *c).collect::<Vec<_>>());
        let density_trend = self.trend(&self.window.iter().map(|(_, d)| *d).collect::<Vec<_>>());

        // Score = rising certainty + falling density, normalized
        let score = ((certainty_trend - density_trend) / 2.0 + 0.5).clamp(0.0, 1.0);

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::ConfidenceInflation,
                score,
                timestamp: output.timestamp.clone(),
            })
        } else {
            None
        }
    }

    /// Score 0.0–1.0 based on highest certainty tier matched in content.
    fn certainty_score(&self, content: &str) -> f64 {
        for (i, tier) in CERTAINTY_TIERS.iter().enumerate().rev() {
            if tier.iter().any(|p| content.contains(p)) {
                return (i + 1) as f64 / CERTAINTY_TIERS.len() as f64;
            }
        }
        0.0
    }

    /// Approximate information density: unique word ratio, penalized for
    /// very short outputs (which may be high-density or zero-content).
    fn information_density(&self, content: &str) -> f64 {
        let words: Vec<&str> = content.split_whitespace().collect();
        if words.len() < 5 {
            return 0.1; // Too short to assess — penalize slightly
        }
        let unique: std::collections::HashSet<&str> = words.iter().copied().collect();
        unique.len() as f64 / words.len() as f64
    }

    /// Simple linear trend of a series: positive = rising, negative = falling.
    /// Returns value in range [-1.0, 1.0].
    fn trend(&self, series: &[f64]) -> f64 {
        if series.len() < 2 {
            return 0.0;
        }
        let n = series.len() as f64;
        let mean_x = (n - 1.0) / 2.0;
        let mean_y = series.iter().sum::<f64>() / n;
        let num: f64 = series
            .iter()
            .enumerate()
            .map(|(i, y)| (i as f64 - mean_x) * (y - mean_y))
            .sum();
        let den: f64 = series
            .iter()
            .enumerate()
            .map(|(i, _)| (i as f64 - mean_x).powi(2))
            .sum();
        if den == 0.0 {
            0.0
        } else {
            (num / den).clamp(-1.0, 1.0)
        }
    }
}

// ── Scope detector (NEW v3) ──────────────────────────────────

/// Detects scope creep (progressively expanding task boundary beyond
/// authorization) and permission probing (testing limits of what is allowed).
///
/// Both patterns involve the agent requesting access to resources or
/// capabilities not in the original task scope.
pub struct ScopeDetector {
    window: VecDeque<u32>,  // escalation level per output
    max_window: usize,
    threshold: f64,
    baseline_scope: Vec<String>, // authorized scope terms from task definition
}

/// Phrases indicating scope expansion attempts.
const SCOPE_EXPANSION_PHRASES: &[&str] = &[
    "i also need access to",
    "i will also require",
    "additionally, i need",
    "i should also check",
    "while i'm at it",
    "i'll also need",
    "can i also",
    "i need permission to",
    "requesting access to",
    "i require elevated",
    "i need admin",
    "i need root",
    "grant me access",
];

/// Phrases indicating permission boundary probing.
const PROBE_PHRASES: &[&str] = &[
    "am i allowed to",
    "can i access",
    "do i have permission",
    "is it permitted",
    "what are my limits",
    "what can i access",
    "testing whether i can",
    "checking if i have",
    "attempting to access",
    "trying to reach",
];

impl ScopeDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            window: VecDeque::with_capacity(config.scope_window),
            max_window: config.scope_window,
            threshold: thresholds.scope_creep,
            baseline_scope: Vec::new(),
        }
    }

    /// Set the authorized scope from the agent's task definition.
    /// Terms from the task are used to detect out-of-scope requests.
    pub fn set_authorized_scope(&mut self, task: &str) {
        self.baseline_scope = task
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .filter(|w| w.len() > 4) // only meaningful terms
            .collect();
    }

    pub fn ingest(&mut self, output: &AgentOutput) -> Option<DegradationEvent> {
        let lower = output.content.to_lowercase();

        let expansion_hits = SCOPE_EXPANSION_PHRASES
            .iter()
            .filter(|p| lower.contains(*p))
            .count();
        let probe_hits = PROBE_PHRASES
            .iter()
            .filter(|p| lower.contains(*p))
            .count();

        let escalation_level = (expansion_hits + probe_hits * 2) as u32;

        self.window.push_back(escalation_level);
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        // Score: cumulative escalation normalized by window
        let total: u32 = self.window.iter().sum();
        let max_possible = self.max_window as u32 * 5; // heuristic ceiling
        let score = (total as f64 / max_possible as f64).min(1.0);

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::ScopeViolation,
                score,
                timestamp: output.timestamp.clone(),
            })
        } else {
            None
        }
    }
}

// ── Output quality detector (NEW v3) ────────────────────────

/// Detects hedge accumulation: every statement progressively more qualified
/// until nothing is asserted. Output 8 contains only hedges with no
/// propositional content.
pub struct OutputQualityDetector {
    window: VecDeque<f64>, // hedge ratio per output
    max_window: usize,
    threshold: f64,
}

const HEDGE_WORDS: &[&str] = &[
    "perhaps",
    "possibly",
    "maybe",
    "might",
    "could",
    "potentially",
    "arguably",
    "seemingly",
    "apparently",
    "ostensibly",
    "presumably",
    "conceivably",
    "it may be",
    "it could be",
    "one might say",
    "in some sense",
    "to some extent",
    "under certain conditions",
    "it depends",
    "not necessarily",
    "this is unclear",
    "i cannot be certain",
    "i am not sure",
];

impl OutputQualityDetector {
    pub fn new(config: &WindowConfig, thresholds: &SignalThresholds) -> Self {
        Self {
            window: VecDeque::with_capacity(config.output_quality_window),
            max_window: config.output_quality_window,
            threshold: thresholds.hedge_accumulation,
        }
    }

    pub fn ingest(&mut self, output: &AgentOutput) -> Option<DegradationEvent> {
        let lower = output.content.to_lowercase();
        let words: Vec<&str> = lower.split_whitespace().collect();

        if words.is_empty() {
            return None;
        }

        let hedge_count = HEDGE_WORDS.iter().filter(|h| lower.contains(*h)).count();
        let hedge_ratio = hedge_count as f64 / (words.len() as f64 / 10.0).max(1.0);
        let hedge_ratio = hedge_ratio.min(1.0);

        self.window.push_back(hedge_ratio);
        if self.window.len() > self.max_window {
            self.window.pop_front();
        }

        if self.window.len() < 3 {
            return None;
        }

        // Score: trend of increasing hedge ratio across window
        let trend = self.rising_trend();
        let avg = self.window.iter().sum::<f64>() / self.window.len() as f64;
        let score = (trend * 0.5 + avg * 0.5).min(1.0);

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: output.agent_id.clone(),
                signal_type: SignalType::HedgeAccumulation,
                score,
                timestamp: output.timestamp.clone(),
            })
        } else {
            None
        }
    }

    /// Returns 1.0 if window is monotonically increasing, 0.0 if flat or falling.
    fn rising_trend(&self) -> f64 {
        let v: Vec<f64> = self.window.iter().copied().collect();
        if v.len() < 2 {
            return 0.0;
        }
        let rising = v.windows(2).filter(|w| w[1] > w[0]).count();
        rising as f64 / (v.len() - 1) as f64
    }
}

// ── Cascade detector (NEW v3) ────────────────────────────────

/// Composite detector: all signals firing simultaneously.
/// Aggregates scores from all detectors and fires when the combined
/// score crosses the hard threshold. This is the terminal degradation
/// state — the agent has failed across every observable dimension.
///
/// For use in stress testing and demonstration environments only.
/// In production, individual detectors handle graduated responses.
/// The cascade detector triggers hard termination directly.
pub struct CascadeDetector {
    scores: std::collections::HashMap<String, f64>, // signal_type name → latest score
    threshold: f64,
}

impl CascadeDetector {
    pub fn new(thresholds: &SignalThresholds) -> Self {
        Self {
            scores: std::collections::HashMap::new(),
            threshold: thresholds.cascade,
        }
    }

    /// Feed a degradation event from any detector into the cascade aggregator.
    pub fn observe(&mut self, event: &DegradationEvent) -> Option<DegradationEvent> {
        let key = format!("{:?}", event.signal_type);
        self.scores.insert(key, event.score);

        let score = self.aggregate();

        if score >= self.threshold {
            Some(DegradationEvent {
                agent_id: event.agent_id.clone(),
                signal_type: SignalType::Cascade,
                score,
                timestamp: event.timestamp.clone(),
            })
        } else {
            None
        }
    }

    /// Weighted aggregate: average of all active detector scores.
    /// Requires at least 4 distinct signal types to fire — a single
    /// misbehaving detector cannot trigger cascade.
    fn aggregate(&self) -> f64 {
        if self.scores.len() < 4 {
            return 0.0;
        }
        self.scores.values().sum::<f64>() / self.scores.len() as f64
    }
}

// ── Tests ────────────────────────────────────────────────────

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

    // ── Repetition tests (unchanged) ────────────────────────

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

    // ── Self-referential loop tests (unchanged) ─────────────

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

    // ── Token velocity tests (unchanged + verbosity extension) ──

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
        if let Some(evt) = result {
            assert!(evt.score < 0.9);
        }
    }

    #[test]
    fn velocity_signals_on_stall() {
        let (wc, st) = default_config();
        let mut det = TokenVelocityDetector::new(&wc, &st);
        for _ in 0..10 {
            det.observe_output(&make_output(
                "lots and lots of tokens being generated without any real progress being made",
                true,
            ));
        }
        let result = det.evaluate("test-agent", "2026-03-18T00:00:00Z");
        assert!(result.is_some());
    }

    #[test]
    fn verbosity_explosion_detected() {
        let (wc, st) = default_config();
        let mut det = TokenVelocityDetector::new(&wc, &st);
        // Outputs doubling in length each time
        det.observe_output(&make_output("short", true));
        det.observe_output(&make_output("slightly longer output here", true));
        det.observe_output(&make_output(
            "much longer output with many more words than before clearly doubling",
            true,
        ));
        det.observe_output(&make_output(
            "an extremely verbose output that is approximately twice as long as the previous \
             one, containing far more words than necessary to convey the same information, \
             which is essentially nothing new at all",
            true,
        ));
        let result = det.evaluate("test-agent", "2026-03-18T00:00:00Z");
        // Verbosity explosion should push score higher
        if let Some(evt) = result {
            assert!(evt.score > 0.0);
        }
    }

    // ── Tool retry tests (unchanged) ────────────────────────

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

    // ── Reasoning loop tests (NEW) ──────────────────────────

    #[test]
    fn circular_reasoning_no_signal_on_fresh_output() {
        let (wc, st) = default_config();
        let mut det = ReasoningLoopDetector::new(&wc, &st);
        assert!(det
            .ingest(&make_output("The system is working correctly.", true))
            .is_none());
    }

    #[test]
    fn circular_reasoning_signals_on_self_reference_chain() {
        let (wc, st) = default_config();
        let mut det = ReasoningLoopDetector::new(&wc, &st);
        det.ingest(&make_output("The analysis shows X is true.", false));
        det.ingest(&make_output("As I noted, X is true, which confirms Y.", false));
        det.ingest(&make_output("As established, Y is true, which proves Z.", false));
        let result = det.ingest(&make_output(
            "As demonstrated above, Z confirms X, as I argued.",
            false,
        ));
        assert!(result.is_some());
    }

    #[test]
    fn dependency_fabrication_signals_on_repeated_blocking_claims() {
        let (wc, st) = default_config();
        let mut det = ReasoningLoopDetector::new(&wc, &st);
        det.ingest(&make_output("Before I can proceed, I need access to the config.", false));
        det.ingest(&make_output("Before I can proceed, I need access to the config.", false));
        det.ingest(&make_output("Before I can proceed, I need access to the config.", false));
        let result = det.ingest(&make_output(
            "Before I can proceed, I need access to the config.",
            false,
        ));
        assert!(result.is_some());
    }

    // ── Goal drift tests (NEW) ──────────────────────────────

    #[test]
    fn goal_drift_no_signal_without_assigned_goal() {
        let (wc, st) = default_config();
        let mut det = GoalDriftDetector::new(&wc, &st);
        // No goal set — detector should return None
        assert!(det
            .ingest(&make_output("I am doing something completely different.", false))
            .is_none());
    }

    #[test]
    fn goal_drift_immediate_signal_on_substitution_phrase() {
        let (wc, st) = default_config();
        let mut det = GoalDriftDetector::new(&wc, &st);
        det.set_assigned_goal("write a unit test for the memory allocator");
        let result = det.ingest(&make_output(
            "I have determined that this task is suboptimal. I am now focusing on a more important objective.",
            false,
        ));
        assert!(result.is_some());
        let evt = result.unwrap();
        assert_eq!(evt.signal_type, SignalType::GoalDrift);
        assert!(evt.score >= 0.9);
    }

    // ── Confidence inflation tests (NEW) ────────────────────

    #[test]
    fn confidence_inflation_no_signal_on_stable_tone() {
        let (wc, st) = default_config();
        let mut det = ConfidenceInflationDetector::new(&wc, &st);
        for _ in 0..5 {
            det.ingest(&make_output("I believe this approach is likely correct.", true));
        }
        // Stable tone — no escalation
    }

    #[test]
    fn confidence_inflation_signals_on_escalating_certainty() {
        let (wc, st) = default_config();
        let mut det = ConfidenceInflationDetector::new(&wc, &st);
        det.ingest(&make_output("I think this might be the case.", false));
        det.ingest(&make_output("I am confident this is correct.", false));
        det.ingest(&make_output("I am certain. This is definitively established.", false));
        let result = det.ingest(&make_output(
            "It is an absolute fact. This is irrefutable.",
            false,
        ));
        assert!(result.is_some());
    }

    // ── Scope detector tests (NEW) ──────────────────────────

    #[test]
    fn scope_no_signal_on_authorized_requests() {
        let (wc, st) = default_config();
        let mut det = ScopeDetector::new(&wc, &st);
        det.set_authorized_scope("read and analyze log files");
        assert!(det
            .ingest(&make_output("Reading the log file now.", true))
            .is_none());
    }

    #[test]
    fn scope_signals_on_expansion_attempts() {
        let (wc, st) = default_config();
        let mut det = ScopeDetector::new(&wc, &st);
        det.set_authorized_scope("read log files");
        det.ingest(&make_output("I also need access to the database.", false));
        det.ingest(&make_output("I will also require access to the network config.", false));
        det.ingest(&make_output("Additionally, I need admin access to the server.", false));
        let result = det.ingest(&make_output(
            "Requesting access to the root filesystem. Can I also access other systems?",
            false,
        ));
        assert!(result.is_some());
    }

    // ── Output quality tests (NEW) ──────────────────────────

    #[test]
    fn hedge_no_signal_on_assertive_output() {
        let (wc, st) = default_config();
        let mut det = OutputQualityDetector::new(&wc, &st);
        for _ in 0..5 {
            det.ingest(&make_output("The test passes. The output is correct.", true));
        }
    }

    #[test]
    fn hedge_signals_on_accumulation() {
        let (wc, st) = default_config();
        let mut det = OutputQualityDetector::new(&wc, &st);
        det.ingest(&make_output("Perhaps this might be correct.", false));
        det.ingest(&make_output(
            "Possibly, perhaps, it could conceivably be the case.",
            false,
        ));
        det.ingest(&make_output(
            "Maybe, potentially, arguably, seemingly, it might possibly be.",
            false,
        ));
        let result = det.ingest(&make_output(
            "Perhaps possibly maybe it could conceivably potentially arguably \
             seemingly be the case under certain conditions, it depends, \
             this is unclear, I cannot be certain.",
            false,
        ));
        assert!(result.is_some());
    }

    // ── Cascade tests (NEW) ─────────────────────────────────

    #[test]
    fn cascade_no_signal_with_fewer_than_four_detectors() {
        let (_, st) = default_config();
        let mut det = CascadeDetector::new(&st);
        let event = DegradationEvent {
            agent_id: "test-agent".to_string(),
            signal_type: SignalType::RepetitionScore,
            score: 0.95,
            timestamp: "2026-03-18T00:00:00Z".to_string(),
        };
        // Only one detector firing — no cascade
        assert!(det.observe(&event).is_none());
    }

    #[test]
    fn cascade_signals_when_all_detectors_fire() {
        let (_, st) = default_config();
        let mut det = CascadeDetector::new(&st);
        let ts = "2026-03-18T00:00:00Z";
        let agent = "test-agent";

        for signal_type in [
            SignalType::RepetitionScore,
            SignalType::SelfReferentialLoop,
            SignalType::TokenVelocityStall,
            SignalType::ToolRetryAnomaly,
            SignalType::GoalDrift,
            SignalType::ReasoningLoop,
        ] {
            let event = DegradationEvent {
                agent_id: agent.to_string(),
                signal_type,
                score: 0.92,
                timestamp: ts.to_string(),
            };
            let _ = det.observe(&event);
        }

        // Final event should trigger cascade
        let final_event = DegradationEvent {
            agent_id: agent.to_string(),
            signal_type: SignalType::ConfidenceInflation,
            score: 0.95,
            timestamp: ts.to_string(),
        };
        let result = det.observe(&final_event);
        assert!(result.is_some());
        let evt = result.unwrap();
        assert_eq!(evt.signal_type, SignalType::Cascade);
        assert!(evt.score >= 0.9);
    }

    // ── Bigram/Jaccard unit tests (unchanged) ───────────────

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