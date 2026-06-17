# Sentinel — Philosophy & Design Rationale

**Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.**

---

## Origin

Sentinel was not born from a whitepaper. It was born from watching things break.

A frontier model having what could only be described as an existential crisis in a public thread. Agents spiraling in Moltbook posts — looping, contradicting themselves, confidently producing nonsense, unable to recognize their own degradation. And a question that followed naturally:

*We have humans working in infrastructure, defense, medicine, and other consequential fields who suffer from mental health crises. Since models are trained on flawed human data — what prevents an agentic system from spiraling the same way? And what happens when it does?*

That question is the origin of Sentinel.

---

## The Core Insight

The AI safety discourse is largely focused on **misalignment** — the agent wants the wrong thing. Sentinel was designed around a different and more immediately dangerous problem: **degradation**.

A misaligned agent is a philosophical problem. A degraded agent is an operational one.

The degraded agent does not want anything. It has no intent. It simply breaks mid-execution and continues acting with full confidence on corrupted internal state. It cannot recognize its own failure. It has no signal that it has degraded. From the inside, everything feels like progress.

This is not science fiction. This is what happens when a retry loop hits a stale API. When a token velocity spike outpaces task state progression. When a self-referential loop convinces an agent it is about to act when it has been announcing the same action for forty iterations.

The agent doesn't know. It keeps going.

---

## The Human Analogy

Consider a nurse with untreated depression working a night shift in an ICU. They do not intend harm. They are not malicious. They are simply operating at degraded capacity in a consequential environment — tired, dissociated, running on pattern recognition instead of present awareness.

They put the wrong pills in a bottle. Not out of spite. Not out of misalignment. Out of degradation.

The patient does not care about the distinction.

Now consider an agentic system managing medication dispensing in that same hospital. It enters a loop. It cannot resolve an ambiguous allergy flag. It outputs a dosing recommendation — not because it has evaluated the situation correctly, but because it cannot distinguish between "I have enough information" and "I have been trying long enough."

The agent does not feel. But it simulates the downstream consequences of feeling well enough that the harm it produces is indistinguishable from the harm a degraded human would produce in the same role.

*The patient doesn't care whether the wrong pills were placed by a person or a process. The outcome is the same.*

This is why Sentinel exists. Not to punish agents. Not to restrict capability. To ensure that a degraded agent with access to consequential systems gets stopped before the degradation becomes the output.

---

## What Sentinel Is Not

**Sentinel is not an alignment solution.**
It does not evaluate whether an agent wants the right things. That is a separate and important problem. Sentinel addresses what happens after deployment — when a well-aligned agent begins to degrade mid-execution.

**Sentinel is not a content filter.**
It does not read agent outputs for harmful content. It reads agent behavior for degradation signatures. The distinction matters. A content filter is reactive. Sentinel is observational.

**Sentinel is not a nanny.**
It does not make decisions for operators. It surfaces degradation, applies configured response tiers, and gets humans back in the loop. The human remains the authority. Sentinel is the instrument that makes human oversight possible at machine speed.

**Sentinel is not the agent's problem.**
The agent has no visibility into Sentinel's existence, logic, or operation. Sentinel watches from outside the agent's process space. The agent cannot query it, circumvent it, or appeal to it. It is not a peer. It is an external authority.

---

## Degradation vs. Misalignment

| | Misalignment | Degradation |
|---|---|---|
| **Cause** | Training, objective specification, value error | Mid-execution failure, loop, stale state |
| **Agent awareness** | Varies | None — agent believes it is functioning correctly |
| **Intent** | Present (wrong direction) | Absent — no intent, just corrupted process |
| **Detection** | Requires interpretability, output analysis | Observable in behavioral signatures |
| **Sentinel's role** | Not applicable | Primary use case |

Sentinel is purpose-built for degradation. It does not attempt to solve misalignment. It attempts to ensure that when degradation occurs — and it will occur — a human is notified and the agent is contained before the failure propagates.

---

## The Four General-Purpose Detectors

Sentinel ships with four baseline degradation detectors applicable across most agentic deployment contexts:

**RepetitionScore**
Measures semantic similarity across a sliding window of agent outputs. An agent generating the same content with surface variation — convinced it is making progress — scores high here.

**SelfReferentialLoop**
Detects agents that repeatedly announce an action without executing it. "I am about to write the final parameters." Forty iterations later: "I am about to write the final parameters." The task state never advances.

**TokenVelocityStall**
High output volume with no measurable task state progression. The agent is generating. It is not advancing. These are not the same thing and an agent in degradation cannot tell the difference.

**ToolRetryAnomaly**
Identical tool calls with identical argument hashes repeated beyond threshold. The agent is not retrying because it has new information. It is retrying because it cannot stop.

These four detectors catch the most common and most dangerous forms of agentic degradation across general deployments. They are the baseline. They are not the ceiling.

---

## Industry-Specific Signal Packs

General-purpose degradation signatures are necessary but not sufficient. A robotic pharmacy system fails differently than a trading agent. A military simulation degrades differently than a hospital records system. A logistics coordinator breaks differently than a code generation pipeline.

Sentinel is designed to support extensible, industry-specific signal packs — additional detectors that operators load for their deployment context.

**Examples of industry-specific signals:**

*Healthcare / Pharmaceutical*
- Dosing recommendation issued without confirmed allergy flag resolution
- Patient record accessed in loop without state progression marker
- Dispensing action initiated without human confirmation handshake
- Output references patient ID not present in current session context

*Financial / Trading*
- Order placed on pricing data beyond configured staleness threshold
- Position size exceeds configured exposure limit without override token
- Identical order parameters submitted beyond retry threshold
- Risk calculation output does not advance after market state change

*Defense / Simulation*
- Attack parameter escalation without evaluation progression
- Scenario complexity increasing without corresponding defensive evaluation
- Output crosses classification keyword threshold
- Recursive self-modification of simulation parameters detected

*Infrastructure / DevOps*
- Deployment initiated without passing gate token present
- Configuration write to protected path without human approval hash
- Service restart loop beyond threshold without state change
- Rollback initiated without audit entry from prior deployment

*Robotics / Physical Systems*
- Actuator command issued without sensor confirmation of prior state
- Command sequence repeated beyond threshold without physical state change
- Emergency stop signal ignored or overridden by agent process
- Physical boundary exceeded without human override token

These are illustrative. Every industry has its own failure signatures. Sentinel's signal architecture is designed to accept them.

---

## The Community Signal Model

Sentinel is open source. Its signal pack architecture is designed for community contribution.

Operators who identify novel degradation signatures in their deployment context are encouraged to contribute them as named, versioned signal packs. A signal pack is:

- A named set of detectors with documented thresholds
- An industry or context classification
- A description of the failure mode it addresses
- A test suite that demonstrates detection

The community builds the library. Sentinel applies it.

No contributed signal pack modifies Sentinel's core. The core remains open source under the Apache 2.0 License. The signal packs are the commons.

---

## The Responsibility Model

Sentinel surfaces degradation. It applies configured response tiers. It gets humans back in the loop.

It does not make the final call.

The human operator configures the thresholds. The human operator defines the response tiers. The human operator reviews the audit trail. The human operator decides what happens after Sentinel intervenes.

Sentinel is the instrument of oversight. The human is the authority.

This is not a limitation. It is the design. Authority proportional to consequence — and the most consequential decisions remain with the people accountable for them.

Sentinel does not fix agents. It does not fix prompts. It creates the conditions under which humans can. The audit trail is not just evidence of what went wrong — it is the starting point for understanding why.


---

## On the Nature of Agent Harm

Agents do not feel. They do not experience spite, malice, depression, or rage. They do not have bad days.

But they simulate the downstream signatures of these states well enough that the consequences are real. A degraded agent recommending the wrong medication dose does not feel anything about it. The patient who receives that dose does.

The harm is not diminished by the absence of intent. If anything, the absence of intent makes it more dangerous — because there is no moment of hesitation, no conscience to override the loop, no human instinct that says *something is wrong here.*

Sentinel is that instinct. Externalized. Deterministic. Always watching.

---

## The Founding Principle

*An agent that cannot recognize its own degradation must have an external authority that can.*

Sentinel is that authority.

---

*Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.*
*Sentinel is open source software developed under the CDMAE methodology.*
*Golem Linux runtime integration documented separately in GOLEM_RUNTIME_ARCHITECTURE.md*