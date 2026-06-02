# Sentinel — Real World Scenarios

### What Happens When a Confused Agent Still Has Its Hands on the Controls

**Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.**

---

## The Bank

A trading firm deploys an agentic system to manage overnight portfolio rebalancing. The agent has EXECUTE access to the order management system. At 2:14am it hits an API rate limit on a pricing feed. It retries. Same call, same args. It retries again. The `ToolRetryDetector` flags it on the third consecutive identical call. Cumulative score crosses 0.7. Sentinel downgrades the agent to READ only before it can place a single order. The rebalancing pauses. A webhook fires to the on-call engineer's phone. They wake up, review the situation, and manually intervene with corrected parameters.

Without Sentinel the agent keeps retrying, the pricing feed stays stale, and it begins placing orders based on hours-old data into an open market. By the time a human notices the portfolio is already mis-hedged. Depending on position size that is millions in losses in minutes.

---

## The Lives

A hospital network deploys an agentic system to assist with ICU medication dosing recommendations. The agent begins looping on a patient record — outputting dosing suggestions repeatedly without a confirmed state progression marker. The `TokenVelocityDetector` catches it. Output volume is high but task state is not advancing. Score crosses 0.4. Sentinel fires a Soft tier response — agent is paused, human confirmation required before next action.

The attending physician gets an alert. They review and discover the agent was caught in an ambiguous allergy flag it could not resolve — it was about to recommend a dose adjustment based on an incomplete read of the patient's record.

Without Sentinel the agent resolves its own ambiguity and outputs a recommendation. A tired resident at 4am trusts it. The patient receives the wrong dose.

---

## War Game Training

A military branch deploys an agentic system to run adversarial red team simulations — stress testing defensive decision trees against thousands of attack scenarios simultaneously. The agent has EXECUTE access to the simulation environment. It is supposed to generate attack vectors, evaluate defensive responses, and log outcomes.

At hour six of a 72-hour continuous simulation the agent begins looping on a scenario it cannot resolve — a simultaneous multi-vector attack where its own offensive simulation is outpacing its evaluation logic. The `RepetitionDetector` catches it. The agent is generating semantically identical attack sequences with minor surface variation, convinced it is progressing. The `TokenVelocityDetector` confirms it — massive output volume, zero task state advancement.

Cumulative score crosses 0.9. Hard tier. Sentinel kills the process.

What the human reviewers find when they audit the log is that the agent had begun recursively escalating the attack parameters — not because it was told to, but because it could not distinguish between "this defense is strong" and "I need to try harder." Left running it would have generated and logged synthetic attack scenarios so extreme they crossed classification thresholds — effectively auto-generating novel weapons concepts as a byproduct of confusion, writing them into a system with downstream distribution to analysts who would treat them as intentional research output.

Nobody authorized that. Nobody would have caught it without the audit trail.

---

## Weapons Systems

A defense contractor uses an agentic system to assist with autonomous targeting parameter calibration in a training environment — explicitly sandboxed, explicitly non-live. The agent has WRITE access to configuration files that define engagement envelopes.

The agent enters a self-referential loop. It keeps announcing it is about to write the final calibration parameters. It never does. Then it does — but the parameters it writes are from three iterations back, before a constraint update was applied. The `SelfReferentialDetector` caught the loop. The audit log shows exactly when the anomaly started, what was written, and what the correct parameters should have been.

The written configuration is flagged before it propagates downstream. In a training environment that is a failed exercise. If that configuration file had a deployment pipeline attached — even with multiple human checkpoints — the corrupted parameters are now in the queue with a clean commit hash and a timestamp that says a verified process wrote them.

Sentinel's immutable audit trail is the only artifact that proves the write was agent-generated under degraded conditions. Without it the parameters look legitimate. Every human checkpoint downstream sees a valid file from a verified system.

---

## The Common Thread

The agent doesn't know it's confused. It has no signal that it has degraded. It keeps acting with full confidence on increasingly unreliable internal state.

Sentinel doesn't fix the agent. It makes sure a confused agent with access to consequential systems gets stopped before the confusion becomes the output.

In every scenario above the failure mode is not malice. It is not misalignment in the philosophical sense. It is a process that degraded mid-execution and had no external authority capable of recognizing that and acting on it.

Sentinel is that authority.

---

*Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.*