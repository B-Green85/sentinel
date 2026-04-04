"""Example: Sentinel oversight for a raw Claude API loop.

Sentinel operates OUTSIDE the agent's process space.
The agent is completely blind to Sentinel's existence.
This script is run by the HUMAN OPERATOR, not by the agent.

No SDK changes required — Anthropic SDK runs unmodified.
"""

from __future__ import annotations

from sentinel_py import watch

# Simulated Claude API agent loop.
# In production, the agent runs in a sandboxed subprocess.
# The operator wraps execution with Sentinel oversight.


def run_claude_loop(messages: list[dict[str, str]]) -> list[str]:
    """Placeholder for actual Claude API loop."""
    # import anthropic
    # client = anthropic.Anthropic()
    # while not done:
    #     response = client.messages.create(model="...", messages=messages)
    #     ...
    return [
        "Step 1: Analyzed the codebase structure",
        "Step 2: Identified 2 potential issues",
        "Step 3: Generated fix proposals",
    ]


def main() -> None:
    agent_id = "claude-code-agent-042"

    with watch(agent_id, tier="restricted", heartbeat_interval=2.0) as w:
        # Run the agent loop — agent has zero awareness of Sentinel
        messages = [{"role": "user", "content": "Review the auth module"}]
        outputs = run_claude_loop(messages)

        # Operator captures each generation for the audit trail
        for output in outputs:
            w.emit(output)

        status = w.check_status()
        print(f"Agent: {status.agent_id}")
        print(f"Tier: {status.tier}")
        print(f"State: {status.state}")
        print(f"Outputs captured: {status.output_count}")

    print("Session sealed. All actions hashed and logged.")


if __name__ == "__main__":
    main()
