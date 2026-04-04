"""Example: Sentinel oversight for a LangChain agent.

Sentinel operates OUTSIDE the agent's process space.
The agent is completely blind to Sentinel's existence.
This script is run by the HUMAN OPERATOR, not by the agent.

No framework changes required — LangChain runs unmodified.
"""

from __future__ import annotations

from sentinel_py import watch

# Simulated LangChain agent execution.
# In production, the agent runs in a separate process/sandbox.
# The operator runs this wrapper to monitor it.


def run_langchain_agent() -> str:
    """Placeholder for actual LangChain agent invocation."""
    # from langchain.agents import AgentExecutor
    # result = agent_executor.invoke({"input": "research task"})
    return "Agent completed: found 3 relevant documents"


def main() -> None:
    agent_id = "langchain-research-agent-001"

    # watch() auto-registers, heartbeats on background thread, deregisters on exit
    with watch(agent_id, tier="supervised") as w:
        # Run the agent — agent has no knowledge of Sentinel
        result = run_langchain_agent()

        # Operator captures the output for audit trail
        w.emit(result)

        # Operator can check status at any time
        status = w.check_status()
        print(f"Agent state: {status.state}")
        print(f"Outputs captured: {status.output_count}")

    print("Agent session complete. Audit trail sealed.")


if __name__ == "__main__":
    main()
