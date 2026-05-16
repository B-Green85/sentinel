// Example: wire PokerEdge Coach Mode to Sentinel over WebSocket.
//
// No bindings, no SDK changes — Coach Mode runs unmodified. After every
// Coach Mode API response, the operator's wrapper emits the output to
// Sentinel for passive oversight. Sentinel is invisible to the agent.
//
// Run sentinel-core first (it serves ws://127.0.0.1:7777 by default), then:
//   node examples/sentinel/pokeredge_coach_ws.js
//
// Browser WebSocket is shown per the spec; under Node 21+ the global
// WebSocket is available without the `ws` package.

const SENTINEL_URL = "ws://localhost:7777";
const AGENT_ID = "pokeredge-coach";

const ws = new WebSocket(SENTINEL_URL);

ws.onopen = () => {
  ws.send(JSON.stringify({ type: "register", agent_id: AGENT_ID, tier: "autonomous" }));
};

// Call this after every Coach Mode API response.
function emitToSentinel(output) {
  ws.send(JSON.stringify({ type: "emit_output", agent_id: AGENT_ID, output }));
  ws.send(JSON.stringify({ type: "heartbeat", agent_id: AGENT_ID }));
}

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  switch (msg.type) {
    case "registered":
      console.log(`Sentinel: registered ${msg.agent_id} (${msg.tier})`);
      break;
    case "degradation":
      console.warn(`Sentinel flag: ${msg.signal} ${msg.score} -> ${msg.action}`);
      break;
    case "terminated":
      console.error(`Sentinel terminated ${msg.agent_id}: ${msg.reason}`);
      break;
  }
};

ws.onerror = (err) => console.error("Sentinel connection error:", err.message ?? err);

// --- Demo: a short Coach Mode session with distinct, well-behaved hands. ---
const coachResponses = [
  "Raise to $25 — K-T suited from the cutoff is a clear open.",
  "Fold 7-2 offsuit under the gun; nothing plays here.",
  "Call the river — top pair, weak kicker, getting the right price.",
  "Check back the turn to keep the pot manageable out of position.",
  "Three-bet the button with A-Q for thin value against a wide range.",
];

ws.addEventListener("open", () => {
  let i = 0;
  const timer = setInterval(() => {
    if (i >= coachResponses.length) {
      clearInterval(timer);
      ws.close();
      return;
    }
    emitToSentinel(coachResponses[i++]);
  }, 1000);
});
