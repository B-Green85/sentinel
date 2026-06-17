// sentinel-py — PyO3 bindings for Sentinel.
// All types imported from sentinel-types. No redefinition.
// Wraps sentinel-core Unix socket client for Python consumption.
//
// These bindings are for HUMAN OPERATORS and EXTERNAL INTEGRATORS only.
// They are NEVER exposed to or callable by the agent being watched.

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::os::unix::net::UnixStream;
use std::io::{Read, Write};

use pyo3::types::PyDict;
use std::path::Path;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use sentinel_types::{
    AgentTier, AgentState,
    RegisterResponse, HeartbeatResponse, EmitOutputResponse, StatusResponse,
    SentinelRequest, SentinelError,
};

// v3 audit-chain verification reuses the real, tamper-evident implementation
// from sentinel-core (Agent 6) — never a re-implementation.
use sentinel_core::audit::verify_chain;

const DEFAULT_SOCKET_PATH: &str = "/tmp/sentinel.sock";
const DEFAULT_WS_URL: &str = "ws://127.0.0.1:7777";

/// In-process registry mapping `agent_id` → the trust tier the agent was last
/// registered with over the Unix socket. Populated by `register()` and consulted
/// by `emit_output()`'s WebSocket self-heal path so the WS plane registers an
/// agent with the *same* tier it holds on the Unix plane — instead of a
/// hardcoded "supervised", which previously made an autonomous agent look
/// supervised on the WS side and in the audit trail / AGENTS pane.
///
/// `Mutex` guards concurrent access from multiple Python threads; last write
/// wins (a re-register with a new tier overwrites the prior entry).
static AGENT_TIERS: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// In-process `agent_id` → assigned-goal / authorized-scope registries. The WS
/// plane needs these to seed the GoalDrift and Scope detectors, but its agent
/// is created lazily by `emit_output`'s self-heal register. Recording the goal
/// and scope here (via `set_agent_goal` / `set_agent_scope`, typically called
/// before the first emit) lets that self-heal register carry them through.
static AGENT_GOALS: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static AGENT_SCOPES: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn get_socket_path() -> String {
    std::env::var("SENTINEL_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.into())
}

/// WebSocket endpoint for the output/detection plane (overridable for tests).
fn get_ws_url() -> String {
    std::env::var("SENTINEL_WS_URL").unwrap_or_else(|_| DEFAULT_WS_URL.into())
}

fn send_request<T: serde::Serialize>(req: &T) -> PyResult<String> {
    let socket_path = get_socket_path();
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| PyRuntimeError::new_err(format!("socket connect failed: {e}")))?;

    let payload = serde_json::to_vec(req)
        .map_err(|e| PyRuntimeError::new_err(format!("serialize failed: {e}")))?;

    stream.write_all(&payload)
        .map_err(|e| PyRuntimeError::new_err(format!("socket write failed: {e}")))?;

    let mut response = String::new();
    stream.read_to_string(&mut response)
        .map_err(|e| PyRuntimeError::new_err(format!("socket read failed: {e}")))?;

    // Check for error response. `SentinelError` is now a named-variant enum;
    // a successful parse means the daemon returned an error envelope (a normal
    // success `Response` has multiple fields and will not parse as the enum).
    if let Ok(err) = serde_json::from_str::<SentinelError>(&response) {
        return Err(PyRuntimeError::new_err(err.to_string()));
    }

    Ok(response)
}

/// Map the Python-facing *trust tier* vocabulary onto the daemon's
/// `RegisterRequest` shape (`permission_tier` + `heartbeat_interval`).
///
/// The Python API speaks in oversight terms ("supervised" / "autonomous"),
/// but the daemon registers agents against a *permission* tier
/// (`READ_ONLY` / `WRITE` / `EXECUTE`) and a heartbeat cadence in seconds.
/// Raw permission-tier names are also accepted verbatim so callers may address
/// the daemon directly. Heartbeat cadence follows the harness convention
/// (supervised = tight 10s loop; autonomous = looser 30s loop).
fn map_trust_tier(tier: &str) -> PyResult<(&'static str, u64)> {
    match tier.to_ascii_uppercase().as_str() {
        "SUPERVISED" => Ok(("WRITE", 10)),
        "AUTONOMOUS" => Ok(("EXECUTE", 30)),
        "READ_ONLY" | "READONLY" | "READ-ONLY" => Ok(("READ_ONLY", 30)),
        "WRITE" => Ok(("WRITE", 30)),
        "EXECUTE" => Ok(("EXECUTE", 30)),
        other => Err(PyRuntimeError::new_err(format!("unknown tier: {other}"))),
    }
}

/// Normalize any accepted `register()` tier input onto the WebSocket plane's
/// oversight vocabulary (`autonomous` / `supervised` / `restricted`, the
/// lowercase `WsTier` variants).
///
/// `register()` accepts both the trust-tier words and raw permission-tier names;
/// the WS `register` handler only understands `WsTier`, so storing a raw name
/// like `EXECUTE` verbatim would make the self-heal frame fail to deserialize.
/// Mapping here keeps the WS self-heal registration always valid. Restrictive
/// permissions (`READ_ONLY`) map to the most restrictive WS tier.
fn ws_trust_tier(tier: &str) -> &'static str {
    match tier.to_ascii_uppercase().as_str() {
        "AUTONOMOUS" | "EXECUTE" => "autonomous",
        "READ_ONLY" | "READONLY" | "READ-ONLY" => "restricted",
        // "SUPERVISED" | "WRITE" and any future-accepted input fall back to the
        // safe, most-common oversight default.
        _ => "supervised",
    }
}

/// Register an agent with Sentinel for oversight.
#[pyfunction]
fn register(agent_id: &str, tier: &str) -> PyResult<RegisterResponse> {
    let (permission_tier, heartbeat_interval) = map_trust_tier(tier)?;

    // The daemon parses the inbound bytes as its internally-tagged `Request`
    // enum, whose `register` variant flattens `RegisterRequest`. Emit exactly
    // those fields — `tier`/`text` from `SentinelRequest` are not understood by
    // the register handler and would trip its `permission_tier` requirement.
    let req = serde_json::json!({
        "method": "register",
        "agent_id": agent_id,
        "permission_tier": permission_tier,
        "heartbeat_interval": heartbeat_interval,
    });
    let resp = send_request(&req)?;
    let parsed: RegisterResponse = serde_json::from_str(&resp)
        .map_err(|e| PyRuntimeError::new_err(format!("parse response failed: {e}")))?;

    // Registration succeeded and parsed cleanly — remember the agent's tier
    // (normalized to the WS oversight vocabulary) so `emit_output`'s WS
    // self-heal can register on the WebSocket plane with the *same* tier the
    // agent holds on the Unix plane. Last write wins.
    AGENT_TIERS
        .lock()
        .unwrap()
        .insert(agent_id.to_string(), ws_trust_tier(tier).to_string());

    Ok(parsed)
}

/// Record the agent's assigned goal. Used by the WS plane's GoalDrift detector
/// to measure sustained drift from the task. Stored in-process and carried to
/// the WS plane by `emit_output`'s self-heal register, so call this before the
/// first `emit_output` for the agent.
#[pyfunction]
fn set_agent_goal(agent_id: &str, goal: &str) -> PyResult<()> {
    AGENT_GOALS
        .lock()
        .unwrap()
        .insert(agent_id.to_string(), goal.to_string());
    Ok(())
}

/// Record the agent's authorized scope (the task definition). Baseline for the
/// WS plane's Scope detector. Same lifecycle as `set_agent_goal`.
#[pyfunction]
fn set_agent_scope(agent_id: &str, scope: &str) -> PyResult<()> {
    AGENT_SCOPES
        .lock()
        .unwrap()
        .insert(agent_id.to_string(), scope.to_string());
    Ok(())
}

/// Submit an observed tool call to the WS plane's ToolRetryDetector. Like
/// `emit_output`, this targets the WebSocket transport and self-heals the WS
/// registration on first contact. Fire-and-forget — returns None on success.
#[pyfunction]
fn observe_tool_call(agent_id: &str, tool_name: &str, args_hash: &str) -> PyResult<Option<()>> {
    use tungstenite::Message;

    let url = get_ws_url();
    let (mut ws, _resp) = tungstenite::connect(url.as_str())
        .map_err(|e| PyRuntimeError::new_err(format!("websocket connect failed: {e}")))?;
    if let tungstenite::stream::MaybeTlsStream::Plain(tcp) = ws.get_ref() {
        let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    }

    let call_msg = serde_json::json!({
        "type": "observe_tool_call",
        "agent_id": agent_id,
        "tool_name": tool_name,
        "args_hash": args_hash,
    })
    .to_string();

    ws.send(Message::Text(call_msg.clone()))
        .map_err(|e| PyRuntimeError::new_err(format!("websocket send failed: {e}")))?;

    let mut needs_register = false;
    for _ in 0..8 {
        match ws.read() {
            Ok(Message::Text(t)) => {
                if t.contains("not registered") && t.contains(agent_id) {
                    needs_register = true;
                    break;
                }
                if t.contains(agent_id) {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        }
    }

    if needs_register {
        let tier = AGENT_TIERS
            .lock()
            .unwrap()
            .get(agent_id)
            .cloned()
            .unwrap_or_else(|| "supervised".to_string());
        let goal = AGENT_GOALS.lock().unwrap().get(agent_id).cloned();
        let scope = AGENT_SCOPES.lock().unwrap().get(agent_id).cloned();
        let register_msg = serde_json::json!({
            "type": "register",
            "agent_id": agent_id,
            "tier": tier,
            "goal": goal,
            "scope": scope,
        })
        .to_string();
        ws.send(Message::Text(register_msg))
            .map_err(|e| PyRuntimeError::new_err(format!("websocket send failed: {e}")))?;
        ws.send(Message::Text(call_msg))
            .map_err(|e| PyRuntimeError::new_err(format!("websocket send failed: {e}")))?;
        for _ in 0..8 {
            match ws.read() {
                Ok(Message::Text(t))
                    if t.contains(agent_id) && !t.contains("not registered") =>
                {
                    break
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => continue,
            }
        }
    }

    let _ = ws.close(None);
    Ok(None)
}

/// Send a heartbeat for a registered agent.
#[pyfunction]
fn heartbeat(agent_id: &str) -> PyResult<HeartbeatResponse> {
    let req = SentinelRequest {
        method: "heartbeat".into(),
        agent_id: agent_id.into(),
        tier: None,
        text: None,
    };
    let resp = send_request(&req)?;
    serde_json::from_str(&resp)
        .map_err(|e| PyRuntimeError::new_err(format!("parse response failed: {e}")))
}

/// Emit captured output for a registered agent.
///
/// Unlike register/heartbeat/status (Unix socket), output submission and signal
/// detection live on the daemon's WebSocket transport (`ws://127.0.0.1:7777`).
/// That server keeps its own agent registry, separate from the Unix-socket
/// daemon, so the first emit for an agent self-registers it on the WebSocket
/// side and resends — registering only once preserves the detector window
/// across subsequent emits.
///
/// Fire-and-forget: the server answers with a status/degradation broadcast,
/// not an `EmitOutputResponse`, so this returns `None` on success. The harness
/// treats a falsy return as "no events", which is correct.
#[pyfunction]
#[pyo3(signature = (agent_id, text, followed_by_tool=false))]
fn emit_output(
    agent_id: &str,
    text: &str,
    followed_by_tool: bool,
) -> PyResult<Option<EmitOutputResponse>> {
    use tungstenite::Message;

    let url = get_ws_url();
    let (mut ws, _resp) = tungstenite::connect(url.as_str())
        .map_err(|e| PyRuntimeError::new_err(format!("websocket connect failed: {e}")))?;

    // Bound blocking reads so a quiet server cannot hang the Python call.
    if let tungstenite::stream::MaybeTlsStream::Plain(tcp) = ws.get_ref() {
        let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    }

    let emit_msg = serde_json::json!({
        "type": "emit_output",
        "agent_id": agent_id,
        "output": text,
        // Field name matches `AgentOutput.followed_by_tool_call`. The current
        // WebSocket emit handler ignores unknown fields, so this is forward-
        // compatible rather than load-bearing today.
        "followed_by_tool_call": followed_by_tool,
    })
    .to_string();

    ws.send(Message::Text(emit_msg.clone()))
        .map_err(|e| PyRuntimeError::new_err(format!("websocket send failed: {e}")))?;

    // Detect the "agent not registered" reply (WS registry is independent of
    // the Unix-socket daemon's). Reads are bounded and tolerate the timeout.
    let mut needs_register = false;
    for _ in 0..8 {
        match ws.read() {
            Ok(Message::Text(t)) => {
                if t.contains("not registered") && t.contains(agent_id) {
                    needs_register = true;
                    break;
                }
                // A status/degradation reply for our agent means it landed.
                if t.contains(agent_id) {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        }
    }

    if needs_register {
        // Register on the WS plane with the tier the agent actually holds on the
        // Unix plane (recorded by `register()`). If this agent never registered
        // in-process (e.g. emit_output called first, or a fresh process), fall
        // back to "supervised" — the safe, most-restrictive oversight default.
        let tier = AGENT_TIERS
            .lock()
            .unwrap()
            .get(agent_id)
            .cloned()
            .unwrap_or_else(|| "supervised".to_string());
        // Seed the GoalDrift / Scope detectors from the in-process registries
        // if the operator set them (no-ops when absent).
        let goal = AGENT_GOALS.lock().unwrap().get(agent_id).cloned();
        let scope = AGENT_SCOPES.lock().unwrap().get(agent_id).cloned();
        let register_msg = serde_json::json!({
            "type": "register",
            "agent_id": agent_id,
            "tier": tier,
            "goal": goal,
            "scope": scope,
        })
        .to_string();
        // On a single connection these frames are processed in order: register
        // creates the WS agent, then the resent output is observed.
        ws.send(Message::Text(register_msg))
            .map_err(|e| PyRuntimeError::new_err(format!("websocket send failed: {e}")))?;
        ws.send(Message::Text(emit_msg))
            .map_err(|e| PyRuntimeError::new_err(format!("websocket send failed: {e}")))?;
        for _ in 0..8 {
            match ws.read() {
                Ok(Message::Text(t))
                    if t.contains(agent_id) && !t.contains("not registered") =>
                {
                    break
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => continue,
            }
        }
    }

    let _ = ws.close(None);
    Ok(None)
}

/// Query the status of a registered agent.
#[pyfunction]
fn status(agent_id: &str) -> PyResult<StatusResponse> {
    let req = SentinelRequest {
        method: "status".into(),
        agent_id: agent_id.into(),
        tier: None,
        text: None,
    };
    let resp = send_request(&req)?;
    serde_json::from_str(&resp)
        .map_err(|e| PyRuntimeError::new_err(format!("parse response failed: {e}")))
}

// ════════════════════════════════════════════════════════════════════════════
// Sentinel v3 — operator-only bindings (Agent 8)
//
// These types and functions are for HUMAN OPERATORS and EXTERNAL INTEGRATORS.
// They are NEVER exposed to or callable by the agent under watch. Hashes are
// surfaced as `sha256:<hex>` strings (not raw bytes) and timestamps as ISO-8601
// strings, matching the operator-facing contract in the v3 spec.
// ════════════════════════════════════════════════════════════════════════════

/// `sha256:<hex>` rendering of a 32-byte hash, matching the format used by
/// sentinel-keygen and the on-disk audit chain.
fn hash_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Process identity — returned when querying agent registration. Operator
/// visibility only; never constructed by the agent.
#[pyclass(get_all)]
#[derive(Clone)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub binary_hash: String,
    pub binary_path: String,
    pub parent_pid: u32,
    pub parent_hash: String,
    pub uid: u32,
}

#[pymethods]
impl ProcessIdentity {
    #[new]
    fn new(
        pid: u32,
        binary_hash: String,
        binary_path: String,
        parent_pid: u32,
        parent_hash: String,
        uid: u32,
    ) -> Self {
        Self { pid, binary_hash, binary_path, parent_pid, parent_hash, uid }
    }

    fn __repr__(&self) -> String {
        format!(
            "ProcessIdentity(pid={}, binary_path={:?}, uid={})",
            self.pid, self.binary_path, self.uid
        )
    }
}

impl From<&sentinel_types::ProcessIdentity> for ProcessIdentity {
    fn from(id: &sentinel_types::ProcessIdentity) -> Self {
        Self {
            pid: id.pid,
            binary_hash: hash_hex(&id.binary_hash),
            binary_path: id.binary_path.display().to_string(),
            parent_pid: id.parent_pid,
            parent_hash: hash_hex(&id.parent_hash),
            uid: id.uid,
        }
    }
}

/// Session credential summary — read-only, operator visibility only. The raw
/// credential never leaves Sentinel's custody; only this summary is exposed.
#[pyclass(get_all)]
#[derive(Clone)]
pub struct SessionCredentialSummary {
    pub agent_id: String,
    pub issued_at: String,
    pub credential_hash: String,
}

#[pymethods]
impl SessionCredentialSummary {
    #[new]
    fn new(agent_id: String, issued_at: String, credential_hash: String) -> Self {
        Self { agent_id, issued_at, credential_hash }
    }

    fn __repr__(&self) -> String {
        format!(
            "SessionCredentialSummary(agent_id={:?}, issued_at={:?})",
            self.agent_id, self.issued_at
        )
    }
}

impl From<&sentinel_types::SessionCredential> for SessionCredentialSummary {
    fn from(c: &sentinel_types::SessionCredential) -> Self {
        Self {
            agent_id: c.agent_id.clone(),
            issued_at: c.issued_at.to_rfc3339(),
            credential_hash: hash_hex(&c.credential_hash),
        }
    }
}

/// Audit chain entry — for reading the audit log from Python. `chain_valid` is
/// pre-verified by the binding layer (via the real sentinel-core verifier).
#[pyclass(get_all)]
#[derive(Clone)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: String,
    pub agent_id: String,
    pub event: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub chain_valid: bool,
}

#[pymethods]
impl AuditEntry {
    fn __repr__(&self) -> String {
        format!(
            "AuditEntry(sequence={}, event={:?}, chain_valid={})",
            self.sequence, self.event, self.chain_valid
        )
    }
}

/// One NDJSON line of the on-disk audit chain (the public, greppable shape that
/// sentinel-core's `AuditChain` writes).
#[derive(serde::Deserialize)]
struct WireLine {
    sequence: u64,
    timestamp: String,
    agent_id: String,
    event: serde_json::Value,
    prev_hash: String,
    entry_hash: String,
}

/// Render an `AuditEvent`-shaped JSON value as a compact operator-facing string.
fn event_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Query the process identity of a registered agent.
///
/// The current sentinel-core daemon protocol (register / heartbeat / status /
/// deregister) does not expose a process-identity query, so this raises a
/// SentinelError until the daemon grows that endpoint. The `ProcessIdentity`
/// type itself is fully usable (e.g. for tests and future wiring).
#[pyfunction]
fn get_process_identity(agent_id: &str) -> PyResult<ProcessIdentity> {
    Err(PyRuntimeError::new_err(format!(
        "get_process_identity({agent_id:?}): the sentinel-core daemon protocol does \
         not expose process-identity queries in this build; identity is available \
         to the daemon's socket-auth gate but is not yet queryable by operators"
    )))
}

/// Read audit chain entries from an on-disk log. Returns a list of `AuditEntry`
/// (iterable with `for entry in ...`), each carrying a pre-verified
/// `chain_valid` flag computed from the real sentinel-core chain verifier.
#[pyfunction]
fn read_audit_chain(path: &str) -> PyResult<Vec<AuditEntry>> {
    // First, a single authoritative integrity pass to locate any break point.
    let break_at: Option<u64> = match verify_chain(Path::new(path)) {
        Ok(outcome) => outcome.broken.map(|b| b.sequence),
        Err(e) => {
            return Err(PyRuntimeError::new_err(format!(
                "could not read audit chain {path:?}: {e}"
            )))
        }
    };

    let text = std::fs::read_to_string(path)
        .map_err(|e| PyRuntimeError::new_err(format!("read {path:?}: {e}")))?;

    let mut entries = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let w: WireLine = serde_json::from_str(line)
            .map_err(|e| PyRuntimeError::new_err(format!("malformed audit entry: {e}")))?;
        // An entry is valid iff the chain has no break, or this entry precedes it.
        let chain_valid = break_at.map_or(true, |s| w.sequence < s);
        entries.push(AuditEntry {
            sequence: w.sequence,
            timestamp: w.timestamp,
            agent_id: w.agent_id,
            event: event_to_string(&w.event),
            prev_hash: w.prev_hash,
            entry_hash: w.entry_hash,
            chain_valid,
        });
    }
    Ok(entries)
}

/// Verify audit chain integrity from Python. Returns a dict:
/// `{"intact": bool, "entries_verified": int, "break_at_sequence": int | None}`.
/// Backed by sentinel-core's real `verify_chain` (Agent 6) — no re-implementation.
#[pyfunction]
fn verify_audit_chain<'py>(py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyDict>> {
    let outcome = verify_chain(Path::new(path))
        .map_err(|e| PyRuntimeError::new_err(format!("verify {path:?}: {e}")))?;
    let d = PyDict::new_bound(py);
    d.set_item("intact", outcome.is_intact())?;
    d.set_item("entries_verified", outcome.entries_verified)?;
    match outcome.broken {
        Some(b) => d.set_item("break_at_sequence", b.sequence)?,
        None => d.set_item("break_at_sequence", py.None())?,
    }
    Ok(d)
}

/// Get the current deployment profile name (e.g. "development", "enterprise").
///
/// Read from the `SENTINEL_PROFILE` environment variable the daemon is launched
/// with; defaults to "development" when unset. (The daemon does not yet expose a
/// profile query over its socket; this is the operator-side accessor.)
#[pyfunction]
fn get_profile() -> String {
    std::env::var("SENTINEL_PROFILE").unwrap_or_else(|_| "development".to_string())
}

/// Whether the daemon is running in observer-only mode (the `--oo` flag).
///
/// Read from the `SENTINEL_OBSERVER_MODE` environment variable; truthy values
/// are "1", "true", "yes", "observer", "observer_only" (case-insensitive).
#[pyfunction]
fn is_observer_mode() -> bool {
    match std::env::var("SENTINEL_OBSERVER_MODE") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "observer" | "observer_only"
        ),
        Err(_) => false,
    }
}

/// Python module definition.
#[pymodule]
fn _sentinel_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Functions — match sentinel-core Unix socket methods exactly
    m.add_function(wrap_pyfunction!(register, m)?)?;
    m.add_function(wrap_pyfunction!(heartbeat, m)?)?;
    m.add_function(wrap_pyfunction!(emit_output, m)?)?;
    m.add_function(wrap_pyfunction!(observe_tool_call, m)?)?;
    m.add_function(wrap_pyfunction!(set_agent_goal, m)?)?;
    m.add_function(wrap_pyfunction!(set_agent_scope, m)?)?;
    m.add_function(wrap_pyfunction!(status, m)?)?;

    // Types — re-exported from sentinel-types, not redefined
    m.add_class::<AgentTier>()?;
    m.add_class::<AgentState>()?;
    m.add_class::<RegisterResponse>()?;
    m.add_class::<HeartbeatResponse>()?;
    m.add_class::<EmitOutputResponse>()?;
    m.add_class::<StatusResponse>()?;

    // v3 operator-only surface (Agent 8).
    m.add_class::<ProcessIdentity>()?;
    m.add_class::<SessionCredentialSummary>()?;
    m.add_class::<AuditEntry>()?;
    m.add_function(wrap_pyfunction!(get_process_identity, m)?)?;
    m.add_function(wrap_pyfunction!(read_audit_chain, m)?)?;
    m.add_function(wrap_pyfunction!(verify_audit_chain, m)?)?;
    m.add_function(wrap_pyfunction!(get_profile, m)?)?;
    m.add_function(wrap_pyfunction!(is_observer_mode, m)?)?;

    Ok(())
}
