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

use sentinel_types::{
    AgentTier, AgentState,
    RegisterResponse, HeartbeatResponse, EmitOutputResponse, StatusResponse,
    SentinelRequest, SentinelError,
};

const DEFAULT_SOCKET_PATH: &str = "/tmp/sentinel.sock";

fn get_socket_path() -> String {
    std::env::var("SENTINEL_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.into())
}

fn send_request(req: &SentinelRequest) -> PyResult<String> {
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

    // Check for error response
    if let Ok(err) = serde_json::from_str::<SentinelError>(&response) {
        if !err.code.is_empty() {
            return Err(PyRuntimeError::new_err(err.to_string()));
        }
    }

    Ok(response)
}

/// Register an agent with Sentinel for oversight.
#[pyfunction]
fn register(agent_id: &str, tier: &str) -> PyResult<RegisterResponse> {
    let req = SentinelRequest {
        method: "register".into(),
        agent_id: agent_id.into(),
        tier: Some(tier.into()),
        text: None,
    };
    let resp = send_request(&req)?;
    serde_json::from_str(&resp)
        .map_err(|e| PyRuntimeError::new_err(format!("parse response failed: {e}")))
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
#[pyfunction]
fn emit_output(agent_id: &str, text: &str) -> PyResult<EmitOutputResponse> {
    let req = SentinelRequest {
        method: "emit_output".into(),
        agent_id: agent_id.into(),
        tier: None,
        text: Some(text.into()),
    };
    let resp = send_request(&req)?;
    serde_json::from_str(&resp)
        .map_err(|e| PyRuntimeError::new_err(format!("parse response failed: {e}")))
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

/// Python module definition.
#[pymodule]
fn _sentinel_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Functions — match sentinel-core Unix socket methods exactly
    m.add_function(wrap_pyfunction!(register, m)?)?;
    m.add_function(wrap_pyfunction!(heartbeat, m)?)?;
    m.add_function(wrap_pyfunction!(emit_output, m)?)?;
    m.add_function(wrap_pyfunction!(status, m)?)?;

    // Types — re-exported from sentinel-types, not redefined
    m.add_class::<AgentTier>()?;
    m.add_class::<AgentState>()?;
    m.add_class::<RegisterResponse>()?;
    m.add_class::<HeartbeatResponse>()?;
    m.add_class::<EmitOutputResponse>()?;
    m.add_class::<StatusResponse>()?;

    Ok(())
}
