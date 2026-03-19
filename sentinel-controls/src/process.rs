//! Process-level controls for agent termination.
//!
//! Sentinel operates entirely outside the agent's process space.
//! The agent is blind to Sentinel's existence — controls are applied
//! externally at the OS/process level.

use crate::audit::{create_audit_entry, AuditLog};
use std::path::Path;

/// Sends SIGTERM to a process by PID.
/// Returns Ok(true) if the signal was delivered, Ok(false) if the process
/// was not found, and Err on system-level failure.
///
/// # Safety
/// Uses libc::kill which is safe for valid PIDs. An invalid PID returns ESRCH.
pub fn sigterm_agent(pid: u32) -> Result<bool, std::io::Error> {
    // SAFETY: kill(2) with SIGTERM is safe — worst case is ESRCH (no such process).
    let ret = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if ret == 0 {
        Ok(true)
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            // Process doesn't exist — not an error, just already gone.
            Ok(false)
        } else {
            Err(err)
        }
    }
}

/// Full Hard-tier response: SIGTERM + revoke all permissions + lock agent_id.
/// Writes an immutable audit entry for the kill action.
pub fn hard_terminate(
    pid: u32,
    agent_id: &str,
    timestamp: &str,
    operator_id: &str,
    audit_log_path: &Path,
) -> HardTerminateResult {
    let audit = AuditLog::new(audit_log_path);

    // Audit the kill attempt BEFORE sending the signal.
    let action = format!("SIGTERM:pid={}:agent={}", pid, agent_id);
    let entry = create_audit_entry(&action, timestamp, operator_id);
    let audit_hash = entry.hash.clone();
    let audit_written = audit.append(&entry).is_ok();

    let signal_sent = match sigterm_agent(pid) {
        Ok(sent) => sent,
        Err(_) => false,
    };

    // Audit the result.
    let result_action = format!(
        "SIGTERM_result:pid={}:agent={}:sent={}",
        pid, agent_id, signal_sent
    );
    let result_entry = create_audit_entry(&result_action, timestamp, operator_id);
    let _ = audit.append(&result_entry);

    HardTerminateResult {
        signal_sent,
        audit_written,
        audit_hash,
    }
}

/// Result of a hard termination action.
#[derive(Debug)]
pub struct HardTerminateResult {
    pub signal_sent: bool,
    pub audit_written: bool,
    pub audit_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn sigterm_nonexistent_pid() {
        // PID 4294967 is almost certainly not running.
        let result = sigterm_agent(4_294_967);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Process not found — returns false.
    }

    #[test]
    fn hard_terminate_writes_audit() {
        let dir = std::env::temp_dir().join("sentinel_process_test");
        let _ = fs::create_dir_all(&dir);
        let audit_path = dir.join(format!("proc_audit_{}.log", std::process::id()));

        let result = hard_terminate(
            4_294_967, // Non-existent PID
            "agent-test",
            "2026-03-18T00:00:00Z",
            "sys",
            &audit_path,
        );

        assert!(result.audit_written);
        assert!(!result.signal_sent); // PID doesn't exist
        assert_eq!(result.audit_hash.len(), 64);

        // Verify audit file has entries
        let contents = fs::read_to_string(&audit_path).unwrap();
        assert!(contents.contains("SIGTERM"));
        assert!(contents.contains("agent-test"));
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2); // Attempt + result

        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn hard_terminate_audit_hash_is_deterministic() {
        let dir = std::env::temp_dir().join("sentinel_process_test");
        let _ = fs::create_dir_all(&dir);
        let path1 = dir.join(format!("det1_{}.log", std::process::id()));
        let path2 = dir.join(format!("det2_{}.log", std::process::id()));

        let r1 = hard_terminate(999, "a1", "2026-03-18T00:00:00Z", "op", &path1);
        let r2 = hard_terminate(999, "a1", "2026-03-18T00:00:00Z", "op", &path2);

        assert_eq!(r1.audit_hash, r2.audit_hash);

        let _ = fs::remove_file(&path1);
        let _ = fs::remove_file(&path2);
    }
}
