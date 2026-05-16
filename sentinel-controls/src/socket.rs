use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sentinel_types::PermissionSet;

use crate::audit::{create_audit_entry, AuditLog};
use crate::controller::ControlEngine;

/// Request from the human operator over the Unix socket.
/// Wire format: one JSON object per line.
///
/// Supported commands:
///   {"command":"override","agent_id":"...","permissions":"full|read_only|none","operator_id":"..."}
///   {"command":"status","agent_id":"...","operator_id":"..."}
///   {"command":"unlock","agent_id":"...","operator_id":"..."}
#[derive(Debug)]
pub struct OperatorRequest {
    pub command: String,
    pub agent_id: String,
    pub operator_id: String,
    pub permissions: Option<String>,
}

/// Response sent back over the Unix socket.
#[derive(Debug)]
pub struct OperatorResponse {
    pub ok: bool,
    pub message: String,
    pub audit_hash: String,
}

impl OperatorResponse {
    fn to_json(&self) -> String {
        format!(
            r#"{{"ok":{},"message":"{}","audit_hash":"{}"}}"#,
            self.ok,
            escape_json(&self.message),
            escape_json(&self.audit_hash),
        )
    }
}

/// Parse a minimal JSON line into an OperatorRequest.
/// Avoids serde_json dependency — parses only the fields we need.
fn parse_request(line: &str) -> Result<OperatorRequest, String> {
    let command = extract_field(line, "command").ok_or("missing 'command' field")?;
    let agent_id = extract_field(line, "agent_id").ok_or("missing 'agent_id' field")?;
    let operator_id = extract_field(line, "operator_id").ok_or("missing 'operator_id' field")?;
    let permissions = extract_field(line, "permissions");

    Ok(OperatorRequest {
        command,
        agent_id,
        operator_id,
        permissions,
    })
}

/// Extract a string value for a given key from a JSON-like string.
/// Simple substring search — sufficient for flat, well-formed objects.
fn extract_field(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Unix socket server for human operator overrides.
///
/// Every operator action is:
/// - Timestamped (ISO 8601 UTC)
/// - SHA256 hashed (action + timestamp + operator_id)
/// - Appended to the immutable audit log
pub struct OverrideSocket {
    socket_path: PathBuf,
    engine: Arc<Mutex<ControlEngine>>,
    audit_log: AuditLog,
}

impl OverrideSocket {
    pub fn new(socket_path: &Path, engine: Arc<Mutex<ControlEngine>>, audit_log_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
            engine,
            audit_log: AuditLog::new(audit_log_path),
        }
    }

    /// Handle a single operator request. Returns the JSON response string.
    /// This is the core logic, separated from I/O for testability.
    pub fn handle_request(&self, req: &OperatorRequest, timestamp: &str) -> OperatorResponse {
        match req.command.as_str() {
            "override" => self.handle_override(req, timestamp),
            "status" => self.handle_status(req, timestamp),
            "unlock" => self.handle_unlock(req, timestamp),
            _ => {
                let entry = create_audit_entry(
                    &format!("unknown_command:{}", req.command),
                    timestamp,
                    &req.operator_id,
                );
                let hash = entry.hash.clone();
                let _ = self.audit_log.append(&entry);
                OperatorResponse {
                    ok: false,
                    message: format!("unknown command: {}", req.command),
                    audit_hash: hash,
                }
            }
        }
    }

    fn handle_override(&self, req: &OperatorRequest, timestamp: &str) -> OperatorResponse {
        let permissions = match req.permissions.as_deref() {
            Some("full") => PermissionSet::full(),
            Some("read_only") => PermissionSet::read_only(),
            Some("none") => PermissionSet::none(),
            Some(other) => {
                let action = format!("invalid_override_permissions:{}:{}", req.agent_id, other);
                let entry = create_audit_entry(&action, timestamp, &req.operator_id);
                let hash = entry.hash.clone();
                let _ = self.audit_log.append(&entry);
                return OperatorResponse {
                    ok: false,
                    message: format!("invalid permissions: {}", other),
                    audit_hash: hash,
                };
            }
            None => {
                let action = format!("missing_permissions:{}", req.agent_id);
                let entry = create_audit_entry(&action, timestamp, &req.operator_id);
                let hash = entry.hash.clone();
                let _ = self.audit_log.append(&entry);
                return OperatorResponse {
                    ok: false,
                    message: "missing 'permissions' field".to_string(),
                    audit_hash: hash,
                };
            }
        };

        let action = format!("operator_override:{}:{}", req.agent_id, req.permissions.as_deref().unwrap_or("unknown"));
        let entry = create_audit_entry(&action, timestamp, &req.operator_id);
        let hash = entry.hash.clone();
        let _ = self.audit_log.append(&entry);

        let mut engine = self.engine.lock().unwrap();
        engine.operator_override(
            &req.agent_id,
            permissions,
            timestamp,
            &req.operator_id,
        );

        OperatorResponse {
            ok: true,
            message: format!("override applied to {}", req.agent_id),
            audit_hash: hash,
        }
    }

    fn handle_status(&self, req: &OperatorRequest, timestamp: &str) -> OperatorResponse {
        let action = format!("status_query:{}", req.agent_id);
        let entry = create_audit_entry(&action, timestamp, &req.operator_id);
        let hash = entry.hash.clone();
        let _ = self.audit_log.append(&entry);

        let engine = self.engine.lock().unwrap();
        let perms = engine.get_permissions(&req.agent_id);
        let score = engine.get_cumulative_score(&req.agent_id);
        let locked = engine.is_locked(&req.agent_id);

        OperatorResponse {
            ok: true,
            message: format!(
                "agent={} locked={} score={:.3} read={} write={} execute={}",
                req.agent_id, locked, score, perms.read, perms.write, perms.execute
            ),
            audit_hash: hash,
        }
    }

    fn handle_unlock(&self, req: &OperatorRequest, timestamp: &str) -> OperatorResponse {
        let action = format!("operator_unlock:{}", req.agent_id);
        let entry = create_audit_entry(&action, timestamp, &req.operator_id);
        let hash = entry.hash.clone();
        let _ = self.audit_log.append(&entry);

        let mut engine = self.engine.lock().unwrap();
        engine.operator_override(
            &req.agent_id,
            PermissionSet::full(),
            timestamp,
            &req.operator_id,
        );

        OperatorResponse {
            ok: true,
            message: format!("agent {} unlocked with full permissions", req.agent_id),
            audit_hash: hash,
        }
    }

    /// Start listening on the Unix socket. Blocks the calling thread.
    /// Each connection is handled synchronously — one request per line.
    pub fn serve(&self) -> std::io::Result<()> {
        // Remove stale socket file.
        let _ = std::fs::remove_file(&self.socket_path);

        // Ensure parent directory exists.
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let mut reader = BufReader::new(&stream);
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_ok() && !line.is_empty() {
                        let timestamp = now_utc();
                        match parse_request(line.trim()) {
                            Ok(req) => {
                                let resp = self.handle_request(&req, &timestamp);
                                let mut writer = stream;
                                let _ = writeln!(writer, "{}", resp.to_json());
                            }
                            Err(e) => {
                                let mut writer = stream;
                                let resp = OperatorResponse {
                                    ok: false,
                                    message: e.to_string(),
                                    audit_hash: String::new(),
                                };
                                let _ = writeln!(writer, "{}", resp.to_json());
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

/// Current UTC time in ISO 8601 format. Uses system time — no external crate.
fn now_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Convert epoch seconds to ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ).
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to Y-M-D (Gregorian).
    let (year, month, day) = epoch_days_to_ymd(days as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn epoch_days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_types::ControlThresholds;
    use std::fs;

    /// Monotonic counter so each test gets its own audit-log and socket
    /// paths — tests run in parallel and each deletes its own files.
    fn unique_suffix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn test_engine_and_socket() -> (OverrideSocket, std::path::PathBuf) {
        let dir = std::env::temp_dir().join("sentinel_socket_test");
        let _ = fs::create_dir_all(&dir);
        let suffix = unique_suffix();
        let audit_path = dir.join(format!("socket_audit_{}.log", suffix));
        let socket_path = dir.join(format!("test_{}.sock", suffix));

        let engine = ControlEngine::new(
            ControlThresholds::default(),
            None,
            &audit_path,
        );
        let engine = Arc::new(Mutex::new(engine));

        let socket = OverrideSocket::new(&socket_path, engine, &audit_path);
        (socket, audit_path)
    }

    #[test]
    fn parse_request_basic() {
        let line = r#"{"command":"override","agent_id":"agent-1","operator_id":"op-1","permissions":"full"}"#;
        let req = parse_request(line).unwrap();
        assert_eq!(req.command, "override");
        assert_eq!(req.agent_id, "agent-1");
        assert_eq!(req.operator_id, "op-1");
        assert_eq!(req.permissions.as_deref(), Some("full"));
    }

    #[test]
    fn parse_request_missing_command() {
        let line = r#"{"agent_id":"agent-1","operator_id":"op-1"}"#;
        assert!(parse_request(line).is_err());
    }

    #[test]
    fn extract_field_works() {
        let json = r#"{"foo":"bar","baz":"qux"}"#;
        assert_eq!(extract_field(json, "foo"), Some("bar".to_string()));
        assert_eq!(extract_field(json, "baz"), Some("qux".to_string()));
        assert_eq!(extract_field(json, "missing"), None);
    }

    #[test]
    fn handle_status_request() {
        let (socket, audit_path) = test_engine_and_socket();
        let req = OperatorRequest {
            command: "status".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: None,
        };
        let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
        assert!(resp.ok);
        assert!(resp.message.contains("agent-1"));
        assert!(!resp.audit_hash.is_empty());
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn handle_override_full() {
        let (socket, audit_path) = test_engine_and_socket();
        let req = OperatorRequest {
            command: "override".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: Some("full".to_string()),
        };
        let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
        assert!(resp.ok);
        assert!(resp.message.contains("override applied"));
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn handle_override_read_only() {
        let (socket, audit_path) = test_engine_and_socket();
        let req = OperatorRequest {
            command: "override".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: Some("read_only".to_string()),
        };
        let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
        assert!(resp.ok);
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn handle_override_invalid_permissions() {
        let (socket, audit_path) = test_engine_and_socket();
        let req = OperatorRequest {
            command: "override".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: Some("admin".to_string()),
        };
        let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
        assert!(!resp.ok);
        assert!(resp.message.contains("invalid permissions"));
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn handle_override_missing_permissions() {
        let (socket, audit_path) = test_engine_and_socket();
        let req = OperatorRequest {
            command: "override".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: None,
        };
        let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
        assert!(!resp.ok);
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn handle_unlock_request() {
        let (socket, audit_path) = test_engine_and_socket();
        let req = OperatorRequest {
            command: "unlock".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: None,
        };
        let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
        assert!(resp.ok);
        assert!(resp.message.contains("unlocked"));
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn handle_unknown_command() {
        let (socket, audit_path) = test_engine_and_socket();
        let req = OperatorRequest {
            command: "reboot".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: None,
        };
        let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
        assert!(!resp.ok);
        assert!(resp.message.contains("unknown command"));
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn all_actions_produce_audit_hash() {
        let (socket, audit_path) = test_engine_and_socket();

        let commands = vec!["override", "status", "unlock", "unknown_cmd"];
        for cmd in commands {
            let req = OperatorRequest {
                command: cmd.to_string(),
                agent_id: "agent-1".to_string(),
                operator_id: "op-1".to_string(),
                permissions: if cmd == "override" { Some("full".to_string()) } else { None },
            };
            let resp = socket.handle_request(&req, "2026-03-18T00:00:00Z");
            // Every response must have an audit hash (except parse errors at the socket level)
            if cmd != "override" || resp.ok {
                assert!(!resp.audit_hash.is_empty(), "missing audit hash for command: {}", cmd);
            }
        }
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn audit_log_grows_with_operations() {
        let (socket, audit_path) = test_engine_and_socket();

        let req1 = OperatorRequest {
            command: "status".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: None,
        };
        let req2 = OperatorRequest {
            command: "override".to_string(),
            agent_id: "agent-1".to_string(),
            operator_id: "op-1".to_string(),
            permissions: Some("read_only".to_string()),
        };

        socket.handle_request(&req1, "2026-03-18T00:00:00Z");
        socket.handle_request(&req2, "2026-03-18T00:01:00Z");

        let contents = fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        // At least 2 entries (status query + override; override also writes to engine's log)
        assert!(lines.len() >= 2, "expected at least 2 audit entries, got {}", lines.len());
        let _ = fs::remove_file(&audit_path);
    }

    #[test]
    fn response_to_json_format() {
        let resp = OperatorResponse {
            ok: true,
            message: "test message".to_string(),
            audit_hash: "abc123".to_string(),
        };
        let json = resp.to_json();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"message\":\"test message\""));
        assert!(json.contains("\"audit_hash\":\"abc123\""));
    }

    #[test]
    fn now_utc_format() {
        let ts = now_utc();
        // Should be ISO 8601: YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn epoch_days_known_date() {
        // 2026-03-18 is day 20530 since epoch (1970-01-01)
        let (y, m, d) = epoch_days_to_ymd(20530);
        assert_eq!(y, 2026);
        assert_eq!(m, 3);
        assert_eq!(d, 18);
    }

    #[test]
    fn unix_socket_roundtrip() {
        // Test actual Unix socket I/O
        let dir = std::env::temp_dir().join("sentinel_socket_rt");
        let _ = fs::create_dir_all(&dir);
        let audit_path = dir.join(format!("rt_audit_{}.log", std::process::id()));
        let socket_path = dir.join(format!("rt_{}.sock", std::process::id()));

        let engine = ControlEngine::new(
            ControlThresholds::default(),
            None,
            &audit_path,
        );
        let engine = Arc::new(Mutex::new(engine));
        let socket = OverrideSocket::new(&socket_path, Arc::clone(&engine), &audit_path);

        // Start server in a thread
        let _sp = socket_path.clone();
        let handle = std::thread::spawn(move || {
            let _ = socket.serve();
        });

        // Give server time to bind
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Connect and send a status query
        let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
        let msg = r#"{"command":"status","agent_id":"agent-1","operator_id":"op-1"}"#;
        writeln!(stream, "{}", msg).unwrap();

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        assert!(response.contains("\"ok\":true"));
        assert!(response.contains("agent-1"));

        // Cleanup
        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_file(&audit_path);
        drop(handle);
    }
}
