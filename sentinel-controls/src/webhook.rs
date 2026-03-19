use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use sentinel_types::WebhookPayload;

/// Sends a webhook POST to the configured URL with the event payload.
/// Uses raw TCP + HTTP/1.1 to avoid external dependencies.
/// Returns Ok(status_code) on success, Err on connection/write failure.
pub fn send_webhook(url: &str, payload: &WebhookPayload) -> Result<u16, WebhookError> {
    let parsed = parse_url(url)?;
    let body = serialize_payload(payload);

    let mut stream = TcpStream::connect_timeout(
        &parsed.addr.parse().map_err(|_| WebhookError::InvalidUrl)?,
        Duration::from_millis(5000),
    )
    .map_err(|e| WebhookError::Connection(e.to_string()))?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        parsed.path, parsed.host, body.len(), body
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| WebhookError::Write(e.to_string()))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| WebhookError::Read(e.to_string()))?;

    parse_status_code(&response)
}

#[derive(Debug)]
pub enum WebhookError {
    InvalidUrl,
    Connection(String),
    Write(String),
    Read(String),
    BadResponse,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => write!(f, "invalid webhook URL"),
            Self::Connection(e) => write!(f, "connection failed: {}", e),
            Self::Write(e) => write!(f, "write failed: {}", e),
            Self::Read(e) => write!(f, "read failed: {}", e),
            Self::BadResponse => write!(f, "could not parse HTTP response"),
        }
    }
}

impl std::error::Error for WebhookError {}

struct ParsedUrl {
    host: String,
    addr: String,
    path: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, WebhookError> {
    let stripped = url
        .strip_prefix("http://")
        .ok_or(WebhookError::InvalidUrl)?;
    let (host_port, path) = stripped
        .split_once('/')
        .map(|(h, p)| (h.to_string(), format!("/{}", p)))
        .unwrap_or_else(|| (stripped.to_string(), "/".to_string()));

    let addr = if host_port.contains(':') {
        host_port.clone()
    } else {
        format!("{}:80", host_port)
    };

    Ok(ParsedUrl {
        host: host_port,
        addr,
        path,
    })
}

fn parse_status_code(response: &str) -> Result<u16, WebhookError> {
    // HTTP/1.1 200 OK
    let first_line = response.lines().next().ok_or(WebhookError::BadResponse)?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(WebhookError::BadResponse);
    }
    parts[1].parse().map_err(|_| WebhookError::BadResponse)
}

/// Minimal JSON serializer for WebhookPayload — no serde_json dependency.
fn serialize_payload(payload: &WebhookPayload) -> String {
    format!(
        r#"{{"event":{{"agent_id":"{}","signal_type":"{}","score":{},"timestamp":"{}"}},"action":{{"agent_id":"{}","tier":"{}","permissions":{{"read":{},"write":{},"execute":{}}},"reason":"{}","timestamp":"{}"}}}}"#,
        escape_json(&payload.event.agent_id),
        format!("{:?}", payload.event.signal_type),
        payload.event.score,
        escape_json(&payload.event.timestamp),
        escape_json(&payload.action.agent_id),
        format!("{:?}", payload.action.tier),
        payload.action.permissions.read,
        payload.action.permissions.write,
        payload.action.permissions.execute,
        escape_json(&payload.action.reason),
        escape_json(&payload.action.timestamp),
    )
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_basic() {
        let p = parse_url("http://localhost:9090/sentinel/events").unwrap();
        assert_eq!(p.host, "localhost:9090");
        assert_eq!(p.addr, "localhost:9090");
        assert_eq!(p.path, "/sentinel/events");
    }

    #[test]
    fn parse_url_no_port() {
        let p = parse_url("http://example.com/hook").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.addr, "example.com:80");
        assert_eq!(p.path, "/hook");
    }

    #[test]
    fn parse_url_rejects_https() {
        assert!(parse_url("https://example.com/hook").is_err());
    }

    #[test]
    fn parse_status_code_ok() {
        assert_eq!(
            parse_status_code("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n").unwrap(),
            200
        );
    }

    #[test]
    fn parse_status_code_404() {
        assert_eq!(
            parse_status_code("HTTP/1.1 404 Not Found\r\n").unwrap(),
            404
        );
    }

    #[test]
    fn escape_json_special_chars() {
        assert_eq!(escape_json("he\"llo"), "he\\\"llo");
        assert_eq!(escape_json("new\nline"), "new\\nline");
    }

    #[test]
    fn serialize_payload_produces_valid_structure() {
        use sentinel_types::*;
        let payload = WebhookPayload {
            event: DegradationEvent {
                agent_id: "agent-1".to_string(),
                signal_type: SignalType::RepetitionScore,
                score: 0.75,
                timestamp: "2026-03-18T00:00:00Z".to_string(),
            },
            action: ControlAction {
                agent_id: "agent-1".to_string(),
                tier: ResponseTier::Soft,
                permissions: PermissionSet::full(),
                reason: "test reason".to_string(),
                timestamp: "2026-03-18T00:00:00Z".to_string(),
            },
        };
        let json = serialize_payload(&payload);
        assert!(json.contains("agent-1"));
        assert!(json.contains("0.75"));
        assert!(json.contains("RepetitionScore"));
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
    }
}
