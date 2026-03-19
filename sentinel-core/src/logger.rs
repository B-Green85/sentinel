use crate::types::now_timestamp;
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use tokio::sync::mpsc;

/// Structured JSON log entry written to /var/log/sentinel/agents.log.
#[derive(Debug, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub component: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Async JSON logger. Receives log entries on a channel, writes to file.
/// Falls back to stderr if the log file is not writable.
pub struct Logger {
    tx: mpsc::UnboundedSender<LogEntry>,
}

impl Logger {
    /// Start the logger. Spawns a background task that writes entries.
    pub fn start(log_path: &str) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let path = log_path.to_string();
        tokio::spawn(Self::writer_task(rx, path));
        Self { tx }
    }

    /// Send a log entry (non-blocking).
    pub fn log(&self, entry: LogEntry) {
        let _ = self.tx.send(entry);
    }

    /// Convenience: log an info message.
    pub fn info(&self, component: &str, message: &str, agent_id: Option<&str>) {
        self.log(LogEntry {
            timestamp: now_timestamp(),
            level: "INFO".into(),
            component: component.into(),
            message: message.into(),
            agent_id: agent_id.map(String::from),
            detail: None,
        });
    }

    /// Convenience: log a warning.
    pub fn warn(&self, component: &str, message: &str, agent_id: Option<&str>) {
        self.log(LogEntry {
            timestamp: now_timestamp(),
            level: "WARN".into(),
            component: component.into(),
            message: message.into(),
            agent_id: agent_id.map(String::from),
            detail: None,
        });
    }

    async fn writer_task(mut rx: mpsc::UnboundedReceiver<LogEntry>, path: String) {
        // Ensure parent directory exists
        if let Some(parent) = Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        while let Some(entry) = rx.recv().await {
            let line = match serde_json::to_string(&entry) {
                Ok(json) => json,
                Err(_) => continue,
            };

            // Append to file, fall back to stderr
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "{line}");
                }
                Err(_) => {
                    eprintln!("{line}");
                }
            }
        }
    }
}

impl Clone for Logger {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_entry_serialization() {
        let entry = LogEntry {
            timestamp: "2026-01-01T00:00:00Z".into(),
            level: "INFO".into(),
            component: "daemon".into(),
            message: "agent registered".into(),
            agent_id: Some("agent-1".into()),
            detail: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"level\":\"INFO\""));
        assert!(json.contains("\"agent_id\":\"agent-1\""));
    }

    #[tokio::test]
    async fn test_logger_write_to_temp() {
        let dir = std::env::temp_dir().join("sentinel-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.log");
        let path_str = path.to_str().unwrap().to_string();

        let logger = Logger::start(&path_str);
        logger.info("test", "hello world", Some("agent-x"));

        // Give writer task time to flush
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(contents.contains("hello world"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
