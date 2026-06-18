// Configuration loaded from sentinel.toml.
//
// Only the keys the daemon needs are modeled. Serde ignores unknown keys,
// so the existing [thresholds.window], [controls.webhook] and [audit]
// blocks remain valid and untouched — this struct reads, never rewrites.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level sentinel.toml view.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub websocket: WebsocketConfig,
    pub thresholds: Thresholds,
    pub controls: Controls,
    pub transport: TransportConfig,
    /// Observer-only mode (`--oo` / `--observer-only`). When set, detectors
    /// still run and every signal is scored, audited and broadcast — but NO
    /// enforcement action is taken (no soft pause, write suspend or terminate).
    /// Normally driven by the CLI flag; defaults off and may also be set in
    /// `sentinel.toml` for a permanently observe-only deployment.
    #[serde(default)]
    pub observer_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            websocket: WebsocketConfig::default(),
            thresholds: Thresholds::default(),
            controls: Controls::default(),
            transport: TransportConfig::default(),
            observer_mode: false,
        }
    }
}

/// `[websocket]` block — WS server alongside the Unix socket.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebsocketConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
}

impl Default for WebsocketConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 7777,
        }
    }
}

impl WebsocketConfig {
    /// `host:port` for binding the TCP listener.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// `[thresholds]` block — signal detection thresholds.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub repetition_score: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            repetition_score: 0.6,
        }
    }
}

/// `[controls]` block — cumulative score thresholds for response tiers.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Controls {
    pub soft_threshold: f64,
    pub medium_threshold: f64,
    pub hard_threshold: f64,
}

impl Default for Controls {
    fn default() -> Self {
        Self {
            soft_threshold: 0.4,
            medium_threshold: 0.7,
            hard_threshold: 0.9,
        }
    }
}

/// `[transport]` block — selects the OS-agnostic transport (Agent 3).
///
/// ```toml
/// [transport]
/// type = "auto"              # auto | unix | pipe
/// path = "/tmp/sentinel.sock"
/// pipe_name = "\\\\.\\pipe\\sentinel"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    #[serde(rename = "type")]
    pub transport_type: TransportType,
    pub path: PathBuf,
    pub pipe_name: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Auto,
            path: PathBuf::from("/tmp/sentinel.sock"),
            pipe_name: r"\\.\pipe\sentinel".to_string(),
        }
    }
}

/// Which transport implementation to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    /// Pick the native transport for the build target (Unix socket on
    /// Linux/macOS, named pipe on Windows).
    Auto,
    /// Force the Unix domain socket transport.
    Unix,
    /// Force the Windows named-pipe transport.
    Pipe,
}

impl Default for TransportType {
    fn default() -> Self {
        TransportType::Auto
    }
}

impl Config {
    /// Load configuration from a TOML file. On any failure, fall back to
    /// defaults and warn — the daemon must still come up.
    pub fn load(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => match toml::from_str::<Config>(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!(
                        "sentinel-core: failed to parse {path}: {e} — using defaults"
                    );
                    Config::default()
                }
            },
            Err(_) => {
                eprintln!("sentinel-core: config {path} not found — using defaults");
                Config::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let c = Config::default();
        assert!(c.websocket.enabled);
        assert_eq!(c.websocket.host, "127.0.0.1");
        assert_eq!(c.websocket.port, 7777);
        assert_eq!(c.websocket.bind_addr(), "127.0.0.1:7777");
    }

    #[test]
    fn transport_defaults() {
        let c = Config::default();
        assert_eq!(c.transport.transport_type, TransportType::Auto);
        assert_eq!(c.transport.path, PathBuf::from("/tmp/sentinel.sock"));
        assert_eq!(c.transport.pipe_name, r"\\.\pipe\sentinel");
    }

    #[test]
    fn parses_transport_block() {
        let toml = r#"
            [transport]
            type = "unix"
            path = "/run/sentinel.sock"
            pipe_name = "\\\\.\\pipe\\custom"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert_eq!(c.transport.transport_type, TransportType::Unix);
        assert_eq!(c.transport.path, PathBuf::from("/run/sentinel.sock"));
        assert_eq!(c.transport.pipe_name, r"\\.\pipe\custom");
    }

    #[test]
    fn transport_partial_uses_defaults() {
        // type given, path/pipe_name fall back to defaults
        let c: Config = toml::from_str("[transport]\ntype = \"pipe\"\n").unwrap();
        assert_eq!(c.transport.transport_type, TransportType::Pipe);
        assert_eq!(c.transport.path, PathBuf::from("/tmp/sentinel.sock"));
    }

    #[test]
    fn missing_transport_block_uses_defaults() {
        // The legacy config (no [transport]) must still load.
        let c: Config = toml::from_str("[websocket]\nport = 9000\n").unwrap();
        assert_eq!(c.websocket.port, 9000);
        assert_eq!(c.transport.transport_type, TransportType::Auto);
    }

    #[test]
    fn parses_websocket_block() {
        let toml = r#"
            [websocket]
            enabled = true
            port    = 7777
            host    = "127.0.0.1"

            [thresholds]
            repetition_score = 0.6

            [thresholds.window]
            repetition_window = 10

            [controls]
            soft_threshold = 0.4
            medium_threshold = 0.7
            hard_threshold = 0.9

            [controls.webhook]
            url = "http://localhost:9090/sentinel/events"

            [audit]
            log_path = "/var/log/sentinel/actions.log"
        "#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.websocket.enabled);
        assert_eq!(c.websocket.port, 7777);
        assert_eq!(c.thresholds.repetition_score, 0.6);
        assert_eq!(c.controls.hard_threshold, 0.9);
    }

    #[test]
    fn partial_block_uses_defaults() {
        let c: Config = toml::from_str("[websocket]\nport = 9000\n").unwrap();
        assert_eq!(c.websocket.port, 9000);
        assert_eq!(c.websocket.host, "127.0.0.1");
        assert!(c.websocket.enabled);
    }
}
