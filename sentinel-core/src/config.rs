// Configuration loaded from sentinel.toml.
//
// Only the keys the daemon needs are modeled. Serde ignores unknown keys,
// so the existing [thresholds.window], [controls.webhook] and [audit]
// blocks remain valid and untouched — this struct reads, never rewrites.

use serde::Deserialize;

/// Top-level sentinel.toml view.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub websocket: WebsocketConfig,
    pub thresholds: Thresholds,
    pub controls: Controls,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            websocket: WebsocketConfig::default(),
            thresholds: Thresholds::default(),
            controls: Controls::default(),
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
