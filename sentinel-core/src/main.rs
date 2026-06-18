// sentinel-core — systemd-compatible agent oversight daemon.
//
// Usage:
//   sentinel-core [--socket /path/to/socket] [--log /path/to/log]
//                 [--config /path/to/sentinel.toml]
//
// Defaults:
//   socket: /tmp/sentinel.sock   (overrides [transport].path)
//   log:    /var/log/sentinel/agents.log
//   config: sentinel.toml
//
// Interfaces (both speak the same JSON message protocol):
//   - Transport    — Unix socket / named pipe / kernel IPC, selected by the
//                    [transport] config block (see transport::create_transport)
//   - WebSocket    — language-agnostic clients, ws://host:port from config
//
// systemd unit example:
//   [Unit]
//   Description=Sentinel Agent Oversight Daemon
//   After=network.target
//
//   [Service]
//   Type=simple
//   ExecStart=/usr/local/bin/sentinel-core
//   Restart=always
//   RestartSec=5
//
//   [Install]
//   WantedBy=multi-user.target

use sentinel_core::config::Config;
use sentinel_core::transport::create_transport;
use sentinel_core::websocket::WsServer;
use sentinel_core::SentinelDaemon;
use std::sync::Arc;

fn parse_arg(args: &[String], flag: &str, default: &str) -> String {
    for i in 0..args.len() {
        if args[i] == flag {
            if let Some(val) = args.get(i + 1) {
                return val.clone();
            }
        }
    }
    default.to_string()
}

/// True if any of `flags` is present as a bare (valueless) switch.
fn has_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| flags.contains(&a.as_str()))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = parse_arg(&args, "--socket", "/tmp/sentinel.sock");
    let log_path = parse_arg(&args, "--log", "/var/log/sentinel/agents.log");
    let config_path = parse_arg(&args, "--config", "sentinel.toml");

    let mut config = Config::load(&config_path);
    // The `--socket` flag continues to drive the Unix transport path, so
    // existing invocations behave identically.
    config.transport.path = std::path::PathBuf::from(&socket_path);

    // `--oo` / `--observer-only` engages observer mode: signals are still
    // detected, scored, audited and broadcast, but no enforcement action is
    // ever taken. The flag overrides whatever the config file specified.
    if has_flag(&args, &["--oo", "--observer-only"]) {
        config.observer_mode = true;
    }

    let daemon = Arc::new(SentinelDaemon::new(&log_path));

    // Record the operating mode as the first audit entry so the trail itself
    // proves whether enforcement was live for this run.
    if config.observer_mode {
        eprintln!("sentinel-core: starting in OBSERVER-ONLY mode — no enforcement actions will be taken");
        daemon
            .audit()
            .record("sentinel", "sentinel_start", "observer_only")
            .await;
    } else {
        daemon
            .audit()
            .record("sentinel", "sentinel_start", "enforcement")
            .await;
    }

    // Start heartbeat monitor (checks every second).
    daemon.start_heartbeat_monitor(1);

    // Start the WebSocket server alongside the primary transport — it shares
    // the same audit trail, logger and event bus. Connectivity only; the
    // governance constraints are identical on both interfaces.
    if config.websocket.enabled {
        let ws = WsServer::new(
            Arc::clone(daemon.audit()),
            Arc::clone(daemon.event_bus()),
            daemon.logger(),
            config.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = ws.serve().await {
                eprintln!("sentinel-core: websocket server error: {e}");
            }
        });
    }

    // Serve over the configured transport (blocks forever — systemd manages
    // lifecycle).
    let transport = create_transport(&config);
    daemon
        .serve_transport(transport)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}
