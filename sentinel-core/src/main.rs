// sentinel-core — systemd-compatible agent oversight daemon.
//
// Usage:
//   sentinel-core [--socket /path/to/socket] [--log /path/to/log]
//
// Defaults:
//   socket: /tmp/sentinel.sock
//   log:    /var/log/sentinel/agents.log
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

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let socket_path = parse_arg(&args, "--socket", "/tmp/sentinel.sock");
    let log_path = parse_arg(&args, "--log", "/var/log/sentinel/agents.log");

    let daemon = Arc::new(SentinelDaemon::new(&log_path));

    // Start heartbeat monitor (checks every second)
    daemon.start_heartbeat_monitor(1);

    // Serve on Unix socket (blocks forever — systemd manages lifecycle)
    daemon.serve(&socket_path).await
}
