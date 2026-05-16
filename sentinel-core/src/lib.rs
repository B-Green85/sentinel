// sentinel-core — Agent oversight daemon.
// Persistent background process, systemd-compatible.
// Accepts agent registrations via Unix socket.
// Tracks heartbeats, auto-downgrades tiers on missed thresholds.
//
// Operational security:
// - Sentinel has READ + EXECUTE only — never writes to agent sandbox
// - Agent is completely blind to Sentinel's existence
// - All operator actions timestamped, SHA256 hashed, immutable audit trail
// - No untracked writes. Ever. Not even from the operator.

pub mod audit;
pub mod config;
pub mod event_bus;
pub mod heartbeat;
pub mod logger;
pub mod sha256;
pub mod types;
pub mod websocket;

use audit::AuditTrail;
use event_bus::EventBus;
use heartbeat::HeartbeatMonitor;
use logger::Logger;
use types::{AgentRecord, Event, Request, Response, now_timestamp};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

/// The Sentinel daemon. All state is internal — invisible to agents.
pub struct SentinelDaemon {
    agents: Arc<Mutex<HashMap<String, AgentRecord>>>,
    event_bus: Arc<EventBus>,
    audit: Arc<AuditTrail>,
    logger: Logger,
}

impl SentinelDaemon {
    pub fn new(log_path: &str) -> Self {
        let logger = Logger::start(log_path);
        Self {
            agents: Arc::new(Mutex::new(HashMap::new())),
            event_bus: EventBus::new(256).into_shared(),
            audit: AuditTrail::new().into_shared(),
            logger,
        }
    }

    /// Get a reference to the event bus for signal detector integration.
    pub fn event_bus(&self) -> &Arc<EventBus> {
        &self.event_bus
    }

    /// Get a reference to the audit trail.
    pub fn audit(&self) -> &Arc<AuditTrail> {
        &self.audit
    }

    /// Get a clone of the logger handle (e.g. for the WebSocket server).
    pub fn logger(&self) -> Logger {
        self.logger.clone()
    }

    /// Start the heartbeat monitor as a background task.
    pub fn start_heartbeat_monitor(
        &self,
        check_interval_secs: u64,
    ) -> Arc<HeartbeatMonitor> {
        let monitor = Arc::new(HeartbeatMonitor::new(
            self.agents.clone(),
            self.event_bus.clone(),
            self.audit.clone(),
            self.logger.clone(),
        ));
        let m = monitor.clone();
        tokio::spawn(async move {
            m.run(check_interval_secs).await;
        });
        monitor
    }

    /// Process a request and return a JSON response string.
    pub async fn handle_request(&self, req: Request) -> String {
        match req {
            Request::Register(r) => self.handle_register(r).await,
            Request::Heartbeat(h) => self.handle_heartbeat(h).await,
            Request::Status { agent_id } => self.handle_status(&agent_id).await,
            Request::Deregister { agent_id } => self.handle_deregister(&agent_id).await,
        }
    }

    async fn handle_register(&self, req: types::RegisterRequest) -> String {
        let ts = now_timestamp();
        let hash = self
            .audit
            .record("operator", "register", &req.agent_id)
            .await;

        let tier_str = req.permission_tier.to_string();
        let record = AgentRecord::new(&req);

        let mut agents = self.agents.lock().await;
        agents.insert(req.agent_id.clone(), record);

        self.event_bus.publish(Event::AgentRegistered {
            agent_id: req.agent_id.clone(),
            tier: tier_str.clone(),
            timestamp: ts.clone(),
        });

        self.logger
            .info("daemon", "agent registered", Some(&req.agent_id));

        let resp = Response {
            success: true,
            agent_id: req.agent_id,
            message: "registered".into(),
            tier: Some(tier_str),
            state: None,
            timestamp: ts,
            audit_hash: hash,
        };
        serde_json::to_string(&resp).unwrap()
    }

    async fn handle_heartbeat(&self, req: types::HeartbeatRequest) -> String {
        let ts = now_timestamp();
        let hash = self
            .audit
            .record("infrastructure", "heartbeat", &req.agent_id)
            .await;

        let mut agents = self.agents.lock().await;
        let success = if let Some(record) = agents.get_mut(&req.agent_id) {
            record.last_heartbeat = std::time::SystemTime::now();
            true
        } else {
            false
        };

        if success {
            self.event_bus.publish(Event::HeartbeatReceived {
                agent_id: req.agent_id.clone(),
                timestamp: ts.clone(),
            });
        }

        let resp = Response {
            success,
            agent_id: req.agent_id,
            message: if success {
                "heartbeat acknowledged".into()
            } else {
                "agent not found".into()
            },
            tier: None,
            state: None,
            timestamp: ts,
            audit_hash: hash,
        };
        serde_json::to_string(&resp).unwrap()
    }

    async fn handle_status(&self, agent_id: &str) -> String {
        let ts = now_timestamp();
        let hash = self.audit.record("operator", "status", agent_id).await;

        let agents = self.agents.lock().await;
        if let Some(record) = agents.get(agent_id) {
            let resp = Response {
                success: true,
                agent_id: agent_id.to_string(),
                message: "status retrieved".into(),
                tier: Some(record.tier.to_string()),
                state: Some(if record.downgraded {
                    "downgraded".to_string()
                } else {
                    "active".to_string()
                }),
                timestamp: ts,
                audit_hash: hash,
            };
            serde_json::to_string(&resp).unwrap()
        } else {
            let resp = Response {
                success: false,
                agent_id: agent_id.to_string(),
                message: "agent not found".into(),
                tier: None,
                state: None,
                timestamp: ts,
                audit_hash: hash,
            };
            serde_json::to_string(&resp).unwrap()
        }
    }

    async fn handle_deregister(&self, agent_id: &str) -> String {
        let ts = now_timestamp();
        let hash = self
            .audit
            .record("operator", "deregister", agent_id)
            .await;

        let mut agents = self.agents.lock().await;
        let removed = agents.remove(agent_id).is_some();

        if removed {
            self.event_bus.publish(Event::AgentDeregistered {
                agent_id: agent_id.to_string(),
                timestamp: ts.clone(),
            });
            self.logger
                .info("daemon", "agent deregistered", Some(agent_id));
        }

        let resp = Response {
            success: removed,
            agent_id: agent_id.to_string(),
            message: if removed {
                "deregistered".into()
            } else {
                "agent not found".into()
            },
            tier: None,
            state: None,
            timestamp: ts,
            audit_hash: hash,
        };
        serde_json::to_string(&resp).unwrap()
    }

    /// Start listening on a Unix socket. Runs until the process is terminated.
    pub async fn serve(self: Arc<Self>, socket_path: &str) -> std::io::Result<()> {
        // Remove stale socket file
        let _ = std::fs::remove_file(socket_path);

        let listener = UnixListener::bind(socket_path)?;
        self.logger.info(
            "daemon",
            &format!("sentinel-core listening on {socket_path}"),
            None,
        );

        loop {
            let (mut stream, _) = listener.accept().await?;
            let daemon = Arc::clone(&self);

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let request_bytes = &buf[..n];
                        match serde_json::from_slice::<Request>(request_bytes) {
                            Ok(req) => {
                                let response = daemon.handle_request(req).await;
                                let _ = stream.write_all(response.as_bytes()).await;
                            }
                            Err(e) => {
                                let resp = Response {
                                    success: false,
                                    agent_id: String::new(),
                                    message: format!("parse error: {e}"),
                                    tier: None,
                                    state: None,
                                    timestamp: now_timestamp(),
                                    audit_hash: String::new(),
                                };
                                let json = serde_json::to_string(&resp).unwrap();
                                let _ = stream.write_all(json.as_bytes()).await;
                            }
                        }
                    }
                    _ => {}
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::PermissionTier;

    fn test_daemon() -> SentinelDaemon {
        let dir = std::env::temp_dir().join("sentinel-daemon-test");
        let _ = std::fs::create_dir_all(&dir);
        SentinelDaemon::new(dir.join("test.log").to_str().unwrap())
    }

    #[tokio::test]
    async fn test_register_and_status() {
        let daemon = test_daemon();

        let req = Request::Register(types::RegisterRequest {
            agent_id: "test-agent".into(),
            permission_tier: PermissionTier::Write,
            heartbeat_interval: 30,
        });

        let resp_json = daemon.handle_request(req).await;
        let resp: Response = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.tier.as_deref(), Some("WRITE"));

        // Check status
        let status_req = Request::Status {
            agent_id: "test-agent".into(),
        };
        let status_json = daemon.handle_request(status_req).await;
        let status: Response = serde_json::from_str(&status_json).unwrap();
        assert!(status.success);
        assert_eq!(status.tier.as_deref(), Some("WRITE"));
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let daemon = test_daemon();

        // Register first
        let reg = Request::Register(types::RegisterRequest {
            agent_id: "hb-agent".into(),
            permission_tier: PermissionTier::Execute,
            heartbeat_interval: 10,
        });
        daemon.handle_request(reg).await;

        // Send heartbeat
        let hb = Request::Heartbeat(types::HeartbeatRequest {
            agent_id: "hb-agent".into(),
        });
        let resp_json = daemon.handle_request(hb).await;
        let resp: Response = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.message, "heartbeat acknowledged");
    }

    #[tokio::test]
    async fn test_heartbeat_unknown_agent() {
        let daemon = test_daemon();

        let hb = Request::Heartbeat(types::HeartbeatRequest {
            agent_id: "ghost".into(),
        });
        let resp_json = daemon.handle_request(hb).await;
        let resp: Response = serde_json::from_str(&resp_json).unwrap();
        assert!(!resp.success);
    }

    #[tokio::test]
    async fn test_deregister() {
        let daemon = test_daemon();

        let reg = Request::Register(types::RegisterRequest {
            agent_id: "temp-agent".into(),
            permission_tier: PermissionTier::ReadOnly,
            heartbeat_interval: 5,
        });
        daemon.handle_request(reg).await;

        let dereg = Request::Deregister {
            agent_id: "temp-agent".into(),
        };
        let resp_json = daemon.handle_request(dereg).await;
        let resp: Response = serde_json::from_str(&resp_json).unwrap();
        assert!(resp.success);

        // Status should now fail
        let status = Request::Status {
            agent_id: "temp-agent".into(),
        };
        let s_json = daemon.handle_request(status).await;
        let s: Response = serde_json::from_str(&s_json).unwrap();
        assert!(!s.success);
    }

    #[tokio::test]
    async fn test_audit_trail_integrity() {
        let daemon = test_daemon();

        let req = Request::Register(types::RegisterRequest {
            agent_id: "audit-test".into(),
            permission_tier: PermissionTier::Execute,
            heartbeat_interval: 10,
        });
        daemon.handle_request(req).await;

        let result = daemon.audit.verify().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_event_bus_receives_registration() {
        let daemon = test_daemon();
        let mut rx = daemon.event_bus.subscribe();

        let req = Request::Register(types::RegisterRequest {
            agent_id: "bus-test".into(),
            permission_tier: PermissionTier::Write,
            heartbeat_interval: 15,
        });
        daemon.handle_request(req).await;

        let event = rx.recv().await.unwrap();
        match event {
            Event::AgentRegistered { agent_id, tier, .. } => {
                assert_eq!(agent_id, "bus-test");
                assert_eq!(tier, "WRITE");
            }
            _ => panic!("expected AgentRegistered"),
        }
    }
}
