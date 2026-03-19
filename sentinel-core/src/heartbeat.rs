use crate::audit::AuditTrail;
use crate::event_bus::EventBus;
use crate::logger::Logger;
use crate::types::{AgentRecord, Event, now_timestamp};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;

/// Heartbeat monitor. Runs as a background task.
/// Checks all registered agents; if heartbeat is missed beyond threshold,
/// automatically downgrades the agent's permission tier.
pub struct HeartbeatMonitor {
    agents: Arc<Mutex<HashMap<String, AgentRecord>>>,
    event_bus: Arc<EventBus>,
    audit: Arc<AuditTrail>,
    logger: Logger,
    /// Multiplier for heartbeat_interval before triggering downgrade.
    /// Default: 3 (miss 3 intervals → downgrade).
    pub miss_threshold: u64,
}

impl HeartbeatMonitor {
    pub fn new(
        agents: Arc<Mutex<HashMap<String, AgentRecord>>>,
        event_bus: Arc<EventBus>,
        audit: Arc<AuditTrail>,
        logger: Logger,
    ) -> Self {
        Self {
            agents,
            event_bus,
            audit,
            logger,
            miss_threshold: 3,
        }
    }

    /// Run the monitor loop. Checks every second.
    pub async fn run(self: Arc<Self>, check_interval_secs: u64) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(check_interval_secs));

        loop {
            interval.tick().await;
            self.check_all().await;
        }
    }

    async fn check_all(&self) {
        let now = SystemTime::now();
        let mut agents = self.agents.lock().await;

        for record in agents.values_mut() {
            let elapsed = now
                .duration_since(record.last_heartbeat)
                .unwrap_or_default()
                .as_secs();

            let threshold = record.heartbeat_interval * self.miss_threshold;

            if elapsed > threshold {
                self.handle_missed(record, elapsed).await;
            }
        }
    }

    async fn handle_missed(&self, record: &mut AgentRecord, elapsed_secs: u64) {
        let ts = now_timestamp();

        self.event_bus.publish(Event::HeartbeatMissed {
            agent_id: record.agent_id.clone(),
            missed_by_secs: elapsed_secs,
            timestamp: ts.clone(),
        });

        self.logger.warn(
            "heartbeat",
            &format!(
                "heartbeat missed by {}s (threshold: {}s)",
                elapsed_secs,
                record.heartbeat_interval * self.miss_threshold
            ),
            Some(&record.agent_id),
        );

        // Downgrade tier if possible
        if let Some(new_tier) = record.tier.downgrade() {
            let from = record.tier.to_string();
            let to = new_tier.to_string();

            record.tier = new_tier;
            record.downgraded = true;

            self.audit
                .record("sentinel", "tier_downgrade", &record.agent_id)
                .await;

            self.event_bus.publish(Event::TierDowngraded {
                agent_id: record.agent_id.clone(),
                from_tier: from.clone(),
                to_tier: to.clone(),
                reason: "missed heartbeat".into(),
                timestamp: ts,
            });

            self.logger.warn(
                "heartbeat",
                &format!("tier downgraded: {from} -> {to}"),
                Some(&record.agent_id),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PermissionTier;

    fn make_deps() -> (
        Arc<Mutex<HashMap<String, AgentRecord>>>,
        Arc<EventBus>,
        Arc<AuditTrail>,
        Logger,
    ) {
        let agents = Arc::new(Mutex::new(HashMap::new()));
        let bus = EventBus::new(64).into_shared();
        let audit = AuditTrail::new().into_shared();
        let dir = std::env::temp_dir().join("sentinel-hb-test");
        let _ = std::fs::create_dir_all(&dir);
        let logger = Logger::start(dir.join("test.log").to_str().unwrap());
        (agents, bus, audit, logger)
    }

    #[tokio::test]
    async fn test_downgrade_on_missed_heartbeat() {
        let (agents, bus, audit, logger) = make_deps();
        let mut rx = bus.subscribe();

        // Insert an agent with a stale heartbeat
        {
            let mut map = agents.lock().await;
            let mut record = AgentRecord::new(&crate::types::RegisterRequest {
                agent_id: "stale-agent".into(),
                permission_tier: PermissionTier::Execute,
                heartbeat_interval: 1,
            });
            // Set last heartbeat to 10 seconds ago
            record.last_heartbeat =
                SystemTime::now() - std::time::Duration::from_secs(10);
            map.insert("stale-agent".into(), record);
        }

        let monitor = Arc::new(HeartbeatMonitor::new(
            agents.clone(),
            bus.clone(),
            audit,
            logger,
        ));

        // Run one check cycle
        monitor.check_all().await;

        // Verify tier was downgraded
        let map = agents.lock().await;
        let record = map.get("stale-agent").unwrap();
        assert_eq!(record.tier, PermissionTier::Write);
        assert!(record.downgraded);

        // Verify event was published
        let event = rx.recv().await.unwrap();
        match event {
            Event::HeartbeatMissed { agent_id, .. } => {
                assert_eq!(agent_id, "stale-agent");
            }
            _ => panic!("expected HeartbeatMissed first"),
        }
    }

    #[tokio::test]
    async fn test_no_downgrade_within_threshold() {
        let (agents, bus, audit, logger) = make_deps();

        // Insert agent with fresh heartbeat
        {
            let mut map = agents.lock().await;
            let record = AgentRecord::new(&crate::types::RegisterRequest {
                agent_id: "fresh-agent".into(),
                permission_tier: PermissionTier::Execute,
                heartbeat_interval: 60,
            });
            map.insert("fresh-agent".into(), record);
        }

        let monitor = Arc::new(HeartbeatMonitor::new(agents.clone(), bus, audit, logger));
        monitor.check_all().await;

        let map = agents.lock().await;
        let record = map.get("fresh-agent").unwrap();
        assert_eq!(record.tier, PermissionTier::Execute);
        assert!(!record.downgraded);
    }
}
