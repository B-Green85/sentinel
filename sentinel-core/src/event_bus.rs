use crate::types::Event;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Internal event bus for signal detectors and daemon components.
/// Publishers push events; subscribers receive them asynchronously.
/// Operates entirely within Sentinel's process space — invisible to agents.
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Create a new event bus with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: Event) {
        // Ignore send errors (no active subscribers).
        let _ = self.sender.send(event);
    }

    /// Subscribe to the event bus. Returns a receiver handle.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Create a shareable handle to this event bus.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_subscribe() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        bus.publish(Event::AgentRegistered {
            agent_id: "test-1".into(),
            tier: "WRITE".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        });

        let event = rx.recv().await.unwrap();
        match event {
            Event::AgentRegistered { agent_id, .. } => {
                assert_eq!(agent_id, "test-1");
            }
            _ => panic!("wrong event type"),
        }
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.publish(Event::HeartbeatReceived {
            agent_id: "agent-a".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        });

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();

        match (e1, e2) {
            (
                Event::HeartbeatReceived { agent_id: a, .. },
                Event::HeartbeatReceived { agent_id: b, .. },
            ) => {
                assert_eq!(a, "agent-a");
                assert_eq!(b, "agent-a");
            }
            _ => panic!("wrong events"),
        }
    }

    #[test]
    fn test_publish_no_subscribers() {
        let bus = EventBus::new(16);
        // Should not panic even with no subscribers.
        bus.publish(Event::AgentDeregistered {
            agent_id: "ghost".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        });
    }
}
