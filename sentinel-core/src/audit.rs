use crate::sha256::sha256_hex;
use crate::types::now_timestamp;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Immutable audit trail entry.
/// All operator actions are timestamped, SHA256-hashed, and appended.
/// Chain integrity: each entry hashes the previous entry's hash for tamper detection.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub hash: String,
    pub prev_hash: String,
}

/// Append-only audit trail. No deletions. No modifications.
pub struct AuditTrail {
    entries: Mutex<Vec<AuditEntry>>,
    last_hash: Mutex<String>,
    sequence: Mutex<u64>,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            last_hash: Mutex::new("0".repeat(64)),
            sequence: Mutex::new(0),
        }
    }

    /// Record an action. Returns the entry's hash.
    pub async fn record(
        &self,
        actor: &str,
        action: &str,
        target: &str,
    ) -> String {
        let timestamp = now_timestamp();
        let mut seq = self.sequence.lock().await;
        let mut prev = self.last_hash.lock().await;

        *seq += 1;
        let payload = format!(
            "{seq}|{timestamp}|{actor}|{action}|{target}|{prev}"
        );
        let hash = sha256_hex(payload.as_bytes());

        let entry = AuditEntry {
            sequence: *seq,
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            hash: hash.clone(),
            prev_hash: prev.clone(),
        };

        let mut entries = self.entries.lock().await;
        entries.push(entry);
        *prev = hash.clone();

        hash
    }

    /// Verify chain integrity. Returns Ok(count) or Err on first broken link.
    pub async fn verify(&self) -> Result<usize, String> {
        let entries = self.entries.lock().await;
        let mut expected_prev = "0".repeat(64);

        for (i, entry) in entries.iter().enumerate() {
            if entry.prev_hash != expected_prev {
                return Err(format!(
                    "chain broken at sequence {}: expected prev_hash {expected_prev}, got {}",
                    entry.sequence, entry.prev_hash
                ));
            }
            let payload = format!(
                "{}|{}|{}|{}|{}|{}",
                entry.sequence, entry.timestamp, entry.actor,
                entry.action, entry.target, entry.prev_hash
            );
            let computed = sha256_hex(payload.as_bytes());
            if computed != entry.hash {
                return Err(format!(
                    "hash mismatch at sequence {}: computed {computed}, stored {}",
                    entry.sequence, entry.hash
                ));
            }
            expected_prev = entry.hash.clone();
            // Suppress unused variable warning — i is used only for iteration
            let _ = i;
        }
        Ok(entries.len())
    }

    /// Get all entries (read-only snapshot).
    pub async fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().await.clone()
    }

    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_and_verify() {
        let trail = AuditTrail::new();
        trail.record("operator", "register", "agent-1").await;
        trail.record("operator", "heartbeat", "agent-1").await;
        trail.record("operator", "downgrade", "agent-1").await;

        let result = trail.verify().await;
        assert_eq!(result, Ok(3));
    }

    #[tokio::test]
    async fn test_chain_hashes_differ() {
        let trail = AuditTrail::new();
        let h1 = trail.record("op", "register", "a1").await;
        let h2 = trail.record("op", "register", "a2").await;
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn test_entries_immutable_snapshot() {
        let trail = AuditTrail::new();
        trail.record("op", "act", "tgt").await;
        let snap = trail.entries().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].sequence, 1);
    }
}
