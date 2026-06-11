// sentinel-core — Cryptographic audit chain.
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// Every audited action is appended to a hash-linked, tamper-evident chain
// persisted to disk in NDJSON. Each entry's `entry_hash` is SHA-256 over the
// entry's own fields plus the prior entry's `entry_hash`. Any modification to
// any field of any entry changes that entry's hash and breaks the chain at
// that point — detectable by walking the chain and recomputing every hash
// (see `verify_chain` and the `sentinel-verify` binary).
//
// Two layers live here:
//   * `AuditChain`  — the synchronous, file-backed cryptographic chain. This is
//                     the source of truth. `write()` flushes and fsyncs on every
//                     call; audit entries are never lost on crash.
//   * `AuditTrail`  — the async daemon-facing facade the rest of sentinel-core
//                     already uses (`record`/`entries`/`verify`). The write
//                     interface is unchanged from callers' perspective: the
//                     chain is constructed transparently inside this module. When
//                     opened with a path, every `record()` is mirrored onto the
//                     on-disk `AuditChain`.

use crate::sha256::sha256_hex;
use crate::types::now_timestamp;
use chrono::{DateTime, SecondsFormat, Utc};
use sentinel_types::{AgentId, AuditEvent, ChainedAuditEntry, SentinelError};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Genesis `prev_hash`: 32 zero bytes.
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Agent id stamped on the genesis entry of a fresh log.
const GENESIS_AGENT: &str = "sentinel-daemon";
/// Event recorded as the genesis entry of a fresh log.
const GENESIS_EVENT: &str = "sentinel_start";

// ───────────────────────────────────────────────────────────────────────────
// Hashing
// ───────────────────────────────────────────────────────────────────────────

/// Deterministic entry hash. The same inputs always produce the same hash.
///
/// Field order (concatenated, then SHA-256'd):
///   sequence  — 8 bytes little-endian
///   timestamp — 8 bytes little-endian (Unix nanos)
///   agent_id  — UTF-8 bytes
///   event     — JSON bytes
///   prev_hash — 32 raw bytes
fn compute_entry_hash(
    sequence: u64,
    timestamp: u64,
    agent_id: &AgentId,
    event: &AuditEvent,
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(8 + 8 + agent_id.len() + 32 + 32);
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf.extend_from_slice(agent_id.as_bytes());
    // AuditEvent JSON is deterministic for a given value.
    let event_json = serde_json::to_vec(event).unwrap_or_default();
    buf.extend_from_slice(&event_json);
    buf.extend_from_slice(prev_hash);
    sha256_32(&buf)
}

/// SHA-256 over `data`, returned as 32 raw bytes. Built on the embedded
/// `sha256_hex` implementation — no external crypto crate.
fn sha256_32(data: &[u8]) -> [u8; 32] {
    let hex = sha256_hex(data);
    hex_to_32(&hex).expect("sha256_hex always returns 64 hex chars")
}

// ───────────────────────────────────────────────────────────────────────────
// Hex helpers (no `hex` crate dependency in sentinel-core)
// ───────────────────────────────────────────────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0x0f));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hexval(bytes[2 * i])?;
        let lo = hexval(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Format a 32-byte hash as the on-disk / display form: `sha256:<64 hex>`.
pub fn hash_display(hash: &[u8; 32]) -> String {
    format!("sha256:{}", to_hex(hash))
}

/// Parse a `sha256:<64 hex>` string back into 32 raw bytes.
fn parse_hash(s: &str) -> Option<[u8; 32]> {
    let hex = s.strip_prefix("sha256:").unwrap_or(s);
    hex_to_32(hex)
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn serr(code: &str, msg: impl Into<String>) -> SentinelError {
    // `sentinel_types::SentinelError` is now a named-variant enum; the legacy
    // `{ code, message }` pair is folded into a `Generic` via `generic()`.
    SentinelError::generic(code, msg.into())
}

// ───────────────────────────────────────────────────────────────────────────
// On-disk NDJSON representation
// ───────────────────────────────────────────────────────────────────────────

/// One NDJSON line. Hashes are stored as `sha256:<hex>` for greppability;
/// the timestamp is RFC 3339 with nanosecond precision (lossless round-trip).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireEntry {
    sequence: u64,
    timestamp: String,
    agent_id: String,
    event: AuditEvent,
    prev_hash: String,
    entry_hash: String,
}

impl WireEntry {
    fn from_entry(e: &ChainedAuditEntry) -> Self {
        Self {
            sequence: e.sequence,
            timestamp: e.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true),
            agent_id: e.agent_id.clone(),
            event: e.event.clone(),
            prev_hash: hash_display(&e.prev_hash),
            entry_hash: hash_display(&e.entry_hash),
        }
    }

    fn into_entry(self) -> Result<ChainedAuditEntry, SentinelError> {
        let timestamp = DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|e| serr("audit.parse", format!("bad timestamp: {e}")))?
            .with_timezone(&Utc);
        let prev_hash = parse_hash(&self.prev_hash)
            .ok_or_else(|| serr("audit.parse", "bad prev_hash"))?;
        let entry_hash = parse_hash(&self.entry_hash)
            .ok_or_else(|| serr("audit.parse", "bad entry_hash"))?;
        Ok(ChainedAuditEntry {
            sequence: self.sequence,
            timestamp,
            agent_id: self.agent_id,
            event: self.event,
            prev_hash,
            entry_hash,
        })
    }
}

/// Recompute the entry hash for a parsed entry from its fields.
fn rehash(entry: &ChainedAuditEntry) -> [u8; 32] {
    let nanos = entry.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64;
    compute_entry_hash(
        entry.sequence,
        nanos,
        &entry.agent_id,
        &entry.event,
        &entry.prev_hash,
    )
}

// ───────────────────────────────────────────────────────────────────────────
// AuditChain — synchronous, file-backed cryptographic chain
// ───────────────────────────────────────────────────────────────────────────

/// Append-only cryptographic audit chain, persisted as NDJSON.
pub struct AuditChain {
    log_path: PathBuf,
    last_hash: [u8; 32],
    sequence: u64,
    writer: BufWriter<File>,
}

impl AuditChain {
    /// Open or create the audit log at `path`.
    ///
    /// If the log exists and has entries, the last entry is read to resume the
    /// chain (`last_hash` = that entry's `entry_hash`, next `sequence` =
    /// last + 1). If the log is new or empty, the genesis entry is written with
    /// `prev_hash = [0u8; 32]`.
    pub fn open(path: &Path) -> Result<Self, SentinelError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| serr("audit.io", format!("create dir: {e}")))?;
            }
        }

        let resume = read_last_entry(path)?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| serr("audit.io", format!("open {}: {e}", path.display())))?;
        let writer = BufWriter::new(file);

        match resume {
            Some(last) => Ok(Self {
                log_path: path.to_path_buf(),
                last_hash: last.entry_hash,
                sequence: last.sequence + 1,
                writer,
            }),
            None => {
                let mut chain = Self {
                    log_path: path.to_path_buf(),
                    last_hash: ZERO_HASH,
                    sequence: 0,
                    writer,
                };
                // Genesis: sequence 0, prev_hash = zeros.
                chain.write(
                    GENESIS_AGENT.to_string(),
                    AuditEvent::Custom(GENESIS_EVENT.to_string()),
                )?;
                Ok(chain)
            }
        }
    }

    /// Write a single event to the audit chain. Computes `prev_hash` from the
    /// last written entry, computes `entry_hash` over the full entry content,
    /// appends one NDJSON line, and flushes + fsyncs to disk before returning.
    pub fn write(
        &mut self,
        agent_id: AgentId,
        event: AuditEvent,
    ) -> Result<ChainedAuditEntry, SentinelError> {
        let sequence = self.sequence;
        let nanos = now_nanos();
        let prev_hash = self.last_hash;
        let entry_hash = compute_entry_hash(sequence, nanos, &agent_id, &event, &prev_hash);

        let entry = ChainedAuditEntry {
            sequence,
            timestamp: DateTime::<Utc>::from_timestamp_nanos(nanos as i64),
            agent_id,
            event,
            prev_hash,
            entry_hash,
        };

        let line = serde_json::to_string(&WireEntry::from_entry(&entry))
            .map_err(|e| serr("audit.encode", format!("serialize entry: {e}")))?;
        writeln!(self.writer, "{line}")
            .map_err(|e| serr("audit.io", format!("write entry: {e}")))?;
        // Durability: flush the buffer and force to disk every write.
        self.writer
            .flush()
            .map_err(|e| serr("audit.io", format!("flush: {e}")))?;
        self.writer
            .get_ref()
            .sync_all()
            .map_err(|e| serr("audit.io", format!("fsync: {e}")))?;

        self.last_hash = entry_hash;
        self.sequence = sequence + 1;
        Ok(entry)
    }

    /// Flush the write buffer to disk.
    pub fn flush(&mut self) -> Result<(), SentinelError> {
        self.writer
            .flush()
            .map_err(|e| serr("audit.io", format!("flush: {e}")))?;
        self.writer
            .get_ref()
            .sync_all()
            .map_err(|e| serr("audit.io", format!("fsync: {e}")))
    }

    /// Hash of the most recently written entry.
    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Next sequence number to be assigned.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Path of the underlying log file.
    pub fn path(&self) -> &Path {
        &self.log_path
    }
}

/// Read the last non-empty NDJSON entry from `path`, if any. Returns `None` for
/// a missing or empty file (a fresh chain).
fn read_last_entry(path: &Path) -> Result<Option<ChainedAuditEntry>, SentinelError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(serr("audit.io", format!("read {}: {e}", path.display()))),
    };
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    match last {
        None => Ok(None),
        Some(line) => {
            let wire: WireEntry = serde_json::from_str(line)
                .map_err(|e| serr("audit.parse", format!("last entry: {e}")))?;
            Ok(Some(wire.into_entry()?))
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Verification
// ───────────────────────────────────────────────────────────────────────────

/// Why the chain broke at a particular entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakKind {
    /// Genesis `prev_hash` was not all zeros.
    GenesisPrev,
    /// `prev_hash` did not match the prior entry's `entry_hash`.
    LinkMismatch,
    /// Recomputed `entry_hash` did not match the stored one (content tampered).
    ContentMismatch,
    /// A line could not be parsed as a chain entry.
    Malformed,
}

/// Where and how the chain broke.
#[derive(Debug, Clone)]
pub struct BreakInfo {
    pub sequence: u64,
    pub kind: BreakKind,
    pub expected: [u8; 32],
    pub found: [u8; 32],
}

/// Result of walking and verifying a chain.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub entries_verified: usize,
    pub total_entries: usize,
    pub genesis_ok: bool,
    pub last_hash: Option<[u8; 32]>,
    pub broken: Option<BreakInfo>,
}

impl VerifyOutcome {
    pub fn is_intact(&self) -> bool {
        self.broken.is_none()
    }
}

/// Walk every entry in the log from genesis to last, recomputing each
/// `entry_hash` and checking each `prev_hash` link. Stops at the first break.
pub fn verify_chain(path: &Path) -> Result<VerifyOutcome, SentinelError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| serr("audit.io", format!("read {}: {e}", path.display())))?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let total_entries = lines.len();

    let mut entries_verified = 0usize;
    let mut genesis_ok = false;
    let mut last_hash: Option<[u8; 32]> = None;
    let mut expected_prev = ZERO_HASH;

    for (i, line) in lines.iter().enumerate() {
        let wire: WireEntry = match serde_json::from_str(line) {
            Ok(w) => w,
            Err(_) => {
                return Ok(VerifyOutcome {
                    entries_verified,
                    total_entries,
                    genesis_ok,
                    last_hash,
                    broken: Some(BreakInfo {
                        sequence: i as u64,
                        kind: BreakKind::Malformed,
                        expected: ZERO_HASH,
                        found: ZERO_HASH,
                    }),
                });
            }
        };
        let entry = match wire.into_entry() {
            Ok(e) => e,
            Err(_) => {
                return Ok(VerifyOutcome {
                    entries_verified,
                    total_entries,
                    genesis_ok,
                    last_hash,
                    broken: Some(BreakInfo {
                        sequence: i as u64,
                        kind: BreakKind::Malformed,
                        expected: ZERO_HASH,
                        found: ZERO_HASH,
                    }),
                });
            }
        };

        // Genesis check.
        if i == 0 {
            if entry.prev_hash != ZERO_HASH {
                return Ok(VerifyOutcome {
                    entries_verified,
                    total_entries,
                    genesis_ok: false,
                    last_hash,
                    broken: Some(BreakInfo {
                        sequence: entry.sequence,
                        kind: BreakKind::GenesisPrev,
                        expected: ZERO_HASH,
                        found: entry.prev_hash,
                    }),
                });
            }
            genesis_ok = true;
        }

        // Link check: prev_hash must equal the prior entry's entry_hash.
        if entry.prev_hash != expected_prev {
            return Ok(VerifyOutcome {
                entries_verified,
                total_entries,
                genesis_ok,
                last_hash,
                broken: Some(BreakInfo {
                    sequence: entry.sequence,
                    kind: BreakKind::LinkMismatch,
                    expected: expected_prev,
                    found: entry.prev_hash,
                }),
            });
        }

        // Content check: recomputed entry_hash must equal the stored one.
        let recomputed = rehash(&entry);
        if recomputed != entry.entry_hash {
            return Ok(VerifyOutcome {
                entries_verified,
                total_entries,
                genesis_ok,
                last_hash,
                broken: Some(BreakInfo {
                    sequence: entry.sequence,
                    kind: BreakKind::ContentMismatch,
                    expected: recomputed,
                    found: entry.entry_hash,
                }),
            });
        }

        expected_prev = entry.entry_hash;
        last_hash = Some(entry.entry_hash);
        entries_verified += 1;
    }

    Ok(VerifyOutcome {
        entries_verified,
        total_entries,
        genesis_ok,
        last_hash,
        broken: None,
    })
}

// ───────────────────────────────────────────────────────────────────────────
// AuditTrail — async daemon-facing facade
// ───────────────────────────────────────────────────────────────────────────

/// Immutable audit trail entry (in-memory view used for dashboard snapshots).
/// The tamper-evident source of truth is the on-disk `AuditChain`.
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
///
/// When opened with a path, every recorded action is mirrored onto the on-disk
/// cryptographic `AuditChain`; the in-memory `entries` are a convenience cache
/// for the dashboard snapshot.
pub struct AuditTrail {
    entries: Mutex<Vec<AuditEntry>>,
    last_hash: Mutex<String>,
    sequence: Mutex<u64>,
    chain: Mutex<Option<AuditChain>>,
}

impl AuditTrail {
    /// In-memory-only trail. Used by tests and any caller without a log path.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            last_hash: Mutex::new("0".repeat(64)),
            sequence: Mutex::new(0),
            chain: Mutex::new(None),
        }
    }

    /// Open a trail backed by the cryptographic chain at `path`. If the chain
    /// cannot be opened, falls back to in-memory so the daemon still boots, and
    /// warns on stderr.
    pub fn open(path: &Path) -> Self {
        let chain = match AuditChain::open(path) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!(
                    "sentinel-core: audit chain at {} unavailable ({e}) — \
                     continuing in-memory only",
                    path.display()
                );
                None
            }
        };
        Self {
            entries: Mutex::new(Vec::new()),
            last_hash: Mutex::new("0".repeat(64)),
            sequence: Mutex::new(0),
            chain: Mutex::new(chain),
        }
    }

    /// Record an action. Returns the entry's hash. Mirrors the action onto the
    /// on-disk cryptographic chain when one is attached.
    pub async fn record(&self, actor: &str, action: &str, target: &str) -> String {
        let timestamp = now_timestamp();
        let mut seq = self.sequence.lock().await;
        let mut prev = self.last_hash.lock().await;

        *seq += 1;
        let payload = format!("{seq}|{timestamp}|{actor}|{action}|{target}|{prev}");
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

        // Mirror onto the cryptographic chain. The chain is the tamper-evident
        // record; a failure here must not break the daemon's response path.
        {
            let mut chain = self.chain.lock().await;
            if let Some(c) = chain.as_mut() {
                if let Err(e) = c.write(target.to_string(), action_to_event(action)) {
                    eprintln!("sentinel-core: audit chain write failed: {e}");
                }
            }
        }

        hash
    }

    /// Verify in-memory chain integrity. Returns Ok(count) or Err on first
    /// broken link. (On-disk verification is handled by `verify_chain` /
    /// `sentinel-verify`.)
    pub async fn verify(&self) -> Result<usize, String> {
        let entries = self.entries.lock().await;
        let mut expected_prev = "0".repeat(64);

        for entry in entries.iter() {
            if entry.prev_hash != expected_prev {
                return Err(format!(
                    "chain broken at sequence {}: expected prev_hash {expected_prev}, got {}",
                    entry.sequence, entry.prev_hash
                ));
            }
            let payload = format!(
                "{}|{}|{}|{}|{}|{}",
                entry.sequence, entry.timestamp, entry.actor, entry.action, entry.target,
                entry.prev_hash
            );
            let computed = sha256_hex(payload.as_bytes());
            if computed != entry.hash {
                return Err(format!(
                    "hash mismatch at sequence {}: computed {computed}, stored {}",
                    entry.sequence, entry.hash
                ));
            }
            expected_prev = entry.hash.clone();
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

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a legacy `(action)` label onto a semantic `AuditEvent` for the chain.
/// The `target` of a `record()` call is always the agent id, carried as the
/// chain entry's `agent_id`; the `actor` is folded into `Custom` events that
/// have no dedicated variant.
fn action_to_event(action: &str) -> AuditEvent {
    match action {
        "register" => AuditEvent::AgentRegistered,
        "heartbeat" => AuditEvent::Heartbeat,
        "status" => AuditEvent::StatusQueried,
        "emit_output" => AuditEvent::OutputEmitted,
        other => AuditEvent::Custom(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("sentinel-audit-chain-tests");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(format!("{name}-{}.ndjson", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn genesis_is_written_on_fresh_log() {
        let path = temp_log("genesis");
        let chain = AuditChain::open(&path).unwrap();
        // Genesis consumed sequence 0; next sequence is 1.
        assert_eq!(chain.sequence(), 1);
        drop(chain);

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);
        let g: WireEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(g.sequence, 0);
        assert_eq!(g.agent_id, GENESIS_AGENT);
        assert_eq!(g.prev_hash, hash_display(&ZERO_HASH));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hundred_entries_verify_intact() {
        let path = temp_log("hundred");
        {
            let mut chain = AuditChain::open(&path).unwrap();
            for i in 0..100 {
                chain
                    .write(format!("agent-{i:03}"), AuditEvent::Heartbeat)
                    .unwrap();
            }
        }
        let outcome = verify_chain(&path).unwrap();
        assert!(outcome.is_intact(), "expected INTACT, got {outcome:?}");
        assert!(outcome.genesis_ok);
        // 1 genesis + 100 written.
        assert_eq!(outcome.entries_verified, 101);
        assert_eq!(outcome.total_entries, 101);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tamper_breaks_chain_at_sequence() {
        let path = temp_log("tamper");
        {
            let mut chain = AuditChain::open(&path).unwrap();
            for i in 0..20 {
                chain
                    .write(format!("agent-{i}"), AuditEvent::Heartbeat)
                    .unwrap();
            }
        }
        // Flip a byte inside the agent_id of the entry at sequence 10 by
        // rewriting that line's agent_id. This changes the content so the
        // recomputed entry_hash no longer matches the stored one.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        let mut wire: WireEntry = serde_json::from_str(&lines[10]).unwrap();
        assert_eq!(wire.sequence, 10);
        wire.agent_id = "tampered".to_string();
        lines[10] = serde_json::to_string(&wire).unwrap();
        std::fs::write(&path, lines.join("\n")).unwrap();

        let outcome = verify_chain(&path).unwrap();
        assert!(!outcome.is_intact());
        let brk = outcome.broken.unwrap();
        assert_eq!(brk.sequence, 10);
        assert_eq!(brk.kind, BreakKind::ContentMismatch);
        assert_eq!(outcome.entries_verified, 10);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopen_resumes_chain_continuously() {
        let path = temp_log("reopen");
        {
            let mut chain = AuditChain::open(&path).unwrap();
            for i in 0..100 {
                chain
                    .write(format!("agent-{i}"), AuditEvent::Heartbeat)
                    .unwrap();
            }
        }
        // Simulate daemon restart: reopen and append 10 more.
        {
            let mut chain = AuditChain::open(&path).unwrap();
            assert_eq!(chain.sequence(), 101); // 0..=100 already used
            for i in 0..10 {
                chain
                    .write(format!("restart-{i}"), AuditEvent::Heartbeat)
                    .unwrap();
            }
        }
        let outcome = verify_chain(&path).unwrap();
        assert!(outcome.is_intact(), "expected INTACT, got {outcome:?}");
        // 1 genesis + 100 + 10.
        assert_eq!(outcome.entries_verified, 111);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entry_hash_is_deterministic() {
        let prev = [7u8; 32];
        let a = compute_entry_hash(5, 1_234_567_890, &"agent-x".to_string(), &AuditEvent::Heartbeat, &prev);
        let b = compute_entry_hash(5, 1_234_567_890, &"agent-x".to_string(), &AuditEvent::Heartbeat, &prev);
        assert_eq!(a, b);
        let c = compute_entry_hash(6, 1_234_567_890, &"agent-x".to_string(), &AuditEvent::Heartbeat, &prev);
        assert_ne!(a, c);
    }

    #[tokio::test]
    async fn facade_record_and_verify_in_memory() {
        let trail = AuditTrail::new();
        trail.record("operator", "register", "agent-1").await;
        trail.record("operator", "heartbeat", "agent-1").await;
        trail.record("operator", "downgrade", "agent-1").await;
        assert_eq!(trail.verify().await, Ok(3));
    }

    #[tokio::test]
    async fn facade_mirrors_to_disk_chain() {
        let path = temp_log("facade");
        let trail = AuditTrail::open(&path);
        trail.record("operator", "register", "agent-7").await;
        trail.record("infrastructure", "heartbeat", "agent-7").await;
        // Drop to flush the writer fully (each write already fsynced).
        drop(trail);

        let outcome = verify_chain(&path).unwrap();
        assert!(outcome.is_intact(), "expected INTACT, got {outcome:?}");
        // genesis + 2 recorded actions.
        assert_eq!(outcome.entries_verified, 3);
        let _ = std::fs::remove_file(&path);
    }
}
