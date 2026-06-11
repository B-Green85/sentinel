// Sentinel v3 — Agent 8 test suite: tests/sentinel_audit
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// Contractual test names from the v3 spec, exercised against the REAL on-disk
// cryptographic audit chain (Agent 6) — no mocks. Each test writes to a real
// temp NDJSON log and verifies with the real `verify_chain` / `sentinel-verify`.
//
// Note on counts: `AuditChain::open` writes a genesis entry (sequence 0) on a
// fresh log, so a chain with N application writes contains N+1 verified entries.
// The tests assert the true count and comment where genesis accounts for the +1.

use sentinel_core::audit::{verify_chain, AuditChain, BreakKind};
use sentinel_types::AuditEvent;
use std::path::PathBuf;
use std::process::Command;

fn temp_log(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("sentinel-audit-it");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{tag}-{}.ndjson", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn test_chain_integrity_clean_log() {
    let path = temp_log("clean");
    {
        let mut chain = AuditChain::open(&path).unwrap();
        for i in 0..100 {
            chain.write(format!("agent-{i:03}"), AuditEvent::Heartbeat).unwrap();
        }
    }
    let outcome = verify_chain(&path).unwrap();
    assert!(outcome.is_intact(), "expected INTACT, got {outcome:?}");
    // 100 application writes + 1 genesis entry.
    assert_eq!(outcome.entries_verified, 101);
    assert_eq!(outcome.total_entries, 101);
}

#[test]
fn test_chain_break_detected_on_tamper() {
    let path = temp_log("tamper");
    {
        let mut chain = AuditChain::open(&path).unwrap();
        for i in 0..100 {
            chain.write(format!("agent-{i}"), AuditEvent::Heartbeat).unwrap();
        }
    }
    // Flip a byte inside the entry whose sequence == 50 (line 50; genesis is
    // line 0 / sequence 0). Mutating the agent_id changes the content so the
    // recomputed entry_hash no longer matches the stored one.
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let mut v: serde_json::Value = serde_json::from_str(&lines[50]).unwrap();
    assert_eq!(v["sequence"].as_u64(), Some(50));
    v["agent_id"] = serde_json::Value::String("tampered".into());
    lines[50] = serde_json::to_string(&v).unwrap();
    std::fs::write(&path, lines.join("\n")).unwrap();

    let outcome = verify_chain(&path).unwrap();
    assert!(!outcome.is_intact());
    let brk = outcome.broken.unwrap();
    assert_eq!(brk.sequence, 50, "break must be reported at sequence 50");
    assert_eq!(brk.kind, BreakKind::ContentMismatch);
}

#[test]
fn test_genesis_entry_correct() {
    let path = temp_log("genesis");
    {
        let _chain = AuditChain::open(&path).unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let first = text.lines().next().expect("genesis line");
    let v: serde_json::Value = serde_json::from_str(first).unwrap();

    // sequence == 0
    assert_eq!(v["sequence"].as_u64(), Some(0));
    // prev_hash == 32 zero bytes (stored as "sha256:<64 zeros>")
    assert_eq!(
        v["prev_hash"].as_str().unwrap(),
        format!("sha256:{}", "0".repeat(64))
    );
    // entry_hash is a valid SHA-256: "sha256:" + 64 lowercase hex chars
    let eh = v["entry_hash"].as_str().unwrap();
    let hex = eh.strip_prefix("sha256:").expect("entry_hash sha256: prefix");
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    // The chain verifies as intact end-to-end (genesis hash recomputes).
    assert!(verify_chain(&path).unwrap().is_intact());
}

#[test]
fn test_verify_tool_passes_clean() {
    let path = temp_log("tool-clean");
    {
        let mut chain = AuditChain::open(&path).unwrap();
        for i in 0..10 {
            chain.write(format!("agent-{i}"), AuditEvent::Heartbeat).unwrap();
        }
    }
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel-verify"))
        .args(["--log", path.to_str().unwrap()])
        .output()
        .expect("spawn sentinel-verify");
    assert_eq!(
        out.status.code(),
        Some(0),
        "sentinel-verify must exit 0 on a clean log; stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("INTACT"));
}

#[test]
fn test_verify_tool_fails_tampered() {
    let path = temp_log("tool-tampered");
    {
        let mut chain = AuditChain::open(&path).unwrap();
        for i in 0..10 {
            chain.write(format!("agent-{i}"), AuditEvent::Heartbeat).unwrap();
        }
    }
    // Tamper: rewrite the agent_id of the line at sequence 5.
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let mut v: serde_json::Value = serde_json::from_str(&lines[5]).unwrap();
    v["agent_id"] = serde_json::Value::String("evil".into());
    lines[5] = serde_json::to_string(&v).unwrap();
    std::fs::write(&path, lines.join("\n")).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sentinel-verify"))
        .args(["--log", path.to_str().unwrap()])
        .output()
        .expect("spawn sentinel-verify");
    assert_ne!(out.status.code(), Some(0), "tampered log must exit non-zero");
    assert!(String::from_utf8_lossy(&out.stdout).contains("BROKEN"));
}

#[test]
fn test_chain_continuous_across_restart() {
    let path = temp_log("restart");
    {
        let mut chain = AuditChain::open(&path).unwrap();
        for i in 0..50 {
            chain.write(format!("agent-{i}"), AuditEvent::Heartbeat).unwrap();
        }
    } // drop the AuditChain — simulates daemon shutdown
    {
        // Reopen on the same file: must resume the chain, not restart it.
        let mut chain = AuditChain::open(&path).unwrap();
        for i in 0..50 {
            chain.write(format!("restart-{i}"), AuditEvent::Heartbeat).unwrap();
        }
    }
    let outcome = verify_chain(&path).unwrap();
    assert!(
        outcome.is_intact(),
        "chain must be continuous across the restart boundary, got {outcome:?}"
    );
    // genesis + 50 + 50, with no break at the reopen boundary.
    assert_eq!(outcome.entries_verified, 101);
    assert!(outcome.broken.is_none());
}
