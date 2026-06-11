// Sentinel v3 — Agent 8 test suite: tests/sentinel_keygen
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// Contractual test names from the v3 spec. These drive the real
// `sentinel-keygen` binary (Agent 2) end-to-end against a temp directory.
// Cargo exposes the freshly built binary path via CARGO_BIN_EXE_<name>.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sentinel-keygen")
}

/// A unique temp directory for one test, removed first if stale.
fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sentinel-keygen-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to spawn sentinel-keygen")
}

const ARTIFACTS: [&str; 4] = [
    "sentinel.allowlist",
    "sentinel.signing.key",
    "sentinel.signing.pub",
    "sentinel.install.json",
];

#[test]
fn test_keygen_generates_all_artifacts() {
    let dir = workdir("generate");
    let out = run(&["--output", dir.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for name in ARTIFACTS {
        assert!(
            dir.join(name).exists(),
            "expected artifact {name} to exist after generate"
        );
    }
    // The committed manifest is produced too (records generation, not secrets).
    assert!(dir.join(".sentinel-keygen-manifest.json").exists());
}

#[test]
fn test_keygen_idempotent_on_rotate() {
    let dir = workdir("rotate");
    assert!(run(&["--output", dir.to_str().unwrap()]).status.success());

    let key_path = dir.join("sentinel.signing.key");
    let pub_path = dir.join("sentinel.signing.pub");
    let old_key = std::fs::read(&key_path).unwrap();
    let manifest_before = std::fs::read_to_string(dir.join(".sentinel-keygen-manifest.json")).unwrap();

    let out = run(&["--rotate", "--output", dir.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "rotate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Old keys archived with a timestamp suffix (file name starts with the
    // original name plus a dotted suffix).
    let archived: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("sentinel.signing.key.") || n.starts_with("sentinel.signing.pub."))
        .collect();
    assert!(
        archived.len() >= 2,
        "expected archived old keypair with timestamp suffix, found {archived:?}"
    );

    // New keys differ from old keys.
    let new_key = std::fs::read(&key_path).unwrap();
    assert!(pub_path.exists());
    assert_ne!(old_key, new_key, "rotated private key must differ from the old one");

    // Manifest updated (fingerprint changed → content changed).
    let manifest_after = std::fs::read_to_string(dir.join(".sentinel-keygen-manifest.json")).unwrap();
    assert_ne!(manifest_before, manifest_after, "manifest must be updated on rotate");
}

#[test]
fn test_allowlist_add_remove() {
    let dir = workdir("addremove");
    assert!(run(&["--output", dir.to_str().unwrap()]).status.success());
    let allowlist = dir.join("sentinel.allowlist");

    // Use a real, stable binary on disk as the "agent" to hash.
    let agent_binary = bin(); // the keygen binary itself is a convenient stable file
    let add = run(&[
        "--add-agent",
        "--binary",
        agent_binary,
        "--description",
        "test agent",
        "--allowlist",
        allowlist.to_str().unwrap(),
    ]);
    assert!(
        add.status.success(),
        "add-agent failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    // The printed hash is the entry's binary_hash; capture it and confirm it is
    // present in the allowlist file.
    let stdout = String::from_utf8_lossy(&add.stdout);
    let hash = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("hash:"))
        .map(|s| s.trim().to_string())
        .expect("add-agent should print the entry hash");
    let body = std::fs::read_to_string(&allowlist).unwrap();
    assert!(body.contains(&hash), "allowlist must contain the added hash {hash}");

    // Remove by hash → entry absent.
    let remove = run(&[
        "--remove-agent",
        "--binary-hash",
        &hash,
        "--allowlist",
        allowlist.to_str().unwrap(),
    ]);
    assert!(
        remove.status.success(),
        "remove-agent failed: {}",
        String::from_utf8_lossy(&remove.stderr)
    );
    let body_after = std::fs::read_to_string(&allowlist).unwrap();
    assert!(!body_after.contains(&hash), "allowlist must not contain the removed hash");
}

#[test]
fn test_verify_passes_clean_install() {
    let dir = workdir("verify-clean");
    assert!(run(&["--output", dir.to_str().unwrap()]).status.success());

    let out = run(&["--verify", "--output", dir.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "verify should exit 0 on a clean install; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0));
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(report.contains("PASS"), "verify output should report PASS lines");
    assert!(!report.contains("[FAIL]"), "clean install must have no FAIL lines");
}

#[test]
fn test_verify_fails_missing_artifacts() {
    let dir = workdir("verify-missing");
    assert!(run(&["--output", dir.to_str().unwrap()]).status.success());

    // Delete the signing key, then verify.
    std::fs::remove_file(dir.join("sentinel.signing.key")).unwrap();
    assert!(!Path::new(&dir.join("sentinel.signing.key")).exists());

    let out = run(&["--verify", "--output", dir.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "verify must exit non-zero when an artifact is missing"
    );
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        report.contains("FAIL") && report.contains("sentinel.signing.key"),
        "verify should report signing.key FAIL; got:\n{report}"
    );
}
