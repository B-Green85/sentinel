// The five sentinel-keygen subcommands: generate, rotate, add-agent,
// remove-agent, verify. Each returns a human-readable error on failure — this
// tool runs at install time and its operator may not be a developer.

use crate::artifacts::{
    self, AgentEntry, Allowlist, InstallRecord, Manifest, ALLOWLIST, INSTALL_JSON, MANIFEST,
    SECRET_ARTIFACTS, SIGNING_KEY, SIGNING_PUB,
};
use crate::crypto;
use std::path::{Path, PathBuf};

const KEY_MODE: u32 = 0o600;
const PUB_MODE: u32 = 0o644;

// ── Shared helpers ──────────────────────────────────────────────

/// RFC3339 UTC timestamp, e.g. `2026-06-09T17:00:00Z`.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Filesystem-safe compact UTC timestamp for archive suffixes, e.g.
/// `2026-06-09T170000Z` (no colons, which are awkward in filenames).
fn now_compact() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H%M%SZ").to_string()
}

/// Best-effort stable machine identity: a machine-id file if present, else the
/// system hostname, else "unknown".
fn system_identity() -> String {
    for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(p) {
            let s = s.trim();
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Ok(out) = std::process::Command::new("hostname").output() {
        if out.status.success() {
            let h = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !h.is_empty() {
                return h;
            }
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// SHA-256 of the authorizing parent binary. Per spec this is the binary at
/// `/proc/self/exe` (Unix) / the current executable — i.e. this keygen tool,
/// which is what authorizes an agent onto the allowlist. Falls back to the zero
/// hash with a warning if the path cannot be resolved.
fn parent_hash() -> String {
    match std::env::current_exe() {
        Ok(path) => match crypto::hash_file(&path) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("warning: could not hash parent binary ({e}); using zero hash.");
                crypto::ZERO_HASH.to_string()
            }
        },
        Err(e) => {
            eprintln!("warning: could not locate parent binary ({e}); using zero hash.");
            crypto::ZERO_HASH.to_string()
        }
    }
}

fn require<'a>(opt: &'a Option<String>, flag: &str, mode: &str) -> Result<&'a str, String> {
    opt.as_deref()
        .ok_or_else(|| format!("{mode} requires {flag}. Run 'sentinel-keygen --help'."))
}

/// Write the manifest (the one committed artifact) into the output directory.
fn write_manifest(dir: &Path, fingerprint: &str, description: &str) -> Result<(), String> {
    let manifest = Manifest {
        last_run: now_rfc3339(),
        output_path: dir.display().to_string(),
        artifacts: SECRET_ARTIFACTS.iter().map(|s| s.to_string()).collect(),
        key_fingerprint: fingerprint.to_string(),
        description: description.to_string(),
    };
    artifacts::write_json(&artifacts::path_in(dir, MANIFEST), &manifest, None)
}

// ── generate ────────────────────────────────────────────────────

pub fn generate(output: &Option<String>, description: &Option<String>) -> Result<(), String> {
    let dir = PathBuf::from(require(output, "--output <DIR>", "Initial setup")?);
    let description = description.clone().unwrap_or_default();

    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create output directory '{}': {e}", dir.display()))?;

    // Preserve an existing allowlist's agents rather than wiping them on re-run.
    let allowlist_path = artifacts::path_in(&dir, ALLOWLIST);
    let allowlist = Allowlist::load_or_empty(&allowlist_path)?;
    artifacts::atomic_write(&allowlist_path, allowlist.to_toml()?.as_bytes(), None)?;

    // Signing keypair.
    let keypair = crypto::generate_keypair()?;
    artifacts::atomic_write(
        &artifacts::path_in(&dir, SIGNING_KEY),
        &keypair.private_pem,
        Some(KEY_MODE),
    )?;
    artifacts::atomic_write(
        &artifacts::path_in(&dir, SIGNING_PUB),
        &keypair.public_pem,
        Some(PUB_MODE),
    )?;
    let fingerprint = crypto::hash_bytes(&keypair.public_pem);

    // Installation record.
    let install = InstallRecord {
        generated_at: now_rfc3339(),
        output_path: dir.display().to_string(),
        description: description.clone(),
        system_identity: system_identity(),
        key_fingerprint: fingerprint.clone(),
        rotated_at: None,
    };
    artifacts::write_json(&artifacts::path_in(&dir, INSTALL_JSON), &install, None)?;

    write_manifest(&dir, &fingerprint, &description)?;

    println!("Sentinel installation generated in {}", dir.display());
    for name in SECRET_ARTIFACTS {
        println!("  created {name}");
    }
    println!("  created {MANIFEST} (commit this; it records generation, not secrets)");
    println!("Key fingerprint: {fingerprint}");
    Ok(())
}

// ── rotate ──────────────────────────────────────────────────────

pub fn rotate(output: &Option<String>) -> Result<(), String> {
    let dir = PathBuf::from(require(output, "--output <DIR>", "Key rotation")?);
    let key_path = artifacts::path_in(&dir, SIGNING_KEY);
    let pub_path = artifacts::path_in(&dir, SIGNING_PUB);

    if !key_path.exists() || !pub_path.exists() {
        return Err(format!(
            "no existing keys found in {}. Run initial setup first:\n  \
             sentinel-keygen --output {}",
            dir.display(),
            dir.display()
        ));
    }

    // Archive the current keypair with a timestamp suffix. Both files are kept
    // so signatures made under the old key remain verifiable.
    let stamp = now_compact();
    let archived_key = with_suffix(&key_path, &stamp);
    let archived_pub = with_suffix(&pub_path, &stamp);
    std::fs::rename(&key_path, &archived_key)
        .map_err(|e| format!("could not archive existing private key: {e}"))?;
    std::fs::rename(&pub_path, &archived_pub)
        .map_err(|e| format!("could not archive existing public key: {e}"))?;

    // Generate and write the new keypair.
    let keypair = crypto::generate_keypair()?;
    artifacts::atomic_write(&key_path, &keypair.private_pem, Some(KEY_MODE))?;
    artifacts::atomic_write(&pub_path, &keypair.public_pem, Some(PUB_MODE))?;
    let fingerprint = crypto::hash_bytes(&keypair.public_pem);

    // Update the install record with the rotation timestamp + new fingerprint.
    let install_path = artifacts::path_in(&dir, INSTALL_JSON);
    let mut install = read_install(&install_path).unwrap_or_else(|_| InstallRecord {
        generated_at: now_rfc3339(),
        output_path: dir.display().to_string(),
        description: String::new(),
        system_identity: system_identity(),
        key_fingerprint: fingerprint.clone(),
        rotated_at: None,
    });
    install.rotated_at = Some(now_rfc3339());
    install.key_fingerprint = fingerprint.clone();
    artifacts::write_json(&install_path, &install, None)?;

    write_manifest(&dir, &fingerprint, &install.description)?;

    println!("Key rotation complete. Prior keys archived. Prior audit log entries remain verifiable with archived keys.");
    println!("  archived {}", archived_key.display());
    println!("  archived {}", archived_pub.display());
    println!("New key fingerprint: {fingerprint}");
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push('.');
    name.push_str(suffix);
    path.with_file_name(name)
}

fn read_install(path: &Path) -> Result<InstallRecord, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("'{}' is not valid JSON: {e}", path.display()))
}

// ── add-agent ───────────────────────────────────────────────────

pub fn add_agent(
    binary: &Option<String>,
    description: &Option<String>,
    allowlist: &Option<String>,
) -> Result<(), String> {
    let binary = require(binary, "--binary <PATH>", "Adding an agent")?;
    let allowlist_path = PathBuf::from(require(allowlist, "--allowlist <FILE>", "Adding an agent")?);
    let description = description.clone().unwrap_or_default();

    let binary_path = Path::new(binary);
    if !binary_path.exists() {
        return Err(format!("binary '{binary}' does not exist."));
    }
    let binary_hash = crypto::hash_file(binary_path)?;

    let mut allowlist = Allowlist::load_or_empty(&allowlist_path)?;
    if allowlist.agents.iter().any(|a| a.binary_hash == binary_hash) {
        println!("Agent already present in allowlist (hash {binary_hash}); nothing to do.");
        return Ok(());
    }

    allowlist.agents.push(AgentEntry {
        binary_hash: binary_hash.clone(),
        binary_path: binary_path.display().to_string(),
        parent_hash: parent_hash(),
        description,
        added_at: now_rfc3339(),
    });
    artifacts::atomic_write(&allowlist_path, allowlist.to_toml()?.as_bytes(), None)?;

    println!("Added agent to {}", allowlist_path.display());
    println!("  binary: {binary}");
    println!("  hash:   {binary_hash}");
    Ok(())
}

// ── remove-agent ────────────────────────────────────────────────

pub fn remove_agent(binary_hash: &Option<String>, allowlist: &Option<String>) -> Result<(), String> {
    let target = require(binary_hash, "--binary-hash <HASH>", "Removing an agent")?;
    let allowlist_path =
        PathBuf::from(require(allowlist, "--allowlist <FILE>", "Removing an agent")?);

    let mut allowlist = Allowlist::load_or_empty(&allowlist_path)?;
    let before = allowlist.agents.len();
    allowlist.agents.retain(|a| a.binary_hash != target);
    let removed = before - allowlist.agents.len();

    if removed == 0 {
        return Err(format!(
            "no allowlist entry matched hash '{target}' in {}.",
            allowlist_path.display()
        ));
    }

    artifacts::atomic_write(&allowlist_path, allowlist.to_toml()?.as_bytes(), None)?;
    println!(
        "Removed {removed} agent(s) matching '{target}' from {}.",
        allowlist_path.display()
    );
    Ok(())
}

// ── verify ──────────────────────────────────────────────────────

pub fn verify(output: &Option<String>) -> Result<(), String> {
    let dir = PathBuf::from(require(output, "--output <DIR>", "Verification")?);
    let mut ok = true;
    let mut check = |label: &str, passed: bool| {
        println!("  [{}] {label}", if passed { "PASS" } else { "FAIL" });
        if !passed {
            ok = false;
        }
    };

    println!("Verifying Sentinel installation in {}", dir.display());

    // 1. All four secret artifacts exist.
    for name in SECRET_ARTIFACTS {
        let exists = artifacts::path_in(&dir, name).exists();
        check(&format!("artifact present: {name}"), exists);
    }

    // 2. Private key permissions are 0600 (Unix only).
    let key_path = artifacts::path_in(&dir, SIGNING_KEY);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(&key_path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                check(
                    &format!("private key permissions are 0600 (found {mode:#o})"),
                    mode == KEY_MODE,
                );
            }
            Err(_) => check("private key permissions are 0600", false),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &key_path;
        println!("  [WARN] permission enforcement (0600) is not available on this platform");
    }

    // 3. Allowlist parses as TOML.
    let allowlist_path = artifacts::path_in(&dir, ALLOWLIST);
    let allowlist_ok = std::fs::read_to_string(&allowlist_path)
        .ok()
        .and_then(|t| Allowlist::from_toml(&t).ok())
        .is_some();
    check("allowlist is valid TOML", allowlist_ok);

    // 4. Install record parses as JSON.
    let install_path = artifacts::path_in(&dir, INSTALL_JSON);
    let install = read_install(&install_path).ok();
    check("install record is valid JSON", install.is_some());

    // 5. Manifest fingerprint matches the actual public key.
    let manifest_path = artifacts::path_in(&dir, MANIFEST);
    let pub_path = artifacts::path_in(&dir, SIGNING_PUB);
    let fingerprint_ok = (|| {
        let text = std::fs::read_to_string(&manifest_path).ok()?;
        let manifest: Manifest = serde_json::from_str(&text).ok()?;
        let actual = crypto::hash_file(&pub_path).ok()?;
        Some(manifest.key_fingerprint == actual)
    })()
    .unwrap_or(false);
    check("manifest fingerprint matches public key", fingerprint_ok);

    println!();
    if ok {
        println!("Verification PASSED: all checks succeeded.");
        Ok(())
    } else {
        Err("verification FAILED — see the PASS/FAIL details above.".to_string())
    }
}
