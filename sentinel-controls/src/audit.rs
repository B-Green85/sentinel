use std::fmt::Write as FmtWrite;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use sentinel_types::AuditEntry;

/// Computes SHA256 hex digest of the input string.
/// Pure deterministic — uses a minimal built-in implementation.
fn sha256_hex(input: &str) -> String {
    // Minimal SHA-256 implementation — no external crate needed.
    // Based on FIPS 180-4.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn bsig0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    fn bsig1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
    fn ssig0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }
    fn ssig1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    let msg = input.as_bytes();
    let bit_len = (msg.len() as u64) * 8;

    // Padding
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = ssig1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(ssig0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let t1 = hh
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = String::with_capacity(64);
    for word in &h {
        write!(result, "{:08x}", word).unwrap();
    }
    result
}

/// Create a hash for an audit entry: SHA256(action + timestamp + operator_id).
pub fn compute_audit_hash(action: &str, timestamp: &str, operator_id: &str) -> String {
    let input = format!("{}{}{}", action, timestamp, operator_id);
    sha256_hex(&input)
}

/// Create an AuditEntry with computed hash.
pub fn create_audit_entry(action: &str, timestamp: &str, operator_id: &str) -> AuditEntry {
    let hash = compute_audit_hash(action, timestamp, operator_id);
    AuditEntry {
        timestamp: timestamp.to_string(),
        operator_id: operator_id.to_string(),
        action: action.to_string(),
        hash,
    }
}

/// Append-only audit log writer. Opens file in append mode on every write
/// to ensure atomicity. Never modifies or deletes existing entries.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    /// Append a single entry to the audit log. Returns an error if the
    /// write fails — the caller must handle this, as no writes may be lost.
    pub fn append(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let line = format!(
            "{}\t{}\t{}\t{}\n",
            entry.timestamp, entry.operator_id, entry.action, entry.hash
        );
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        // SHA-256("hello") known value
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn audit_hash_deterministic() {
        let h1 = compute_audit_hash("pause_agent", "2026-03-18T00:00:00Z", "operator-1");
        let h2 = compute_audit_hash("pause_agent", "2026-03-18T00:00:00Z", "operator-1");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn audit_hash_changes_with_input() {
        let h1 = compute_audit_hash("pause_agent", "2026-03-18T00:00:00Z", "operator-1");
        let h2 = compute_audit_hash("kill_agent", "2026-03-18T00:00:00Z", "operator-1");
        assert_ne!(h1, h2);
    }

    #[test]
    fn create_entry_populates_hash() {
        let entry = create_audit_entry("test_action", "2026-03-18T00:00:00Z", "op-1");
        assert_eq!(entry.action, "test_action");
        assert!(!entry.hash.is_empty());
        assert_eq!(entry.hash.len(), 64);
    }

    #[test]
    fn audit_log_append_only() {
        let dir = std::env::temp_dir().join("sentinel_test_audit");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_audit.log");
        let _ = fs::remove_file(&path);

        let log = AuditLog::new(&path);
        let e1 = create_audit_entry("action_1", "2026-03-18T00:00:00Z", "op-1");
        let e2 = create_audit_entry("action_2", "2026-03-18T00:01:00Z", "op-1");

        log.append(&e1).unwrap();
        log.append(&e2).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("action_1"));
        assert!(lines[1].contains("action_2"));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
