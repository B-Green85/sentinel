// Generate a real cryptographic audit-chain log for use as a test fixture.
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// Usage: cargo run -p sentinel-core --example gen_audit_fixture -- <path> [count]
//
// Writes a fresh chain (genesis + `count` heartbeat entries) at <path> using the
// production `AuditChain` so the on-disk format and hashes are authentic. Used to
// produce the fixtures the sentinel-py pytest suite verifies against.

use sentinel_core::audit::AuditChain;
use sentinel_types::AuditEvent;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: gen_audit_fixture <path> [count]");
    let count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);

    let _ = std::fs::remove_file(path);
    let mut chain = AuditChain::open(std::path::Path::new(path)).expect("open chain");
    for i in 0..count {
        chain
            .write(format!("agent-{i}"), AuditEvent::Heartbeat)
            .expect("write entry");
    }
    println!("wrote {} entries (+genesis) to {path}", count);
}
