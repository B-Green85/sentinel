// sentinel-verify — verify the integrity of a cryptographic audit chain.
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// Usage:
//   sentinel-verify --log /var/log/sentinel/actions.log
//
// Walks every entry from genesis to last, recomputing each entry_hash and
// checking each prev_hash link. Exits 0 if the chain is INTACT, non-zero if
// BROKEN (or the log cannot be read).

use sentinel_core::audit::{hash_display, verify_chain, BreakInfo, BreakKind};
use std::path::Path;
use std::process::ExitCode;

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Group a count with thousands separators, e.g. 10482 -> "10,482".
fn commas(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let len = bytes.len();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// First 8 hex chars of a hash, formatted as `sha256:xxxxxxxx...`.
fn short(hash: &[u8; 32]) -> String {
    let full = hash_display(hash); // "sha256:<64 hex>"
    let hex = full.strip_prefix("sha256:").unwrap_or(&full);
    format!("sha256:{}...", &hex[..8.min(hex.len())])
}

fn kind_label(kind: BreakKind) -> &'static str {
    match kind {
        BreakKind::GenesisPrev => "prev_hash",
        BreakKind::LinkMismatch => "prev_hash",
        BreakKind::ContentMismatch => "entry_hash",
        BreakKind::Malformed => "entry",
    }
}

fn report_break(brk: &BreakInfo, verified: usize, total: usize) {
    println!("chain integrity:  BROKEN at sequence {}", brk.sequence);
    match brk.kind {
        BreakKind::Malformed => {
            println!("  malformed entry at line {} — not valid chain NDJSON", brk.sequence);
        }
        _ => {
            let label = kind_label(brk.kind);
            println!("  expected {label}: {}", short(&brk.expected));
            println!("  found    {label}: {}", short(&brk.found));
        }
    }
    let after = total.saturating_sub(verified);
    println!("entries after break:  {} (unverified)", commas(after));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let log = match parse_arg(&args, "--log") {
        Some(p) => p,
        None => {
            eprintln!("usage: sentinel-verify --log <path>");
            return ExitCode::from(2);
        }
    };

    println!("sentinel-verify: checking {log}");

    let outcome = match verify_chain(Path::new(&log)) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("sentinel-verify: cannot read log: {e}");
            return ExitCode::from(2);
        }
    };

    println!("entries verified: {}", commas(outcome.entries_verified));

    if let Some(brk) = &outcome.broken {
        report_break(brk, outcome.entries_verified, outcome.total_entries);
        return ExitCode::from(1);
    }

    println!("chain integrity:  INTACT");
    println!(
        "genesis entry:    {}",
        if outcome.genesis_ok { "OK" } else { "MISSING" }
    );
    match outcome.last_hash {
        Some(h) => println!("last hash:        {}", short(&h)),
        None => println!("last hash:        (empty log)"),
    }
    ExitCode::SUCCESS
}
