// sentinel-keygen — generates Sentinel deployment secrets at install time.
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// This is a standalone CLI run once at setup, again on key rotation, and
// on-demand for allowlist management. It writes signing keys, an allowlist, and
// an install record (all gitignored, never committed) plus a manifest that
// records *that* generation happened without exposing any secret.

mod artifacts;
mod cli;
mod commands;
mod crypto;

use cli::Mode;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    let result = match cli::parse(&argv) {
        Ok(parsed) => dispatch(parsed),
        Err(e) => Err(e),
    };

    if let Err(message) = result {
        eprintln!("Error: {message}");
        std::process::exit(1);
    }
}

fn dispatch(parsed: cli::Cli) -> Result<(), String> {
    let a = &parsed.args;
    match parsed.mode {
        Mode::Help => {
            print!("{}", cli::USAGE);
            Ok(())
        }
        Mode::Generate => commands::generate(&a.output, &a.description),
        Mode::Rotate => commands::rotate(&a.output),
        Mode::Verify => commands::verify(&a.output),
        Mode::AddAgent => commands::add_agent(&a.binary, &a.description, &a.allowlist),
        Mode::RemoveAgent => commands::remove_agent(&a.binary_hash, &a.allowlist),
    }
}
