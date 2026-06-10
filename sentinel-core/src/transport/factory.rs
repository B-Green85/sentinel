// sentinel-core — transport selection factory (Agent 3).
//
// Maps the `[transport]` config block onto a concrete `SentinelTransport`.
//
// Agent 3 note: the prompt's `create_transport(config: &SentinelConfig)` is
// written against the *existing* sentinel-core config type, which is named
// `Config` (in `crate::config`), not `SentinelConfig`. We bind to the real type
// here. The selection semantics are exactly as specified.

use crate::config::{Config, TransportType};
use crate::transport::{PipeTransport, SentinelTransport};

#[cfg(unix)]
use crate::transport::UnixTransport;

/// Construct the transport selected by configuration.
///
/// * `Unix` → [`UnixTransport`] (falls back to a pipe on non-Unix hosts).
/// * `Pipe` → [`PipeTransport`].
/// * `Auto` → the native transport for the build target.
pub fn create_transport(config: &Config) -> Box<dyn SentinelTransport> {
    match config.transport.transport_type {
        TransportType::Unix => unix_transport(config),
        TransportType::Pipe => {
            Box::new(PipeTransport::new(config.transport.pipe_name.clone()))
        }
        TransportType::Auto => default_transport(config),
    }
}

// ── `Unix` selection ───────────────────────────────────────────────────────

#[cfg(unix)]
fn unix_transport(config: &Config) -> Box<dyn SentinelTransport> {
    Box::new(UnixTransport::new(config.transport.path.clone()))
}

#[cfg(not(unix))]
fn unix_transport(config: &Config) -> Box<dyn SentinelTransport> {
    // No Unix domain sockets on this platform; fall back to the named pipe.
    Box::new(PipeTransport::new(config.transport.pipe_name.clone()))
}

// ── `Auto` selection — native transport for the target ──────────────────────

#[cfg(unix)]
fn default_transport(config: &Config) -> Box<dyn SentinelTransport> {
    Box::new(UnixTransport::new(config.transport.path.clone()))
}

#[cfg(windows)]
fn default_transport(config: &Config) -> Box<dyn SentinelTransport> {
    Box::new(PipeTransport::new(config.transport.pipe_name.clone()))
}

#[cfg(not(any(unix, windows)))]
fn default_transport(config: &Config) -> Box<dyn SentinelTransport> {
    // Last-resort default: attempt a Unix socket path (compiles via the
    // non-unix `UnixTransport` fallback through `PipeTransport`).
    Box::new(PipeTransport::new(config.transport.pipe_name.clone()))
}
