// sentinel-core — error type for the transport abstraction layer.
//
// Agent 3 note: the Agent 3 prompt imports `crate::error::SentinelError` and
// uses `SentinelError::UnsupportedPlatform`, describing it as an *existing*
// sentinel-core contract. It did not exist. `sentinel-types` already exports a
// `SentinelError` *struct* (`{ code, message }`) for the JSON wire protocol,
// which is a different concern and has no platform/IO variants. To satisfy the
// transport contract exactly as written — including `UnsupportedPlatform` — we
// introduce this crate-local error enum at the path the prompt expects.

use std::fmt;

/// Error type for sentinel-core transport operations.
///
/// Distinct from `sentinel_types::SentinelError`, which models the JSON
/// request/response error envelope. This type models local OS-level transport
/// failures (binding/accepting sockets, reading peer credentials, and
/// platforms a given transport cannot serve).
#[derive(Debug)]
pub enum SentinelError {
    /// An underlying I/O failure (bind, accept, read, write, …).
    Io(std::io::Error),
    /// The selected transport is not available on this platform
    /// (e.g. `PipeTransport` on Unix, `UnixTransport` on Windows).
    UnsupportedPlatform,
    /// A transport-level protocol or lifecycle error (e.g. `accept()` called
    /// before `listen()`), carrying a human-readable description.
    Transport(String),
    /// Failed to resolve the peer's process identity from the OS.
    PeerIdentity(String),
}

impl fmt::Display for SentinelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SentinelError::Io(e) => write!(f, "transport I/O error: {e}"),
            SentinelError::UnsupportedPlatform => {
                write!(f, "transport not supported on this platform")
            }
            SentinelError::Transport(msg) => write!(f, "transport error: {msg}"),
            SentinelError::PeerIdentity(msg) => {
                write!(f, "peer identity resolution failed: {msg}")
            }
        }
    }
}

impl std::error::Error for SentinelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SentinelError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SentinelError {
    fn from(e: std::io::Error) -> Self {
        SentinelError::Io(e)
    }
}
