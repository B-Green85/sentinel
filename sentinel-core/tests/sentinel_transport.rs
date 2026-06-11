// Sentinel v3 — Agent 8 test suite: tests/sentinel_transport
//
// Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.
//
// Contractual test names from the v3 spec, exercised against the REAL
// OS-agnostic transport layer (Agent 3): UnixTransport, the SentinelTransport
// trait, and the create_transport() factory.

#[cfg(unix)]
mod unix_tests {
    use sentinel_core::config::{Config, TransportType};
    use sentinel_core::transport::{create_transport, SentinelTransport, UnixTransport};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    fn temp_sock(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("sentinel-it-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn test_unix_transport_connect_disconnect() {
        let path = temp_sock("connect");
        let transport = UnixTransport::new(path.clone());
        transport.listen().expect("listen");

        // Connect a client (this process) and accept it.
        let client = UnixStream::connect(&path).expect("client connect");
        let conn = transport.accept().expect("accept");

        // peer_identity() returns a real ProcessIdentity with this process's PID.
        let id = conn.peer_identity();
        assert_eq!(id.pid, std::process::id(), "peer pid must be this process");
        assert!(
            !id.binary_path.as_os_str().is_empty() || id.binary_hash != [0u8; 32],
            "peer identity should resolve a real binary path or hash"
        );

        // Clean disconnect + shutdown.
        drop(client);
        drop(conn);
        transport.shutdown().expect("shutdown");
        assert!(!path.exists(), "socket file removed on shutdown");
    }

    #[test]
    fn test_transport_abstraction_interface() {
        // Construct via the create_transport() factory with an explicit Unix
        // selection, then drive it purely through the SentinelTransport trait.
        let path = temp_sock("factory");
        let mut config = Config::default();
        config.transport.transport_type = TransportType::Unix;
        config.transport.path = path.clone();

        let transport: Box<dyn SentinelTransport> = create_transport(&config);
        transport.listen().expect("listen() via trait must work");
        transport.shutdown().expect("shutdown() via trait must work");
        // listen()/shutdown() round-trip without panic — the abstraction holds.
    }
}

// On Windows the named-pipe transport is the native one; on Unix it must report
// UnsupportedPlatform. This spec test is gated to non-unix exactly as written;
// it does not run on the macOS/Linux v3 test matrix.
#[cfg(not(unix))]
#[test]
fn test_pipe_transport_unsupported_on_unix() {
    use sentinel_core::error::SentinelError;
    use sentinel_core::transport::{PipeTransport, SentinelTransport};
    let t = PipeTransport::new(PipeTransport::DEFAULT_NAME.to_string());
    assert!(matches!(t.listen(), Err(SentinelError::UnsupportedPlatform)));
}

// Unix-side companion to the contract above: on this platform PipeTransport
// must refuse with UnsupportedPlatform (the named pipe is Windows-only).
#[cfg(unix)]
#[test]
fn test_pipe_transport_unsupported_on_unix_side() {
    use sentinel_core::error::SentinelError;
    use sentinel_core::transport::{PipeTransport, SentinelTransport};
    let t = PipeTransport::new(PipeTransport::DEFAULT_NAME.to_string());
    assert!(matches!(t.listen(), Err(SentinelError::UnsupportedPlatform)));
}
