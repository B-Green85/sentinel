// sentinel-core — OS-agnostic transport abstraction layer (Agent 3).
//
// Replaces the daemon's hardcoded Unix-socket accept loop with a trait-based
// system. Three concrete transports are provided:
//
//   * `UnixTransport`   — Linux and macOS (std Unix domain sockets). Real
//                         peer-identity resolution: peer PID + UID from the
//                         kernel, binary path + SHA-256 hash from disk.
//   * `PipeTransport`   — Windows named pipes. Compiles everywhere; on
//                         non-Windows platforms every operation returns
//                         `SentinelError::UnsupportedPlatform`.
//   * `KernelTransport` — GolemLinux kernel IPC. Feature-gated stub (see below).
//
// The daemon wires these in via `create_transport()` (see `transport::factory`)
// and drives them through `SentinelDaemon::serve_transport`.
//
// Agent 3 note on dependencies: this module consumes `sentinel_types::ProcessIdentity`
// (Agent 1's contract) and `crate::error::SentinelError`. At authoring time
// Agent 1 had not yet landed `ProcessIdentity`; this code is written against the
// documented Agent 1 contract:
//   ProcessIdentity { pid: u32, binary_hash: [u8;32], binary_path: PathBuf,
//                     parent_pid: u32, parent_hash: [u8;32], uid: u32 }

use crate::error::SentinelError;
use sentinel_types::ProcessIdentity;

pub mod factory;
pub use factory::create_transport;

/// OS-agnostic transport trait. All connection handling goes through this
/// interface. Implementations are blocking; the daemon bridges them onto its
/// async runtime via `tokio::task::spawn_blocking`.
pub trait SentinelTransport: Send + Sync {
    /// Begin listening for connections (bind the socket / create the pipe).
    fn listen(&self) -> Result<(), SentinelError>;
    /// Block until a peer connects, returning the active connection.
    fn accept(&self) -> Result<Box<dyn Connection>, SentinelError>;
    /// Stop listening and release the underlying resource.
    fn shutdown(&self) -> Result<(), SentinelError>;
}

/// A single active connection to a registering agent.
pub trait Connection: Send + Sync {
    /// Write a complete message to the peer.
    fn send(&self, msg: &[u8]) -> Result<(), SentinelError>;
    /// Read the next message from the peer.
    fn recv(&self) -> Result<Vec<u8>, SentinelError>;
    /// Kernel-verified identity of the connected peer.
    fn peer_identity(&self) -> ProcessIdentity;
}

// ─────────────────────────────────────────────────────────────────────────
// UnixTransport — Linux and macOS
// ─────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
pub use unix_impl::{UnixConnection, UnixTransport};

#[cfg(unix)]
mod unix_impl {
    use super::{Connection, ProcessIdentity, SentinelError, SentinelTransport};
    use std::io::{Read, Write};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Unix domain socket transport. The blessed constructor is
    /// [`UnixTransport::new`]; `socket_path` remains public per the contract.
    ///
    /// A private `listener` cell holds the bound listener between `listen()`
    /// and `accept()` (the trait methods take `&self`, so the listening state
    /// lives behind interior mutability).
    pub struct UnixTransport {
        pub socket_path: PathBuf,
        listener: Mutex<Option<UnixListener>>,
    }

    impl UnixTransport {
        /// Default socket path used when none is configured.
        pub const DEFAULT_PATH: &'static str = "/tmp/sentinel.sock";

        pub fn new(socket_path: PathBuf) -> Self {
            Self {
                socket_path,
                listener: Mutex::new(None),
            }
        }
    }

    impl SentinelTransport for UnixTransport {
        fn listen(&self) -> Result<(), SentinelError> {
            // Remove a stale socket file from a prior run (matches the legacy
            // daemon behaviour exactly — bind fails on a leftover path).
            let _ = std::fs::remove_file(&self.socket_path);
            let listener = UnixListener::bind(&self.socket_path)?;
            *self.listener.lock().unwrap() = Some(listener);
            Ok(())
        }

        fn accept(&self) -> Result<Box<dyn Connection>, SentinelError> {
            // Clone the listener handle and release the lock *before* the
            // blocking accept, so `shutdown()` is never starved.
            let listener = {
                let guard = self.listener.lock().unwrap();
                guard
                    .as_ref()
                    .ok_or_else(|| {
                        SentinelError::Transport(
                            "accept() called before listen()".to_string(),
                        )
                    })?
                    .try_clone()?
            };
            let (stream, _addr) = listener.accept()?;
            Ok(Box::new(UnixConnection::new(stream)))
        }

        fn shutdown(&self) -> Result<(), SentinelError> {
            // Drop the listener, then remove the socket file.
            *self.listener.lock().unwrap() = None;
            let _ = std::fs::remove_file(&self.socket_path);
            Ok(())
        }
    }

    /// A single accepted Unix-socket connection.
    pub struct UnixConnection {
        stream: UnixStream,
    }

    impl UnixConnection {
        pub fn new(stream: UnixStream) -> Self {
            Self { stream }
        }
    }

    impl Connection for UnixConnection {
        fn send(&self, msg: &[u8]) -> Result<(), SentinelError> {
            // `&UnixStream` implements `Write`, so `&self` is sufficient.
            (&self.stream).write_all(msg)?;
            (&self.stream).flush()?;
            Ok(())
        }

        fn recv(&self) -> Result<Vec<u8>, SentinelError> {
            let mut buf = vec![0u8; 65536];
            let n = (&self.stream).read(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        }

        fn peer_identity(&self) -> ProcessIdentity {
            resolve_identity(self.stream.as_raw_fd())
        }
    }

    // ── Real peer-identity resolution ──────────────────────────────────────
    //
    // Linux: SO_PEERCRED gives (pid, uid); /proc/<pid>/exe gives the binary
    // path and contents; /proc/<pid>/stat gives the parent pid.
    // macOS: getpeereid gives uid, LOCAL_PEERPID gives pid, proc_pidpath gives
    // the binary path, proc_pidinfo(PROC_PIDTBSDINFO) gives the parent pid.
    //
    // The binary hash is always read from disk via the crate's own SHA-256
    // (`crate::sha256`) — never zeroed on the happy path, never placeholder.

    fn hash_file(path: &Path) -> [u8; 32] {
        match std::fs::read(path) {
            Ok(bytes) => hex_to_32(&crate::sha256::sha256_hex(&bytes)),
            Err(_) => [0u8; 32],
        }
    }

    fn hex_to_32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = hex.as_bytes();
        if bytes.len() < 64 {
            return out;
        }
        for i in 0..32 {
            out[i] = (from_hex(bytes[i * 2]) << 4) | from_hex(bytes[i * 2 + 1]);
        }
        out
    }

    fn from_hex(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    #[cfg(target_os = "linux")]
    fn resolve_identity(fd: RawFd) -> ProcessIdentity {
        let (pid, uid) = linux::peer_pid_uid(fd).unwrap_or((0, 0));
        let exe = format!("/proc/{pid}/exe");
        let binary_path =
            std::fs::read_link(&exe).unwrap_or_else(|_| PathBuf::from(&exe));
        let binary_hash = hash_file(Path::new(&exe));

        let parent_pid = linux::read_ppid(pid).unwrap_or(0);
        let parent_hash = hash_file(Path::new(&format!("/proc/{parent_pid}/exe")));

        ProcessIdentity {
            pid,
            binary_hash,
            binary_path,
            parent_pid,
            parent_hash,
            uid,
        }
    }

    #[cfg(target_os = "macos")]
    fn resolve_identity(fd: RawFd) -> ProcessIdentity {
        let pid = macos::peer_pid(fd).unwrap_or(0);
        let uid = macos::peer_uid(fd).unwrap_or(0);

        let binary_path = macos::proc_path(pid).unwrap_or_default();
        let binary_hash = if binary_path.as_os_str().is_empty() {
            [0u8; 32]
        } else {
            hash_file(&binary_path)
        };

        let parent_pid = macos::parent_pid(pid).unwrap_or(0);
        let parent_path = macos::proc_path(parent_pid).unwrap_or_default();
        let parent_hash = if parent_path.as_os_str().is_empty() {
            [0u8; 32]
        } else {
            hash_file(&parent_path)
        };

        ProcessIdentity {
            pid,
            binary_hash,
            binary_path,
            parent_pid,
            parent_hash,
            uid,
        }
    }

    // Other Unix flavours (BSDs): best-effort UID via getpeereid. PID/hash
    // resolution is platform-specific and left unimplemented here — not part
    // of the v3 test matrix (Linux + macOS).
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn resolve_identity(fd: RawFd) -> ProcessIdentity {
        let uid = generic::peer_uid(fd).unwrap_or(0);
        ProcessIdentity {
            pid: 0,
            binary_hash: [0u8; 32],
            binary_path: PathBuf::new(),
            parent_pid: 0,
            parent_hash: [0u8; 32],
            uid,
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::os::raw::{c_int, c_void};
        use std::os::unix::io::RawFd;

        #[repr(C)]
        struct Ucred {
            pid: i32,
            uid: u32,
            gid: u32,
        }

        extern "C" {
            fn getsockopt(
                sockfd: c_int,
                level: c_int,
                optname: c_int,
                optval: *mut c_void,
                optlen: *mut u32,
            ) -> c_int;
        }

        const SOL_SOCKET: c_int = 1;
        const SO_PEERCRED: c_int = 17;

        pub fn peer_pid_uid(fd: RawFd) -> Option<(u32, u32)> {
            let mut cred = Ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<Ucred>() as u32;
            let rc = unsafe {
                getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_PEERCRED,
                    &mut cred as *mut Ucred as *mut c_void,
                    &mut len,
                )
            };
            if rc == 0 {
                Some((cred.pid as u32, cred.uid))
            } else {
                None
            }
        }

        /// Parse the parent pid (field 4) from `/proc/<pid>/stat`. The comm
        /// field (2) may contain spaces and parens, so we split after the last
        /// ')' — the canonical, robust way to read this file.
        pub fn read_ppid(pid: u32) -> Option<u32> {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let after_comm = &stat[stat.rfind(')')? + 1..];
            let mut fields = after_comm.split_whitespace();
            let _state = fields.next()?; // field 3
            fields.next()?.parse().ok() // field 4: ppid
        }
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use std::os::raw::{c_int, c_void};
        use std::os::unix::io::RawFd;
        use std::path::PathBuf;

        extern "C" {
            fn getpeereid(s: c_int, euid: *mut u32, egid: *mut u32) -> c_int;
            fn getsockopt(
                sockfd: c_int,
                level: c_int,
                optname: c_int,
                optval: *mut c_void,
                optlen: *mut u32,
            ) -> c_int;
            fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
            fn proc_pidinfo(
                pid: c_int,
                flavor: c_int,
                arg: u64,
                buffer: *mut c_void,
                buffersize: c_int,
            ) -> c_int;
        }

        const SOL_LOCAL: c_int = 0;
        const LOCAL_PEERPID: c_int = 0x002;
        const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;
        const PROC_PIDTBSDINFO: c_int = 3;

        // Subset of <sys/proc_info.h> struct proc_bsdinfo. Only pbi_ppid is
        // read, but the full layout is declared so proc_pidinfo's size check
        // passes (it requires buffersize == sizeof(struct proc_bsdinfo)).
        #[repr(C)]
        struct ProcBsdInfo {
            pbi_flags: u32,
            pbi_status: u32,
            pbi_xstatus: u32,
            pbi_pid: u32,
            pbi_ppid: u32,
            pbi_uid: u32,
            pbi_gid: u32,
            pbi_ruid: u32,
            pbi_rgid: u32,
            pbi_svuid: u32,
            pbi_svgid: u32,
            rfu_1: u32,
            pbi_comm: [u8; 16],   // MAXCOMLEN
            pbi_name: [u8; 32],   // 2 * MAXCOMLEN
            pbi_nfiles: u32,
            pbi_pgid: u32,
            pbi_pjobc: u32,
            e_tdev: u32,
            e_tpgid: u32,
            pbi_nice: i32,
            pbi_start_tvsec: u64,
            pbi_start_tvusec: u64,
        }

        pub fn peer_uid(fd: RawFd) -> Option<u32> {
            let mut euid: u32 = 0;
            let mut egid: u32 = 0;
            let rc = unsafe { getpeereid(fd, &mut euid, &mut egid) };
            if rc == 0 {
                Some(euid)
            } else {
                None
            }
        }

        pub fn peer_pid(fd: RawFd) -> Option<u32> {
            let mut pid: i32 = 0;
            let mut len = std::mem::size_of::<i32>() as u32;
            let rc = unsafe {
                getsockopt(
                    fd,
                    SOL_LOCAL,
                    LOCAL_PEERPID,
                    &mut pid as *mut i32 as *mut c_void,
                    &mut len,
                )
            };
            if rc == 0 && pid > 0 {
                Some(pid as u32)
            } else {
                None
            }
        }

        pub fn proc_path(pid: u32) -> Option<PathBuf> {
            if pid == 0 {
                return None;
            }
            let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
            let n = unsafe {
                proc_pidpath(
                    pid as c_int,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                )
            };
            if n <= 0 {
                return None;
            }
            buf.truncate(n as usize);
            Some(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
        }

        pub fn parent_pid(pid: u32) -> Option<u32> {
            if pid == 0 {
                return None;
            }
            let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<ProcBsdInfo>() as c_int;
            let n = unsafe {
                proc_pidinfo(
                    pid as c_int,
                    PROC_PIDTBSDINFO,
                    0,
                    &mut info as *mut ProcBsdInfo as *mut c_void,
                    size,
                )
            };
            if n == size {
                Some(info.pbi_ppid)
            } else {
                None
            }
        }
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    mod generic {
        use std::os::raw::c_int;
        use std::os::unix::io::RawFd;

        extern "C" {
            fn getpeereid(s: c_int, euid: *mut u32, egid: *mut u32) -> c_int;
        }

        pub fn peer_uid(fd: RawFd) -> Option<u32> {
            let mut euid: u32 = 0;
            let mut egid: u32 = 0;
            let rc = unsafe { getpeereid(fd, &mut euid, &mut egid) };
            if rc == 0 {
                Some(euid)
            } else {
                None
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// PipeTransport — Windows named pipes
// ─────────────────────────────────────────────────────────────────────────

/// Windows named-pipe transport. The struct compiles on every platform; the
/// behaviour is platform-gated. On non-Windows targets every operation returns
/// [`SentinelError::UnsupportedPlatform`].
pub struct PipeTransport {
    pub pipe_name: String,
}

impl PipeTransport {
    /// Default pipe name used when none is configured.
    pub const DEFAULT_NAME: &'static str = r"\\.\pipe\sentinel";

    pub fn new(pipe_name: String) -> Self {
        Self { pipe_name }
    }
}

#[cfg(not(target_os = "windows"))]
impl SentinelTransport for PipeTransport {
    fn listen(&self) -> Result<(), SentinelError> {
        Err(SentinelError::UnsupportedPlatform)
    }
    fn accept(&self) -> Result<Box<dyn Connection>, SentinelError> {
        Err(SentinelError::UnsupportedPlatform)
    }
    fn shutdown(&self) -> Result<(), SentinelError> {
        Err(SentinelError::UnsupportedPlatform)
    }
}

// Real Windows implementation. NOTE: this path cannot be compiled or exercised
// on the macOS/Linux v3 test matrix; build and run it on Windows before merging
// a Windows release. It is fully cfg-isolated and cannot affect the Unix build.
#[cfg(target_os = "windows")]
pub use windows_impl::PipeConnection;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::{Connection, ProcessIdentity, PipeTransport, SentinelError, SentinelTransport};
    use std::os::raw::c_void;
    use std::path::PathBuf;

    type Handle = *mut c_void;
    type Bool = i32;

    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const NMPWAIT_USE_DEFAULT_WAIT: u32 = 0x0000_0000;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const INVALID_HANDLE: isize = -1;

    extern "system" {
        fn CreateNamedPipeW(
            lpName: *const u16,
            dwOpenMode: u32,
            dwPipeMode: u32,
            nMaxInstances: u32,
            nOutBufferSize: u32,
            nInBufferSize: u32,
            nDefaultTimeOut: u32,
            lpSecurityAttributes: *mut c_void,
        ) -> Handle;
        fn ConnectNamedPipe(hNamedPipe: Handle, lpOverlapped: *mut c_void) -> Bool;
        fn DisconnectNamedPipe(hNamedPipe: Handle) -> Bool;
        fn ReadFile(
            hFile: Handle,
            lpBuffer: *mut c_void,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: *mut u32,
            lpOverlapped: *mut c_void,
        ) -> Bool;
        fn WriteFile(
            hFile: Handle,
            lpBuffer: *const c_void,
            nNumberOfBytesToWrite: u32,
            lpNumberOfBytesWritten: *mut u32,
            lpOverlapped: *mut c_void,
        ) -> Bool;
        fn GetNamedPipeClientProcessId(Pipe: Handle, ClientProcessId: *mut u32) -> Bool;
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: Bool, dwProcessId: u32) -> Handle;
        fn QueryFullProcessImageNameW(
            hProcess: Handle,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> Bool;
        fn CloseHandle(hObject: Handle) -> Bool;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A Windows handle wrapped so it can cross thread boundaries. Win32
    /// HANDLEs are process-global and safe to move/share.
    struct SyncHandle(Handle);
    unsafe impl Send for SyncHandle {}
    unsafe impl Sync for SyncHandle {}

    impl SentinelTransport for PipeTransport {
        fn listen(&self) -> Result<(), SentinelError> {
            // Named pipes are created per-connection in accept(); nothing to do
            // here beyond validating the name.
            if self.pipe_name.is_empty() {
                return Err(SentinelError::Transport("empty pipe name".to_string()));
            }
            Ok(())
        }

        fn accept(&self) -> Result<Box<dyn Connection>, SentinelError> {
            let wide = to_wide(&self.pipe_name);
            let handle = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    NMPWAIT_USE_DEFAULT_WAIT,
                    std::ptr::null_mut(),
                )
            };
            if handle as isize == INVALID_HANDLE || handle.is_null() {
                return Err(SentinelError::Io(std::io::Error::last_os_error()));
            }
            let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
            // ConnectNamedPipe returns 0 with ERROR_PIPE_CONNECTED if the client
            // connected between create and connect; treat that as success.
            if connected == 0 {
                let err = std::io::Error::last_os_error();
                const ERROR_PIPE_CONNECTED: i32 = 535;
                if err.raw_os_error() != Some(ERROR_PIPE_CONNECTED) {
                    unsafe { CloseHandle(handle) };
                    return Err(SentinelError::Io(err));
                }
            }
            Ok(Box::new(PipeConnection {
                handle: SyncHandle(handle),
            }))
        }

        fn shutdown(&self) -> Result<(), SentinelError> {
            // No persistent listener handle to release.
            Ok(())
        }
    }

    /// A single accepted named-pipe connection.
    pub struct PipeConnection {
        handle: SyncHandle,
    }

    impl Drop for PipeConnection {
        fn drop(&mut self) {
            unsafe {
                DisconnectNamedPipe(self.handle.0);
                CloseHandle(self.handle.0);
            }
        }
    }

    impl Connection for PipeConnection {
        fn send(&self, msg: &[u8]) -> Result<(), SentinelError> {
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle.0,
                    msg.as_ptr() as *const c_void,
                    msg.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                Err(SentinelError::Io(std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }

        fn recv(&self) -> Result<Vec<u8>, SentinelError> {
            let mut buf = vec![0u8; 65536];
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle.0,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(SentinelError::Io(std::io::Error::last_os_error()));
            }
            buf.truncate(read as usize);
            Ok(buf)
        }

        fn peer_identity(&self) -> ProcessIdentity {
            resolve_identity(self.handle.0)
        }
    }

    fn hash_file(path: &std::path::Path) -> [u8; 32] {
        match std::fs::read(path) {
            Ok(bytes) => super::unix_hex::hex_to_32(&crate::sha256::sha256_hex(&bytes)),
            Err(_) => [0u8; 32],
        }
    }

    fn client_pid(pipe: Handle) -> Option<u32> {
        let mut pid: u32 = 0;
        let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
        if ok != 0 && pid != 0 {
            Some(pid)
        } else {
            None
        }
    }

    fn process_path(pid: u32) -> Option<PathBuf> {
        let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if proc.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32768];
        let mut size = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(proc, 0, buf.as_mut_ptr(), &mut size) };
        unsafe { CloseHandle(proc) };
        if ok == 0 {
            return None;
        }
        buf.truncate(size as usize);
        Some(PathBuf::from(String::from_utf16_lossy(&buf)))
    }

    fn resolve_identity(pipe: Handle) -> ProcessIdentity {
        let pid = client_pid(pipe).unwrap_or(0);
        let binary_path = process_path(pid).unwrap_or_default();
        let binary_hash = if binary_path.as_os_str().is_empty() {
            [0u8; 32]
        } else {
            hash_file(&binary_path)
        };
        // Parent identity is not resolved on Windows in v3 (no consumer yet).
        ProcessIdentity {
            pid,
            binary_hash,
            binary_path,
            parent_pid: 0,
            parent_hash: [0u8; 32],
            uid: 0,
        }
    }
}

// Hex helpers shared with the Windows path (the Unix copies live in
// `unix_impl`, which is not compiled on Windows).
#[cfg(target_os = "windows")]
mod unix_hex {
    pub fn hex_to_32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = hex.as_bytes();
        if bytes.len() < 64 {
            return out;
        }
        for i in 0..32 {
            out[i] = (from_hex(bytes[i * 2]) << 4) | from_hex(bytes[i * 2 + 1]);
        }
        out
    }
    fn from_hex(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// KernelTransport — GolemLinux kernel IPC (feature-gated stub)
// ─────────────────────────────────────────────────────────────────────────

/// KernelTransport is implemented in `src/sentinel/` in the GolemLinux kernel.
/// This stub satisfies the trait contract for the workspace build.
///
/// The real implementation (Agent 7) lives in the kernel and is `no_std`. Here
/// it exists only so the workspace compiles with `--features kernel-transport`
/// and so downstream code can name the type; every method is `unimplemented!()`.
#[cfg(feature = "kernel-transport")]
pub struct KernelTransport;

#[cfg(feature = "kernel-transport")]
impl SentinelTransport for KernelTransport {
    fn listen(&self) -> Result<(), SentinelError> {
        unimplemented!("KernelTransport is provided by the GolemLinux kernel (src/sentinel/)")
    }
    fn accept(&self) -> Result<Box<dyn Connection>, SentinelError> {
        unimplemented!("KernelTransport is provided by the GolemLinux kernel (src/sentinel/)")
    }
    fn shutdown(&self) -> Result<(), SentinelError> {
        unimplemented!("KernelTransport is provided by the GolemLinux kernel (src/sentinel/)")
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    fn temp_sock() -> PathBuf {
        std::env::temp_dir().join(format!(
            "sentinel-transport-test-{}.sock",
            std::process::id()
        ))
    }

    #[test]
    fn unix_transport_round_trip_and_real_identity() {
        let path = temp_sock();
        let _ = std::fs::remove_file(&path);

        let transport = UnixTransport::new(path.clone());
        transport.listen().expect("listen");

        // Connect a client (this very process), then accept it.
        let mut client = UnixStream::connect(&path).expect("connect");
        let conn = transport.accept().expect("accept");

        // Peer identity must be real, not placeholder.
        let id = conn.peer_identity();
        assert_eq!(id.pid, std::process::id(), "peer pid must be this process");
        assert_ne!(id.binary_hash, [0u8; 32], "binary hash must be read from disk");
        assert!(
            !id.binary_path.as_os_str().is_empty(),
            "binary path must resolve"
        );

        // Message round-trip in both directions.
        client.write_all(b"ping").expect("client write");
        let got = conn.recv().expect("server recv");
        assert_eq!(&got, b"ping");

        conn.send(b"pong").expect("server send");
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).expect("client read");
        assert_eq!(&reply, b"pong");

        transport.shutdown().expect("shutdown");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn accept_before_listen_errors() {
        let transport = UnixTransport::new(temp_sock());
        // `Box<dyn Connection>` is not `Debug`, so assert on the error shape
        // directly rather than `{:?}`-formatting the whole Result.
        assert!(
            matches!(transport.accept(), Err(SentinelError::Transport(_))),
            "accept() before listen() must return a Transport error"
        );
    }

    #[test]
    fn pipe_transport_unsupported_on_unix() {
        let transport = PipeTransport::new(PipeTransport::DEFAULT_NAME.to_string());
        assert!(matches!(
            transport.listen(),
            Err(SentinelError::UnsupportedPlatform)
        ));
    }
}
