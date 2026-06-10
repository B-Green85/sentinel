# Agent 4 — eBPF Interception + Socket Authentication — Contract Declaration

Scope delivered: `sentinel-core/src/ebpf/` (new module) + `--oo` wiring in `main.rs`.

## CONTRACTS_PRODUCED
- `EbpfInterceptor` struct + `InterceptorMode` enum (`Enforce` / `Observe`)
  - `new(mode, allowlist, audit_tx) -> Result<Self, SentinelError>`
  - `load() / unload() -> Result<(), SentinelError>`
  - `intercept(syscall, args, pid) -> InterceptionDecision`
  - `make_decision()` / `binary_hash_changed()` (decision core)
- `SocketAuth` struct
  - `authenticate(peer_pid) -> Result<ProcessIdentity, SentinelError>` (silent-drop on Err)
  - `authenticate_identity(identity)` (pure, cross-platform check)
  - `peer_pid(&UnixStream)` helper (SO_PEERCRED, `cfg(unix)`)
- `Allowlist` + `AllowlistEntry` (`load` / `contains` / `contains_parent` / `from_entries` / `empty`)
- `programs::Backend` (+ `BackendKind`, `SYSCALL_PROBES` table)
- ebpf module public interface (re-exported from `sentinel_core::ebpf`)

## CONTRACTS_CONSUMED — STATUS: NOT YET SATISFIED BY UPSTREAM AGENTS
The prompt declared these as consumed from Agent 1 / Agent 3. As of this build,
NONE of them existed anywhere in the workspace:
- sentinel-types: `ProcessIdentity`, `InterceptionEvent`, `InterceptionDecision`,
  `DenyReason`, `SyscallId`, `SentinelError` — **absent**. `sentinel-core` does
  not even depend on `sentinel-types`. The `SentinelError` in `sentinel-types`
  is a `{code, message}` struct, incompatible with the
  `SentinelError::UnsupportedPlatform` enum shape the interface requires.
- sentinel-core: `SentinelConfig` — actual type is `config::Config`; audit path
  is `AuditTrail` (async `record`), not a `Sender<InterceptionEvent>`.
- Agent 3: `SentinelTransport` — **absent**.

### Resolution taken
To keep Agent 4 self-contained, building, and tested with ZERO new
dependencies, the consumed types are defined LOCALLY in `ebpf/mod.rs`, each
marked `// CONTRACT (sentinel-types / Agent 1)`. Field shapes follow the prompt.

**Reconciliation TODO (when Agents 1 & 3 land):**
1. Hoist `ProcessIdentity`, `InterceptionEvent`, `InterceptionDecision`,
   `DenyReason`, `SyscallId`, `SentinelError` into `sentinel-types`; delete the
   local definitions and re-export, OR keep local and add a `path` dep.
2. Reconcile `SentinelError`: the interface needs an enum with
   `UnsupportedPlatform`; the existing struct must either become that enum or
   gain a conversion. (This repo already has a "reconcile sentinel-types" pattern.)
3. Wire live socket-auth enforcement into Agent 3's `SentinelTransport` accept
   loop via `SocketAuth::authenticate(peer_pid(&stream)?)`. `SocketAuth` is
   constructed in `main.rs` today but the existing `serve()` accept loop is left
   untouched (Agent 3's seam) so the working daemon/clients are not broken.

## MODIFIES_EXISTING
- `sentinel-core/src/lib.rs`: `pub mod ebpf;`
- `sentinel-core/src/main.rs`: `--oo` / `--observer-only` + `--allowlist` flags,
  allowlist load, audit-event drain thread, interceptor construct/load,
  `SocketAuth` construct, `sentinel_start` audit event.

## NEW_DEPENDENCIES
None. Uses std + tokio (existing) + the crate's own `sha256` module. tokio's
`UnixStream::peer_cred()` provides SO_PEERCRED without `nix`/`libc`.

## Backend reality
Neither `aya` nor `libbpf-rs` is present; `ptrace` would itself need `nix`/`libc`
(also absent). So the backend is the userspace-simulation path: kernel attach is
a documented no-op and `intercept()` is the live seam a real eBPF ring-buffer
poller (or ptrace loop) would drive. Decision + auth logic are fully real.

## Verification (run on macOS host; Linux paths type-checked via cross `cargo check`)
1. `cargo build -p sentinel-core` — PASS (macOS).
2. `cargo check -p sentinel-core --target x86_64-unknown-linux-gnu` — PASS
   (Linux-gated paths type-check; a full `cargo build` on real Linux will link).
3. `cargo test -p sentinel-core` — 56 passed, 0 failed (19 ebpf tests).
4. `EbpfInterceptor::new()` constructs without panic — covered by tests.
5. `SocketAuth` authenticates an allowlisted process; un-allowlisted → silent
   drop (Err, no rejection payload) — covered by tests.
6. Daemon smoke test: `--oo` → `mode=observer_only, enforcement=false`;
   default → `mode=enforcer, enforcement=true`; missing allowlist → fail-closed
   empty allowlist, daemon still boots; macOS load → `UnsupportedPlatform`
   (non-fatal), `ebpf_loaded=false`.

Clippy: ebpf module is warning-clean (3 pre-existing warnings remain in
sha256.rs / audit.rs / config.rs — out of scope, untouched).
