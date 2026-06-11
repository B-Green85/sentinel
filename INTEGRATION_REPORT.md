# Sentinel v3 — Agent 8 Integration & Test Report

**Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.**

Agent 8 is the last agent: it exposes the v3 types to `sentinel-py` and writes
the complete test suite for every new v3 component. This report logs what was
found during integration — per the prompt's instruction to *log what you find*.

---

## 1. State of agents 1–7 on arrival

The session's other agents landed unevenly. Some merged their work directly into
`~/Projects/sentinel`; others only left files in their staging directories; two
(plus the kernel agent, a different repo) produced no Rust beyond a contract doc.

| Agent | Scope | Where the code was | Action taken by Agent 8 |
|------|-------|--------------------|-------------------------|
| 1 — sentinel-types | new v3 types | **merged in repo** (`ProcessIdentity`, `SessionCredential`, `ChainedAuditEntry`, `AuditEvent`, `AgentId`, `SyscallId`, `DenyReason`, `InterceptionDecision`, …) | consumed as-is |
| 2 — sentinel-keygen | new crate | **staging only** (`agent_002/`) | copied into repo, added to workspace, tested |
| 3 — transport | `sentinel-core` transport | **staging only** (`agent_003/`) | integrated `error.rs`, `transport.rs`, `transport/factory.rs`, merged `config.rs`, wired modules into `lib.rs`, tested |
| 4 — eBPF / socket auth | `sentinel-core/src/ebpf/` | **merged in repo** (`EbpfInterceptor`, `SocketAuth`, `Allowlist`, local `ProcessIdentity`/`InterceptionDecision`/`DenyReason`) | consumed as-is, tested |
| 5 — controls / legionnaire | `sentinel-controls` | **merged in repo** (`Observer`, `Enforcer`, `SentinelCapability`, `LegionnairePolicy`, 5 profiles, `TelegramNotifier`) | consumed as-is, tested |
| 6 — audit chain | `sentinel-core` audit | **staging only** (`agent_006/`) | replaced `audit.rs` (superset, API-compatible), added `sentinel-verify` bin + `chrono`/`sentinel-types` deps, tested |
| 7 — GolemLinux kernel | `~/Projects/GolemLinux` | different repo, not present here | out of scope for this repo |

> Note: the agents' staging directories (`agent_00N/`) each contain a `.done`
> marker, but 001/004/005/007 contain **no source files** — their work, where it
> exists, was merged into the repo directly. 002/003/006 delivered only into
> staging and had **not** been merged; Agent 8 performed that integration.

---

## 2. Integration performed by Agent 8

Additive and surgical — no already-merged agent work was overwritten.

- **Workspace** (`Cargo.toml`): added `sentinel-keygen` member.
- **sentinel-keygen/**: copied crate from `agent_002/` (self-contained; uses the
  system `openssl` for EC P-256 keypairs, `sha2`/`hex`/`toml`/`chrono`).
- **sentinel-core**:
  - `src/audit.rs` ← Agent 6 version. It is a strict superset: the v2
    `AuditEntry` shape and the `AuditTrail` facade (`new`/`open`/`record`/
    `verify`/`entries`/`into_shared`) are preserved exactly — `websocket.rs`
    and `lib.rs` consume them unchanged — and it adds the on-disk hash-linked
    `AuditChain` + `verify_chain` + `BreakKind`/`VerifyOutcome`.
  - `src/bin/sentinel-verify.rs` ← Agent 6; registered as a `[[bin]]`.
  - `src/error.rs`, `src/transport.rs`, `src/transport/factory.rs` ← Agent 3.
  - `src/config.rs` ← Agent 3 superset (adds the `[transport]` block; websocket/
    thresholds/controls blocks byte-identical to the prior version).
  - `src/lib.rs`: added `pub mod error;` and `pub mod transport;`.
  - `Cargo.toml`: added `chrono` and `sentinel-types` dependencies.
  - `examples/gen_audit_fixture.rs`: small utility that writes a real chain — used
    to produce the sentinel-py pytest fixtures (no hand-rolled crypto in tests).
- **sentinel-py**:
  - `src/lib.rs`: added the v3 operator-only bindings (see §4). Existing client
    bindings (`register`/`heartbeat`/`emit_output`/`status`) left **unchanged**.
  - `Cargo.toml`: added `serde` (derive) and an empty `[workspace]` table so the
    standalone extension crate `cargo check`s/builds outside the main workspace.
  - `sentinel/__init__.py`: created the missing Python package directory that
    `pyproject.toml`'s `module-name = "sentinel._sentinel_core"` requires (it did
    not exist, so `maturin develop` could not have succeeded before).

---

## 3. Test suite — results

All v3 spec test names are present (contractual). Verification commands:

```
cargo test -p sentinel-types     →  5 passed
cargo test -p sentinel-keygen    →  8 unit + 5 integration passed
cargo test -p sentinel-controls  → 61 unit + 14 integration passed, 3 ignored
cargo test -p sentinel-core      → 67 unit + 19 integration passed, 3 ignored
pytest sentinel-py/tests/        → 17 passed   (after `maturin develop`)
```

Test files written by Agent 8:

| File | Named tests | Notes |
|------|-------------|-------|
| `sentinel-keygen/tests/sentinel_keygen.rs` | 5 | drives the real binary end-to-end |
| `sentinel-core/tests/sentinel_audit.rs` | 6 | real temp NDJSON logs + real `sentinel-verify` (no mocks) |
| `sentinel-core/tests/sentinel_auth.rs` | 4 | 1 ignored (see §5) |
| `sentinel-core/tests/sentinel_interception.rs` | 4 | 2 ignored (eBPF benchmark; allowlisted-allow needs `/proc`) |
| `sentinel-core/tests/sentinel_transport.rs` | 3 | real Unix socket round-trip + factory |
| `sentinel-controls/tests/sentinel_observer.rs` | 5 | 1 ignored (see §5) |
| `sentinel-controls/tests/sentinel_legionnaire.rs` | 9 | 2 ignored (see §5) |
| `sentinel-py/tests/test_v3_bindings.py` | 17 | real audit-chain fixtures |

---

## 4. sentinel-py v3 bindings

Added (operator-only — never agent-accessible):

- **Classes**: `ProcessIdentity`, `SessionCredentialSummary`, `AuditEntry`.
  Hashes are surfaced as `sha256:<hex>` strings and timestamps as ISO-8601,
  matching the v3 operator contract (the underlying `sentinel-types` structs use
  raw `[u8; 32]` / `DateTime<Utc>` and have no `#[pyclass]`).
- **`verify_audit_chain(path)`** → `{"intact", "entries_verified",
  "break_at_sequence"}`. Backed by the real `sentinel_core::audit::verify_chain`
  (Agent 6) — not a re-implementation.
- **`read_audit_chain(path)`** → list of `AuditEntry`, each with a `chain_valid`
  flag pre-computed from the real verifier's break point.
- **`get_profile()`** / **`is_observer_mode()`** — operator-side accessors backed
  by `SENTINEL_PROFILE` / `SENTINEL_OBSERVER_MODE` env vars (see §5).
- **`get_process_identity(agent_id)`** — raises (see §5).

---

## 5. Findings, divergences, and blocked tests

Logged honestly rather than papered over. Every blocked test is **present** and
marked `#[ignore]`/`importorskip` with a reason.

1. **`sentinel-signals` does not compile (pre-existing, NOT introduced here).**
   `sentinel-signals/src/detectors.rs` was already a *modified, uncommitted*
   working-tree change before Agent 8 started, and references `SignalThresholds`
   fields / `SignalType` variants that do not exist in `sentinel-types`
   (`hedge_accumulation`, `output_quality_window`, `SignalType::HedgeAccumulation`,
   `SignalType::Cascade`, …). This breaks `cargo build --workspace` but **none of
   Agent 8's verification targets** (`sentinel-types`/`core`/`controls`/`keygen`)
   depend on `sentinel-signals`, so all five verification commands pass. Left
   untouched — it is outside Agent 8's scope and not part of the v3 type work.

2. **`test_spoofed_parent_rejected` (auth) — `#[ignore]`.** Agent 4's decision
   core implements no parent-hash verification: the local `ebpf::DenyReason` has
   only `NotAllowlisted`/`TamperedBinary` (only `sentinel_types::DenyReason` has
   `SpoofedParent`), and `Allowlist::contains_parent` exists but is never called
   by `make_decision`/`authenticate_identity`. Blocked pending that wiring.

3. **`test_operator_allow_releases_syscall` / `test_operator_deny_blocks_syscall`
   (legionnaire) — `#[ignore]`.** Agent 5's `TelegramNotifier` has **no inbound
   operator-reply channel** ("There is no inbound operator-reply channel yet" —
   `notify.rs`). `notify_and_hold` can therefore only ever apply the timeout
   default; an operator Allow/Deny cannot be injected. Blocked pending the reply
   channel. The timeout-default path *is* tested (`test_hold_timeout_applies_default`,
   `test_no_hold_when_timeout_zero`).

4. **`test_observer_build_contains_no_sigterm` (observer) — `#[ignore]`.** The spec
   inspects an "observer-only build" for the absence of SIGTERM/`kill` symbols.
   Agent 5 ships `Observer` **and** `Enforcer` (plus `process::sigterm_agent` /
   `hard_terminate`, which call `libc::kill`) in one crate with no compile-time
   `observer`-only feature gate, so no observer-only artifact exists to inspect.
   The source-level guarantee (the Observer has no enforcement path) is instead
   asserted behaviourally by `test_oo_all_enforcement_methods_noop`.

5. **`test_interception_latency_under_500ns` — `#[ignore]`** (per spec: needs a
   real eBPF environment / CAP_BPF). The current build is a userspace simulation.

6. **`test_allowed_syscall_passes` (interception)** runs on Linux, `#[ignore]`'d
   elsewhere via `cfg_attr` — it resolves the live pid's binary from
   `/proc/<pid>/exe`, which is Linux-only.

7. **Naming/shape divergences (adapted, documented in-test):**
   - `SentinelError::UnknownProfile(_)` (spec) vs the real
     `sentinel_types::SentinelError { code: "UnknownProfile", message }` struct —
     `test_unknown_profile_rejected_at_startup` asserts on `.code`.
   - Genesis audit record: the spec expects a literal `enforcement == false`
     field; Agent 5's `genesis_audit_json` encodes mode (`"observer_only"`)
     instead. `test_oo_flag_audit_log_records_mode` asserts the mode string.
   - Two `ProcessIdentity` types coexist by design: `sentinel_types::ProcessIdentity`
     (full: pid/hashes/parent/uid — used by transport, legionnaire, the py binding)
     and the leaner `sentinel_core::ebpf::ProcessIdentity` (pid/path/hash — used by
     the interceptor/auth). Tests use the correct one per component.

8. **`get_process_identity` / `get_profile` / `is_observer_mode` bindings.** The
   daemon's socket protocol (register/heartbeat/status/deregister) exposes no
   identity, profile, or mode query, so these cannot be backed by a live daemon
   call. `get_process_identity` therefore raises a clear `SentinelError`; profile
   and observer-mode are read from the env vars the daemon is launched with.
   Wiring real daemon queries is a follow-up once the protocol grows those verbs.

9. **Pre-existing warning (not addressed):** `sentinel-core` emits an
   `unexpected cfg` warning for `feature = "kernel-transport"` (Agent 3's
   feature-gated `KernelTransport` stub) because the feature is not declared in
   `Cargo.toml`. Harmless; left to the transport owner.

---

## 6. Untouched (out of scope)

`README.md` (unresolved merge conflict), `Philosophy_and_design_rationale.md`,
`sentinel-signals/src/detectors.rs`, and the untracked `gift for claude 2.zip`
were all dirty/conflicted on arrival and are **not** Agent 8's scope — left as-is.
