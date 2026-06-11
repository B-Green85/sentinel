"""Sentinel v3 — Agent 8 pytest suite for the operator-only bindings.

Copyright © 2026 Brandon Green. Licensed under the Apache 2.0 License.

These exercise the compiled PyO3 extension (`sentinel._sentinel_core`). Building
it requires `maturin develop` with a PyO3-supported CPython (≤ 3.13, or set
PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1). When the extension is not built, the
whole module is skipped rather than failing — so `pytest sentinel-py/tests/`
is green both before and after the extension is built.

Audit-chain assertions run against real fixtures produced by sentinel-core's
production `AuditChain` (see examples/gen_audit_fixture.rs), not hand-rolled JSON.
"""

from __future__ import annotations

import pathlib

import pytest

# Skip the entire module cleanly if the compiled extension is not available.
sc = pytest.importorskip(
    "sentinel._sentinel_core",
    reason="compiled extension not built — run `maturin develop` (PyO3 ≤ CPython 3.13)",
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES / "clean_chain.ndjson")
TAMPERED = str(FIXTURES / "tampered_chain.ndjson")


# ── deployment profile / mode accessors ──────────────────────────────────────

def test_get_profile_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_PROFILE", raising=False)
    assert sc.get_profile() == "development"


def test_get_profile_from_env(monkeypatch):
    monkeypatch.setenv("SENTINEL_PROFILE", "enterprise")
    assert sc.get_profile() == "enterprise"


def test_is_observer_mode_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_OBSERVER_MODE", raising=False)
    assert sc.is_observer_mode() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "observer", "observer_only", "OBSERVER_ONLY"])
def test_is_observer_mode_truthy(monkeypatch, val):
    monkeypatch.setenv("SENTINEL_OBSERVER_MODE", val)
    assert sc.is_observer_mode() is True


def test_is_observer_mode_falsy(monkeypatch):
    monkeypatch.setenv("SENTINEL_OBSERVER_MODE", "0")
    assert sc.is_observer_mode() is False


# ── process identity ──────────────────────────────────────────────────────────

def test_get_process_identity_raises():
    # The daemon protocol does not expose identity queries in this build.
    with pytest.raises(RuntimeError):
        sc.get_process_identity("agent-1")


def test_process_identity_class():
    pid = sc.ProcessIdentity(
        pid=4242,
        binary_hash="sha256:" + "ab" * 32,
        binary_path="/usr/bin/python3",
        parent_pid=1,
        parent_hash="sha256:" + "00" * 32,
        uid=1000,
    )
    assert pid.pid == 4242
    assert pid.binary_hash.startswith("sha256:")
    assert pid.binary_path == "/usr/bin/python3"
    assert pid.parent_pid == 1
    assert pid.uid == 1000


def test_session_credential_summary_class():
    cred = sc.SessionCredentialSummary(
        agent_id="agent-7",
        issued_at="2026-06-09T00:00:00+00:00",
        credential_hash="sha256:" + "cd" * 32,
    )
    assert cred.agent_id == "agent-7"
    assert cred.issued_at.startswith("2026-")
    assert cred.credential_hash.startswith("sha256:")


# ── audit chain: verify ───────────────────────────────────────────────────────

def test_verify_audit_chain_clean():
    result = sc.verify_audit_chain(CLEAN)
    assert result["intact"] is True
    assert result["break_at_sequence"] is None
    # genesis + 5 written entries
    assert result["entries_verified"] == 6


def test_verify_audit_chain_tampered():
    result = sc.verify_audit_chain(TAMPERED)
    assert result["intact"] is False
    assert result["break_at_sequence"] == 3
    # genesis (0), 1, 2 verified before the break at sequence 3
    assert result["entries_verified"] == 3


# ── audit chain: read ─────────────────────────────────────────────────────────

def test_read_audit_chain_clean():
    entries = list(sc.read_audit_chain(CLEAN))
    assert len(entries) == 6
    # Genesis is sequence 0 with an all-zero prev_hash.
    genesis = entries[0]
    assert genesis.sequence == 0
    assert genesis.prev_hash == "sha256:" + "0" * 64
    assert all(e.chain_valid for e in entries), "a clean chain has every entry valid"
    # Entries expose the operator-facing display fields.
    assert all(e.entry_hash.startswith("sha256:") for e in entries)


def test_read_audit_chain_tampered():
    entries = list(sc.read_audit_chain(TAMPERED))
    by_seq = {e.sequence: e for e in entries}
    # Entries before the break are valid; from the break onward they are not.
    assert by_seq[0].chain_valid is True
    assert by_seq[2].chain_valid is True
    assert by_seq[3].chain_valid is False
    assert by_seq[5].chain_valid is False
