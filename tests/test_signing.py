"""Tests for app.signing — REQ-RCA-013 (Ed25519 signatures).

Covers:
- generate -> sign -> verify round-trip
- payload tamper detection
- signature tamper detection
- key persistence + key_id stability across loads
- end-to-end Merkle root signing round-trip
- end-to-end report signing round-trip
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path

import pytest

from app import signing
from app.signing import (
    canonical_json,
    load_or_generate_key,
    public_key_metadata,
    resolve_public_key,
    sign_bytes,
    sign_payload,
    verify_signature,
)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_key_dir(tmp_path, monkeypatch):
    """Provide a per-test signing-key directory and clear the module cache."""
    key_dir = tmp_path / "signing-keys"
    monkeypatch.setenv("SIGNING_KEY_DIR", str(key_dir))
    # Reload Config so it picks up the new env var
    from app import config as cfg_mod
    importlib.reload(cfg_mod)
    # Reset cached signing key in case of reuse across tests
    signing.reset_cache()
    yield key_dir
    signing.reset_cache()


# ---------------------------------------------------------------------------
# core round-trip
# ---------------------------------------------------------------------------

def test_generate_sign_verify_success(isolated_key_dir):
    key = load_or_generate_key(isolated_key_dir)
    payload = {"hello": "world", "answer": 42}
    canon = canonical_json(payload)
    sig = sign_bytes(key, canon)

    assert sig["algo"] == "ed25519"
    assert len(sig["signature"]) == 128  # 64 bytes hex
    assert len(sig["public_key"]) == 64  # 32 bytes hex
    assert sig["key_id"] == sig["public_key"][:16]

    assert verify_signature(sig["public_key"], canon, sig["signature"]) is True


def test_canonical_json_is_deterministic():
    a = {"b": 1, "a": 2, "nested": {"y": 1, "x": 2}}
    b = {"a": 2, "nested": {"x": 2, "y": 1}, "b": 1}
    assert canonical_json(a) == canonical_json(b)
    # And it has the compact form
    assert canonical_json(a) == b'{"a":2,"b":1,"nested":{"x":2,"y":1}}'


# ---------------------------------------------------------------------------
# tamper detection
# ---------------------------------------------------------------------------

def test_tamper_payload_fails_verify(isolated_key_dir):
    key = load_or_generate_key(isolated_key_dir)
    canon = canonical_json({"v": "ok"})
    sig = sign_bytes(key, canon)

    tampered = canonical_json({"v": "tampered"})
    assert verify_signature(sig["public_key"], tampered, sig["signature"]) is False


def test_tamper_signature_fails_verify(isolated_key_dir):
    key = load_or_generate_key(isolated_key_dir)
    canon = canonical_json({"v": "ok"})
    sig = sign_bytes(key, canon)

    # Flip the last hex char
    bad_hex_char = "a" if sig["signature"][-1] != "a" else "b"
    tampered_sig = sig["signature"][:-1] + bad_hex_char
    assert verify_signature(sig["public_key"], canon, tampered_sig) is False


def test_tamper_signature_with_garbage_returns_false(isolated_key_dir):
    key = load_or_generate_key(isolated_key_dir)
    canon = canonical_json({"v": "ok"})
    assert verify_signature(key.verify_key.encode().hex(), canon, "not-hex") is False
    assert verify_signature(key.verify_key.encode().hex(), canon, "00" * 64) is False


def test_wrong_public_key_fails(isolated_key_dir, tmp_path):
    key = load_or_generate_key(isolated_key_dir)
    canon = canonical_json({"v": "ok"})
    sig = sign_bytes(key, canon)

    # Generate a *different* keypair
    other_dir = tmp_path / "other-keys"
    signing.reset_cache()
    other_key = load_or_generate_key(other_dir)
    assert other_key.verify_key.encode().hex() != sig["public_key"]
    assert verify_signature(other_key.verify_key.encode().hex(), canon, sig["signature"]) is False


# ---------------------------------------------------------------------------
# persistence + key_id stability
# ---------------------------------------------------------------------------

def test_key_id_stable_across_loads(isolated_key_dir):
    key1 = load_or_generate_key(isolated_key_dir)
    sig1 = sign_bytes(key1, b"x")

    # Drop in-memory references and reload from disk
    signing.reset_cache()
    key2 = load_or_generate_key(isolated_key_dir)
    sig2 = sign_bytes(key2, b"x")

    assert sig1["public_key"] == sig2["public_key"]
    assert sig1["key_id"] == sig2["key_id"]
    # Ed25519 signatures are deterministic
    assert sig1["signature"] == sig2["signature"]


def test_private_key_file_mode(isolated_key_dir):
    load_or_generate_key(isolated_key_dir)
    private = isolated_key_dir / "ed25519_private.key"
    assert private.exists()
    mode = private.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_public_key_metadata(isolated_key_dir):
    load_or_generate_key(isolated_key_dir)
    meta = public_key_metadata(isolated_key_dir)
    assert meta["algo"] == "ed25519"
    assert len(meta["public_key_hex"]) == 64
    assert meta["key_id"] == meta["public_key_hex"][:16]
    # base64 of 32 raw bytes is 44 chars (with padding)
    assert len(meta["public_key_b64"]) == 44


def test_resolve_public_key_current(isolated_key_dir):
    key = load_or_generate_key(isolated_key_dir)
    pub_hex = key.verify_key.encode().hex()
    key_id = pub_hex[:16]
    assert resolve_public_key(isolated_key_dir, key_id) == pub_hex


def test_resolve_public_key_archive(isolated_key_dir, tmp_path):
    """Simulate key rotation: archive the current key, generate a new one,
    confirm verify endpoint can still resolve the archived one."""
    key1 = load_or_generate_key(isolated_key_dir)
    pub1 = key1.verify_key.encode().hex()
    kid1 = pub1[:16]

    # Move current key into archive/<key_id>/
    archive_dir = isolated_key_dir / "archive" / kid1
    archive_dir.mkdir(parents=True, exist_ok=True)
    for fname in (
        "ed25519_private.key",
        "ed25519_public.key.hex",
        "ed25519_public.key.b64",
        "current_key_id",
    ):
        src = isolated_key_dir / fname
        if src.exists():
            src.rename(archive_dir / fname)

    # Generate new key in the same dir
    signing.reset_cache()
    key2 = load_or_generate_key(isolated_key_dir)
    pub2 = key2.verify_key.encode().hex()
    kid2 = pub2[:16]
    assert kid1 != kid2

    # Both should resolve
    assert resolve_public_key(isolated_key_dir, kid1) == pub1
    assert resolve_public_key(isolated_key_dir, kid2) == pub2
    # Unknown key_id resolves to None
    assert resolve_public_key(isolated_key_dir, "0" * 16) is None


def test_resolve_unknown_key_id(isolated_key_dir):
    load_or_generate_key(isolated_key_dir)
    assert resolve_public_key(isolated_key_dir, "deadbeefdeadbeef") is None
    assert resolve_public_key(isolated_key_dir, "") is None


# ---------------------------------------------------------------------------
# end-to-end: Merkle root signing
# ---------------------------------------------------------------------------

def test_merkle_root_round_trip(isolated_key_dir):
    """Simulate the merkle.publish_hourly_root signing flow."""
    key = load_or_generate_key(isolated_key_dir)
    payload = {
        "period_start": "2026-05-01T00:00:00+00:00",
        "period_end": "2026-05-01T01:00:00+00:00",
        "event_count": 3,
        "root_hash": hashlib.sha256(b"abc").hexdigest(),
        "parent_root_hash": None,
        "leaf_hashes": [
            hashlib.sha256(str(i).encode()).hexdigest() for i in range(3)
        ],
        "sources": ["/governance/audit.db"],
        "created_at": "2026-05-01T01:00:30+00:00",
    }
    canon = canonical_json(payload)
    sig = sign_bytes(key, canon)
    # Verifier reproduces canonical bytes from the same payload
    canon2 = canonical_json(payload)
    assert canon == canon2
    assert verify_signature(sig["public_key"], canon2, sig["signature"]) is True

    # Sanity: changing the root_hash invalidates the signature
    tampered = dict(payload)
    tampered["root_hash"] = hashlib.sha256(b"different").hexdigest()
    assert verify_signature(
        sig["public_key"], canonical_json(tampered), sig["signature"]
    ) is False


# ---------------------------------------------------------------------------
# end-to-end: regulatory report signing
# ---------------------------------------------------------------------------

def test_report_round_trip(isolated_key_dir):
    """Simulate the reports._sign_artifact flow with a representative body."""
    key = load_or_generate_key(isolated_key_dir)
    body = {
        "report_id": "test-1",
        "type": "sox_attestation",
        "title": "SOX Section 404 — Management Attestation (AI Controls Scope)",
        "controls": ["ITGC-01", "ITGC-02"],
        "period": {"start": "2025-01-01T00:00:00+00:00",
                   "end": "2025-12-31T23:59:59+00:00"},
        "operator_id": "compliance-jobs-system",
        "generated_at": "2026-01-15T00:00:00+00:00",
        "evidence": {"audit_event_counts": [], "merkle_chain": {}, "retention_runs": []},
    }
    canon = canonical_json(body)
    digest = hashlib.sha256(canon).hexdigest()
    sig = sign_bytes(key, canon)

    # Verify both integrity + authenticity
    assert hashlib.sha256(canonical_json(body)).hexdigest() == digest
    assert verify_signature(sig["public_key"], canonical_json(body), sig["signature"]) is True

    # The on-disk artifact would embed both fields. Verifier must strip them
    # before reproducing canonical bytes.
    on_disk = dict(body)
    on_disk["artifact_sha256"] = digest
    on_disk["signature"] = sig

    stripped = {k: v for k, v in on_disk.items() if k not in {"artifact_sha256", "signature"}}
    assert verify_signature(sig["public_key"], canonical_json(stripped), sig["signature"]) is True


# ---------------------------------------------------------------------------
# convenience helpers
# ---------------------------------------------------------------------------

def test_sign_payload_helper(isolated_key_dir):
    key = load_or_generate_key(isolated_key_dir)
    payload = {"foo": "bar"}
    sig = sign_payload(key, payload)
    assert verify_signature(sig["public_key"], canonical_json(payload), sig["signature"]) is True


def test_sign_bytes_rejects_non_bytes(isolated_key_dir):
    key = load_or_generate_key(isolated_key_dir)
    with pytest.raises(TypeError):
        sign_bytes(key, "not-bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# get_signing_key cache behaviour
# ---------------------------------------------------------------------------

def test_get_signing_key_is_cached(isolated_key_dir):
    """Calling get_signing_key twice returns the same instance until reset."""
    k1 = signing.get_signing_key()
    k2 = signing.get_signing_key()
    assert k1 is k2
    signing.reset_cache()
    k3 = signing.get_signing_key()
    # Even after reset the on-disk key is loaded back in, so the public key
    # is identical.
    assert k1.verify_key.encode() == k3.verify_key.encode()
