"""Ed25519 cryptographic signing — REQ-RCA-013.

Provides authenticity for evidence packages and Merkle roots beyond the
SHA-256 integrity hashes already produced. Uses PyNaCl (libsodium) for
deterministic Ed25519 signatures.

Key lifecycle
=============
On first run a new keypair is generated under ``Config.SIGNING_KEY_DIR``
(default ``/state/signing-keys``):

  ed25519_private.key       raw 32 bytes, mode 0600 (chmod after write)
  ed25519_public.key.hex    public key as hex (64 chars)
  ed25519_public.key.b64    public key as base64 (44 chars w/ padding)
  current_key_id            16-char hex prefix of the public key

Rotation: if an operator copies the existing key files into
``signing-keys/archive/<key_id>/`` and removes the top-level files, a new
keypair is minted on next service start. Verification falls back to the
archived public key when its ``key_id`` is presented.

Canonical JSON
==============
All payloads must be serialised with ``json.dumps(payload, sort_keys=True,
separators=(',', ':'), default=str)`` so signatures are deterministic and
verifiers can reproduce the exact byte sequence that was signed.
"""

from __future__ import annotations

import base64
import re
import json
import logging
import os
from pathlib import Path
from typing import Any

from nacl import exceptions as nacl_exc
from nacl.signing import SigningKey, VerifyKey

logger = logging.getLogger(__name__)

PRIVATE_KEY_FILE = "ed25519_private.key"
PUBLIC_KEY_HEX_FILE = "ed25519_public.key.hex"

# A key id is an opaque identifier, never a path fragment.
_SAFE_KEY_ID = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")
PUBLIC_KEY_B64_FILE = "ed25519_public.key.b64"
CURRENT_KEY_ID_FILE = "current_key_id"
KEY_ID_LENGTH = 16


# ---------------------------------------------------------------------------
# canonicalisation helper (single source of truth)
# ---------------------------------------------------------------------------

def canonical_json(payload: dict[str, Any]) -> bytes:
    """Return canonical JSON bytes suitable for signing/verifying.

    ``sort_keys=True`` and the compact separator pair guarantee byte-for-byte
    determinism across producers and verifiers, including those written in
    other languages.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# key management
# ---------------------------------------------------------------------------

def _key_id_for(public_key_hex: str) -> str:
    return public_key_hex[:KEY_ID_LENGTH]


def _write_keypair(key_dir: Path, signing_key: SigningKey) -> str:
    """Persist private + public keys, return the new key_id.

    Private key is written first then chmod'd to 0600 atomically as possible.
    Public key files are written 0644 so verifiers can read them freely.
    """
    key_dir.mkdir(parents=True, exist_ok=True)

    verify_key = signing_key.verify_key
    pub_hex = verify_key.encode().hex()
    pub_b64 = base64.b64encode(verify_key.encode()).decode("ascii")
    key_id = _key_id_for(pub_hex)

    private_path = key_dir / PRIVATE_KEY_FILE
    public_hex_path = key_dir / PUBLIC_KEY_HEX_FILE
    public_b64_path = key_dir / PUBLIC_KEY_B64_FILE
    current_key_id_path = key_dir / CURRENT_KEY_ID_FILE

    # Write private key with restrictive perms via O_CREAT|O_WRONLY|O_EXCL
    # then chmod. We open with mode 0o600 in case the system honours it.
    fd = os.open(str(private_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, signing_key.encode())  # raw 32-byte seed
    finally:
        os.close(fd)
    try:
        os.chmod(private_path, 0o600)
    except OSError as exc:
        logger.warning("could not chmod private key 0600: %s", exc)

    public_hex_path.write_text(pub_hex)
    public_b64_path.write_text(pub_b64)
    current_key_id_path.write_text(key_id)

    return key_id


def _load_existing(key_dir: Path) -> SigningKey | None:
    """Load existing private key if present, otherwise None."""
    private_path = key_dir / PRIVATE_KEY_FILE
    if not private_path.is_file():
        return None
    raw = private_path.read_bytes()
    if len(raw) != 32:
        raise RuntimeError(
            f"signing key at {private_path} is {len(raw)} bytes; expected 32"
        )
    return SigningKey(raw)


def load_or_generate_key(key_dir: Path) -> SigningKey:
    """Load the persistent Ed25519 signing key or generate one on first run.

    Returns the in-memory ``SigningKey``. The associated public key files and
    ``current_key_id`` marker are kept in sync. The private key is **never**
    logged; only the key_id and public key are emitted to logs.
    """
    key_dir.mkdir(parents=True, exist_ok=True)

    existing = _load_existing(key_dir)
    if existing is not None:
        # Self-heal public key files if missing or stale
        verify_key = existing.verify_key
        pub_hex = verify_key.encode().hex()
        pub_b64 = base64.b64encode(verify_key.encode()).decode("ascii")
        key_id = _key_id_for(pub_hex)

        public_hex_path = key_dir / PUBLIC_KEY_HEX_FILE
        if not public_hex_path.is_file() or public_hex_path.read_text().strip() != pub_hex:
            public_hex_path.write_text(pub_hex)
        public_b64_path = key_dir / PUBLIC_KEY_B64_FILE
        if not public_b64_path.is_file() or public_b64_path.read_text().strip() != pub_b64:
            public_b64_path.write_text(pub_b64)
        current_key_id_path = key_dir / CURRENT_KEY_ID_FILE
        if not current_key_id_path.is_file() or current_key_id_path.read_text().strip() != key_id:
            current_key_id_path.write_text(key_id)
        return existing

    # First run — generate new keypair
    signing_key = SigningKey.generate()
    key_id = _write_keypair(key_dir, signing_key)
    logger.warning(
        "[signing] generated new Ed25519 keypair: key_id=%s public_key=%s",
        key_id,
        signing_key.verify_key.encode().hex(),
    )
    return signing_key


# ---------------------------------------------------------------------------
# sign / verify primitives
# ---------------------------------------------------------------------------

def sign_bytes(key: SigningKey, payload: bytes) -> dict[str, str]:
    """Sign ``payload`` (already canonical bytes) and return a result dict.

    Returns
    -------
    dict with keys::
        signature   hex-encoded 64-byte Ed25519 signature
        public_key  hex-encoded 32-byte Ed25519 public key
        key_id      16-char prefix of the public key (stable identifier)
        algo        "ed25519"
    """
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes; canonicalise first")
    signed = key.sign(bytes(payload))
    pub_hex = key.verify_key.encode().hex()
    return {
        "signature": signed.signature.hex(),
        "public_key": pub_hex,
        "key_id": _key_id_for(pub_hex),
        "algo": "ed25519",
    }


def verify_signature(public_key_hex: str, payload: bytes, signature_hex: str) -> bool:
    """Return True iff ``signature_hex`` is a valid Ed25519 signature.

    Any malformed input (wrong length, non-hex characters) yields False;
    only a cryptographically valid signature returns True.
    """
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key_hex))
        signature = bytes.fromhex(signature_hex)
        verify_key.verify(bytes(payload), signature)
        return True
    except (nacl_exc.BadSignatureError, ValueError):
        return False


# ---------------------------------------------------------------------------
# key resolution for verify endpoint
# ---------------------------------------------------------------------------

def resolve_public_key(key_dir: Path, key_id: str) -> str | None:
    """Return the hex-encoded public key for ``key_id`` or None.

    Looks first at the current key, then falls back to
    ``<key_dir>/archive/<key_id>/ed25519_public.key.hex``.
    """
    if not key_id:
        return None

    current_hex_path = key_dir / PUBLIC_KEY_HEX_FILE
    if current_hex_path.is_file():
        current_hex = current_hex_path.read_text().strip()
        if _key_id_for(current_hex) == key_id:
            return current_hex

    # key_id reaches this function from request parameters, so it must be a
    # single plain path segment: "../.." would otherwise escape the archive
    # directory and read an arbitrary PUBLIC_KEY_HEX_FILE from disk.
    if not _SAFE_KEY_ID.match(key_id or ""):
        return None

    archive_path = key_dir / "archive" / key_id / PUBLIC_KEY_HEX_FILE
    try:
        archive_path.resolve().relative_to((key_dir / "archive").resolve())
    except (ValueError, OSError):
        return None
    if archive_path.is_file():
        return archive_path.read_text().strip()

    return None


def public_key_metadata(key_dir: Path) -> dict[str, str]:
    """Return public-key metadata for the current key (no private material)."""
    pub_hex_path = key_dir / PUBLIC_KEY_HEX_FILE
    pub_b64_path = key_dir / PUBLIC_KEY_B64_FILE
    if not pub_hex_path.is_file() or not pub_b64_path.is_file():
        raise RuntimeError(
            f"signing key not initialised at {key_dir}; call load_or_generate_key() first"
        )
    pub_hex = pub_hex_path.read_text().strip()
    pub_b64 = pub_b64_path.read_text().strip()
    return {
        "public_key_hex": pub_hex,
        "public_key_b64": pub_b64,
        "key_id": _key_id_for(pub_hex),
        "algo": "ed25519",
    }


# ---------------------------------------------------------------------------
# convenience: sign a JSON-serialisable payload in one call
# ---------------------------------------------------------------------------

def sign_payload(key: SigningKey, payload: dict[str, Any]) -> dict[str, str]:
    """Sign canonical JSON of ``payload`` and return the signature dict."""
    return sign_bytes(key, canonical_json(payload))


# ---------------------------------------------------------------------------
# module-level singleton for app code
# ---------------------------------------------------------------------------

_cached_key: SigningKey | None = None
_cached_dir: Path | None = None


def get_signing_key() -> SigningKey:
    """Return the lazily-loaded module-level signing key.

    The key dir is read from ``Config.SIGNING_KEY_DIR`` (env-overridable).
    """
    global _cached_key, _cached_dir
    from .config import Config  # local import — avoid import cycle

    if _cached_key is None or _cached_dir != Config.SIGNING_KEY_DIR:
        _cached_key = load_or_generate_key(Config.SIGNING_KEY_DIR)
        _cached_dir = Config.SIGNING_KEY_DIR
    return _cached_key


def reset_cache() -> None:
    """Clear the cached signing key (used by tests)."""
    global _cached_key, _cached_dir
    _cached_key = None
    _cached_dir = None
