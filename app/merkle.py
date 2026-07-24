"""Merkle root publisher — REQ-RCA-006.

Hourly:
  1. Reads audit_events from each configured audit bus SQLite (read-only)
  2. Computes leaf hashes (sha256 of canonical event JSON)
  3. Builds Merkle tree, derives root
  4. Writes locally to append-only sequence file (write-once on disk)
  5. POSTs to external write-once endpoint if configured
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from .config import Config
from .db import connect as our_connect, transaction
from .signing import canonical_json, get_signing_key, sign_bytes


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _read_audit_events(period_start: str, period_end: str) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    sources: list[str] = []
    for db_path in Config.AUDIT_BUS_DBS:
        if not db_path.exists():
            continue
        try:
            try:
                ro = sqlite3.connect(f"file:{db_path}?immutable=1", uri=True)
            except sqlite3.OperationalError:
                ro = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            ro.row_factory = sqlite3.Row
            with closing(ro) as conn:
                tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                table = "audit_events" if "audit_events" in tables else "forensic_events" if "forensic_events" in tables else None
                if not table:
                    continue
                # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                # `table` is chosen from the fixed set {audit_events, forensic_events}
                # above; the time window is passed as bind parameters. No user input.
                cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}  # noqa: S608
                ts_col = "timestamp" if "timestamp" in cols else "created_at"
                # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query,configs.sql-string-concatenation-python
                # `table` and `ts_col` are whitelisted identifiers (not bindable in
                # SQLite); the actual period values are passed as ? bind parameters.
                rows = conn.execute(
                    f"SELECT * FROM {table} WHERE {ts_col} >= ? AND {ts_col} < ? ORDER BY {ts_col} ASC",  # noqa: S608
                    (period_start, period_end),
                ).fetchall()
                for r in rows:
                    d = dict(r)
                    d["_source_db"] = str(db_path)
                    events.append(d)
                if rows:
                    sources.append(str(db_path))
        except sqlite3.OperationalError:
            continue
    return events, sources


def _merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return _sha256(b"")
    nodes = [bytes.fromhex(h) for h in leaves]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [hashlib.sha256(nodes[i] + nodes[i + 1]).digest() for i in range(0, len(nodes), 2)]
    return nodes[0].hex()


def _write_immutable_root_file(seq: int, payload: dict[str, Any]) -> Path:
    """Write to append-only file. Creates the file with read-only permissions on next run."""
    Config.MERKLE_ROOTS_DIR.mkdir(parents=True, exist_ok=True)
    fname = Config.MERKLE_ROOTS_DIR / f"merkle-{seq:08d}.json"
    if fname.exists():
        # Already exists — never overwrite (write-once semantic)
        return fname
    fname.write_text(json.dumps(payload, indent=2, default=str))
    try:
        fname.chmod(0o444)
    except OSError:
        pass
    return fname


async def publish_external(payload: dict[str, Any]) -> tuple[bool, str]:
    if not Config.MERKLE_PUBLISH_URL:
        return False, "no external endpoint configured"
    headers = {"Content-Type": "application/json"}
    if Config.MERKLE_PUBLISH_TOKEN:
        headers["Authorization"] = f"Bearer {Config.MERKLE_PUBLISH_TOKEN}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(Config.MERKLE_PUBLISH_URL, json=payload, headers=headers)
            return 200 <= resp.status_code < 300, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except httpx.RequestError as exc:
        return False, f"network: {exc}"


def _last_root_hash() -> str | None:
    with closing(our_connect()) as conn:
        row = conn.execute(
            "SELECT root_hash FROM merkle_roots ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["root_hash"] if row else None


async def publish_hourly_root() -> dict[str, Any]:
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=1)
    events, sources = _read_audit_events(start.isoformat(), end.isoformat())

    leaf_hashes = [_sha256(_canonical(e)) for e in events]
    root = _merkle_root(leaf_hashes)
    parent = _last_root_hash()

    payload_for_storage: dict[str, Any] = {
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "event_count": len(events),
        "root_hash": root,
        "parent_root_hash": parent,
        "leaf_hashes": leaf_hashes,
        "sources": sources,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # REQ-RCA-013 — Ed25519 signature over the canonical JSON of the
    # immutable storage payload (excluding the signature itself and the
    # auto-generated seq, which is added afterwards).
    signing_key = get_signing_key()
    signature = sign_bytes(signing_key, canonical_json(payload_for_storage))

    with transaction() as conn:
        cur = conn.execute(
            """
            INSERT INTO merkle_roots
                (period_start, period_end, event_count, leaf_hashes_json,
                 root_hash, parent_root_hash, sources, created_at,
                 signature, signing_key_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload_for_storage["period_start"],
                payload_for_storage["period_end"],
                payload_for_storage["event_count"],
                json.dumps(leaf_hashes),
                root,
                parent,
                json.dumps(sources),
                payload_for_storage["created_at"],
                signature["signature"],
                signature["key_id"],
            ),
        )
        seq = cur.lastrowid
    payload_for_storage["seq"] = seq
    payload_for_storage["signature"] = signature

    # Write to immutable on-disk file
    artifact = _write_immutable_root_file(seq, payload_for_storage)

    # Try external publish
    ok, reason = await publish_external(payload_for_storage)
    if ok:
        with transaction() as conn:
            conn.execute(
                "UPDATE merkle_roots SET published_to_external = 1, external_response = ? WHERE seq = ?",
                (reason, seq),
            )

    return {
        "seq": seq,
        "root_hash": root,
        "event_count": len(events),
        "period_start": payload_for_storage["period_start"],
        "period_end": payload_for_storage["period_end"],
        "artifact": str(artifact),
        "external_published": ok,
        "external_response": reason,
        "signature": signature,
    }


def list_roots(limit: int = 50) -> list[dict[str, Any]]:
    with closing(our_connect()) as conn:
        rows = conn.execute(
            """
            SELECT seq, period_start, period_end, event_count, root_hash, parent_root_hash,
                   published_to_external, created_at, signature, signing_key_id
            FROM merkle_roots ORDER BY seq DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def verify_chain() -> dict[str, Any]:
    """Walk the chain backwards verifying each parent_root_hash matches the previous root."""
    with closing(our_connect()) as conn:
        rows = conn.execute(
            "SELECT seq, root_hash, parent_root_hash FROM merkle_roots ORDER BY seq ASC"
        ).fetchall()
    breaks: list[dict[str, Any]] = []
    for i, row in enumerate(rows):
        if i == 0:
            if row["parent_root_hash"] is not None:
                breaks.append({"seq": row["seq"], "issue": "first root has parent_root_hash"})
            continue
        prev = rows[i - 1]
        if row["parent_root_hash"] != prev["root_hash"]:
            breaks.append({
                "seq": row["seq"],
                "expected_parent": prev["root_hash"],
                "actual_parent": row["parent_root_hash"],
            })
    return {"total_roots": len(rows), "breaks": breaks, "intact": not breaks}
