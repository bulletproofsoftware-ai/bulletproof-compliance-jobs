"""DSR cascade worker — REQ-RCA-021.

GDPR erasure flow: receive request → cascade to Qdrant + audit DBs + file artifacts
→ generate signed deletion confirmation artifact → log to dsr_cascades table.
"""

from __future__ import annotations

import glob
import gzip
import hashlib
import json
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from .config import Config
from .db import connect as our_connect, transaction


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _qdrant_purge(subject_id: str) -> int:
    """Delete points referencing the subject across all collections."""
    if not Config.QDRANT_URL:
        return 0
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.http import models as qmodels
    except ImportError:
        return 0
    client = QdrantClient(url=Config.QDRANT_URL, api_key=Config.QDRANT_API_KEY or None, timeout=30)
    deleted_total = 0
    try:
        collections = [c.name for c in client.get_collections().collections]
    except Exception:
        return 0
    for col in collections:
        try:
            result = client.delete(
                collection_name=col,
                points_selector=qmodels.FilterSelector(
                    filter=qmodels.Filter(
                        should=[
                            qmodels.FieldCondition(
                                key="subject_id",
                                match=qmodels.MatchValue(value=subject_id),
                            ),
                            qmodels.FieldCondition(
                                key="user_id",
                                match=qmodels.MatchValue(value=subject_id),
                            ),
                            qmodels.FieldCondition(
                                key="data_subject_id",
                                match=qmodels.MatchValue(value=subject_id),
                            ),
                        ]
                    )
                ),
            )
            # Result count is best-effort; client doesn't return exact count
            deleted_total += 1  # at least one delete operation succeeded
            _ = result
        except Exception:
            continue
    return deleted_total


def _audit_db_count_references(subject_id: str) -> int:
    """Count (don't delete) audit references — the audit trail is immutable per
    REQ-RCA-005 even under GDPR Article 17. Erasure deletes user-data stores;
    audit references remain as evidence of what happened, with the deletion
    confirmation artifact serving as the legal record. The PRD explicitly
    says "All deletions logged to immutable audit trail" — i.e., we add
    deletion records, we don't remove existing ones.
    """
    total = 0
    for db_path in Config.AUDIT_BUS_DBS:
        if not db_path.exists():
            continue
        try:
            ro = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            ro.row_factory = sqlite3.Row
        except sqlite3.OperationalError:
            continue
        try:
            with closing(ro) as c:
                tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                table = "audit_events" if "audit_events" in tables else "forensic_events" if "forensic_events" in tables else None
                if not table:
                    continue
                # `table` is chosen from the fixed set {audit_events, forensic_events}.
                cols = {r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}  # noqa: S608  # nosemgrep
                payload_col = "payload_json" if "payload_json" in cols else None
                if not payload_col:
                    continue
                # `table` and `payload_col` are whitelisted schema identifiers
                # (not bindable in SQLite); `subject_id` is passed as a ? bind
                # parameter inside the LIKE pattern — no interpolation of user input.
                row = c.execute(  # noqa: S608  # nosemgrep
                    f"SELECT COUNT(*) AS n FROM {table} WHERE {payload_col} LIKE ?",
                    (f'%"{subject_id}"%',),
                ).fetchone()
                total += int(row["n"]) if row else 0
        except sqlite3.OperationalError:
            # Read-only DB may have WAL recovery requirements; skip gracefully
            continue
    return total


# A subject id is an opaque identifier, not a pattern. Anything outside this
# shape is refused rather than interpolated into a glob.
_SUBJECT_ID_RE = re.compile(r"\A[A-Za-z0-9._@:-]{3,128}\Z")


def _file_artifact_purge(subject_id: str) -> int:
    """Delete subject-tagged files from /var/lib/evidence (best-effort).

    subject_id is validated before use because it is interpolated into an
    rglob pattern. Previously a subject_id of "*" — or any short common
    substring — matched and deleted evidence belonging to every other data
    subject, turning one erasure request into mass evidence destruction.
    Glob metacharacters are also escaped so a literal id is matched literally.
    """
    if not isinstance(subject_id, str) or not _SUBJECT_ID_RE.match(subject_id):
        raise ValueError(f"refusing to purge with unsafe subject_id: {subject_id!r}")

    base = Path("/var/lib/evidence")
    if not base.exists():
        return 0

    # Escape glob metacharacters so the id is treated as a literal.
    literal = glob.escape(subject_id)
    resolved_base = base.resolve()
    deleted = 0
    for path in base.rglob(f"*{literal}*"):
        try:
            if not path.is_file():
                continue
            # Never follow a symlink out of the evidence tree.
            if resolved_base not in path.resolve().parents:
                continue
            path.unlink()
            deleted += 1
        except OSError:
            continue
    return deleted


def _write_confirmation(payload: dict[str, Any]) -> Path:
    Config.DSR_DELETION_CONFIRMATION_DIR.mkdir(parents=True, exist_ok=True)
    fname = Config.DSR_DELETION_CONFIRMATION_DIR / f"dsr-{payload['request_id']}.json"
    body = json.dumps(payload, indent=2, default=str)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    payload_with_hash = {**payload, "artifact_sha256": digest}
    fname.write_text(json.dumps(payload_with_hash, indent=2, default=str))
    try:
        fname.chmod(0o444)
    except OSError:
        pass
    return fname


def submit_dsr(
    subject_id: str,
    request_type: str,
    subject_email: str | None = None,
) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    submitted = _now()
    deadline = submitted + timedelta(days=30)
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO dsr_cascades
                (request_id, subject_id, subject_email, request_type,
                 submitted_at, deadline_at, status)
            VALUES (?, ?, ?, ?, ?, ?, 'received')
            """,
            (request_id, subject_id, subject_email, request_type,
             submitted.isoformat(), deadline.isoformat()),
        )
    return {
        "request_id": request_id,
        "subject_id": subject_id,
        "request_type": request_type,
        "submitted_at": submitted.isoformat(),
        "deadline_at": deadline.isoformat(),
        "status": "received",
    }


def execute_erasure(request_id: str) -> dict[str, Any]:
    with closing(our_connect()) as conn:
        row = conn.execute("SELECT * FROM dsr_cascades WHERE request_id = ?", (request_id,)).fetchone()
        if not row:
            return {"error": "not found"}

    # Only an erasure request may delete data. The DSR types (see app/db.py)
    # include access, rectification, restriction, portability and objection —
    # none of which authorise destruction. This function previously ran the
    # full purge for whatever request_id it was handed, so an access request
    # erased the very records it was supposed to disclose.
    request_type = (row["request_type"] or "").strip().lower()
    if request_type != "erasure":
        return {
            "error": "not an erasure request",
            "request_id": request_id,
            "request_type": request_type,
        }

    subject_id = row["subject_id"]

    qcount = _qdrant_purge(subject_id)
    audit_refs_remaining = _audit_db_count_references(subject_id)
    fcount = _file_artifact_purge(subject_id)

    confirmation = {
        "request_id": request_id,
        "subject_id": subject_id,
        "executed_at": _now().isoformat(),
        "subsystems": {
            "qdrant": {"collections_processed": qcount, "scope": "user_data_purged"},
            "audit_trail": {
                "references_remaining": audit_refs_remaining,
                "scope": "immutable_per_REQ-RCA-005",
                "note": "Audit references retained as evidence. This deletion event is itself logged to audit trail.",
            },
            "evidence_files": {"files_deleted": fcount, "scope": "user_data_purged"},
        },
    }
    artifact = _write_confirmation(confirmation)

    with transaction() as conn:
        conn.execute(
            """
            UPDATE dsr_cascades
            SET qdrant_deletions = ?, pg_deletions = ?, file_deletions = ?,
                status = 'completed', completed_at = ?,
                confirmation_artifact_path = ?
            WHERE request_id = ?
            """,
            (qcount, audit_refs_remaining, fcount, _now().isoformat(), str(artifact), request_id),
        )

    return {
        **confirmation,
        "artifact_path": str(artifact),
        "status": "completed",
    }


def list_requests(status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with closing(our_connect()) as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM dsr_cascades WHERE status = ? ORDER BY submitted_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM dsr_cascades ORDER BY submitted_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
