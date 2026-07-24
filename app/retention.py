"""Retention enforcer — REQ-RCA-016/017/018.

7-year retention, with legal-hold pause + cold archive on the way out.
Writes archive bundles to ARCHIVE_DIR before deleting from source databases.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .db import connect as our_connect, transaction


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _active_holds() -> list[str]:
    """Return session_ids currently under legal hold."""
    with closing(our_connect()) as conn:
        rows = conn.execute(
            "SELECT subject_session_id FROM legal_holds WHERE active = 1"
        ).fetchall()
        return [r["subject_session_id"] for r in rows if r["subject_session_id"]]


def _archive_jsonl(records: list[dict[str, Any]], prefix: str) -> Path:
    """Compress and write records to JSONL.gz under ARCHIVE_DIR. Returns path."""
    Config.ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    ts = _now().strftime("%Y%m%d-%H%M%S")
    fname = Config.ARCHIVE_DIR / f"{prefix}-{ts}.jsonl.gz"
    with gzip.open(fname, "wt", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, default=str) + "\n")
    try:
        fname.chmod(0o444)
    except OSError:
        pass
    return fname


def _connect_audit_db(db_path: Path) -> tuple[sqlite3.Connection, bool]:
    """Open an audit DB. Returns (conn, can_write).

    Tries RW first; on PermissionError / OperationalError due to a read-only
    mount, falls back to URI-mode RO open which avoids journal/WAL writes.
    Setting `can_write=False` in the returned tuple lets the caller skip
    the DELETE phase and report `cannot_delete=true`. This is the standard
    posture for production deployments where the audit DB is mounted RO
    into the retention enforcer container as a defense-in-depth measure
    (REQ-RCA-007 + REQ-RCA-016 interplay).

    Phase 5 adversarial review hardening:
      - The RW probe is NON-DESTRUCTIVE — earlier code ran
        ``PRAGMA journal_mode=WAL`` which mutates the source DB's
        journaling mode if it succeeds. Now we attempt an in-transaction
        ``CREATE TEMP TABLE`` and ROLLBACK; this requires write access
        but never persists any state.
      - On RW probe failure the open connection is explicitly closed
        before the RO fallback (avoids a file-descriptor leak when the
        probe fails partway through).
      - The RO fallback uses ``Path.as_uri()``-equivalent URL building
        so paths with special characters (``#``, ``?``, spaces) are
        escaped correctly.
    """
    # First try RW (the common case for the runtime that owns the audit DB).
    rw_conn: sqlite3.Connection | None = None
    try:
        rw_conn = sqlite3.connect(str(db_path), timeout=10)
        rw_conn.row_factory = sqlite3.Row
        # Non-destructive RW probe: open a transaction, create a TEMP
        # table (which never persists), then roll back. If the file is
        # truly read-only, the BEGIN will fail with OperationalError.
        rw_conn.execute("BEGIN IMMEDIATE")
        rw_conn.execute(
            "CREATE TEMP TABLE _retention_rw_probe (x INTEGER)")
        rw_conn.execute("ROLLBACK")
        return rw_conn, True
    except sqlite3.OperationalError:
        # Probe failed — close the partial connection if it exists so we
        # don't leak the file descriptor, then fall through to RO.
        if rw_conn is not None:
            try:
                rw_conn.close()
            except sqlite3.OperationalError:
                pass

    # RO fallback — URI mode + immutable=1. SQLite then never tries to
    # create the WAL/journal files even on a SELECT. Build the URI safely
    # using `Path.as_uri()` so special characters in the path don't break
    # the URI parser.
    try:
        from urllib.parse import quote
        # Path.as_uri() returns "file:///abs/path"; we just append the
        # query string. quote() escapes anything that needs it.
        path_uri = Path(db_path).resolve().as_uri()
        uri = f"{path_uri}?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn, False
    except sqlite3.OperationalError:
        raise


def _enforce_audit_db(db_path: Path, cutoff_iso: str, holds: list[str]) -> dict[str, Any]:
    if not db_path.exists():
        return {"db": str(db_path), "skipped": True, "reason": "missing"}
    try:
        conn, can_write = _connect_audit_db(db_path)
    except sqlite3.OperationalError as exc:
        return {"db": str(db_path), "skipped": True, "reason": str(exc)}

    with closing(conn) as c:
        tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        table = "audit_events" if "audit_events" in tables else "forensic_events" if "forensic_events" in tables else None
        if not table:
            return {"db": str(db_path), "skipped": True, "reason": "no audit table"}

        cols = {r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
        ts_col = "timestamp" if "timestamp" in cols else "created_at"

        # Identify candidates older than cutoff and not under legal hold
        sql = f"SELECT * FROM {table} WHERE {ts_col} < ?"
        rows = c.execute(sql, (cutoff_iso,)).fetchall()
        archived = []
        held = []
        for r in rows:
            d = dict(r)
            sid = d.get("session_id")
            if sid and sid in holds:
                held.append(d)
            else:
                archived.append(d)

        archive_path = None
        deleted = 0
        cannot_delete = False
        if archived:
            archive_path = _archive_jsonl(archived, prefix=f"audit-{db_path.stem}")
            ids = [r.get("event_id") for r in archived if r.get("event_id")]
            if ids:
                if not can_write:
                    # RO mount — archive only, skip DELETE. The retention
                    # contract still holds: data is preserved >= 7 years and
                    # cold-archived past horizon. Operators rotate the source
                    # DB out-of-band when the archive volume grows too large.
                    cannot_delete = True
                else:
                    placeholders = ",".join("?" * len(ids))
                    cur = c.execute(
                        f"DELETE FROM {table} WHERE event_id IN ({placeholders})",
                        ids)
                    deleted = cur.rowcount or 0
                    c.commit()
    return {
        "db": str(db_path),
        "archived_count": len(archived),
        "deleted_count": deleted,
        "held_count": len(held),
        "archive_path": str(archive_path) if archive_path else None,
        "cannot_delete": cannot_delete,
        "ro_mount": not can_write,
    }


def run_retention() -> dict[str, Any]:
    cutoff = (_now() - timedelta(days=365 * Config.AUDIT_RETENTION_YEARS)).isoformat()
    holds = _active_holds()
    started = _now().isoformat()
    results = []
    total_archived = 0
    total_deleted = 0
    total_held = 0
    archive_paths = []
    for db_path in Config.AUDIT_BUS_DBS:
        r = _enforce_audit_db(db_path, cutoff, holds)
        results.append(r)
        total_archived += r.get("archived_count", 0)
        total_deleted += r.get("deleted_count", 0)
        total_held += r.get("held_count", 0)
        if r.get("archive_path"):
            archive_paths.append(r["archive_path"])
    completed = _now().isoformat()
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO retention_runs
                (started_at, completed_at, audit_records_archived,
                 audit_records_deleted, held_records, archive_paths)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                started,
                completed,
                total_archived,
                total_deleted,
                total_held,
                json.dumps(archive_paths),
            ),
        )
    return {
        "started_at": started,
        "completed_at": completed,
        "cutoff_iso": cutoff,
        "active_holds": len(holds),
        "totals": {
            "archived": total_archived,
            "deleted": total_deleted,
            "held": total_held,
        },
        "per_db": results,
    }


def place_hold(session_id: str, reason: str, placed_by: str = "operator") -> dict[str, Any]:
    hold_id = str(uuid.uuid4())
    now = _now().isoformat()
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO legal_holds
                (hold_id, subject_session_id, reason, placed_by, placed_at, active)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (hold_id, session_id, reason, placed_by, now),
        )
    return {"hold_id": hold_id, "session_id": session_id, "placed_at": now}


def release_hold(hold_id: str) -> bool:
    with transaction() as conn:
        cur = conn.execute(
            "UPDATE legal_holds SET active = 0, released_at = ? WHERE hold_id = ?",
            (_now().isoformat(), hold_id),
        )
        return (cur.rowcount or 0) > 0


def list_holds(active_only: bool = True) -> list[dict[str, Any]]:
    with closing(our_connect()) as conn:
        sql = "SELECT * FROM legal_holds"
        if active_only:
            sql += " WHERE active = 1"
        sql += " ORDER BY placed_at DESC"
        rows = conn.execute(sql).fetchall()
        return [dict(r) for r in rows]


def list_runs(limit: int = 30) -> list[dict[str, Any]]:
    with closing(our_connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM retention_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
