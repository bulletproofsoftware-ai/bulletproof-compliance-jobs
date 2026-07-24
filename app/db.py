"""SQLite for compliance-jobs internal state."""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from typing import Iterator

from .config import Config

SCHEMA = """
-- Sequence-numbered Merkle roots (append-only, write-once on disk)
CREATE TABLE IF NOT EXISTS merkle_roots (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    leaf_hashes_json TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    parent_root_hash TEXT,
    sources TEXT NOT NULL,
    published_to_external INTEGER NOT NULL DEFAULT 0,
    external_response TEXT,
    created_at TEXT NOT NULL,
    signature TEXT,
    signing_key_id TEXT
);

-- Retention scan history
CREATE TABLE IF NOT EXISTS retention_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    audit_records_archived INTEGER NOT NULL DEFAULT 0,
    audit_records_deleted INTEGER NOT NULL DEFAULT 0,
    evidence_archived INTEGER NOT NULL DEFAULT 0,
    held_records INTEGER NOT NULL DEFAULT 0,
    archive_paths TEXT
);

-- Legal holds (REQ-RCA-018) — pause retention deletion
CREATE TABLE IF NOT EXISTS legal_holds (
    hold_id TEXT PRIMARY KEY,
    subject_session_id TEXT,
    subject_data_class TEXT,
    reason TEXT NOT NULL,
    placed_by TEXT NOT NULL,
    placed_at TEXT NOT NULL,
    released_at TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

-- DSR cascade execution log (REQ-RCA-021)
CREATE TABLE IF NOT EXISTS dsr_cascades (
    request_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    subject_email TEXT,
    request_type TEXT NOT NULL,        -- erasure | access | rectification | restriction | portability | objection
    submitted_at TEXT NOT NULL,
    deadline_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'received',
    qdrant_deletions INTEGER NOT NULL DEFAULT 0,
    pg_deletions INTEGER NOT NULL DEFAULT 0,
    file_deletions INTEGER NOT NULL DEFAULT 0,
    confirmation_artifact_path TEXT,
    completed_at TEXT,
    failure_reason TEXT
);

-- Regulatory report generations (REQ-RCA-029-031)
CREATE TABLE IF NOT EXISTS regulatory_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type TEXT NOT NULL,         -- sox_attestation | nydfs_part500 | eu_ai_act | naic_adverse_action
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    signed INTEGER NOT NULL DEFAULT 0,
    operator_id TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    signing_key_id TEXT
);

-- NAIC adverse-action tracking (REQ-RCA-032) — idempotent per source event
CREATE TABLE IF NOT EXISTS naic_actions (
    event_id TEXT PRIMARY KEY,
    source_db TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    agent_id TEXT,
    session_id TEXT,
    detected_at TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT,
    generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_naic_detected ON naic_actions(detected_at);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    p = path or str(Config.SQLITE_PATH)
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# Idempotent additive migrations — apply on every init() so existing DBs get
# new columns without losing data. SQLite has no ALTER TABLE … ADD COLUMN IF
# NOT EXISTS, so we introspect with PRAGMA table_info first.
#
# Format: (table_name, column_name, column_def_sql)
_ADDITIVE_COLUMNS = (
    # REQ-RCA-013 — Ed25519 signature columns
    ("regulatory_runs", "signing_key_id", "TEXT"),
    ("merkle_roots", "signature", "TEXT"),
    ("merkle_roots", "signing_key_id", "TEXT"),
    # REQ-RCA-016 — per-class retention counts on retention_runs
    ("retention_runs", "gov_audit_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "sec_audit_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "merkle_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "regulatory_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "naic_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "n8n_executions_deleted", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "qdrant_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "evidence_files_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "postgres_archived", "INTEGER NOT NULL DEFAULT 0"),
    ("retention_runs", "per_class_json", "TEXT"),
)


def _existing_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _apply_additive_migrations(conn: sqlite3.Connection) -> None:
    """Apply additive ALTER TABLE migrations idempotently."""
    # Group by table to avoid repeated PRAGMA calls
    tables: dict[str, list[tuple[str, str]]] = {}
    for table, column, coltype in _ADDITIVE_COLUMNS:
        tables.setdefault(table, []).append((column, coltype))

    for table, cols in tables.items():
        # Skip if table doesn't exist yet (CREATE TABLE … IF NOT EXISTS in
        # SCHEMA above will have created it, but be defensive).
        existing_tables = {
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchall()
        }
        if table not in existing_tables:
            continue
        existing = _existing_columns(conn, table)
        for column, coltype in cols:
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def init() -> None:
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
        _apply_additive_migrations(conn)
        conn.commit()


@contextmanager
def transaction(path: str | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
