"""Regulatory report scheduler — REQ-RCA-029-031.

Generates SOX, NY DFS Part 500, EU AI Act, NAIC adverse-action reports as
JSON evidence package variants. Annual or on-demand.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .db import transaction
from .signing import canonical_json, get_signing_key, sign_bytes

# Must contain at least one alphanumeric and may not be dots-only: the class
# permits ".", so "." and ".." would otherwise pass and yield filenames like
# dsr-..json. Harmless where they are embedded, but not worth relying on.
_SAFE_ID_RE = re.compile(r"\A(?!\.+\Z)[A-Za-z0-9._-]{1,128}\Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


REPORT_TYPES = {
    "sox_attestation": {
        "title": "SOX Section 404 — Management Attestation (AI Controls Scope)",
        "controls": ["ITGC-01", "ITGC-02", "ITGC-03", "ENT-AI-01", "ENT-AI-02"],
        "annual": True,
    },
    "nydfs_part500": {
        "title": "NY DFS Part 500 Annual Certification",
        "controls": ["500.02", "500.03", "500.04", "500.07", "500.09", "500.16", "500.17"],
        "annual": True,
    },
    "eu_ai_act": {
        "title": "EU AI Act Conformity Declaration (Annex VI)",
        "controls": ["Art-9", "Art-10", "Art-12", "Art-13", "Art-14", "Art-15", "Art-17"],
        "annual": False,
    },
    "naic_adverse_action": {
        "title": "NAIC Adverse Action Log",
        "controls": ["MDL-2024-AI-01"],
        "annual": False,
    },
}


def _gather_evidence(period_start: str, period_end: str) -> dict[str, Any]:
    summary = {"audit_event_counts": [], "merkle_chain": {}, "retention_runs": [], "dsr_cascades": []}

    # Counts from each audit DB
    for db_path in Config.AUDIT_BUS_DBS:
        if not db_path.exists():
            continue
        try:
            try:
                ro = sqlite3.connect(f"file:{db_path}?immutable=1", uri=True)
            except sqlite3.OperationalError:
                ro = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            ro.row_factory = sqlite3.Row
            with closing(ro) as c:
                tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                table = "audit_events" if "audit_events" in tables else "forensic_events" if "forensic_events" in tables else None
                if not table:
                    continue
                # `table` is chosen from the fixed set {audit_events, forensic_events};
                # no user input reaches the identifier.
                cols = {r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}  # noqa: S608  # nosemgrep
                ts_col = "timestamp" if "timestamp" in cols else "created_at"
                # `table`/`ts_col` are whitelisted identifiers (SQLite can't bind them);
                # the period bounds are passed as ? bind parameters.
                rows = c.execute(  # noqa: S608  # nosemgrep
                    f"SELECT event_type, COUNT(*) AS n FROM {table} "
                    f"WHERE {ts_col} BETWEEN ? AND ? GROUP BY event_type",
                    (period_start, period_end),
                ).fetchall()
                summary["audit_event_counts"].append({
                    "db": str(db_path),
                    "events": [dict(r) for r in rows],
                })
        except sqlite3.OperationalError:
            continue

    # Merkle chain status from local sqlite
    from .merkle import verify_chain  # local import to avoid cycle
    summary["merkle_chain"] = verify_chain()

    # Retention runs in period
    from .db import connect as our_connect
    with closing(our_connect()) as conn:
        rrows = conn.execute(
            "SELECT * FROM retention_runs WHERE started_at BETWEEN ? AND ?",
            (period_start, period_end),
        ).fetchall()
        summary["retention_runs"] = [dict(r) for r in rrows]
        drows = conn.execute(
            "SELECT * FROM dsr_cascades WHERE submitted_at BETWEEN ? AND ?",
            (period_start, period_end),
        ).fetchall()
        summary["dsr_cascades"] = [dict(r) for r in drows]

    return summary


def _sign_artifact(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Compute SHA-256 integrity hash + Ed25519 authenticity signature.

    SHA-256 is computed over the same canonical JSON used for the signature so
    verifiers can re-derive both with one serialisation. Returns a dict with
    ``artifact_sha256`` plus the signature dict produced by ``sign_bytes``.
    """
    canonical = canonical_json(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    signing_key = get_signing_key()
    signature = sign_bytes(signing_key, canonical)
    return {"artifact_sha256": digest, "signature": signature}


def generate_report(report_type: str, period_start: str, period_end: str) -> dict[str, Any]:
    spec = REPORT_TYPES.get(report_type)
    if not spec:
        return {"error": f"unknown report_type: {report_type}"}

    Config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_id = str(uuid.uuid4())
    body = {
        "report_id": report_id,
        "type": report_type,
        "title": spec["title"],
        "controls": spec["controls"],
        "period": {"start": period_start, "end": period_end},
        "operator_id": Config.REPORT_OPERATOR_ID,
        "generated_at": _now().isoformat(),
        "evidence": _gather_evidence(period_start, period_end),
    }

    # Both halves land in a filename; reject anything that is not a plain
    # identifier before touching the filesystem (CodeQL py/path-injection).
    if not _SAFE_ID_RE.match(str(report_type)) or not _SAFE_ID_RE.match(str(report_id)):
        raise ValueError("unsafe report identifier")
    fname = (Config.REPORTS_DIR.resolve() / f"{report_type}-{report_id}.json")
    if fname.parent != Config.REPORTS_DIR.resolve():
        raise ValueError("path escapes REPORTS_DIR")

    # _sign_artifact computes BOTH SHA-256 (integrity) and Ed25519 (authenticity)
    # over the canonical JSON of the body BEFORE either is embedded, so a verifier
    # can strip both fields and reproduce the exact bytes that were signed.
    sig_result = _sign_artifact(fname, body)
    digest = sig_result["artifact_sha256"]
    signature = sig_result["signature"]

    # Embed alongside the body so the on-disk artifact is self-describing.
    body["artifact_sha256"] = digest
    body["signature"] = signature

    # Pretty JSON for human readability; canonicalisation is preserved
    # via "signed_canonical_json" reproducibility (see signing.canonical_json).
    fname.write_text(json.dumps(body, indent=2, default=str, sort_keys=True))
    try:
        fname.chmod(0o444)
    except OSError:
        pass

    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO regulatory_runs
                (report_type, period_start, period_end, artifact_path,
                 signed, operator_id, generated_at, signing_key_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_type,
                period_start,
                period_end,
                str(fname),
                1,
                body["operator_id"],
                body["generated_at"],
                signature["key_id"],
            ),
        )

    return {
        **body,
        "artifact_path": str(fname),
    }


def annual_run(year: int | None = None) -> dict[str, Any]:
    """Trigger all annual reports for a year (default = previous calendar year)."""
    target_year = year or (_now().year - 1)
    period_start = f"{target_year}-01-01T00:00:00+00:00"
    period_end = f"{target_year}-12-31T23:59:59+00:00"
    results = []
    for rt, spec in REPORT_TYPES.items():
        if not spec["annual"]:
            continue
        results.append(generate_report(rt, period_start, period_end))
    return {"year": target_year, "reports": results}


def list_runs(limit: int = 50) -> list[dict[str, Any]]:
    from .db import connect as our_connect
    with closing(our_connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM regulatory_runs ORDER BY generated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
