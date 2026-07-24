"""Compliance Jobs — PRD 18 hardening.

REQ-RCA-006  Hourly Merkle root publishing
REQ-RCA-016  7-year retention with archive
REQ-RCA-018  Legal hold pause
REQ-RCA-021  GDPR cascade deletion
REQ-RCA-029  SOX management attestation (annual auto-fire)
REQ-RCA-030  NY DFS Part 500 annual cert (annual auto-fire)
REQ-RCA-031  EU AI Act conformity declaration (annual auto-fire)
REQ-RCA-032  NAIC adverse action auto-population from audit events
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from contextlib import asynccontextmanager, closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import db, dsr_cascade, merkle, reports, retention, signing
from .config import Config, ensure_dirs


# --- Models ---

class HoldRequest(BaseModel):
    session_id: str
    reason: str
    placed_by: str = "operator"


class DSRRequest(BaseModel):
    subject_id: str
    request_type: str  # erasure | access | rectification | restriction | portability | objection
    subject_email: str | None = None


class ReportRequest(BaseModel):
    report_type: str  # sox_attestation | nydfs_part500 | eu_ai_act | naic_adverse_action
    period_start: str
    period_end: str


class AnnualRunRequest(BaseModel):
    report_type: str  # sox_attestation | nydfs_part500 | eu_ai_act | naic_adverse_action_consolidated
    year: int


class SignatureVerifyRequest(BaseModel):
    """REQ-RCA-013 — Ed25519 verify endpoint payload."""
    payload_canonical_json: str  # exact bytes that were signed (UTF-8 string)
    signature_hex: str
    key_id: str


# --- Schedulers ---

async def _merkle_loop() -> None:
    # Run on the hour
    while True:
        try:
            now = datetime.now(timezone.utc)
            next_hour = (now.replace(minute=5, second=0, microsecond=0) + timedelta(hours=1))
            if now.minute < 5:
                next_hour = now.replace(minute=5, second=0, microsecond=0)
            seconds = max(60, (next_hour - now).total_seconds())
            await asyncio.sleep(seconds)
            result = await merkle.publish_hourly_root()
            print(f"[merkle] seq={result['seq']} events={result['event_count']} root={result['root_hash'][:12]}…")
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[merkle] error: {exc}")


async def _retention_loop() -> None:
    interval = Config.RETENTION_INTERVAL_HOURS * 3600
    while True:
        try:
            await asyncio.sleep(interval)
            r = retention.run_retention()
            print(f"[retention] archived={r['totals']['archived']} deleted={r['totals']['deleted']} held={r['totals']['held']}")
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[retention] error: {exc}")


# --- Annual report scheduler (REQ-RCA-029/030/031) ---

ANNUAL_REPORT_TYPES = ("sox_attestation", "nydfs_part500", "eu_ai_act")


def _last_run_for(report_type: str) -> dict[str, Any] | None:
    """Return the most recent regulatory_runs row for a report_type, or None."""
    with closing(db.connect()) as conn:
        row = conn.execute(
            "SELECT * FROM regulatory_runs WHERE report_type = ? "
            "ORDER BY generated_at DESC LIMIT 1",
            (report_type,),
        ).fetchone()
        return dict(row) if row else None


def _annual_due(report_type: str, now: datetime) -> tuple[bool, str]:
    """Decide if an annual report is due.

    The scheduler's contract: keep at least one report on file that covers
    the previous calendar year (target_year = now.year - 1).

    Due when:
      - never run before, OR
      - last successful run > 365 days ago, OR
      - no run on file covers ``target_year`` (i.e. period_start year != target_year)
        AND the last covered year is < target_year — i.e. we crossed Jan 1
        since the last covering run, OR
      - the most recent run's period_start year is strictly less than
        target_year (defensive duplicate of the above for clarity).
    """
    last = _last_run_for(report_type)
    if not last:
        return True, "never_run"
    try:
        gen_at = datetime.fromisoformat(last["generated_at"])
        if gen_at.tzinfo is None:
            gen_at = gen_at.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return True, "unparseable_last_run"
    if (now - gen_at).days > 365:
        return True, f"stale_{(now - gen_at).days}d"

    # Check whether ANY run for this report_type covers target_year.
    target_year = now.year - 1
    target_prefix = f"{target_year}-"
    with closing(db.connect()) as conn:
        row = conn.execute(
            "SELECT 1 FROM regulatory_runs "
            "WHERE report_type = ? AND period_start LIKE ? LIMIT 1",
            (report_type, f"{target_prefix}%"),
        ).fetchone()
        if not row:
            return True, f"no_run_for_target_year_{target_year}"

    return False, "current"


def _generate_annual(report_type: str, year: int) -> dict[str, Any]:
    """Generate one annual report for the given year (period = whole calendar year)."""
    period_start = f"{year}-01-01T00:00:00+00:00"
    period_end = f"{year}-12-31T23:59:59+00:00"
    return reports.generate_report(report_type, period_start, period_end)


async def _annual_report_loop() -> None:
    interval = max(60, Config.ANNUAL_CHECK_HOURS * 3600)
    print(f"[annual] scheduler started, check_interval={interval}s")
    while True:
        try:
            await asyncio.sleep(interval)
            now = datetime.now(timezone.utc)
            target_year = now.year - 1
            for rt in ANNUAL_REPORT_TYPES:
                try:
                    due, reason = _annual_due(rt, now)
                    if not due:
                        continue
                    print(f"[annual] firing {rt} year={target_year} reason={reason}")
                    result = _generate_annual(rt, target_year)
                    if result.get("error"):
                        print(f"[annual] {rt} error: {result['error']}")
                    else:
                        print(f"[annual] {rt} generated artifact={result.get('artifact_path')}")
                except Exception as exc:  # noqa: BLE001
                    print(f"[annual] {rt} unexpected error: {exc}")
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[annual] loop error: {exc}")


# --- NAIC adverse-action listener (REQ-RCA-032) ---

# Governance audit DB event types that signal adverse actions
_GOV_ADVERSE_TYPES = (
    "policy_deny",
    "security.threat_detected",
    "security.guardian_action",
    "security.injection_blocked",
    "security.escalation_blocked",
    "security.exfiltration_alert",
)
# Security audit_bus DB event types that signal adverse actions
_SEC_ADVERSE_TYPES = (
    "threat.injection.detected",
    "guardian.action.taken",
    "threat.detected",
    "policy.deny",
)
_HIGH_SEVERITIES = ("high", "critical")


def _seen_event_ids() -> set[str]:
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT event_id FROM naic_actions").fetchall()
        return {r["event_id"] for r in rows}


def _open_audit_ro(db_path: Path) -> sqlite3.Connection | None:
    """Open an audit DB read-only.

    Mount points are typically ``ro`` so SQLite cannot create the journal file
    that ``mode=ro`` URI mode still expects. ``immutable=1`` skips the journal
    entirely. We try both and prefer ``immutable=1`` for resilience.
    """
    for uri in (
        f"file:{db_path}?immutable=1",
        f"file:{db_path}?mode=ro",
    ):
        try:
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            continue
    return None


def _scan_gov_adverse_events(db_path: Path) -> list[dict[str, Any]]:
    """Scan the governance audit DB for adverse action events."""
    out: list[dict[str, Any]] = []
    if not db_path.exists():
        return out
    ro = _open_audit_ro(db_path)
    if ro is None:
        return out
    try:
        with closing(ro) as c:
            tables = [r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            if "audit_events" not in tables:
                return out
            cols = {r["name"] for r in c.execute("PRAGMA table_info(audit_events)").fetchall()}
            ts_col = "timestamp" if "timestamp" in cols else "created_at"
            type_placeholders = ",".join("?" * len(_GOV_ADVERSE_TYPES))
            sql = (
                f"SELECT * FROM audit_events "
                f"WHERE event_type IN ({type_placeholders}) "
                f"   OR outcome = 'adverse_action' "
                f"   OR (detail IS NOT NULL AND detail LIKE '%adverse_action%') "
                f"ORDER BY {ts_col} ASC"
            )
            rows = c.execute(sql, _GOV_ADVERSE_TYPES).fetchall()
            for r in rows:
                d = dict(r)
                # Severity: governance DB typically lacks an explicit severity
                # column; treat all matched events as high by default and only
                # downgrade if outcome=allow/warn signals advisory-only.
                outcome = (d.get("outcome") or "").lower()
                severity = "high"
                if outcome in {"allow", "warn"} and (d.get("event_type") or "") not in {
                    "policy_deny",
                    "security.threat_detected",
                    "security.guardian_action",
                    "security.injection_blocked",
                    "security.escalation_blocked",
                    "security.exfiltration_alert",
                }:
                    continue
                out.append({
                    "event_id": d.get("event_id") or "",
                    "event_type": d.get("event_type") or "",
                    "severity": severity,
                    "agent_id": d.get("agent_id"),
                    "session_id": d.get("audit_session_id"),
                    "detected_at": d.get(ts_col) or d.get("timestamp") or "",
                    "raw": d,
                })
    except sqlite3.OperationalError:
        return out
    return out


def _scan_sec_adverse_events(db_path: Path) -> list[dict[str, Any]]:
    """Scan the security audit_bus for adverse action events.

    Only high/critical severity events qualify, plus any event whose
    payload_json includes ``handled=1`` for guardian actions.
    """
    out: list[dict[str, Any]] = []
    if not db_path.exists():
        return out
    ro = _open_audit_ro(db_path)
    if ro is None:
        return out
    try:
        with closing(ro) as c:
            tables = [r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            if "audit_events" not in tables:
                return out
            cols = {r["name"] for r in c.execute("PRAGMA table_info(audit_events)").fetchall()}
            ts_col = "timestamp" if "timestamp" in cols else "created_at"
            type_placeholders = ",".join("?" * len(_SEC_ADVERSE_TYPES))
            severity_placeholders = ",".join("?" * len(_HIGH_SEVERITIES))
            sql = (
                f"SELECT * FROM audit_events "
                f"WHERE event_type IN ({type_placeholders}) "
                f"  AND severity IN ({severity_placeholders}) "
                f"ORDER BY {ts_col} ASC"
            )
            rows = c.execute(sql, _SEC_ADVERSE_TYPES + _HIGH_SEVERITIES).fetchall()
            for r in rows:
                d = dict(r)
                payload: dict[str, Any] = {}
                try:
                    payload = json.loads(d.get("payload_json") or "{}")
                except (ValueError, TypeError):
                    payload = {}
                # For guardian.action.taken require handled=true OR severity is critical
                if (d.get("event_type") or "") == "guardian.action.taken":
                    if not payload.get("handled") and (d.get("severity") or "").lower() != "critical":
                        # still allow critical guardian actions even if not yet handled
                        if (d.get("severity") or "").lower() != "high":
                            continue
                out.append({
                    "event_id": d.get("event_id") or "",
                    "event_type": d.get("event_type") or "",
                    "severity": (d.get("severity") or "").lower() or None,
                    "agent_id": d.get("agent_id"),
                    "session_id": d.get("session_id"),
                    "detected_at": d.get(ts_col) or d.get("timestamp") or "",
                    "raw": d,
                })
    except sqlite3.OperationalError:
        return out
    return out


def _process_naic_event(event: dict[str, Any], source_db: str) -> dict[str, Any] | None:
    """Generate a NAIC artifact for one adverse-action event and record it.

    Returns the artifact metadata, or None on failure. Idempotent — caller
    is expected to skip already-tracked event_ids, but a UNIQUE constraint
    on naic_actions.event_id provides defense-in-depth.
    """
    event_id = event.get("event_id") or ""
    if not event_id:
        return None
    detected_at = event.get("detected_at") or datetime.now(timezone.utc).isoformat()
    period = detected_at
    try:
        report = reports.generate_report(
            "naic_adverse_action",
            period_start=period,
            period_end=period,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[naic] generate_report failed for event {event_id}: {exc}")
        return None
    if report.get("error"):
        print(f"[naic] generate_report error for event {event_id}: {report['error']}")
        return None
    artifact_path = report.get("artifact_path") or ""
    artifact_sha = report.get("artifact_sha256") or ""
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with db.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO naic_actions
                    (event_id, source_db, event_type, severity, agent_id,
                     session_id, detected_at, artifact_path,
                     artifact_sha256, generated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    source_db,
                    event.get("event_type") or "",
                    event.get("severity"),
                    event.get("agent_id"),
                    event.get("session_id"),
                    detected_at,
                    artifact_path,
                    artifact_sha,
                    now_iso,
                ),
            )
    except sqlite3.Error as exc:
        print(f"[naic] DB insert failed for event {event_id}: {exc}")
        return None
    return {
        "event_id": event_id,
        "source_db": source_db,
        "event_type": event.get("event_type"),
        "artifact_path": artifact_path,
        "artifact_sha256": artifact_sha,
        "generated_at": now_iso,
    }


def run_naic_iteration() -> dict[str, Any]:
    """Single iteration of the NAIC scan — exposed for tests + manual triggers."""
    seen = _seen_event_ids()
    new_actions: list[dict[str, Any]] = []
    skipped = 0
    for db_path in Config.AUDIT_BUS_DBS:
        try:
            if str(db_path).endswith("audit.db"):
                events = _scan_gov_adverse_events(db_path)
            else:
                events = _scan_sec_adverse_events(db_path)
        except Exception as exc:  # noqa: BLE001
            print(f"[naic] scan {db_path} error: {exc}")
            continue
        for ev in events:
            eid = ev.get("event_id") or ""
            if not eid or eid in seen:
                skipped += 1
                continue
            result = _process_naic_event(ev, source_db=str(db_path))
            if result:
                new_actions.append(result)
                seen.add(eid)
    return {
        "scanned_dbs": [str(p) for p in Config.AUDIT_BUS_DBS],
        "new_artifacts": len(new_actions),
        "skipped_already_tracked": skipped,
        "actions": new_actions,
    }


async def _naic_adverse_action_loop() -> None:
    interval = max(30, Config.NAIC_POLL_SECONDS)
    print(f"[naic] adverse-action listener started, poll_interval={interval}s")
    while True:
        try:
            await asyncio.sleep(interval)
            result = run_naic_iteration()
            if result["new_artifacts"]:
                print(
                    f"[naic] new_artifacts={result['new_artifacts']} "
                    f"skipped={result['skipped_already_tracked']}"
                )
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[naic] loop error: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_dirs()
    db.init()
    # Pre-warm Ed25519 signing key (REQ-RCA-013) — generates a new keypair on
    # first run and logs the new key_id once.
    try:
        signing.get_signing_key()
    except Exception as exc:  # noqa: BLE001
        print(f"[signing] failed to initialise signing key: {exc}")
    merkle_t = asyncio.create_task(_merkle_loop())
    retention_t = asyncio.create_task(_retention_loop())
    annual_t = asyncio.create_task(_annual_report_loop())
    naic_t = asyncio.create_task(_naic_adverse_action_loop())
    yield
    for t in (merkle_t, retention_t, annual_t, naic_t):
        t.cancel()


app = FastAPI(title="Compliance Jobs — PRD 18 hardening", version="1.0.0", lifespan=lifespan)


# --- Health ---

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "compliance-jobs",
        "components": [
            "merkle-publisher",
            "retention-enforcer",
            "dsr-cascade-worker",
            "regulatory-report-scheduler",
            "annual-report-scheduler",
            "naic-adverse-action-listener",
        ],
        "audit_dbs_configured": [str(p) for p in Config.AUDIT_BUS_DBS],
        "annual_check_hours": Config.ANNUAL_CHECK_HOURS,
        "naic_poll_seconds": Config.NAIC_POLL_SECONDS,
    }


# --- Merkle (REQ-RCA-006) ---

@app.post("/api/merkle/publish-now")
async def merkle_publish_now() -> dict[str, Any]:
    return await merkle.publish_hourly_root()


@app.get("/api/merkle/roots")
async def list_merkle_roots(limit: int = Query(default=50, le=500)) -> dict[str, Any]:
    return {"roots": merkle.list_roots(limit)}


@app.get("/api/merkle/verify-chain")
async def verify_chain() -> dict[str, Any]:
    return merkle.verify_chain()


# --- Retention (REQ-RCA-016/017/018) ---

@app.post("/api/retention/run-now")
async def retention_run_now() -> dict[str, Any]:
    return retention.run_retention()


@app.get("/api/retention/runs")
async def retention_history(limit: int = 30) -> dict[str, Any]:
    return {"runs": retention.list_runs(limit)}


@app.post("/api/retention/holds")
async def place_hold(req: HoldRequest) -> dict[str, Any]:
    return retention.place_hold(req.session_id, req.reason, req.placed_by)


@app.delete("/api/retention/holds/{hold_id}")
async def release_hold(hold_id: str) -> dict[str, Any]:
    ok = retention.release_hold(hold_id)
    if not ok:
        raise HTTPException(404, "hold not found")
    return {"hold_id": hold_id, "released": True}


@app.get("/api/retention/holds")
async def list_holds(active_only: bool = True) -> dict[str, Any]:
    return {"holds": retention.list_holds(active_only)}


# --- DSR cascade (REQ-RCA-021) ---

@app.post("/api/dsr/submit")
async def dsr_submit(req: DSRRequest) -> dict[str, Any]:
    return dsr_cascade.submit_dsr(req.subject_id, req.request_type, req.subject_email)


@app.post("/api/dsr/{request_id}/execute")
async def dsr_execute(request_id: str) -> dict[str, Any]:
    return dsr_cascade.execute_erasure(request_id)


@app.get("/api/dsr/requests")
async def list_dsr(status: str | None = None, limit: int = 50) -> dict[str, Any]:
    return {"requests": dsr_cascade.list_requests(status, limit)}


# --- Regulatory reports (REQ-RCA-029-032) ---

@app.post("/api/reports/generate")
async def report_generate(req: ReportRequest) -> dict[str, Any]:
    return reports.generate_report(req.report_type, req.period_start, req.period_end)


@app.post("/api/reports/annual")
async def report_annual(year: int | None = None) -> dict[str, Any]:
    return reports.annual_run(year)


@app.get("/api/reports/runs")
async def report_runs(limit: int = 50) -> dict[str, Any]:
    return {"runs": reports.list_runs(limit)}


# --- Annual scheduler endpoints (REQ-RCA-029/030/031/032) ---

def _try_signing_key_id() -> str | None:
    """Best-effort fetch of Ed25519 signing key id; None if not yet initialised."""
    try:
        meta = signing.public_key_metadata(Config.SIGNING_KEY_DIR)
        return meta.get("key_id")
    except Exception:  # noqa: BLE001
        return None


@app.post("/annual/run-now")
async def annual_run_now(req: AnnualRunRequest) -> dict[str, Any]:
    """Force generation of an annual report regardless of schedule.

    Body schema::
        {"report_type": "sox_attestation"|"nydfs_part500"|"eu_ai_act"|"naic_adverse_action_consolidated",
         "year": 2025}
    """
    rt = req.report_type
    year = req.year
    if year < 1970 or year > 2200:
        raise HTTPException(400, f"year out of range: {year}")

    period_start = f"{year}-01-01T00:00:00+00:00"
    period_end = f"{year}-12-31T23:59:59+00:00"

    if rt == "naic_adverse_action_consolidated":
        # Consolidated annual NAIC report — distinct from per-event artifacts
        result = reports.generate_report(
            "naic_adverse_action", period_start, period_end
        )
    elif rt in ANNUAL_REPORT_TYPES or rt == "naic_adverse_action":
        result = reports.generate_report(rt, period_start, period_end)
    else:
        raise HTTPException(400, f"unknown report_type: {rt}")

    if result.get("error"):
        raise HTTPException(500, str(result["error"]))

    return {
        "report_type": rt,
        "year": year,
        "artifact_path": result.get("artifact_path"),
        "artifact_sha256": result.get("artifact_sha256"),
        "signing_key_id": _try_signing_key_id(),
        "generated_at": result.get("generated_at"),
        "report_id": result.get("report_id"),
    }


@app.get("/annual/schedule")
async def annual_schedule() -> dict[str, Any]:
    """Show next-fire decision and last-run summary for each annual report type."""
    now = datetime.now(timezone.utc)
    out: list[dict[str, Any]] = []
    for rt in ANNUAL_REPORT_TYPES:
        last = _last_run_for(rt)
        due, reason = _annual_due(rt, now)
        # Estimate next deterministic check time = on the hour next interval
        interval_h = max(1, Config.ANNUAL_CHECK_HOURS)
        next_check = (now.replace(minute=0, second=0, microsecond=0)
                      + timedelta(hours=interval_h))
        out.append({
            "report_type": rt,
            "due_now": due,
            "due_reason": reason,
            "last_run": last,
            "next_scheduler_check_at": next_check.isoformat(),
            "target_year_if_fired": now.year - 1,
        })
    return {
        "as_of": now.isoformat(),
        "check_interval_hours": Config.ANNUAL_CHECK_HOURS,
        "signing_key_id": _try_signing_key_id(),
        "schedule": out,
    }


@app.get("/naic/recent")
async def naic_recent(days: int = Query(default=30, ge=1, le=3650)) -> dict[str, Any]:
    """List NAIC adverse-action artifacts detected within the lookback window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with closing(db.connect()) as conn:
        rows = conn.execute(
            "SELECT event_id, source_db, event_type, severity, agent_id, "
            "session_id, detected_at, artifact_path, artifact_sha256, generated_at "
            "FROM naic_actions WHERE detected_at >= ? "
            "ORDER BY detected_at DESC",
            (cutoff,),
        ).fetchall()
    actions = [dict(r) for r in rows]
    return {
        "window_days": days,
        "since": cutoff,
        "count": len(actions),
        "actions": actions,
    }


@app.post("/naic/scan-now")
async def naic_scan_now() -> dict[str, Any]:
    """Manually trigger a NAIC scan iteration (operator/test path)."""
    return run_naic_iteration()


# --- Cryptographic signing (REQ-RCA-013) ---

@app.get("/signing/public-key")
async def signing_public_key() -> dict[str, Any]:
    """Return the current Ed25519 public key for verifier consumption.

    Output includes hex, base64, and the 16-char key_id. The private key is
    NEVER exposed by this endpoint.
    """
    try:
        meta = signing.public_key_metadata(Config.SIGNING_KEY_DIR)
    except Exception as exc:  # noqa: BLE001
        # Try to lazily generate if missing
        try:
            signing.get_signing_key()
            meta = signing.public_key_metadata(Config.SIGNING_KEY_DIR)
        except Exception as exc2:  # noqa: BLE001
            raise HTTPException(
                500,
                f"signing key not available: {exc2 or exc}",
            ) from exc2
    return {
        **meta,
        "key_dir": str(Config.SIGNING_KEY_DIR),
    }


@app.post("/signing/verify")
async def signing_verify(req: SignatureVerifyRequest) -> dict[str, Any]:
    """Verify an Ed25519 signature against a canonical-JSON payload.

    The verifier resolves ``key_id`` to a public key by looking first at the
    current key on disk, then at any rotated key archived under
    ``<SIGNING_KEY_DIR>/archive/<key_id>/``.

    Returns
    -------
    valid : bool
        True iff the signature cryptographically validates against the
        resolved public key.
    key_matches : bool
        True iff the requested ``key_id`` was resolvable.
    resolved_public_key : str | None
        The hex-encoded public key used for verification, or None.
    """
    public_key_hex = signing.resolve_public_key(Config.SIGNING_KEY_DIR, req.key_id)
    if public_key_hex is None:
        return {
            "valid": False,
            "key_matches": False,
            "resolved_public_key": None,
            "reason": f"unknown key_id: {req.key_id}",
        }
    payload_bytes = req.payload_canonical_json.encode("utf-8")
    valid = signing.verify_signature(public_key_hex, payload_bytes, req.signature_hex)
    return {
        "valid": valid,
        "key_matches": True,
        "resolved_public_key": public_key_hex,
    }


# --- Aggregate dashboard for ops ---

@app.get("/api/dashboard")
async def dashboard() -> dict[str, Any]:
    return {
        "merkle_chain": merkle.verify_chain(),
        "merkle_roots_recent": merkle.list_roots(10),
        "retention_runs_recent": retention.list_runs(10),
        "active_holds": retention.list_holds(active_only=True),
        "dsr_pending": dsr_cascade.list_requests(status="received", limit=20),
        "report_runs_recent": reports.list_runs(10),
    }
