"""Tests for the annual report scheduler and NAIC adverse-action listener.

REQ-RCA-029  SOX management attestation auto-fire
REQ-RCA-030  NY DFS Part 500 auto-fire
REQ-RCA-031  EU AI Act conformity declaration auto-fire
REQ-RCA-032  NAIC adverse-action auto-population
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


# The operator API is authenticated (every route but /health*, /readyz), and the
# service fails closed when no token is configured. Tests therefore have to
# supply one and present it, the same as any real caller.
_TEST_TOKEN = "test-compliance-jobs-token"
_AUTH = {"Authorization": f"Bearer {_TEST_TOKEN}"}


# ---------------------------------------------------------------------------
# Pin every Path Config touches into the per-test tmpdir BEFORE importing
# any app.* module. Config evaluates env-driven Paths at class definition,
# so we set them via env before import.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    state.mkdir()
    gov_db = state / "audit.db"
    sec_db = state / "audit_bus.sqlite"

    monkeypatch.setenv("SQLITE_PATH", str(state / "compliance_jobs.sqlite"))
    monkeypatch.setenv("AUDIT_BUS_DBS", f"{gov_db},{sec_db}")
    monkeypatch.setenv("MERKLE_ROOTS_DIR", str(state / "merkle-roots"))
    monkeypatch.setenv("LEGAL_HOLD_DIR", str(state / "legal-holds"))
    monkeypatch.setenv("ARCHIVE_DIR", str(state / "archive"))
    monkeypatch.setenv("DSR_DELETION_CONFIRMATION_DIR", str(state / "dsr-conf"))
    monkeypatch.setenv("REPORTS_DIR", str(state / "regulatory-reports"))
    monkeypatch.setenv("SIGNING_KEY_DIR", str(state / "signing-keys"))
    monkeypatch.setenv("ANNUAL_CHECK_HOURS", "1")
    monkeypatch.setenv("NAIC_POLL_SECONDS", "300")
    monkeypatch.setenv("COMPLIANCE_JOBS_TOKEN", _TEST_TOKEN)

    # Drop any cached Config / app modules so they re-read env
    for mod in list(sys.modules):
        if mod.startswith("app.") or mod == "app":
            del sys.modules[mod]

    return state


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _create_gov_audit_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            audit_session_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            manifest_id TEXT,
            manifest_version TEXT,
            manifest_hash TEXT,
            trust_level INTEGER,
            data_classification TEXT,
            autonomy_depth_remaining INTEGER,
            tool_name TEXT,
            task_id TEXT,
            target_agent_id TEXT,
            context_hash TEXT,
            detail TEXT,
            outcome TEXT
        );
        CREATE INDEX idx_audit_session ON audit_events(audit_session_id);
        CREATE INDEX idx_audit_type ON audit_events(event_type);
        """
    )
    conn.commit()
    conn.close()


def _insert_gov_event(
    path: Path,
    *,
    event_type: str,
    outcome: str = "deny",
    agent_id: str = "test-agent",
    detail: str = "{}",
) -> str:
    eid = str(uuid.uuid4())
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        INSERT INTO audit_events (event_id, timestamp, audit_session_id,
            event_type, agent_id, outcome, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            eid,
            datetime.now(timezone.utc).isoformat(),
            "session-" + eid[:8],
            event_type,
            agent_id,
            outcome,
            detail,
        ),
    )
    conn.commit()
    conn.close()
    return eid


def _create_sec_audit_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            agent_id TEXT,
            session_id TEXT,
            severity TEXT,
            payload_json TEXT NOT NULL,
            source_service TEXT NOT NULL DEFAULT 'runtime-security'
        );
        """
    )
    conn.commit()
    conn.close()


def _insert_sec_event(
    path: Path,
    *,
    event_type: str,
    severity: str,
    agent_id: str = "test-agent",
    payload: dict | None = None,
) -> str:
    eid = str(uuid.uuid4())
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        INSERT INTO audit_events
            (event_id, event_type, timestamp, agent_id, session_id,
             severity, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            eid,
            event_type,
            datetime.now(timezone.utc).isoformat(),
            agent_id,
            "session-" + eid[:8],
            severity,
            json.dumps(payload or {}),
        ),
    )
    conn.commit()
    conn.close()
    return eid


# ---------------------------------------------------------------------------
# NAIC adverse-action loop tests (REQ-RCA-032)
# ---------------------------------------------------------------------------

def test_naic_processes_governance_deny_event(_isolated_state: Path) -> None:
    from app import db, main
    from app.config import Config

    _create_gov_audit_db(Config.AUDIT_BUS_DBS[0])
    _create_sec_audit_db(Config.AUDIT_BUS_DBS[1])

    db.init()

    eid = _insert_gov_event(
        Config.AUDIT_BUS_DBS[0],
        event_type="policy_deny",
        outcome="deny",
    )

    result = main.run_naic_iteration()
    assert result["new_artifacts"] == 1, result
    assert result["actions"][0]["event_id"] == eid

    # Artifact must exist on disk
    artifact = Path(result["actions"][0]["artifact_path"])
    assert artifact.exists(), f"artifact missing: {artifact}"
    body = json.loads(artifact.read_text())
    assert body["type"] == "naic_adverse_action"

    # Tracking row inserted
    with sqlite3.connect(str(Config.SQLITE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM naic_actions WHERE event_id = ?", (eid,)
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["event_type"] == "policy_deny"


def test_naic_processes_security_threat_event(_isolated_state: Path) -> None:
    from app import db, main
    from app.config import Config

    _create_gov_audit_db(Config.AUDIT_BUS_DBS[0])
    _create_sec_audit_db(Config.AUDIT_BUS_DBS[1])

    db.init()

    eid = _insert_sec_event(
        Config.AUDIT_BUS_DBS[1],
        event_type="threat.injection.detected",
        severity="critical",
        payload={"threat_id": "abc", "handled": True},
    )

    result = main.run_naic_iteration()
    assert result["new_artifacts"] == 1, result
    assert result["actions"][0]["event_id"] == eid


def test_naic_idempotent_across_runs(_isolated_state: Path) -> None:
    """Running the loop twice must not duplicate artifacts."""
    from app import db, main
    from app.config import Config

    _create_gov_audit_db(Config.AUDIT_BUS_DBS[0])
    _create_sec_audit_db(Config.AUDIT_BUS_DBS[1])

    db.init()

    eid = _insert_gov_event(
        Config.AUDIT_BUS_DBS[0],
        event_type="security.threat_detected",
        outcome="deny",
    )

    first = main.run_naic_iteration()
    second = main.run_naic_iteration()

    assert first["new_artifacts"] == 1
    assert second["new_artifacts"] == 0, "second pass must skip already-processed event"
    assert second["skipped_already_tracked"] >= 1

    with sqlite3.connect(str(Config.SQLITE_PATH)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM naic_actions WHERE event_id = ?", (eid,)
        ).fetchone()[0]
    assert n == 1, "must be exactly one tracking row per event"


def test_naic_skips_low_severity_security_events(_isolated_state: Path) -> None:
    """info/medium severity in the security bus must not produce artifacts."""
    from app import db, main
    from app.config import Config

    _create_gov_audit_db(Config.AUDIT_BUS_DBS[0])
    _create_sec_audit_db(Config.AUDIT_BUS_DBS[1])

    db.init()

    _insert_sec_event(
        Config.AUDIT_BUS_DBS[1],
        event_type="threat.injection.detected",
        severity="info",
    )

    result = main.run_naic_iteration()
    assert result["new_artifacts"] == 0, result


def test_naic_handles_missing_audit_dbs(_isolated_state: Path) -> None:
    """Loop must not crash when audit DBs do not exist on disk."""
    from app import db, main

    # Do NOT create either audit DB
    db.init()

    # Should be a clean no-op rather than raising
    result = main.run_naic_iteration()
    assert result["new_artifacts"] == 0
    assert result["skipped_already_tracked"] == 0


# ---------------------------------------------------------------------------
# Annual scheduler tests (REQ-RCA-029/030/031)
# ---------------------------------------------------------------------------

def test_annual_due_when_never_run(_isolated_state: Path) -> None:
    from app import db, main

    db.init()
    now = datetime.now(timezone.utc)

    due, reason = main._annual_due("sox_attestation", now)
    assert due is True
    assert reason == "never_run"


def test_annual_due_when_stale(_isolated_state: Path) -> None:
    """SOX run > 365 days ago must trigger re-fire."""
    from app import db, main
    from app.config import Config

    db.init()
    now = datetime.now(timezone.utc)
    stale_ts = (now - timedelta(days=400)).isoformat()
    period_year = now.year - 2  # last covered year

    with sqlite3.connect(str(Config.SQLITE_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO regulatory_runs
                (report_type, period_start, period_end, artifact_path,
                 signed, operator_id, generated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "sox_attestation",
                f"{period_year}-01-01T00:00:00+00:00",
                f"{period_year}-12-31T23:59:59+00:00",
                "/tmp/fake.json",
                1,
                "test",
                stale_ts,
            ),
        )
        conn.commit()

    due, reason = main._annual_due("sox_attestation", now)
    assert due is True, reason
    assert (
        reason.startswith("stale_")
        or reason.startswith("no_run_for_target_year_")
    )


def test_annual_skipped_when_recent(_isolated_state: Path) -> None:
    """Recent SOX run (within 365 days, current target year) must skip."""
    from app import db, main
    from app.config import Config

    db.init()
    now = datetime.now(timezone.utc)
    recent_ts = (now - timedelta(days=30)).isoformat()
    target_year = now.year - 1  # what scheduler would generate

    with sqlite3.connect(str(Config.SQLITE_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO regulatory_runs
                (report_type, period_start, period_end, artifact_path,
                 signed, operator_id, generated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "sox_attestation",
                f"{target_year}-01-01T00:00:00+00:00",
                f"{target_year}-12-31T23:59:59+00:00",
                "/tmp/fake.json",
                1,
                "test",
                recent_ts,
            ),
        )
        conn.commit()

    due, reason = main._annual_due("sox_attestation", now)
    assert due is False, f"should skip; got reason={reason}"
    assert reason == "current"


def test_annual_due_when_year_boundary_crossed(_isolated_state: Path) -> None:
    """Last run covered year N-2; today is in year N → must re-fire for year N-1."""
    from app import db, main
    from app.config import Config

    db.init()
    now = datetime.now(timezone.utc)
    # Pretend the most recent run was 200 days ago (still <365) but covered an old period
    recent_ts = (now - timedelta(days=200)).isoformat()
    old_year = now.year - 3

    with sqlite3.connect(str(Config.SQLITE_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO regulatory_runs
                (report_type, period_start, period_end, artifact_path,
                 signed, operator_id, generated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "sox_attestation",
                f"{old_year}-01-01T00:00:00+00:00",
                f"{old_year}-12-31T23:59:59+00:00",
                "/tmp/fake.json",
                1,
                "test",
                recent_ts,
            ),
        )
        conn.commit()

    due, reason = main._annual_due("sox_attestation", now)
    assert due is True
    assert reason.startswith("no_run_for_target_year_")


def test_generate_annual_creates_artifact(_isolated_state: Path) -> None:
    from app import db, main
    from app.config import Config

    db.init()
    year = datetime.now(timezone.utc).year - 1
    result = main._generate_annual("sox_attestation", year)
    assert "error" not in result
    artifact = Path(result["artifact_path"])
    assert artifact.exists()
    body = json.loads(artifact.read_text())
    assert body["type"] == "sox_attestation"
    assert body["period"]["start"].startswith(str(year))
    assert body["period"]["end"].startswith(str(year))


def test_annual_loop_fires_for_missing_run_via_helpers(_isolated_state: Path) -> None:
    """Mock regulatory_runs (no SOX) → helpers signal due → generate → row appears."""
    from app import db, main
    from app.config import Config

    db.init()
    now = datetime.now(timezone.utc)

    # No prior runs anywhere
    due, _ = main._annual_due("sox_attestation", now)
    assert due is True

    res = main._generate_annual("sox_attestation", now.year - 1)
    assert "error" not in res

    with sqlite3.connect(str(Config.SQLITE_PATH)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM regulatory_runs WHERE report_type='sox_attestation'"
        ).fetchone()[0]
    assert n == 1


# ---------------------------------------------------------------------------
# AnnualRunRequest endpoint contract sanity
# ---------------------------------------------------------------------------

def test_annual_run_now_validation_rejects_unknown_type(_isolated_state: Path) -> None:
    from fastapi.testclient import TestClient
    from app import main

    with TestClient(main.app) as client:
        resp = client.post(
            "/annual/run-now",
            json={"report_type": "bogus", "year": 2025},
            headers=_AUTH,
        )
        assert resp.status_code == 400


def test_annual_run_now_generates_sox(_isolated_state: Path) -> None:
    from fastapi.testclient import TestClient
    from app import main

    with TestClient(main.app) as client:
        resp = client.post(
            "/annual/run-now",
            json={"report_type": "sox_attestation", "year": 2025},
            headers=_AUTH,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["report_type"] == "sox_attestation"
        assert body["year"] == 2025
        assert body["artifact_path"]
        assert Path(body["artifact_path"]).exists()


def test_annual_schedule_lists_three_types(_isolated_state: Path) -> None:
    from fastapi.testclient import TestClient
    from app import main

    with TestClient(main.app) as client:
        resp = client.get("/annual/schedule", headers=_AUTH)
        assert resp.status_code == 200
        body = resp.json()
        types = {item["report_type"] for item in body["schedule"]}
        assert types == {"sox_attestation", "nydfs_part500", "eu_ai_act"}


def test_naic_recent_endpoint_returns_window(_isolated_state: Path) -> None:
    from fastapi.testclient import TestClient
    from app import db, main
    from app.config import Config

    _create_gov_audit_db(Config.AUDIT_BUS_DBS[0])
    _create_sec_audit_db(Config.AUDIT_BUS_DBS[1])
    db.init()
    _insert_gov_event(Config.AUDIT_BUS_DBS[0], event_type="policy_deny", outcome="deny")

    with TestClient(main.app) as client:
        # Trigger the scan
        scan = client.post("/naic/scan-now", headers=_AUTH)
        assert scan.status_code == 200
        assert scan.json()["new_artifacts"] == 1

        # Now query the listing endpoint
        resp = client.get("/naic/recent?days=30", headers=_AUTH)
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] >= 1
        assert body["actions"][0]["event_type"] == "policy_deny"


# ---------------------------------------------------------------------------
# Operator API authentication (df2b7a0)
# ---------------------------------------------------------------------------

def test_operator_api_rejects_unauthenticated_calls(_isolated_state: Path) -> None:
    """Every destructive route was reachable unauthenticated before df2b7a0.

    The suite now sends a token everywhere, so without this test a regression
    that removed the middleware would go unnoticed — all the other tests would
    still pass.
    """
    from fastapi.testclient import TestClient
    from app import main

    with TestClient(main.app) as client:
        for method, path in [
            ("post", "/annual/run-now"),
            ("get", "/annual/schedule"),
            ("post", "/naic/scan-now"),
            ("get", "/naic/recent?days=30"),
        ]:
            kwargs = {"json": {}} if method == "post" else {}
            resp = getattr(client, method)(path, **kwargs)
            assert resp.status_code == 401, f"{method.upper()} {path} -> {resp.status_code}"


def test_operator_api_rejects_a_wrong_token(_isolated_state: Path) -> None:
    from fastapi.testclient import TestClient
    from app import main

    with TestClient(main.app) as client:
        resp = client.get("/annual/schedule", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401


def test_health_endpoints_stay_public(_isolated_state: Path) -> None:
    from fastapi.testclient import TestClient
    from app import main

    with TestClient(main.app) as client:
        assert client.get("/health").status_code == 200


def test_service_fails_closed_when_no_token_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unset token must refuse everything (503), not open the API."""
    monkeypatch.delenv("COMPLIANCE_JOBS_TOKEN", raising=False)
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "cj.sqlite"))
    for mod in list(sys.modules):
        if mod.startswith("app.") or mod == "app":
            del sys.modules[mod]

    from fastapi.testclient import TestClient
    from app import main

    with TestClient(main.app) as client:
        resp = client.get("/annual/schedule")
        assert resp.status_code == 503
        assert "COMPLIANCE_JOBS_TOKEN is not set" in resp.json()["detail"]
