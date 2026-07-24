"""Compliance Jobs config — env-driven."""

from __future__ import annotations

import os
from pathlib import Path


class Config:
    # Storage
    SQLITE_PATH = Path(os.environ.get("SQLITE_PATH", "/state/compliance_jobs.sqlite"))

    # Audit bus sources — read from governance-plugin SQLite + runtime-security audit_bus
    AUDIT_BUS_DBS = [
        Path(p.strip()) for p in os.environ.get(
            "AUDIT_BUS_DBS",
            "/governance/audit.db,/security/audit_bus.sqlite"
        ).split(",") if p.strip()
    ]

    # Merkle root output (write-once attempt — append-only file with sequence number)
    MERKLE_ROOTS_DIR = Path(os.environ.get("MERKLE_ROOTS_DIR", "/state/merkle-roots"))

    # External write-once endpoint for Merkle root publishing (REQ-RCA-006)
    MERKLE_PUBLISH_URL = os.environ.get("MERKLE_PUBLISH_URL", "")
    MERKLE_PUBLISH_TOKEN = os.environ.get("MERKLE_PUBLISH_TOKEN", "")

    # Retention (REQ-RCA-016)
    AUDIT_RETENTION_YEARS = int(os.environ.get("AUDIT_RETENTION_YEARS", "7"))
    EVIDENCE_RETENTION_YEARS = int(os.environ.get("EVIDENCE_RETENTION_YEARS", "7"))
    LEGAL_HOLD_DIR = Path(os.environ.get("LEGAL_HOLD_DIR", "/state/legal-holds"))
    ARCHIVE_DIR = Path(os.environ.get("ARCHIVE_DIR", "/state/archive"))

    # DSR cascade endpoints
    QDRANT_URL = os.environ.get("QDRANT_URL", "http://qdrant:6333")
    QDRANT_API_KEY = os.environ.get("QDRANT_API_KEY", "")
    COMPLIANCE_PORTAL_URL = os.environ.get("COMPLIANCE_PORTAL_URL", "http://compliance-portal-internal:8001")
    COMPLIANCE_API_TOKEN = os.environ.get("COMPLIANCE_API_TOKEN", "")
    DSR_DELETION_CONFIRMATION_DIR = Path(os.environ.get("DSR_DELETION_CONFIRMATION_DIR", "/state/dsr-confirmations"))

    # Report scheduling
    REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/state/regulatory-reports"))
    REPORT_OPERATOR_ID = os.environ.get("REPORT_OPERATOR_ID", "compliance-jobs-system")

    # Cryptographic signing — Ed25519 (REQ-RCA-013)
    SIGNING_KEY_DIR = Path(os.environ.get("SIGNING_KEY_DIR", "/state/signing-keys"))

    # Cadence
    MERKLE_INTERVAL_MINUTES = int(os.environ.get("MERKLE_INTERVAL_MINUTES", "60"))
    RETENTION_INTERVAL_HOURS = int(os.environ.get("RETENTION_INTERVAL_HOURS", "24"))
    ANNUAL_CHECK_HOURS = int(os.environ.get("ANNUAL_CHECK_HOURS", "1"))
    NAIC_POLL_SECONDS = int(os.environ.get("NAIC_POLL_SECONDS", "300"))

    # Server
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "8087"))


def ensure_dirs() -> None:
    for d in (
        Config.SQLITE_PATH.parent,
        Config.MERKLE_ROOTS_DIR,
        Config.LEGAL_HOLD_DIR,
        Config.ARCHIVE_DIR,
        Config.DSR_DELETION_CONFIRMATION_DIR,
        Config.REPORTS_DIR,
        Config.SIGNING_KEY_DIR,
        Config.SIGNING_KEY_DIR / "archive",
    ):
        d.mkdir(parents=True, exist_ok=True)
