"""Per-class retention policy table — REQ-RCA-016.

Pure data. No I/O, no side effects. The orchestration layer in retention.py
imports `policy_for(class_name)` and `all_classes()` to drive the per-class
enforcement loop.

Retention horizons map to either calendar years (regulatory artifacts that must
survive 7-year SOX/GDPR/EU-AI-Act windows) or operational days (n8n execution
history is debugging telemetry, not a regulatory artifact).

Each policy entry contains:

class_name : str
    Stable identifier used by retention.py and the /retention/policy endpoint.

storage_kind : str
    One of {"sqlite_audit", "sqlite_local", "filesystem", "postgres", "qdrant"}.
    The orchestrator uses this to dispatch to the correct enforcement function.

storage_locator : str
    Path / DSN / collection name. Interpreted per storage_kind. Empty string
    means "discover at runtime" (e.g. multiple audit DBs from Config).

retention_days : int
    Hard horizon in days. 7 years = 2557 days (365.25 * 7 rounded). Operational
    classes use shorter windows and document them in the rationale.

action : str
    One of {"archive_then_delete", "archive_then_delete_keep_n", "delete_only"}.
    delete_only is reserved for purely operational telemetry (n8n) where archive
    overhead would dwarf the data value; it still emits an audit log entry
    counting deleted rows.

archive_prefix : str
    Used to name the JSONL.gz file under ARCHIVE_DIR.

regulatory : bool
    True if the data is subject to SOX/EU-AI-Act/NY-DFS/GDPR/NAIC retention
    requirements. False for operational telemetry that we keep only for
    debugging.

keep_newest : int | None
    For action="archive_then_delete_keep_n", the count of newest rows to
    preserve regardless of horizon. Used to maintain Merkle chain continuity
    so verifiers can always walk the chain backwards from "now" through at
    least N anchors, even if all N are technically past horizon.

rationale : str
    Operator-facing explanation suitable for /retention/policy JSON output.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


SEVEN_YEARS_DAYS = 2557  # 365.25 * 7, rounded down
NINETY_DAYS = 90


@dataclass(frozen=True)
class RetentionPolicy:
    class_name: str
    storage_kind: str
    storage_locator: str
    retention_days: int
    action: str
    archive_prefix: str
    regulatory: bool
    keep_newest: int | None
    rationale: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# All policies are declared here. Order is the execution order in run_retention.
# Audit DBs are first (highest regulatory priority), Merkle next (chain
# integrity), reports/NAIC after, then evidence files, then ops (n8n) last.
_POLICIES: tuple[RetentionPolicy, ...] = (
    # ----- Governance audit DB (signed audit_events) -----
    RetentionPolicy(
        class_name="audit_governance",
        storage_kind="sqlite_audit",
        storage_locator="/governance/audit.db",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="audit-governance",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "Governance audit_events table — primary control evidence for SOX 404, "
            "NY DFS Part 500, EU AI Act conformity. 7-year retention per regulatory "
            "minimums (SOX = 7y, NY DFS = 5y, GDPR Art. 30 = while processing "
            "ongoing + claims window). Archive as JSONL.gz before delete; legal "
            "holds (REQ-RCA-018) override delete."
        ),
    ),
    # ----- Runtime-security forensic + audit_events DB -----
    RetentionPolicy(
        class_name="audit_security_bus",
        storage_kind="sqlite_audit",
        storage_locator="/security/audit_bus.sqlite",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="audit-security-bus",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "runtime-security audit_bus.sqlite — guardian decisions and security "
            "events that fed the forensic record. 7-year retention because these "
            "events back NAIC adverse-action artifacts and EU AI Act post-market "
            "monitoring obligations. Mount must be RW for delete; if RO the "
            "orchestrator archives only and reports cannot_delete=true."
        ),
    ),
    # ----- Runtime-security forensic_events / threat_events / etc. -----
    RetentionPolicy(
        class_name="audit_security_runtime",
        storage_kind="sqlite_audit_multi",
        storage_locator="/security/runtime_security.sqlite",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="audit-security-runtime",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "runtime-security runtime_security.sqlite — threat_events, "
            "guardian_actions, memory_integrity_events, forensic_events, "
            "outbound_observations. Forensic-grade evidence. 7-year retention. "
            "Each table archived to its own JSONL.gz."
        ),
    ),
    # ----- Local Merkle roots (chain integrity) -----
    RetentionPolicy(
        class_name="merkle_roots",
        storage_kind="sqlite_local",
        storage_locator="merkle_roots",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete_keep_n",
        archive_prefix="merkle-roots",
        regulatory=True,
        keep_newest=100,
        rationale=(
            "Hourly Merkle roots — REQ-RCA-006. The chain must be walkable "
            "from any audit verification point back to a published anchor; we "
            "keep the newest 100 unconditionally to ensure chain continuity, "
            "and archive older entries to JSONL.gz before delete. 7-year "
            "regulatory horizon."
        ),
    ),
    # ----- Regulatory report runs + filesystem artifacts -----
    RetentionPolicy(
        class_name="regulatory_runs",
        storage_kind="sqlite_local",
        storage_locator="regulatory_runs",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="regulatory-runs",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "regulatory_runs DB rows + matching artifact files under "
            "/state/regulatory-reports/. Archives the row metadata AND moves "
            "the JSON artifact into /state/archive/regulatory-reports/. "
            "7-year retention."
        ),
    ),
    # ----- NAIC adverse-action artifacts -----
    RetentionPolicy(
        class_name="naic_actions",
        storage_kind="sqlite_local",
        storage_locator="naic_actions",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="naic-actions",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "NAIC adverse-action records (REQ-RCA-032). 7-year retention "
            "matches NAIC Model Act #2024-AI-01 record-keeping for "
            "non-discrimination decisions."
        ),
    ),
    # ----- Evidence files (signed regulatory artifacts) -----
    RetentionPolicy(
        class_name="evidence_files",
        storage_kind="filesystem",
        storage_locator="/state/regulatory-reports",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="evidence-files",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "Signed evidence packages on disk. Files older than horizon are "
            "moved to /state/archive/evidence-files/<YYYY>/ and gzipped in "
            "place; the original path is removed. 7-year retention."
        ),
    ),
    # ----- DSR confirmation artifacts (signed deletion proofs) -----
    RetentionPolicy(
        class_name="evidence_dsr_confirmations",
        storage_kind="filesystem",
        storage_locator="/state/dsr-confirmations",
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="evidence-dsr",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "GDPR Art. 17 deletion confirmation artifacts. Must be retained "
            "for 7 years as proof of compliance with erasure requests."
        ),
    ),
    # ----- Audit-bearing Qdrant collections -----
    RetentionPolicy(
        class_name="qdrant_audit_collections",
        storage_kind="qdrant",
        storage_locator=",".join((
            "audit_log",
            "forensic_events",
            "guardian_audit_log",
            "constitutional_assessments",
            "constitutional_contracts",
            "coordination_scores",
            "injection_signatures",
            "memory_quarantine",
            "memory_rejected",
            "process_knowledge",
            "obsidian_docs",
        )),
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="qdrant",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "Audit-bearing Qdrant collections. Points with payload "
            "created_at older than horizon are scrolled to JSONL.gz and "
            "deleted. Collections without created_at payloads are skipped "
            "(no horizon to evaluate). Operational ephemeral collections "
            "(claude_memories, episodes, etc.) are NOT in scope here."
        ),
    ),
    # ----- Postgres compliance-portal tables -----
    RetentionPolicy(
        class_name="postgres_compliance_portal",
        storage_kind="postgres",
        storage_locator=",".join((
            "evidence_packages",
            "human_gate_decisions",
            "incident_records",
            "dsr_requests",
            "model_cards",
            "audit_events",
        )),
        retention_days=SEVEN_YEARS_DAYS,
        action="archive_then_delete",
        archive_prefix="pg-compliance-portal",
        regulatory=True,
        keep_newest=None,
        rationale=(
            "Compliance-portal PostgreSQL — only confirmed regulatory tables. "
            "Operational tables (sessions, ui_state, etc.) are NOT in scope. "
            "If COMPLIANCE_PORTAL_DB_URL is unset or unreachable, this class "
            "is skipped gracefully."
        ),
    ),
    # ----- n8n execution history (OPERATIONAL, not regulatory) -----
    RetentionPolicy(
        class_name="n8n_executions",
        storage_kind="postgres",
        storage_locator="execution_entity",
        retention_days=NINETY_DAYS,
        action="archive_then_delete",
        archive_prefix="n8n-executions",
        regulatory=False,
        keep_newest=None,
        rationale=(
            "n8n workflow execution telemetry is DEBUGGING data, not a "
            "regulatory artifact. Default 90-day retention; configurable via "
            "N8N_RETENTION_DAYS env. We still archive to JSONL.gz before "
            "delete so executions remain recoverable for incident analysis. "
            "execution_data, execution_metadata, and execution_annotations "
            "cascade-delete via FK from execution_entity."
        ),
    ),
)


def all_classes() -> tuple[RetentionPolicy, ...]:
    """Return the full per-class policy tuple in execution order."""
    return _POLICIES


def policy_for(class_name: str) -> RetentionPolicy | None:
    """Lookup a single policy by class_name. Returns None if unknown."""
    for p in _POLICIES:
        if p.class_name == class_name:
            return p
    return None


def policy_table() -> list[dict[str, Any]]:
    """Return the policy table as a list of dicts — for /retention/policy."""
    return [p.as_dict() for p in _POLICIES]
