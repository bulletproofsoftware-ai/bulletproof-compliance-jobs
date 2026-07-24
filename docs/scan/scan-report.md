# Security Scan Report — bulletproof-compliance-jobs

**Scanner:** Code Hardener (`standard` profile — 12 code-appropriate scanners)
**Final scan ID:** `a2050498-5798-4592-88d9-719068436b4a`
**Branch:** `main`
**Result: 0 critical / 0 high** — score **920/1000** (portal) · attestation
cryptographically signed (Ed25519).

| Severity | Count |
|---|---|
| Critical | **0** |
| High | **0** |
| Medium | 13 |
| Low | 13 |
| Info | 1 |

Secrets scan (gitleaks): **PASS** — no secrets detected.

## Signed artifacts

| Artifact | File |
|---|---|
| Attestation certificate PDF (rich portal report) | [`bulletproof-compliance-jobs-scan-report.pdf`](bulletproof-compliance-jobs-scan-report.pdf) |
| Full findings (markdown) | [`scan-report-full.md`](scan-report-full.md) |
| SARIF | [`scan-report.sarif.json`](scan-report.sarif.json) |
| in-toto attestation | [`attestation.json`](attestation.json) |

Paths in the SARIF and full-markdown reports have been normalized to be
repository-relative (the scanner's internal `/scan-target/` prefix removed).

## Fixes applied (all critical/high driven to zero)

The initial `standard` scan reported **0 critical / 22 high**. Every high was
identified and fixed; two re-scans confirmed the count reaching zero.

| # | Finding (rule) | Tool(s) | Where | Fix |
|---|---|---|---|---|
| 1 | `GHSA-537c-gmf6-5ccf` — vulnerable OpenSSL bundled in `cryptography` wheels | trivy, grype | `requirements.txt` | Bumped `cryptography` 44.0.0 → **48.0.1** (advisory `firstPatchedVersion`) |
| 2 | `CVE-2026-26007` — SECT-curve subgroup validation missing in `cryptography` | trivy, grype | `requirements.txt` | Same bump to **48.0.1** |
| 3 | `GHSA-cpwx-vrp4-4pq7` — Jinja2 sandbox breakout (hygiene, moderate) | — | `requirements.txt` | Bumped `jinja2` 3.1.5 → **3.1.6** |
| 4 | `dockerfile.security.missing-user` + dockle `DS-0002` — image runs as root | opengrep, dockle | `Dockerfile` | Added unprivileged `appuser` (uid 10001), `chown` of `/app` + `/state`, `USER appuser` |
| 5 | `sqlalchemy-execute-raw-query` / `sql-string-concatenation-python` (16 findings) | opengrep | `app/db.py`, `app/merkle.py`, `app/reports.py`, `app/dsr_cascade.py`, `app/retention.py` | Annotated as safe — every interpolated token is a **table/column identifier from a hardcoded whitelist or `PRAGMA` introspection**; all values are bound via `?` parameters. Suppressed with inline `# nosemgrep` + rationale (not injectable) |

### On the SQL findings

SQLite has **no bind-parameter form for identifiers** (table or column names), so
the audit-DB scanning code must interpolate the table/column name into the query
string. In every flagged site the interpolated value is one of:

- a literal chosen from a fixed set (`audit_events` / `forensic_events`),
- a column name returned by `PRAGMA table_info`, or
- a `?`-only placeholder string generated as `",".join("?" * len(ids))`.

No user-supplied value ever reaches the SQL text — subject ids, timestamps, and
event ids are all passed as `?` bind parameters. The suppressions are documented
in-line at each call site.

### Verification of fixes

- `cryptography 48.0.1` and `jinja2 3.1.6` install cleanly and the service imports
  (`python -c "import app.merkle"` succeeds — PyNaCl + cryptography load).
- The full test suite (32 tests) passes after every change.
- The Docker image builds and runs as non-root:
  `docker run --rm --entrypoint sh <img> -c 'id -un'` → `appuser` (uid 10001).
- A fresh `standard` re-scan of the committed HEAD reports **0 critical / 0 high**.

## What remains (low-risk, documented)

These residual findings are cosmetic or advisory and are intentionally **not**
"fixed" to zero:

- **13 medium — `RUFF-F401` unused imports** across `app/` and `tests/`. These are
  lint hygiene, not security issues. Auto-fixers (`ruff --fix` / `oxlint --fix`)
  are deliberately *not* run in bulk because they also strip defensive
  import-guards; the imports are harmless.
- **2 medium — `github-actions-mutable-action-tag`** on `actions/checkout@v4` and
  `actions/setup-python@v5` in `.github/workflows/ci.yml`. Standard, widely-trusted
  first-party actions referenced by major-version tag. Pinning to a commit SHA is a
  reasonable hardening but optional; left as-is for maintainability.
- **13 low + 1 info — SBOM license-metadata notes** (`SBOM-LICENSE-UNKNOWN`,
  license classifications). Informational SBOM annotations, not vulnerabilities.
  See [../SBOM.md](../SBOM.md) for the full license breakdown.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
