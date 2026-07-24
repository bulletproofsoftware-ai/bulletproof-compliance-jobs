# Security Scan Report: bulletproof-compliance-jobs

**Scan ID:** `a2050498-5798-4592-88d9-719068436b4a`
**Date:** 2026-07-24T22:37:36.928Z
**Score:** 1000/1000 (excellent)
**Branch:** main | **Commit:** `N/A`
**Profile:** standard

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 13 |
| Low | 13 |
| Info | 1 |
| **Total (open)** | **27** |

> **Note:** The counts above reflect _open_ findings only.
> 1 scanner(s) were skipped — see "Skipped Scanners" below.

## Scanners Executed

| Scanner | Status | Findings | Duration | Notes |
|---------|--------|----------|----------|-------|
| trivy | pass | 3 | 4.9s |  |
| gitleaks | pass | 0 | 0.8s |  |
| opengrep | pass | 2 | 10.3s |  |
| checkov | pass | 0 | 6.4s |  |
| grype | pass | 0 | 6.3s |  |
| syft | pass | 10 | 1.6s |  |
| package-validator | pass | 0 | 0.4s |  |
| oxlint | skipped | 0 | 0.0s | _skipped: no_matching_files_ |
| ruff | pass | 11 | 0.0s |  |
| actionlint | pass | 0 | 0.0s |  |
| jscpd | pass | 0 | 0.0s |  |
| typos | pass | 1 | 0.0s |  |
| _file_inventory | pass | 0 | 0.0s |  |

## Medium Findings (13)

### [MEDIUM] \`pathlib.Path\` imported but unused

- **File:** `tests/test_signing.py:18`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `pathlib.Path` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `pathlib.Path` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`os\` imported but unused

- **File:** `tests/test_signing.py:17`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `os` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `os` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`json\` imported but unused

- **File:** `tests/test_signing.py:16`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `json` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `json` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`app.config.Config\` imported but unused

- **File:** `tests/test_annual_scheduler.py:422`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `app.config.Config` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `app.config.Config` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`os\` imported but unused

- **File:** `tests/test_annual_scheduler.py:12`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `os` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `os` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`urllib.parse.quote\` imported but unused

- **File:** `app/retention.py:101`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `urllib.parse.quote` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `urllib.parse.quote` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`datetime.timedelta\` imported but unused

- **File:** `app/reports.py:14`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `datetime.timedelta` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `datetime.timedelta` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`fastapi.responses.JSONResponse\` imported but unused

- **File:** `app/main.py:25`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `fastapi.responses.JSONResponse` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `fastapi.responses.JSONResponse` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`hashlib\` imported but unused

- **File:** `app/main.py:16`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `hashlib` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `hashlib` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`httpx\` imported but unused

- **File:** `app/dsr_cascade.py:19`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `httpx` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `httpx` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`gzip\` imported but unused

- **File:** `app/dsr_cascade.py:9`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `gzip` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `gzip` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. \`uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608\`.

- **File:** `.github/workflows/ci.yml:12`
- **Scanner:** opengrep
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`
- **CWE:** [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
- **OWASP:** A08:2021 - Software and Data Integrity Failures

**What's wrong:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**Code:**
```yaml
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-gi

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. \`uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608\`.

- **File:** `.github/workflows/ci.yml:11`
- **Scanner:** opengrep
- **Rule:** `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`
- **CWE:** [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
- **OWASP:** A08:2021 - Software and Data Integrity Failures

**What's wrong:** GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-github-action compromises. Pin the reference to a full 40-character commit SHA instead, e.g. `uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608`.

**Code:**
```yaml
requires login
```

**How to fix:** Review this finding and apply the appropriate fix based on the description: GitHub Actions step uses a mutable tag or branch reference. Tags and branch names can be silently repointed by the action owner, enabling supply-chain attacks — as seen in the trivy-action and kics-gi

**Action:** Plan to fix this issue in your next sprint or release.

---

## Low Findings (13)

- **SBOM-LICENSE-UNKNOWN**: Unknown License: uvicorn@0.34.0 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: qdrant-client@1.12.1 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: pyyaml@6.0.2 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: pydantic@2.10.4 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: jinja2@3.1.6 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: httpx@0.28.1 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: fastapi@0.115.6 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: cryptography@48.0.1 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/setup-python@v5 (`/.github/workflows/ci.yml`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/checkout@v4 (`/.github/workflows/ci.yml`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in  (`LICENSE`)
- **LICENSE-BSD-3-Clause**: License Compliance: BSD-3-Clause in jinja2 (`requirements.txt`)
- **LICENSE-BSD-3-Clause**: License Compliance: BSD-3-Clause in httpx (`requirements.txt`)

## Skipped Scanners (1)

Scanners that did not run on this scan, with the reason why and how to enable them.

| Scanner | Reason | How to enable |
|---------|--------|---------------|
| `oxlint` | no_matching_files | No .js/.ts files found — Oxlint requires a JavaScript/TypeScript project |

## Recommendations

1. Update 3 vulnerable dependency/dependencies -- run `npm audit fix` or equivalent

---
*Generated by Code Hardener v0.1.0 | 2026-07-24T22:39:50.184Z*