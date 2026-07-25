# Security Policy

## Supported Versions

Security fixes are applied to the latest release on the `main` branch. Older
releases do not receive backported fixes.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/bulletproofsoftware-ai/bulletproof-compliance-jobs/security/advisories/new)
("Report a vulnerability" on the repository's Security tab).

Include where possible:

1. **Affected component** — file, module, or endpoint
2. **Vulnerability class** — e.g. injection, SSRF, auth bypass, information disclosure
3. **Impact** — what an attacker can achieve
4. **Reproduction steps** — a minimal proof of concept
5. **Affected version** — git SHA or release tag

## Response Expectations

| Phase | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Triage and severity assignment | 7 days |
| Fix for critical/high issues | 30 days from triage |
| Coordinated disclosure | after a fix is available |

We support coordinated vulnerability disclosure and will credit reporters in
release notes unless anonymity is requested. We will not pursue legal action
against researchers acting in good faith under this policy.

## Scope Notes

- Vulnerabilities in third-party dependencies with an existing public CVE are
  tracked through the normal dependency-update workflow.
- Findings that require physical access to the host are out of scope.
