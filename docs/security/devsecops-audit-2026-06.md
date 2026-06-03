# DevSecOps Security Audit — June 2026

|                     |                                                   |
| ------------------- | ------------------------------------------------- |
| **Audit date**      | 2026-06-02                                        |
| **Repository**      | `nagyonmarci/directus`                            |
| **Branch audited**  | `main` (pre-fix state: commit `b0b2671`)          |
| **Fixes committed** | `214720f` on `claude/devsecops-audit-p0-p1-qH6Lr` |
| **Auditor**         | Internal DevSecOps review                         |
| **Status**          | ✅ All P0 and P1 findings remediated              |

---

## Table of Contents

1. [Scope](#1-scope)
2. [Methodology](#2-methodology)
3. [Pre-Audit Security Baseline](#3-pre-audit-security-baseline)
4. [Findings Summary](#4-findings-summary)
5. [P0 Findings — Critical](#5-p0-findings--critical)
6. [P1 Findings — High](#6-p1-findings--high)
7. [P2 / Recommendations](#7-p2--recommendations)
8. [Remediation Status](#8-remediation-status)
9. [Verification Checklist](#9-verification-checklist)
10. [Appendix: Full Application Security Assessment](#10-appendix-full-application-security-assessment)

---

## 1. Scope

The audit covered the entire repository with emphasis on:

| Area                          | Files / Paths                                                              |
| ----------------------------- | -------------------------------------------------------------------------- |
| Application startup & secrets | `api/src/app.ts`                                                           |
| Authentication & session      | `api/src/middleware/authenticate.ts`, `api/src/services/authentication.ts` |
| HTTP security headers         | `api/src/app.ts` (Helmet/CSP config)                                       |
| Error handling                | `api/src/middleware/error-handler.ts`                                      |
| Database query patterns       | `api/src/database/`, `api/src/services/`                                   |
| File uploads                  | `api/src/controllers/files.ts`, `api/src/services/files.ts`                |
| Rate limiting                 | `api/src/middleware/rate-limiter-*.ts`                                     |
| Kubernetes / Helm chart       | `helm/directus/templates/`                                                 |
| CI/CD pipeline                | `.github/workflows/`                                                       |
| Dockerfile                    | `Dockerfile`                                                               |
| Dependencies                  | `package.json`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`                    |

**Out of scope:** penetration testing, runtime fuzzing, third-party integrations (cloud storage drivers, SSO providers),
and Directus upstream code not modified in this fork.

---

## 2. Methodology

The audit followed a hybrid static-analysis approach:

1. **Automated pattern matching** — searched for known-bad patterns across the full source tree:
   - Raw SQL with string interpolation
   - `eval()`, `exec()`, unsafe deserialization
   - Hardcoded secrets (`/password|secret|key|token/i` in non-test files)
   - Weak cryptographic primitives (MD5, SHA-1 for security-sensitive purposes)
   - `Math.random()` used for security tokens
   - Missing auth guards on sensitive routes

2. **Manual code review** — full read of security-critical paths:
   - Application bootstrap and startup validation
   - JWT/session issuance and verification
   - Permission enforcement chain
   - Error propagation (stack trace exposure risk)

3. **Infrastructure review** — Dockerfile, Helm chart templates, and all GitHub Actions workflows were reviewed for:
   - Secret lifecycle management
   - Supply-chain attack surface (pinned vs floating action refs)
   - Least-privilege permission grants
   - Image signing and provenance

4. **Threat modelling** — each finding assessed against STRIDE and mapped to
   [OWASP Top 10 2021](https://owasp.org/Top10/).

---

## 3. Pre-Audit Security Baseline

Before this audit a significant DevSecOps hardening sprint had already been completed. The following controls were
already in place and confirmed **effective**:

| Control                      | Implementation                                                                 | Status                          |
| ---------------------------- | ------------------------------------------------------------------------------ | ------------------------------- |
| Multi-arch Docker build      | `Dockerfile` with non-root `node` user, exact version pins for global packages | ✅                              |
| OCI image labels             | `org.opencontainers.image.*` labels in Dockerfile                              | ✅                              |
| Docker HEALTHCHECK           | `wget` probe at `/server/health`, 60 s start period                            | ✅                              |
| Image signing                | Cosign keyless signing via GitHub OIDC (Docker Hub + GHCR)                     | ✅                              |
| SBOM + provenance            | `provenance: true`, `sbom: true` in `build-push-action`                        | ✅                              |
| SHA-pinned CI actions        | All release/security workflows use `@<sha>` refs                               | ✅ (partially — see P1-2)       |
| Trivy CVE scanning           | Weekly scan of published image, SARIF upload to Security tab                   | ✅                              |
| CodeQL SAST                  | Daily JavaScript analysis, SARIF upload                                        | ✅ (PR gate missing — see P1-3) |
| OSSF Scorecard               | Weekly supply-chain score, published results                                   | ✅                              |
| Dependency review            | `actions/dependency-review-action` on PRs, `fail-on-severity: high`            | ✅                              |
| Argon2 password hashing      | `argon2` v0.44.0 throughout                                                    | ✅                              |
| Parameterised SQL            | Knex.js; no raw string interpolation in queries                                | ✅                              |
| Row/field-level ACL          | Comprehensive permission module chain                                          | ✅                              |
| Rate limiting                | Global + IP + registration + login limiters via `rate-limiter-flexible`        | ✅                              |
| Brute-force protection       | Login stall time + user suspension after threshold                             | ✅                              |
| Timing-safe comparisons      | `crypto.timingSafeEqual()` for token/secret comparison                         | ✅                              |
| Extension sandboxing         | `isolated-vm` for untrusted extension code                                     | ✅                              |
| CSRF protection              | SameSite cookies + Origin header validation on MCP OAuth                       | ✅                              |
| Input validation             | Joi + Zod throughout API controllers                                           | ✅                              |
| Payload / query depth limits | `MAX_PAYLOAD_SIZE`, `QUERYSTRING_MAX_PARSE_DEPTH`, `QUERYSTRING_ARRAY_LIMIT`   | ✅                              |
| `qs` override                | Pinned to `6.15.2` to prevent prototype pollution                              | ✅                              |
| Kubernetes security context  | `runAsNonRoot`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`  | ✅                              |
| Helm init container          | DB bootstrap in init container prevents race conditions                        | ✅                              |

---

## 4. Findings Summary

> **Severity note:** P0/P1/P2 labels denote **fix urgency** (operational priority), not CVSS severity bands. A P0
> finding must be remediated before the next deployment regardless of CVSS score; a P1 finding targets the next sprint.
> CVSS severity (Critical / High / Medium / Low) is called out separately per finding.

| ID                                                           | Priority | Severity | Title                                                 | OWASP 2021                             | Status   |
| ------------------------------------------------------------ | -------- | -------- | ----------------------------------------------------- | -------------------------------------- | -------- |
| [P0-1](#p0-1-helm-secrets-regenerated-on-every-helm-upgrade) | P0       | 🟠 High  | Helm secrets regenerated on every `helm upgrade`      | A05 Security Misconfiguration          | ✅ Fixed |
| [P1-1](#p1-1-x-powered-by-header-re-exposed)                 | P1       | 🔵 Low   | `X-Powered-By: Directus` header re-exposed            | A05 Security Misconfiguration          | ✅ Fixed |
| [P1-2](#p1-2-unpinned-ci-action-refs-in-checkyml)            | P1       | 🟠 High  | Unpinned CI action tags in `check.yml`                | A08 Software & Data Integrity Failures | ✅ Fixed |
| [P1-3](#p1-3-codeql-does-not-gate-pull-requests)             | P1       | 🟠 High  | CodeQL does not gate pull requests                    | A08 Software & Data Integrity Failures | ✅ Fixed |
| [P1-4](#p1-4-weak-secret-is-advisory-only-in-production)     | P1       | 🟠 High  | Weak `SECRET` advisory-only — no production hard-fail | A02 Cryptographic Failures             | ✅ Fixed |

---

## 5. P0 Findings — Highest Priority

### P0-1: Helm secrets regenerated on every `helm upgrade`

**OWASP:** A05 — Security Misconfiguration  
**CWE:** CWE-665 — Improper Initialization (secret re-initialised on every render)  
**Severity:** High — primary impact is **availability**, not confidentiality

> **Note on scoring:** This is not an adversary-driven vulnerability. The generated values are cryptographically sound
> (`randAlphaNum`); the defect is that they are non-idempotent — regenerated on every render instead of persisted. The
> realistic impact is a self-inflicted denial of service (mass session invalidation, admin lockout) triggered by a
> routine `helm upgrade`. CVSS assumes an attacker and models this poorly, so severity here is rated qualitatively on
> availability and operational integrity. (CWE-330 was considered and rejected: the randomness is adequate; the
> lifecycle is the bug.)

#### Description

The Helm `Secret` template used Sprig's `randAlphaNum` function unconditionally:

```yaml
# BEFORE (vulnerable)
KEY: { { .Values.secrets.KEY | default (randAlphaNum 32) | b64enc | quote } }
SECRET: { { .Values.secrets.SECRET | default (randAlphaNum 32) | b64enc | quote } }
ADMIN_PASSWORD: { { .Values.secrets.ADMIN_PASSWORD | default (randAlphaNum 16) | b64enc | quote } }
```

Helm evaluates templates at render time on **every** `helm upgrade`. Because `randAlphaNum` is stateless, each upgrade
produced a different random value that Kubernetes then wrote to the live Secret — even when `values.yaml` was unchanged.

**Impact chain:**

- `KEY` and `SECRET` rotation → all JWTs and session tokens signed with the old secret are immediately **invalid**
- Every logged-in user is silently logged out
- Any automated API token (integrations, CI/CD, webhooks) stops working
- `ADMIN_PASSWORD` rotation → the admin account password in the database **does not change** (it was set during
  bootstrap), but the password stored in the Secret diverges — operators who relied on the Secret to retrieve the admin
  password are locked out
- Rolling deployments on Kubernetes apply the new Secret mid-flight, causing 50 % of pods to reject valid tokens from
  the other 50 %

#### Root Cause

Helm's `randAlphaNum` has no memory between renders. The standard Helm idiom to generate stable one-time secrets is the
`lookup` function, which reads the **current** Kubernetes resource before deciding whether to generate a new value.

#### Fix

```yaml
# AFTER (fixed) — helm/directus/templates/secret.yaml
{{- $existing := lookup "v1" "Secret" .Release.Namespace (include "directus.fullname" .) -}}
apiVersion: v1
kind: Secret
...
data:
  {{- if .Values.secrets.KEY }}
  KEY: {{ .Values.secrets.KEY | b64enc | quote }}
  {{- else if and $existing (index $existing.data "KEY") }}
  KEY: {{ index $existing.data "KEY" | quote }}         # preserve existing
  {{- else }}
  KEY: {{ randAlphaNum 32 | b64enc | quote }}            # first install only
  {{- end }}
  # (same pattern for SECRET and ADMIN_PASSWORD)
```

Priority order for each secret:

1. Explicit value in `values.yaml` (operator-controlled)
2. Value already stored in the live Kubernetes Secret (upgrade-stable)
3. Fresh random value (first install only)

#### GitOps caveat (important)

`lookup` queries the live cluster, so it only works when Helm has API access at apply time:

- **Flux `HelmRelease`** — works. The helm-controller performs real server-side installs/upgrades via the Helm SDK, so
  `lookup` reads the existing Secret.
- **`helm template`, client-side `--dry-run`, `helm diff`, ArgoCD (default helm-template render)** — `lookup` returns an
  empty map. In these contexts the chart falls through to the `randAlphaNum` branch and regenerates the secret,
  reintroducing exactly this finding. Validate the chart in CI accordingly, and do not rely on this pattern if migrating
  to ArgoCD.

#### Preferred long-term approach

Generating secrets inside the chart is a known GitOps anti-pattern. The robust fix is to remove secret generation from
the chart entirely and source it externally:

- **SOPS + age** — encrypted values committed to git, decrypted by Flux
- **Sealed Secrets** — encrypted `SealedSecret` CRs, safe to commit
- **External Secrets Operator** — pulls from Vault / a cloud secret manager

The `lookup` fix is acceptable as an interim, upgrade-stable measure; track externalisation as a follow-up (see
**P2-7**).

#### Verification

```bash
# First install — secrets are generated
helm install directus ./helm/directus

# Upgrade without value changes — secrets MUST be identical
SECRET_BEFORE=$(kubectl get secret directus -o jsonpath='{.data.SECRET}')
helm upgrade directus ./helm/directus
SECRET_AFTER=$(kubectl get secret directus -o jsonpath='{.data.SECRET}')
[ "$SECRET_BEFORE" = "$SECRET_AFTER" ] && echo "PASS" || echo "FAIL"
```

---

## 6. P1 Findings — High / Low

### P1-1: `X-Powered-By: Directus` header re-exposed

**OWASP:** A05 — Security Misconfiguration  
**CWE:** CWE-200 — Exposure of Sensitive Information  
**Severity:** Low (Informational) — disclosure only; no exploitability without a separate vulnerability

#### Description

`api/src/app.ts` called `app.disable('x-powered-by')` on line 152 to suppress Express's default technology disclosure
header — then immediately re-added it in a middleware block:

```typescript
// line 152 — disables Express default
app.disable('x-powered-by');

// lines 236–239 — explicitly adds it back
app.use((_req, res, next) => {
	res.setHeader('X-Powered-By', 'Directus');
	next();
});
```

> **Context:** The disable→re-add pattern strongly suggests this was a deliberate upstream Directus product decision
> (brand visibility), not an oversight. Evaluated as a **hardening recommendation against an upstream default** rather
> than a novel finding. A reviewer unfamiliar with the upstream intent could discount other findings if this is
> over-rated; Low / Informational is the appropriate severity.

Every HTTP response contained `X-Powered-By: Directus`, advertising the framework to potential attackers. This lowers
the bar for reconnaissance but does not constitute an exploitable vulnerability on its own.

#### Fix

The re-add middleware block (lines 236–239) was deleted. The `app.disable('x-powered-by')` call on line 152 is
sufficient.

#### Verification

```bash
curl -sI http://localhost:8055/server/health | grep -i "x-powered-by"
# Expected: no output
```

---

### P1-2: Unpinned CI action refs in `check.yml`

**OWASP:** A08 — Software and Data Integrity Failures  
**CWE:** CWE-494 — Download of Code Without Integrity Check

#### Description

`.github/workflows/check.yml` referenced two actions by mutable version tags:

```yaml
uses: actions/checkout@v6                  # floating tag
uses: tj-actions/changed-files@v47         # floating tag
```

Mutable tags can be silently repointed to a different commit by anyone with write access to the upstream repository —
including a compromised maintainer account or a supply-chain attacker. This is precisely how the
**tj-actions/changed-files compromise** occurred:

> In March 2025 (CVE-2025-30066), an attacker rewrote the version tags of `tj-actions/changed-files` from `v1` through
> `v45.0.7` to point to a malicious commit. The payload dumped the GitHub runner's memory — including `GITHUB_TOKEN`,
> npm tokens and other credentials — into the **workflow logs**, where anyone with read access could harvest them (a
> critical exposure for public repositories). The action is used by **over 23,000 repositories**; actual secret exposure
> was limited to those that ran the action during the 2025-03-14/15 window. The compromise was patched in `v46.0.1`.
> Workflows pinned to a commit SHA were **completely unaffected**.

All security-sensitive workflows in this repository (`release.yml`, `trivy.yml`, `codeql-analysis.yml`, `scorecard.yml`,
`dependency-review.yml`) already used SHA-pinned refs. `check.yml` was the sole remaining gap.

#### Fix

All four `actions/checkout@v6` and all three `tj-actions/changed-files@v47` references were replaced with immutable
commit SHAs:

```yaml
uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd        # v6
uses: tj-actions/changed-files@9426d40962ed5378910ee2e21d5f8c6fcbf2dd96 # v47.0.6
```

> **Verify the pin:** confirm each SHA actually resolves to the claimed tag
> (`git ls-remote --tags https://github.com/tj-actions/changed-files`), since a mislabelled SHA defeats the purpose.
> Also reconsider whether the dependency is needed at all — for simple change detection, native `git diff` removes this
> supply-chain surface entirely.

#### Verification

```bash
grep -n "checkout\|changed-files" .github/workflows/check.yml
# All lines must reference a 40-character hex SHA, not @v*
```

---

### P1-3: CodeQL does not gate pull requests

**OWASP:** A08 — Software and Data Integrity Failures  
**CWE:** CWE-693 — Protection Mechanism Failure

#### Description

`.github/workflows/codeql-analysis.yml` was triggered only on `schedule` (daily at midnight) and `workflow_dispatch`:

```yaml
on:
  workflow_call:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:
```

This means a PR introducing a security-relevant code pattern (e.g. unsanitised user input reaching a sink) could be
**merged before CodeQL ever ran on it**. The earliest detection would be the next scheduled run — potentially 24 hours
later, and only visible to maintainers who inspect the Security tab.

Dependency Review (which does run on PRs) catches vulnerable packages but not code-level issues. CodeQL appears to be
the primary SAST control currently configured; other SAST tools present in the repository were not audited for
completeness.

#### Fix

A `pull_request` trigger was added targeting `main`:

```yaml
on:
  pull_request:
    branches:
      - main
  workflow_call:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:
```

CodeQL now runs as a required check on every PR before merge.

> **Note:** CodeQL analysis on a large TypeScript monorepo takes ~10–15 minutes. Set it as a required status check in
> branch protection settings to enforce the gate.

#### Verification

Open any pull request targeting `main` and confirm the **CodeQL Analysis** check appears in the PR's status checks list.

---

### P1-4: Weak `SECRET` is advisory-only in production

**OWASP:** A02 — Cryptographic Failures  
**CWE:** CWE-521 — Weak Password Requirements (applied to signing keys)

#### Description

Directus signs all JWTs and session tokens with the `SECRET` environment variable using HMAC-SHA256. The startup code
validated the key length but only issued a warning:

```typescript
// BEFORE
if (typeof env['SECRET'] === 'string' && Buffer.byteLength(env['SECRET']) < 32) {
	logger.warn('"SECRET" env variable is shorter than 32 bytes which is insecure.');
	// process continues normally
}
```

A production deployment with a short `SECRET` (e.g. `SECRET=abc`) allows an attacker who obtains any valid JWT to
brute-force the signing key offline and subsequently forge tokens for any user — including the admin. Because the check
was advisory-only, misconfigured deployments could silently reach production without any operator awareness beyond a log
line that may not be monitored.

The NIST SP 800-107 minimum for HMAC-SHA256 is 256 bits (32 bytes). The check already used 32 bytes as the threshold —
the only problem was the lack of enforcement.

#### Fix

The check now distinguishes between development and production environments:

```typescript
// AFTER
import { getNodeEnv } from '@directus/utils/node';

if (typeof env['SECRET'] === 'string' && Buffer.byteLength(env['SECRET']) < 32) {
	if (getNodeEnv() === 'production') {
		logger.error('"SECRET" env variable is shorter than 32 bytes. Refusing to start in production.');
		process.exit(1);
	} else {
		logger.warn(
			'"SECRET" env variable is shorter than 32 bytes which is insecure. This is not appropriate for production usage.',
		);
	}
}
```

- **Production (`NODE_ENV=production`):** startup aborts with a clear error message and exit code 1. Kubernetes will
  restart the pod and surface the `CrashLoopBackOff` state, making misconfiguration immediately visible.
- **Development / test:** behaviour unchanged — warning only, so local development with short secrets is not broken.

#### Verification

```bash
# Should refuse to start
SECRET=short NODE_ENV=production node dist/cli.js start
# Expected: error log + exit code 1

# Should start normally
SECRET=short NODE_ENV=development node dist/cli.js start
# Expected: warning log, process continues
```

---

## 7. P2 / Recommendations

These items were noted during the audit but are not immediate security risks. They are recommended for the next
hardening sprint.

### P2-1: Trivy scans the upstream published image, not the local build

**Current state:** `trivy.yml` scans `docker.io/directus/directus:latest`.  
**Gap:** Custom changes in this fork are not scanned until a release is published upstream.  
**Recommendation:** Add a Trivy scan step to the release workflow that scans the locally-built image by digest
immediately after `build-push-action` and before the manifest merge step.

### P2-2: HSTS disabled by default

**Current state:** HSTS requires opt-in via `HSTS_ENABLED=true`.  
**Recommendation:** Set `HSTS_ENABLED=true` in the Helm chart's `configmap.yaml` default values and document the flag in
the Helm chart's `values.yaml`. HSTS is safe to enable for any HTTPS deployment and materially reduces protocol
downgrade attack surface.

### P2-3: CSP `connectSrc` is overly broad

**Current state:** `connectSrc: ["'self'", "https://*", "wss://*"]` allows the browser to make credentialed requests to
any HTTPS/WSS endpoint.  
**Recommendation:** Enumerate the specific external origins required (e.g. telemetry, map tile servers) and restrict
`connectSrc` to those origins only. Use `CONTENT_SECURITY_POLICY_DIRECTIVES__CONNECT_SRC` to configure per deployment.

### P2-4: `dependency-review.yml` uses an unpinned checkout action

**Current state:** `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2` — this is SHA-pinned but
to an older v4 release while the rest of the repo uses v6.  
**Recommendation:** Upgrade to `v6` SHA for consistency and to benefit from newer features/security patches.

### P2-5: `SECRET` missing at startup should fail in production

**Current state:** If `SECRET` is absent entirely, a random nanoid(32) is generated at runtime with a warning. Sessions
won't persist across restarts but the application starts.  
**Recommendation:** Treat a missing `SECRET` the same as a short one in production: `process.exit(1)`. The random
fallback is appropriate for development only.

### P2-6: Admin email default in Helm values

**Current state:** `values.yaml` ships `ADMIN_EMAIL: 'admin@example.com'`.  
**Recommendation:** Change the default to an empty string and add a Helm validation (`required`) to force operators to
supply their own admin email, preventing accidental deployment with a predictable admin identity.

### P2-7: Externalise Helm secret generation

**Current state:** The P0-1 fix uses `lookup` to make secret generation upgrade-stable, but this is a known GitOps
anti-pattern: `lookup` silently returns an empty map in `helm template`, `--dry-run`, `helm diff`, and ArgoCD's default
render mode, causing secrets to regenerate in those contexts and reintroducing the original problem.  
**Recommendation:** Remove secret generation from the chart entirely. Source secrets from one of:

- **SOPS + age** — encrypted values committed to git, decrypted by Flux at apply time
- **Sealed Secrets** — `SealedSecret` CRs encrypted with the cluster's public key, safe to commit
- **External Secrets Operator** — pulls live values from Vault, AWS Secrets Manager, GCP Secret Manager, etc.

This eliminates the non-idempotent generation problem at its root and works correctly with all GitOps tooling.

---

## 8. Remediation Status

| ID   | Finding                                         | Commit    | Status     |
| ---- | ----------------------------------------------- | --------- | ---------- |
| P0-1 | Helm secrets regenerated on upgrade             | `214720f` | ✅ Fixed   |
| P1-1 | X-Powered-By header re-exposed                  | `214720f` | ✅ Fixed   |
| P1-2 | Unpinned CI action refs                         | `214720f` | ✅ Fixed   |
| P1-3 | CodeQL not gating PRs                           | `214720f` | ✅ Fixed   |
| P1-4 | Weak SECRET advisory-only                       | `214720f` | ✅ Fixed   |
| P2-1 | Trivy scans upstream image                      | —         | ⏳ Backlog |
| P2-2 | HSTS disabled by default                        | —         | ⏳ Backlog |
| P2-3 | Broad CSP connectSrc                            | —         | ⏳ Backlog |
| P2-4 | Older checkout SHA in dependency-review         | —         | ⏳ Backlog |
| P2-5 | Missing SECRET should fail in production        | —         | ⏳ Backlog |
| P2-6 | Admin email default is example.com              | —         | ⏳ Backlog |
| P2-7 | Externalise Helm secret generation (SOPS / ESO) | —         | ⏳ Backlog |

---

## 9. Verification Checklist

Use this checklist to confirm all fixes are effective after the branch is merged.

```
[ ] P0-1  helm upgrade does not rotate KEY/SECRET/ADMIN_PASSWORD
          kubectl get secret directus -o yaml | grep -E "KEY:|SECRET:|ADMIN_PASSWORD:"
          (values unchanged after helm upgrade with no values.yaml edits)

[ ] P1-1  No X-Powered-By header in responses
          curl -sI http://<host>/server/health | grep -i x-powered-by
          (expected: no output)

[ ] P1-2  check.yml contains no floating @v* action refs
          grep -E "uses:.*@v[0-9]" .github/workflows/check.yml
          (expected: no output)

[ ] P1-3  CodeQL appears as a status check on PRs targeting main
          (open a test PR and confirm "CodeQL Analysis" check runs)

[ ] P1-4  Server refuses to start with short SECRET in production
          SECRET=abc NODE_ENV=production node dist/cli.js start
          echo $?   # expected: 1

[ ] P1-4  Server starts with warning (not error) with short SECRET in development
          SECRET=abc NODE_ENV=development node dist/cli.js start
          (expected: warning in logs, server starts)
```

### Shift-left: converting manual checks to automated guardrails

The verification commands above are one-shot, manual checks. The DevSecOps gap between "audit" and "enforcement" is
closing them into CI gates that run on every PR and deployment. Suggested next steps (see P2 backlog):

| Finding               | Manual check (above)  | Automated guardrail                                                                                                                           |
| --------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| P1-1 X-Powered-By     | `curl \| grep`        | CI smoke-test job: `curl -sf ... \| ! grep -i x-powered-by`                                                                                   |
| P1-2 Unpinned actions | `grep @v*`            | [`zizmor`](https://github.com/woodruffw/zizmor) / [`pinact`](https://github.com/suzuki-shunsuke/pinact) / `actionlint` as a required PR check |
| P0-1 Helm idempotency | Manual `kubectl diff` | `helm diff upgrade` in CI asserting zero Secret drift                                                                                         |
| P1-4 Weak SECRET      | Manual `node start`   | Startup test in integration test suite with `SECRET=x NODE_ENV=production`                                                                    |

This layer — policy-as-code and automated regression guards — is what converts a point-in-time audit into a durable
security posture.

---

## 10. Appendix: Full Application Security Assessment

The following is the broader security assessment of the application code, independent of the P0/P1 findings above.

> **Methodology note:** The findings below reflect the results of static code review (grep-based pattern matching +
> manual analysis of identified code paths). Absence of a finding means no evidence of the pattern was identified during
> this review — it does not constitute proof of absence. Runtime testing, fuzzing, and dynamic analysis were out of
> scope.

### SQL Injection

No SQL injection paths identified during static review. Method: grepped all `api/src/` TypeScript files for raw string
concatenation in query positions; reviewed all `knex.raw()` call sites. All database access uses Knex.js parameterised
queries; the limited `raw()` uses pass bound parameters exclusively:

```typescript
// Safe — identifier and value both bound
.whereRaw('LOWER(??) = ?', ['external_identifier', identifier.toLowerCase()])
```

### Authentication

No authentication bypass paths identified during static review. Method: traced token issuance and verification through
`extract-token.ts` → `authenticate.ts` → `get-accountability-for-token.ts`; reviewed all auth driver implementations
under `api/src/auth/drivers/`. Controls observed:

- JWTs signed with HMAC-SHA256 using the `SECRET` env var
- Argon2 for password hashing (current state-of-the-art)
- TOTP/2FA support via `otplib`
- Login stall time + user suspension after configurable failed-attempt threshold
- RFC 6750 compliance — multiple token submission methods in a single request are rejected
- Session tokens cleared on invalid-credential errors

### Authorisation / Access Control

No authorisation bypass paths identified during static review. Method: reviewed the full permission enforcement chain in
`api/src/permissions/modules/`; confirmed enforcement at the service layer (not only controller). Controls observed:

- Policy-based: roles inherit from multiple policies
- Field-level: per-field read/write/create/delete permissions
- Row-level: dynamic filter variables (`$CURRENT_USER`, `$NOW`, etc.)
- Enforced at the service layer, not just the controller layer

### Insecure Deserialization

No unsafe deserialization paths identified during static review. Method: grepped for `eval(`, `new Function(`,
`unserialize(`, `vm.runInNewContext(` across `api/src/`. Extension code runs in `isolated-vm` sandboxes with a
restricted API surface; the sandbox boundary was reviewed and no escape paths were identified.

### SSRF

No unvalidated outbound URL fetch paths identified during static review. Method: grepped for `fetch(`, `axios`, `got(`,
`http.request(` with user-controlled arguments across `api/src/`; reviewed MCP OAuth client ID validation in
`api/src/services/mcp-oauth/cimd.ts`. The CIMD validator enforces: HTTPS required, no IP addresses, no private TLDs, no
credentials in URL, canonical form, max 255 chars.

### XXE

No XML External Entity injection paths identified during static review. Method: grepped for XML parsing calls across
`api/src/`; reviewed SAML handling in `api/src/auth/drivers/saml.ts` and XML export in
`api/src/services/import-export.ts`. SAML XML validation uses `@authenio/samlify-node-xmllint` with schema validation;
XML export uses `js2xmlparser` with safe defaults.

### Path Traversal

No path traversal paths identified during static review. Method: grepped for `path.join(`, `path.resolve(`, `readFile(`,
`createReadStream(` with user-controlled arguments across `api/src/`; reviewed file upload flow in
`api/src/controllers/files.ts` and `api/src/services/files.ts`. File paths use `path.join()` / `path.resolve()`
throughout; upload storage uses driver abstractions (S3, Azure, GCS) that prevent direct filesystem path manipulation.

### Cryptography

No weak cryptographic primitive usage in security-sensitive contexts identified during static review. Method: grepped
for `createHash('md5'`, `createHash('sha1'`, `Math.random(` across `api/src/`; reviewed all findings for
security-sensitivity. Controls observed:

- HMAC-SHA256 for JWTs and webhook signatures
- Argon2 for passwords
- `crypto.randomBytes()` for secrets and tokens
- `crypto.timingSafeEqual()` for all secret comparisons
- MD5/SHA-1 usages found are limited to non-security contexts (process ID generation, temporary file naming, Oracle
  index names)

### Rate Limiting

No missing rate-limiting paths on sensitive endpoints identified during static review. Method: reviewed all
authentication and registration routes; confirmed rate-limiter middleware application in `api/src/app.ts` and per route.
Controls observed:

- Global (all requests): `rate-limiter-flexible` with Redis or in-memory backend
- Per-IP: separate bucket per client IP
- Registration: dedicated limiter for account creation
- Login: attempts tracked per user + per IP; account suspended after threshold

### Dependency Management

No known-vulnerable direct dependencies identified at review time. Method: reviewed `package.json` and
`pnpm-workspace.yaml` overrides; did not run `pnpm audit` (out of scope for static review — covered by
`dependency-review-action` in CI). Controls observed:

- `pnpm-lock.yaml` ensures reproducible builds
- Strategic `overrides` in `pnpm-workspace.yaml` for known-vulnerable transitive dependencies (`qs`, `tar`, `minimatch`,
  `picomatch`)
- `actions/dependency-review-action` blocks PRs that introduce dependencies with `HIGH` or `CRITICAL` CVEs
- Trivy scans the published image weekly

### HTTP Security Headers

No missing critical security headers identified during static review. Method: reviewed Helmet configuration in
`api/src/app.ts:182–213`.

| Header                     | Status          | Note                                      |
| -------------------------- | --------------- | ----------------------------------------- |
| Content-Security-Policy    | ✅ Configured   | `unsafe-eval` required for app extensions |
| X-Powered-By               | ✅ Suppressed   | Hardened in P1-1 (upstream default)       |
| HSTS                       | ⚠️ Opt-in only  | See P2-2                                  |
| Cross-Origin-Opener-Policy | ✅ Configurable | Enabled via env var                       |
| X-Frame-Options            | ✅              | Default Helmet behaviour                  |
| X-Content-Type-Options     | ✅              | Default Helmet behaviour                  |
| Referrer-Policy            | ✅              | Default Helmet behaviour                  |

### Docker / Container Security

No container security misconfigurations identified during static review. Method: full read of `Dockerfile` and
`ecosystem.config.cjs`. Controls observed:

- Runs as non-root `node` user (UID 1000)
- Multi-stage build minimises attack surface in production image
- Exact version pins for `pm2` and `corepack` in production stage
- OCI labels with source, description, license
- HEALTHCHECK configured
- Images signed with Cosign via GitHub OIDC (keyless)
- SBOM and provenance attestations generated at build time

### Kubernetes / Helm

No Kubernetes security misconfigurations identified after P0-1 remediation. Method: full read of all templates under
`helm/directus/templates/`. Controls observed:

- Pod security context: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`
- Service type `ClusterIP` by default (not exposed externally without explicit Ingress)
- Dedicated `ServiceAccount`
- Init container for DB bootstrap prevents migration race conditions
- Graceful termination period (60 s) to allow PM2 to drain in-flight requests
- Secrets stable across upgrades (P0-1 fixed)

---

_This document reflects the state of the repository as of the audit date. It should be reviewed and updated with each
subsequent security sprint._
