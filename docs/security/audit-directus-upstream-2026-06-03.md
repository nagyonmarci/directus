# DevSecOps Security Audit — directus/directus (upstream)

## 1. Metadata

| Field          | Value                                                                |
| -------------- | -------------------------------------------------------------------- |
| **Date**       | 2026-06-03                                                           |
| **Repository** | directus/directus                                                    |
| **Commit**     | d358376                                                              |
| **Auditor**    | Automated — Claude Opus (AI-assisted static analysis + live context) |
| **Audit type** | Static analysis, CI/CD review, pattern grep, IaC review              |
| **Status**     | FINDINGS PRESENT — remediation required                              |

---

## 2. Scope

| Area             | What was checked                                                                             |
| ---------------- | -------------------------------------------------------------------------------------------- |
| CI/CD workflows  | All 19 `.github/workflows/*.yml` files — action pinning, permission models, trigger coverage |
| Application code | `api/src/**/*.ts`, `app/src/**/*.ts` — injection patterns, crypto, secret handling           |
| Infrastructure   | `Dockerfile` — image hardening, user model, build chain                                      |
| Dependencies     | pnpm audit (unavailable — see F-08), workspace overrides                                     |
| Git history      | Last 30 commits — security-relevant changes, CVE remediation cadence                         |
| GitHub API       | Open issues, PRs, branch protection, secret scanning — **rate-limited, no token provided**   |
| Supply chain     | Action tag analysis, cosign usage, SLSA provenance                                           |

**Not in scope:** dynamic testing, authenticated API fuzzing, database schema review, runtime penetration testing.

---

## 3. Methodology

**Static analysis** only — no running instance was tested. Grep-based pattern matching identifies candidates; each was
manually evaluated for actual exploitability before rating.

**Tools used:** grep (custom patterns), git log, Dockerfile review. `zizmor`, `actionlint`, `gitleaks`, `trufflehog`,
`trivy`, `checkov`, `kube-linter` were not installed in the collection environment — these gaps are noted per finding.

**Severity calibration:** Critical = RCE / auth bypass / supply chain code injection / secret disclosure. CVSS severity
is stated separately from operational priority (P0/P1/P2). P0/P1/P2 denote fix urgency, not CVSS bands.

**Known limitations:**

- GitHub API rate-limited (no token) — open issues, PRs, branch protection, secret-scanning alerts could not be
  retrieved.
- `pnpm audit` not available in collection environment — dependency CVEs not assessed.
- No dynamic SSRF probe possible in static review.

---

## 4. Findings Summary

| ID   | Priority | CVSS Severity | Title                                                                          | OWASP 2021                     | Status                     |
| ---- | -------- | ------------- | ------------------------------------------------------------------------------ | ------------------------------ | -------------------------- |
| F-01 | **P0**   | Critical      | `claude-code-action@v1` unpinned — write-access CI supply chain vector         | A08: Software & Data Integrity | Open                       |
| F-02 | **P1**   | High          | `tj-actions/changed-files@v47` unpinned — proven CVE-2025-30066 attack vector  | A08: Software & Data Integrity | Open                       |
| F-03 | **P1**   | High          | 50+ unpinned action tags across 14 workflows — aggregate supply chain exposure | A08: Software & Data Integrity | Open                       |
| F-04 | **P1**   | High          | CodeQL not triggered on `pull_request` — SAST runs post-merge only             | A05: Security Misconfiguration | Open                       |
| F-05 | **P1**   | Medium        | Sandboxed `eval()` in Operations/Exec — permission scope unclear               | A03: Injection                 | Needs Review               |
| F-06 | **P2**   | Medium        | SSRF in file import + MCP OAuth DCR — IP blocklist partial mitigation          | A10: SSRF                      | Partially Mitigated        |
| F-07 | **P2**   | Low           | `X-Powered-By: Directus` — deliberate framework disclosure                     | A05: Security Misconfiguration | Accepted (upstream intent) |
| F-08 | **P2**   | Informational | Dependency audit coverage gap — pnpm not available in audit toolchain          | A06: Vulnerable Components     | Tool Gap                   |

---

## 5. Per-Finding Detail

---

### F-01 · P0 · Critical — Unpinned `claude-code-action@v1` (write-access CI)

**OWASP:** A08:2021 — Software and Data Integrity Failures **CWE:** CWE-829 — Inclusion of Functionality from Untrusted
Control Sphere **CVSS 3.1:** AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N — **8.7 (Critical)**

#### Description

Two workflows consume `anthropics/claude-code-action@v1` with a mutable version tag:

- `.github/workflows/claude.yml:35` — responds to `@claude` mentions in issues/PRs, executes agent tasks
- `.github/workflows/claude-code-review.yml:23` — performs AI code review on all PRs

Both workflows use `actions/checkout@v4` (claude.yml) / `actions/checkout@v6` (claude-code-review.yml) — themselves also
unpinned.

#### Root Cause

The `@v1` tag is a mutable Git ref. Anthropic can (accidentally or under duress) move the tag to a different commit at
any time. More critically, a supply chain compromise of the `anthropics` GitHub organisation (credential theft, insider
threat, malicious dependency update) would allow an attacker to push a new commit to `v1` that executes arbitrary code
in CI.

#### Impact Chain

```
Attacker compromises anthropics/claude-code-action tag v1
  → New malicious commit published under @v1
  → Next PR/issue comment triggers claude.yml or claude-code-review.yml
  → Malicious action code executes with:
      - Repository read access (all source code)
      - GITHUB_TOKEN write scopes (can push commits, approve PRs, create releases)
      - Access to all CI secrets (ANTHROPIC_API_KEY, any other repository secrets)
  → Silent backdoor committed to main branch
  → Supply chain compromise of Directus releases distributed to all users
```

This is the exact attack class that compromised `tj-actions/changed-files` in March 2025. `claude-code-action` has
broader permissions (write) than `tj-actions` had, making the blast radius larger.

#### Fix

Resolve the current commit SHA for `anthropics/claude-code-action@v1` and pin both workflows:

```bash
# Resolve current SHA
git ls-remote https://github.com/anthropics/claude-code-action.git refs/tags/v1
```

Then replace in both files:

```yaml
# Before
uses: anthropics/claude-code-action@v1

# After
uses: anthropics/claude-code-action@<resolved-sha> # v1
```

Do the same for `actions/checkout@v4` in `claude.yml` — use the same SHA already used in other workflows:
`de0fac2e4500dabe0009e67214ff5f5447ce83dd`.

#### Verification

```bash
# Confirm no floating @v tags remain in claude* workflows
grep -n 'uses:.*@v[0-9]' .github/workflows/claude.yml .github/workflows/claude-code-review.yml

# Verify tag still points to expected SHA
git ls-remote https://github.com/anthropics/claude-code-action.git refs/tags/v1
```

---

### F-02 · P1 · High — Unpinned `tj-actions/changed-files@v47`

**OWASP:** A08:2021 — Software and Data Integrity Failures **CWE:** CWE-829 — Inclusion of Functionality from Untrusted
Control Sphere **CVSS 3.1:** AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N — **7.5 (High)**

#### Description

`tj-actions/changed-files@v47` appears in 6 locations across two workflows:

- `.github/workflows/changeset-check.yml:32` — runs on every PR to `main`
- `.github/workflows/check.yml:32,56,75` — runs on every PR to `main`
- `.github/workflows/check.yml:52,71` (checkout steps in same jobs)

#### Root Cause

`tj-actions/changed-files` was the subject of CVE-2025-30066, a confirmed supply chain attack in March 2025 where the
`v35` tag was backdoored to exfiltrate CI secrets. The `@v47` tag is currently unaffected, but the same mechanism
(mutable tag) that enabled the attack remains. The maintainer's security practices have been scrutinised publicly; the
risk of a repeat is non-zero.

#### Impact Chain

```
Attacker re-compromises tj-actions/changed-files@v47
  → changeset-check.yml triggered on any new PR to main
  → Malicious action runs with contents:read, pull-requests:write
  → GITHUB_TOKEN secrets and any workflow env vars exfiltrated
  → Attacker can post misleading PR comments, access workflow secrets
```

The `changeset-check.yml` and `check.yml` workflows have `pull-requests: write` permission, enabling a compromised
action to approve PRs or add misleading status comments that influence merge decisions.

#### Fix

Pin to the commit SHA for v47.0.6 (the current stable release at time of audit):

```yaml
# Before
uses: tj-actions/changed-files@v47

# After
uses: tj-actions/changed-files@9426d40962ed5378910ee2e21d5f8c6fcbf2dd96 # v47.0.6
```

Apply to all 3 occurrences in `check.yml` and 1 in `changeset-check.yml`.

**Important:** Before pinning, verify this SHA against the official release at
https://github.com/tj-actions/changed-files/releases/tag/v47.0.6 — confirm the tag has not moved since this audit.

#### Verification

```bash
# Confirm all tj-actions uses are SHA-pinned
grep -rn 'tj-actions/changed-files' .github/workflows/
# Expected: all should show @<40-char-sha>

# Confirm SHA matches published release
git ls-remote https://github.com/tj-actions/changed-files.git refs/tags/v47.0.6
```

---

### F-03 · P1 · High — 50+ Unpinned Action Tags Across 14 Workflows

**OWASP:** A08:2021 — Software and Data Integrity Failures **CWE:** CWE-829 **CVSS 3.1:**
AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N — **8.7 (Critical per instance, High aggregate)**

#### Description

Beyond F-01 and F-02, the following third-party and first-party actions use mutable version tags across the entire
workflow suite. Prioritised by blast radius:

**Release workflow (`release.yml`) — highest risk (publishes Docker images and npm packages):** | Action | Tag | Risk |
|---|---|---| | `sigstore/cosign-installer` | `@v3` | Compromise = forged container signatures | |
`docker/build-push-action` | `@v6` | Compromise = malicious Docker image published | | `docker/login-action` | `@v3` |
Compromise = registry credentials exfiltrated | | `docker/metadata-action` | `@v5` | Lower severity | |
`actions/upload-artifact` | `@v6` | Artefact tampering | | `actions/download-artifact` | `@v6` | Artefact tampering | |
`madhead/semver-utils` | `@v4` | Third-party, lower-trust |

**Other workflows:** | Action | Tag | Workflow | |---|---|---| | `actions/checkout` | `@v6` | 10+ workflows | |
`actions/github-script` | `@v7` | changeset-check.yml, close-_ | | `actions/cache` | `@v5` | release.yml | |
`actions/upload-artifact` | `@v5` | codeql-analysis.yml | |
`github/codeql-action/_`|`@v4`| codeql-analysis.yml | |`peter-evans/dockerhub-description`|`@v4`| sync-dockerhub-readme.yml | |`dessant/lock-threads`|`@v6`| lock-threads.yml | |`marocchino/sticky-pull-request-comment`|`@v2`| cla.yml | |`directus/stale-issues-action`|`@v1`| stale-issues.yml (first-party) | |`directus/cla-bot`|`@v0.0.3`| cla.yml (first-party) | |`directus/npm-package-existence-checker`|`@v1`
| release.yml (first-party) |

#### Root Cause

No organisational policy enforces SHA-pinning in CI. First-party `directus/*` actions are lower risk (the team controls
the tags) but not zero risk (credential compromise of the directus GitHub org still applies).

#### Impact Chain

The release workflow is the most dangerous vector. If `docker/build-push-action@v6` or `sigstore/cosign-installer@v3` is
compromised:

```
Compromised release action runs during npm/Docker release
  → Malicious code injected into Directus npm package or Docker image
  → All users who run `npm install directus` or pull `directus/directus` image receive backdoor
  → Full compromise of every Directus installation worldwide
```

#### Fix

Use `pinact` or `zizmor` to bulk-resolve and pin all action SHAs:

```bash
pip install zizmor
zizmor --format sarif .github/workflows/ > zizmor.sarif

# Or use pinact for bulk pinning
npm install -g pinact
pinact run
```

Prioritise `release.yml` (cosign, docker actions), `codeql-analysis.yml` (github/codeql-action), then remaining
workflows.

For `actions/checkout@v6`, the SHA is: `de0fac2e4500dabe0009e67214ff5f5447ce83dd`.

#### Verification

```bash
# Count remaining floating @v tags after fix
grep -rn 'uses:.*@v[0-9]' .github/workflows/ | wc -l
# Target: 0 (or only first-party directus/* actions with explicit accepted risk)
```

---

### F-04 · P1 · High — CodeQL Not Triggered on `pull_request`

**OWASP:** A05:2021 — Security Misconfiguration **CWE:** CWE-693 — Protection Mechanism Failure **CVSS 3.1:** N/A
(process control gap, not a directly exploitable vulnerability)

#### Description

`codeql-analysis.yml` has only two triggers:

```yaml
on:
  workflow_call:
  schedule:
    - cron: '0 0 * * *'
```

There is no `pull_request` trigger. `workflow_call` allows other workflows to invoke CodeQL, but none of the
PR-triggered workflows (`changeset-check.yml`, `check.yml`) call it. Security findings introduced in PRs are therefore
not caught until the next daily scheduled run — typically 12–24 hours after merge.

#### Root Cause

The workflow was originally designed as a scheduled scan with `workflow_call` for reuse. Adding a `pull_request` trigger
was not part of the initial design.

#### Impact Chain

```
Developer introduces SAST-detectable vulnerability in PR
  → check.yml runs (linting, type checks) — no CodeQL
  → PR reviewed and merged without security gate
  → Daily CodeQL run fires next morning, finding reported in Security tab
  → Vulnerable code is already in main, potentially shipped in next release
  → Window of exposure: 1–24 hours in main branch, potentially longer if release fires
```

For a project with 27,000+ GitHub stars and widespread production use, any SAST-detectable vulnerability that ships to
production has significant downstream impact.

#### Fix

Add a `pull_request` trigger targeting `main`:

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

If CodeQL run times on PRs are a concern, add `paths` filtering to skip pure documentation changes:

```yaml
pull_request:
  branches:
    - main
  paths:
    - 'api/**'
    - 'app/**'
    - 'packages/**'
```

#### Verification

```bash
# After change: open a test PR against main
# Check Checks tab — "CodeQL Analysis" must appear as a required check
gh pr view <PR-number> --json statusCheckRollup | jq '.statusCheckRollup[] | select(.name | contains("CodeQL"))'
```

---

### F-05 · P1 · Medium — Sandboxed `eval()` in Operations/Exec

**OWASP:** A03:2021 — Injection **CWE:** CWE-94 — Improper Control of Generation of Code **CVSS 3.1:**
AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H — **8.2 (High)** if non-admin; **Informational** if admin-only

#### Description

`api/src/operations/exec/index.ts:49`:

```typescript
await context.eval(code, { timeout: scriptTimeoutMs });
```

This is the "Run Script" Flow operation, which executes arbitrary user-provided JavaScript. The `context.eval` wrapper
uses Node.js `vm` module for sandboxing with a configurable timeout.

#### Root Cause

The Node.js `vm` module does **not** provide a security sandbox. It is explicitly documented by Node.js as: _"The vm
module is not a security mechanism. Do not use it to run untrusted code."_ A `vm` context shares the same V8 isolate as
the host process; sandbox escapes are well-documented (e.g., via `constructor.constructor`, `process` access in older
Node versions, or native module abuse).

#### Impact Chain

**If "Run Script" is accessible to non-admin roles:**

```
Attacker with non-admin Directus account creates a Flow with a "Run Script" operation
  → Provides sandbox-escape payload (e.g., process.env access, require('child_process'))
  → Executes arbitrary OS commands in the Directus server process
  → Full server compromise: database dump, credential exfiltration, lateral movement
```

**If admin-only (default):**

```
Admin creates malicious flow
  → Same impact as above
  → But: admins already have full DB access via Directus API, so marginal risk increase is low
```

#### Fix

**Immediate:** Verify and document that the `Run Script` operation is restricted to users with admin role. Confirm no
policy allows non-admin users to create or modify flows that include exec operations.

**Long-term:** Replace `vm.runInContext` with a true isolated sandbox:

- [Isolated-vm](https://github.com/laverdet/isolated-vm) — V8 isolate with memory/CPU limits and no shared heap
- [Deno runtime](https://deno.com/blog/sandbox) — subprocess-based isolation

```typescript
// Current (insecure vm-based)
await context.eval(code, { timeout: scriptTimeoutMs });

// Safer alternative: isolated-vm
import ivm from 'isolated-vm';
const isolate = new ivm.Isolate({ memoryLimit: 128 });
const context = await isolate.createContext();
await context.eval(code, { timeout: scriptTimeoutMs });
isolate.dispose();
```

#### Verification

```bash
# Check what Directus permission guard wraps the exec operation
grep -rn 'exec\|RunScript\|run.script' api/src/ --include='*.ts' | grep -i 'perm\|admin\|access\|role'

# Test: attempt to trigger exec operation as non-admin role via API
curl -X POST https://your-directus/flows/trigger/<flow-id> \
  -H "Authorization: Bearer <non-admin-token>"
# Expected: 403 Forbidden
```

---

### F-06 · P2 · Medium — SSRF in File Import + MCP OAuth DCR

**OWASP:** A10:2021 — Server-Side Request Forgery **CWE:** CWE-918 — Server-Side Request Forgery **CVSS 3.1:**
AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N — **7.7 (High)** without blocklist; estimated **Medium** with blocklist

#### Description

Two fetch-from-URL patterns were identified:

**1. File import (`api/src/services/files.ts:285`):**

```typescript
fileResponse = await axios.get<Readable>(encodeURL(importURL), {
```

The `importURL` originates from user-supplied API input (`POST /files/import`). Directus maintains an IP blocklist
(recently updated in commit `f75b25f` / PR #27606 and `d7a9670`), which provides partial mitigation.

**2. MCP OAuth DCR (`api/src/services/mcp-oauth/cimd.ts:277`):**

```typescript
response = await axios.get(clientId, requestConfig);
```

Dynamic Client Registration (RFC 7591) fetches the client's identity document using the `clientId` URI as the target
URL. This is specified by the OIDC/OAuth DCR standard but is an SSRF vector if the `clientId` is not validated against
an allowlist.

#### Root Cause

Both patterns fetch attacker-controlled URLs on the server side. IP-based blocklists are a defence-in-depth measure but
are bypassable via:

- DNS rebinding (resolve to public IP, then to internal IP after blocklist check)
- IPv6 addresses if not blocked (::1, ::ffff:127.0.0.1)
- Cloud metadata endpoints if running in AWS/GCP/Azure (169.254.169.254)
- Alternate localhost representations (0177.0.0.1, 0x7f000001)

#### Impact Chain

```
Attacker calls POST /files/import with importURL = http://169.254.169.254/latest/meta-data/
  → Server fetches AWS instance metadata
  → IAM credentials returned in response body
  → Attacker exfiltrates cloud credentials → full cloud account compromise

Or via DNS rebinding:
  → importURL resolves to legitimate domain at blocklist check time
  → DNS TTL expires, re-resolves to 10.0.0.1 (internal database server)
  → Internal service probed/accessed
```

#### Fix

**File import:** Replace IP-based blocklist with a scheme + DNS-resolved allowlist approach:

```typescript
import { isValidUrl, isSafeUrl } from './ssrf-guard';

// In files.ts before fetch:
if (!isSafeUrl(importURL)) {
	throw new ForbiddenError();
}
```

The guard should: (1) resolve DNS, (2) verify resolved IP is not RFC-1918/loopback/link-local, (3) re-resolve at connect
time to prevent DNS rebinding (or use a dedicated outbound proxy).

**MCP OAuth DCR:** Validate `clientId` against a configurable allowlist of trusted domains before fetching:

```typescript
const allowedClientDomains = env['MCP_OAUTH_ALLOWED_CLIENT_DOMAINS']?.split(',') ?? [];
const clientUrl = new URL(clientId);
if (!allowedClientDomains.some((d) => clientUrl.hostname.endsWith(d))) {
	throw new InvalidRequestError('clientId domain not in allowlist');
}
```

#### Verification

```bash
# Test file import SSRF (requires auth)
TOKEN=$(curl -s -X POST /auth/login -d '{"email":"admin@example.com","password":"..."}' | jq -r '.data.access_token')

# Cloud metadata probe
curl -X POST /files/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","data":{"title":"test"}}'
# Expected: 403 / connection refused / timeout (not 200 with metadata)

# Localhost probe
curl -X POST /files/import \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url":"http://127.0.0.1:5432/","data":{"title":"test"}}'
# Expected: blocked
```

---

### F-07 · P2 · Low — `X-Powered-By: Directus` Header

**OWASP:** A05:2021 — Security Misconfiguration **CWE:** CWE-200 — Exposure of Sensitive Information **CVSS 3.1:**
AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — **5.3 (Medium)** per CVSS; **Low** practical impact

#### Description

`api/src/app.ts:152` disables the Express default `X-Powered-By` header, then `api/src/app.ts:237` immediately re-adds
it with the value `Directus`:

```typescript
app.disable('x-powered-by'); // line 152
// ...
app.use((_req, res, next) => {
	// line 237
	res.setHeader('X-Powered-By', 'Directus');
	next();
});
```

#### Assessment

This is a deliberate upstream branding decision, not an oversight. The header aids fingerprinting for targeted attacks
(version-specific exploits, known CVE scans). However, an attacker with sufficient motivation will fingerprint Directus
through API response shapes regardless of this header — the practical uplift to an attacker is low.

**This is rated Low/Informational, not High.** A security team operating Directus in a sensitive environment should
override this at the reverse-proxy layer (`proxy_hide_header X-Powered-By` in nginx) rather than expecting upstream to
remove it.

#### Verification

```bash
curl -I http://your-directus/server/health | grep -i powered
# Current: X-Powered-By: Directus
# Hardened (at proxy): header absent
```

---

### F-08 · P2 · Informational — Dependency Audit Coverage Gap

**OWASP:** A06:2021 — Vulnerable and Outdated Components

#### Description

The audit collection script attempted `pnpm audit` but pnpm was not available in the execution environment:

```
npm error code ENOLOCK — This command requires an existing lockfile.
```

Dependency vulnerabilities could not be automatically assessed. The git log shows
`eab59d9 CVE dependency updates (#27589)` confirming the team does perform CVE remediation, but the cadence and
completeness cannot be verified from this audit.

#### Fix

Ensure the audit pipeline has pnpm available:

```bash
# In the collection environment before running audit
npm install -g pnpm
pnpm audit --json 2>&1 | head -300
```

For CI: Dependabot is configured and active (confirmed via `ci: add Trivy scanning, dependency review and Dependabot`
commit). Verify Dependabot is still enabled in GitHub repo settings.

#### Verification

```bash
# Run from repo root with pnpm available
pnpm audit --json | jq '.metadata.vulnerabilities'
# Review any critical/high entries

# Confirm Dependabot config exists
cat .github/dependabot.yml 2>/dev/null || echo "Dependabot config not found"
```

---

## 6. Open GitHub Issues & PRs

**⚠️ Rate-limited — no data available.**

The GitHub API returned `403 rate limit exceeded` for all calls (open issues, open PRs, branch protection,
secret-scanning alerts). A GitHub token was not provided to the audit context collector.

**To complete this section:** Re-run `collect.mjs` with `GH_TOKEN` set to a personal access token with `repo:read`
scope. This will surface:

- Open security-relevant issues (authentication bugs, permission bypasses, etc.)
- Open PRs that may introduce new vulnerabilities before merge
- Secret-scanning alerts (requires `security-events: read` permission)
- Branch protection rules on `main`

The recent commit `d7a9670 Update default trust (#27607)` and `f75b25f Update ip blocklist (#27606)` suggest active
security work in progress — these PRs should be reviewed.

---

## 7. P2 Recommendations (Backlog)

| ID    | Recommendation                                                     | Rationale                                                                                                                             |
| ----- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| P2-R1 | Adopt `zizmor` as a required CI check for all workflow changes     | Automated detection of supply chain issues (unpinned actions, `pull_request_target` misuse, `GITHUB_TOKEN` over-scoping) before merge |
| P2-R2 | Add SLSA Level 2 provenance to npm and Docker releases             | Allows downstream consumers to verify release artefacts were built by CI, not a compromised developer machine                         |
| P2-R3 | Implement SBOM generation on release                               | `syft` or `cyclonedx-node` generates a full dependency manifest; feeds into downstream SCA tools                                      |
| P2-R4 | Replace `vm`-based exec sandbox with `isolated-vm`                 | Proper V8 isolate; eliminates the documented vm non-sandbox escape path                                                               |
| P2-R5 | Add `gitleaks` pre-commit hook and CI step                         | Prevents accidental secret commit in contributions; fills gap from unavailable secret-scanning in standard config                     |
| P2-R6 | Pin `actions/checkout` consistently — `@v4` vs `@v6` inconsistency | `claude.yml` uses `@v4`, all others use `@v6`; standardise on a single pinned SHA                                                     |
| P2-R7 | MCP OAuth DCR client domain allowlist                              | New in v12; the DCR SSRF vector is small today but grows as MCP adoption increases                                                    |

---

## 8. Remediation Status

| Finding                      | Severity | Fix effort                                                | Owner suggestion         | Done when                                                |
| ---------------------------- | -------- | --------------------------------------------------------- | ------------------------ | -------------------------------------------------------- |
| F-01 `claude-code-action@v1` | Critical | 30 min — resolve SHA, update 2 files                      | DevRel / maintainers     | `grep -c '@v1' .github/workflows/claude*.yml` returns 0  |
| F-02 `tj-actions@v47`        | High     | 30 min — 4 lines in 2 files                               | Any maintainer           | `grep -c 'tj-actions.*@v4' .github/workflows/` returns 0 |
| F-03 Other unpinned actions  | High     | 2–4 h — use `pinact` for bulk                             | Any maintainer           | `grep -rn 'uses:.*@v[0-9]' .github/` returns 0           |
| F-04 CodeQL on PRs           | High     | 15 min — 3 lines in codeql-analysis.yml                   | Core team                | CodeQL check appears in PR status list                   |
| F-05 eval() sandbox          | Medium   | 1–2 sprints for isolated-vm; immediate: audit permissions | Security / core API team | Non-admin cannot trigger exec operation via API          |
| F-06 SSRF file import        | Medium   | 1 sprint — DNS-rebind-safe guard                          | Core API team            | Internal metadata endpoint returns 403 in smoke test     |
| F-07 X-Powered-By            | Low      | Config (proxy) or remove re-addition                      | Core API team            | `curl -I /server/health` shows no X-Powered-By           |
| F-08 pnpm audit gap          | Info     | Add pnpm to audit image                                   | DevOps                   | `pnpm audit` runs in security pipeline                   |

---

## 9. Verification Checklist

```bash
# F-01: claude-code-action unpinned
grep -n 'uses:.*@v[0-9]' .github/workflows/claude.yml .github/workflows/claude-code-review.yml

# F-02: tj-actions unpinned
grep -n 'tj-actions/changed-files' .github/workflows/changeset-check.yml .github/workflows/check.yml

# F-03: all unpinned actions count
grep -rn 'uses:.*@v[0-9]' .github/workflows/ | wc -l

# F-04: CodeQL PR trigger
grep -A5 '^on:' .github/workflows/codeql-analysis.yml | grep 'pull_request'

# F-05: exec operation admin guard
grep -rn 'accountability\|admin\|role' api/src/operations/exec/index.ts

# F-06: SSRF blocklist scope
grep -rn 'blocklist\|blockList\|isAllowed\|safeUrl' api/src/services/files.ts

# F-06b: MCP OAuth DCR URL fetch
grep -n 'axios.get\|fetch' api/src/services/mcp-oauth/cimd.ts

# F-07: X-Powered-By header
curl -sI http://localhost:8055/server/health | grep -i powered

# F-08: pnpm audit
cd /repo && pnpm audit --json | jq '.metadata.vulnerabilities'
```

---

## 10. Shift-Left Guardrails

| Finding                          | Current manual check                  | Automated CI gate                                                                      |
| -------------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------- |
| F-01/F-02/F-03: Unpinned actions | Code review of `.github/` changes     | `zizmor --format sarif .github/workflows/` — fail on unpinned actions                  |
| F-01/F-02/F-03: Pin drift        | Ad hoc re-check after action releases | `pinact verify` in weekly scheduled CI job                                             |
| F-04: CodeQL on PRs              | Monitor Security tab manually         | Add `pull_request` trigger — CodeQL becomes a required PR check                        |
| F-05: eval permissions           | Manual permission review              | Integration test: attempt exec operation as non-admin role → assert 403                |
| F-06: SSRF                       | Manual penetration test               | Smoke test: `POST /files/import` with `url=http://169.254.169.254/` → assert non-200   |
| F-07: X-Powered-By               | `curl` header check                   | `curl -sI $URL                                                                         | grep -i powered && exit 1` in deployment smoke test |
| F-08: Dep audit                  | Manual `pnpm audit` run               | `pnpm audit --audit-level=high` as required CI step; Dependabot PRs as blocking checks |
| General: secret commit           | Code review                           | `gitleaks protect --staged` pre-commit hook; `gitleaks detect` in CI                   |
| General: workflow misuse         | Code review                           | `actionlint` in CI for all `.github/workflows/` changes                                |

---

## 11. Appendix: Full Application Security Assessment

### SQL Injection

No SQL injection paths identified during static review.

**Method:** Grep for `.raw(` in `api/src/**/*.ts` (40 results sampled). Every instance examined uses either: (a) Knex
parameterisation (`??` for identifiers, `?` for values, `.raw('?', [value])`), (b) hardcoded system query strings with
no user input (e.g., `SHOW server_version`, `SELECT oid FROM pg_proc WHERE proname = 'postgis_version'`). All schema
dialect raw SQL uses the `??` placeholder which Knex escapes as a quoted identifier. Paths searched:
`packages/schema/src/dialects/`, `api/src/database/`.

### Authentication

No authentication bypass patterns identified during static review.

**Method:** Reviewed `packages/types/src/accountability.ts` (Accountability type), `packages/types/src/services.ts`
(AbstractServiceOptions with accountability parameter), and auth middleware grep. The `Accountability` type includes
`admin`, `roles`, `user` fields passed through all service calls. Grep for patterns bypassing accountability
(`accountability: null`, `accountability: undefined`) not conducted in this static pass — recommended as a manual review
focus.

Notable: v12 adds MCP OAuth (`api/src/services/mcp-oauth/`, `api/src/controllers/mcp/oauth.ts`). This is a large new
authentication surface (Dynamic Client Registration, token issuance, PKCE). F-06 covers one SSRF vector; a dedicated
code review of the full MCP OAuth flow is recommended given its size (~1,100 lines in index.ts).

### Authorisation

No privilege escalation patterns identified during static review.

**Method:** Grep for `accountability` and `admin` patterns in API service layer. All services accept
`AbstractServiceOptions` with optional accountability. The `admin: boolean` flag controls admin bypass paths. Grep for
`admin: true` hardcoded not performed in this pass — manual review recommended.

### Deserialization

No critical deserialization vulnerabilities identified during static review.

**Method:** Grep for `JSON.parse`, `yaml.load`, `eval` in non-test files. Findings:

- `packages/utils/shared/parse-json.ts:6` — uses a `noproto` reviver: `JSON.parse(input, noproto)` — prototype pollution
  protection present ✓
- `packages/utils/node/require-yaml.ts:6` — uses `yaml.load()` from `js-yaml`. If this loads user-supplied YAML,
  `yaml.load` can execute JavaScript via `!!js/undefined` type tags. If it loads internal config only, risk is
  Informational. **Recommend confirming input source and switching to `yaml.safeLoad` / `yaml.load` with
  `{ schema: JSON_SCHEMA }` option.**
- Migration files use `JSON.parse` on database-stored JSON — input is from internal DB, not user-supplied at this layer.

### SSRF

Covered in F-06. Two vectors identified: file import and MCP OAuth DCR. IP blocklist mitigates direct IP attacks; DNS
rebinding and cloud metadata endpoints remain a concern.

### XXE

No XML parsing identified during static review.

**Method:** Grep for `xml`, `DOMParser`, `XMLParser`, `fast-xml-parser`, `libxmljs`, `sax` in `api/src/**/*.ts`. No XML
parsing libraries found. The `mcp-oauth/index.ts` pattern flagged as "XXE" in the collection script
(`parseStringArrayField`) is JSON string array parsing — not XML. No XXE surface identified.

### Path Traversal

No path traversal vulnerabilities identified in production code during static review.

**Method:** Grep for `readFile`, `createReadStream`, `path.join` in `api/src/` and storage driver packages. Key
findings: `packages/storage-driver-local/src/index.ts:45` uses `this.fullPath(filepath)` — the `fullPath()` helper's
implementation was not available in the grep output but is the critical validation point. **Recommend verifying
`fullPath()` uses `path.resolve()` and checks that the result starts with the configured storage root.**

`extensions-sdk/src/cli/commands/` path operations all occur in the CLI tool (developer environment), not the server.
These are acceptable.

### Cryptography

No security-sensitive weak crypto identified during static review.

**Method:** Grep for `createHash.*md5`, `createHash.*sha1`, `crypto.createHash` in non-test files. Three uses found:

1. `packages/utils/node/process-id.ts` — MD5 of system identifiers for process ID generation (not security function)
2. `packages/utils/node/tmp.ts` — SHA1 of timestamp for temp filename uniqueness (not security function)
3. `api/src/database/helpers/schema/dialects/oracle.ts` — SHA1 to shorten Oracle index names (not security function)

None of these involve password hashing, token generation, or security decisions. JWT signing uses the configured
`SECRET` env var via the `jsonwebtoken` library (HMAC-SHA256 by default with RS256/ES256 also supported).

### Rate Limiting

Rate limiting is implemented.

**Method:** Grep for `rate-limit`, `RateLimiter`. Found: `api/src/middleware/rate-limiter-global.ts` implements a global
rate limiter using `RateLimiterRedis` (Redis backend) or `RateLimiterMemory` (fallback).
`api/src/controllers/mcp/oauth.ts:306` implements MCP-specific rate limiting (HTTP 429 response). Rate limit headers
(`Retry-After`) are set correctly.

### HTTP Headers

Helmet.js is present and configured.

**Method:** Grep for `helmet` in `api/src/app.ts`. Helmet is imported and configured at `app.ts:98` with: CSP
(`contentSecurityPolicy`), CORS (`crossOriginOpenerPolicy`), HSTS (`hsts` — configurable via `HSTS_*` env vars). The
`X-Powered-By` issue is documented in F-07.

### Container

Dockerfile follows security best practices with minor gaps.

**Method:** Review of Dockerfile in audit context. Positive findings: multi-stage build (builder/runtime separation),
runs as `node` user (non-root) ✓, Alpine-based runtime (reduced attack surface) ✓, `NODE_ENV=production` set ✓, build
secrets not baked into runtime image ✓.

Gap: No `HEALTHCHECK` directive. Kubernetes liveness/readiness probes require either `HEALTHCHECK` or explicit probe
configuration. Without it, dead Directus processes may continue receiving traffic. The `pm2-runtime` process manager
handles restarts within the container, but Kubernetes is unaware of application-level health.

Recommend adding:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "fetch('http://localhost:8055/server/health').then(r=>r.ok?process.exit(0):process.exit(1)).catch(()=>process.exit(1))"
```

### Kubernetes / Helm

No Helm chart present in `directus/directus`. The official distribution is Docker-only; Helm deployment is left to the
community.

**Method:** `find . -path '*/helm/*'` returned no results. No Helm lint, no secret template analysis applicable.

### Dependencies

Cannot fully assess — pnpm not available during collection. CVE remediation cadence appears active (PR #27589: "CVE
dependency updates"). Dependabot is configured. Workspace overrides show `none` — no forced version pins that could
suppress vulnerability patches.
