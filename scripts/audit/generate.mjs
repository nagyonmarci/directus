#!/usr/bin/env node
/**
 * Calls the Claude API with the collected security context and writes a
 * structured Markdown audit report.
 *
 * Run from repo root:  node scripts/audit/generate.mjs
 * Required env:        ANTHROPIC_API_KEY
 * Required file:       audit-context.json  (produced by collect.mjs)
 */

import Anthropic from '@anthropic-ai/sdk';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

if (!process.env.ANTHROPIC_API_KEY) {
	console.error('Error: ANTHROPIC_API_KEY environment variable is not set.');
	process.exit(1);
}

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const context = JSON.parse(readFileSync('audit-context.json', 'utf-8'));

const { date, repo, ref } = context.meta;
const dateShort = date.split('T')[0];

// ── System prompt — marked ephemeral for prompt caching ──────────────────────
// This is static across runs; Claude will serve subsequent calls from cache,
// reducing cost and latency significantly.
const SYSTEM_PROMPT = `You are a senior DevSecOps engineer producing a formal, peer-reviewable security audit report \
for a Node.js/TypeScript application (Directus — an open-source headless CMS). Your output is a single, \
complete Markdown document with no surrounding commentary.

Non-negotiable principles:

1. ROOT CAUSE — explain WHY the issue exists, not just what it is.
2. IMPACT CHAIN — trace the realistic path from finding to harm \
(e.g. non-idempotent Helm secret → secret rotation on upgrade → JWT invalidation → user lockout → service outage).
3. CALIBRATED SEVERITY — Critical = RCE / auth bypass / privilege escalation / secret disclosure. \
An informational header exposure is Low, not High. Over-rating severity destroys reviewer trust in the document.
4. METHODOLOGY TRANSPARENCY — for categories with no findings, write: \
"No <X> paths identified during static review. Method: <what grep pattern, which paths were searched>." \
Never write "X — LOW RISK" — auditors cannot prove a negative, only record what was searched and not found.
5. VERIFICATION COMMANDS — every actionable finding must include concrete, copy-paste shell commands \
(curl, grep, kubectl, helm) that a reviewer can run to confirm the fix.
6. SYNTHESISE, do not dump — a finding is: root cause + impact chain + fix + verification. \
Raw tool output belongs in a raw log, not in an audit report.
7. PRIORITY vs SEVERITY — P0/P1/P2 labels denote fix urgency, not CVSS severity bands. \
State CVSS severity (Critical / High / Medium / Low / Informational) separately per finding.
8. OPEN ISSUES & PRS — surface any security-relevant open GitHub issues or PRs as a dedicated section. \
Assess their risk and flag any that may introduce new vulnerabilities before merge.
9. SHIFT-LEFT — close with a table mapping each manual verification step to an automated CI guardrail \
(e.g. grep in CI, zizmor, smoke tests, helm diff).`;

// ── User prompt — per-run, contains scan data ─────────────────────────────────
const USER_PROMPT = `Generate a complete DevSecOps audit report for the scan results below.

Repository: ${repo}
Commit: ${ref}
Scan date: ${dateShort}

## Collected security context

\`\`\`json
${JSON.stringify(context, null, 2)}
\`\`\`

## Required document structure

Produce the following sections in order. Do not omit any.

1. **Metadata table** — date, repository, commit, auditor ("Automated — Claude Opus"), status
2. **Scope** — what was checked (files, tools, GitHub API calls)
3. **Methodology** — tools used, static vs dynamic distinction, known limitations
4. **Findings Summary** — table with columns: ID | Priority | Severity | Title | OWASP 2021 | Status
5. **Per-finding sections** (one H3 per finding) — each must contain:
   - OWASP, CWE, Severity metadata
   - Description
   - Root Cause
   - Impact Chain
   - Fix (code or config snippet where applicable)
   - Verification (shell commands)
6. **Open GitHub Issues & PRs** — security-relevant items with risk assessment and recommended action
7. **P2 Recommendations** — backlog items: not immediate risks but worth addressing next sprint
8. **Remediation Status table** — all findings with commit or PR reference where fixed
9. **Verification Checklist** — numbered list of copy-paste commands, one per finding
10. **Shift-left guardrails** — table: Finding | Manual check | Automated CI gate
11. **Appendix: Full Application Security Assessment** — one H3 subsection per category \
(SQL Injection, Authentication, Authorisation, Deserialization, SSRF, XXE, Path Traversal, \
Cryptography, Rate Limiting, Dependencies, HTTP Headers, Container, Kubernetes/Helm). \
Each subsection must start with the methodology note before listing observations.`;

console.log('Calling Claude API (model: claude-opus-4-8)…');

const response = await client.messages.create({
	model: 'claude-opus-4-8',
	max_tokens: 8192,
	system: [
		{
			type: 'text',
			text: SYSTEM_PROMPT,
			cache_control: { type: 'ephemeral' },
		},
	],
	messages: [{ role: 'user', content: USER_PROMPT }],
});

const report = response.content[0].text;

mkdirSync('docs/security', { recursive: true });
const outputPath = `docs/security/audit-${dateShort}.md`;
writeFileSync(outputPath, report);

const usage = response.usage;
console.log(`Report written → ${outputPath}`);
console.log(
	`Tokens — input: ${usage.input_tokens} | cache_read: ${usage.cache_read_input_tokens ?? 0} | output: ${usage.output_tokens}`,
);
