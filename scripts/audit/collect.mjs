#!/usr/bin/env node
/**
 * Collects security context from the repository and the GitHub API.
 * Writes: <repo-root>/audit-context.json
 *
 * Run from repo root:  node scripts/audit/collect.mjs
 * Required env:  GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA
 */

import { execSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const REPO = process.env.GITHUB_REPOSITORY ?? 'unknown/repo';
const REF = process.env.GITHUB_SHA?.slice(0, 7) ?? 'unknown';

/** Run a shell command and return stdout; never throws. */
function run(cmd, fallback = '(unavailable)') {
	try {
		return execSync(cmd, {
			encoding: 'utf-8',
			stdio: ['pipe', 'pipe', 'pipe'],
			timeout: 30_000,
		}).trim();
	} catch (e) {
		return ((e.stdout ?? '') + (e.stderr ?? '')).trim() || fallback;
	}
}

/** Run a command and parse its stdout as JSON; returns fallback on error. */
function runJson(cmd, fallback = []) {
	try {
		const raw = execSync(cmd, {
			encoding: 'utf-8',
			stdio: ['pipe', 'pipe', 'pipe'],
			timeout: 30_000,
		}).trim();
		return JSON.parse(raw);
	} catch {
		return fallback;
	}
}

console.log('Collecting security context…');

const context = {
	meta: {
		date: new Date().toISOString(),
		repo: REPO,
		ref: REF,
	},

	// ── CI/CD supply chain ───────────────────────────────────────────────────
	cicd: {
		// Detect floating @vN tags (should be SHA-pinned)
		unpinnedActions: run("grep -rn 'uses:.*@v[0-9]' .github/workflows/ 2>/dev/null || echo 'none'"),
		// zizmor: static analysis of GitHub Actions workflows
		// Install: pip install zizmor
		zizmor: run('zizmor --format json .github/workflows/ 2>&1', 'zizmor not installed — skipped'),
		workflowList: run('ls .github/workflows/ 2>/dev/null'),
	},

	// ── Application code patterns ────────────────────────────────────────────
	code: {
		evalUsage: run("grep -rn 'eval(' api/src/ --include='*.ts' | grep -v '\\.test\\.' 2>/dev/null || echo 'none'"),
		mathRandom: run(
			"grep -rn 'Math\\.random()' api/src/ --include='*.ts' | grep -v '\\.test\\.' 2>/dev/null || echo 'none'",
		),
		// All .raw() calls — auditor should verify each is parameterised
		rawSqlCalls: run(
			"grep -rn '\\.raw(' api/src/ --include='*.ts' | grep -v '\\.test\\.' 2>/dev/null | head -40 || echo 'none'",
		),
		xPoweredByHeader: run(
			"grep -rn 'X-Powered-By\\|x-powered-by' api/src/ --include='*.ts' 2>/dev/null || echo 'none'",
		),
		// Naive hardcoded-secret heuristic — expect many false positives
		hardcodedSecretHints: run(
			"grep -rEn \"(password|secret|api_key)\\s*=\\s*[\\\"'][^\\\"']{4,}[\\\"']\" api/src/ --include='*.ts' | grep -v '\\.test\\.' 2>/dev/null | head -20 || echo 'none'",
		),
		weakCrypto: run(
			"grep -rn 'createHash.*md5\\|createHash.*sha1' api/src/ --include='*.ts' | grep -v '\\.test\\.' 2>/dev/null || echo 'none'",
		),
		processExitCalls: run(
			"grep -rn 'process\\.exit' api/src/ --include='*.ts' | grep -v '\\.test\\.' 2>/dev/null || echo 'none'",
		),
	},

	// ── Infrastructure ───────────────────────────────────────────────────────
	infra: {
		helmLint: run('helm lint helm/directus/ 2>&1', 'helm not installed — skipped'),
		helmSecretTemplate: run('cat helm/directus/templates/secret.yaml 2>/dev/null'),
		helmValues: run('cat helm/directus/values.yaml 2>/dev/null'),
		dockerfile: run('cat Dockerfile 2>/dev/null'),
	},

	// ── Dependencies ─────────────────────────────────────────────────────────
	dependencies: {
		// pnpm audit exits non-zero when vulnerabilities found — capture output anyway
		pnpmAudit: run('pnpm audit --json 2>&1 | head -300', 'pnpm not available — skipped'),
		workspaceOverrides: run("grep -A 40 '^overrides:' pnpm-workspace.yaml 2>/dev/null || echo 'none'"),
	},

	// ── Git ──────────────────────────────────────────────────────────────────
	git: {
		recentCommits: run('git log --oneline -30 2>/dev/null'),
		recentlyChangedFiles: run('git diff HEAD~10..HEAD --name-only 2>/dev/null | head -60 || echo "unavailable"'),
	},

	// ── GitHub: open issues & pull requests ─────────────────────────────────
	// The auditor uses these to surface known security debt and in-flight
	// changes that may introduce new risks before merge.
	github: {
		openIssues: runJson('gh issue list --state open --limit 50 --json number,title,labels,url,createdAt 2>/dev/null'),
		openPRs: runJson(
			'gh pr list --state open --limit 20 --json number,title,labels,url,additions,deletions,changedFiles,createdAt 2>/dev/null',
		),
		// Requires security-events: read permission
		securityAlerts: run(
			'gh api /repos/$GITHUB_REPOSITORY/secret-scanning/alerts --jq ".[].secret_type" 2>/dev/null | head -20 || echo "no access or none"',
		),
	},
};

writeFileSync('audit-context.json', JSON.stringify(context, null, 2));
const bytes = Buffer.byteLength(JSON.stringify(context));
console.log(`Context saved → audit-context.json (${bytes} bytes)`);
