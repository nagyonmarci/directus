# ossf-scout: Audit Tab Implementation Plan

## Goal

Add an "Audit" tab to ossf-scout that lets users run an AI-powered DevSecOps audit on any public GitHub repository. The
audit clones the target repo, runs static analysis, calls the Claude API (claude-opus-4-8), and stores + displays the
Markdown report.

## Overview of Changes

| File                                 | Action                                                            |
| ------------------------------------ | ----------------------------------------------------------------- |
| `audit.go`                           | **Create** — collect context + Claude API call + goroutine runner |
| `db.go`                              | **Modify** — add `audits` table + 7 CRUD functions                |
| `server.go`                          | **Modify** — add 4 `/api/audits` routes                           |
| `frontend/src/api.ts`                | **Modify** — add Audit types + api calls                          |
| `frontend/src/App.tsx`               | **Modify** — add "Audit" nav link + 2 routes                      |
| `frontend/src/pages/AuditPage.tsx`   | **Create** — audit list + new audit form                          |
| `frontend/src/pages/AuditDetail.tsx` | **Create** — audit detail with Markdown report                    |
| `frontend/package.json`              | **Modify** — add `react-markdown` dependency                      |

---

## Step 1 — Create `audit.go`

Create a new file `audit.go` in the repo root with the following content. This file handles three concerns: collecting
security context from the cloned repo, calling the Claude API, and running the audit as a background goroutine.

````go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ── Context structs (mirror collect.mjs output) ──────────────────────────────

type auditMeta struct {
	Date string `json:"date"`
	Repo string `json:"repo"`
	Ref  string `json:"ref"`
}

type auditCICD struct {
	UnpinnedActions string `json:"unpinnedActions"`
	Zizmor          string `json:"zizmor"`
	WorkflowList    string `json:"workflowList"`
}

type auditCode struct {
	EvalUsage            string `json:"evalUsage"`
	MathRandom           string `json:"mathRandom"`
	RawSqlCalls          string `json:"rawSqlCalls"`
	XPoweredByHeader     string `json:"xPoweredByHeader"`
	HardcodedSecretHints string `json:"hardcodedSecretHints"`
	WeakCrypto           string `json:"weakCrypto"`
	ProcessExitCalls     string `json:"processExitCalls"`
}

type auditInfra struct {
	HelmLint           string `json:"helmLint"`
	HelmSecretTemplate string `json:"helmSecretTemplate"`
	HelmValues         string `json:"helmValues"`
	Dockerfile         string `json:"dockerfile"`
}

type auditDeps struct {
	PnpmAudit          string `json:"pnpmAudit"`
	WorkspaceOverrides string `json:"workspaceOverrides"`
}

type auditGit struct {
	RecentCommits       string `json:"recentCommits"`
	RecentlyChangedFiles string `json:"recentlyChangedFiles"`
}

type auditGitHub struct {
	OpenIssues     interface{} `json:"openIssues"`
	OpenPRs        interface{} `json:"openPRs"`
	SecurityAlerts string      `json:"securityAlerts"`
}

type auditContext struct {
	Meta         auditMeta   `json:"meta"`
	CICD         auditCICD   `json:"cicd"`
	Code         auditCode   `json:"code"`
	Infra        auditInfra  `json:"infra"`
	Dependencies auditDeps   `json:"dependencies"`
	Git          auditGit    `json:"git"`
	GitHub       auditGitHub `json:"github"`
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// runIn runs a shell command inside dir; never panics, returns fallback on error.
func runIn(dir, fallback string, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			combined := strings.TrimSpace(string(out) + string(ee.Stderr))
			if combined != "" {
				return combined
			}
		}
		return fallback
	}
	return strings.TrimSpace(string(out))
}

// shIn runs a /bin/sh -c command in dir; never panics.
func shIn(dir, fallback, script string) string {
	return runIn(dir, fallback, "/bin/sh", "-c", script)
}

// ── Collect ──────────────────────────────────────────────────────────────────

// collectContext clones the target repo to a temp directory, runs static
// analysis commands, fetches GitHub metadata, and returns the assembled context.
// The caller is responsible for removing tmpDir when done.
func collectContext(repo, ghToken string) (*auditContext, string, error) {
	tmpDir, err := os.MkdirTemp("", "ossf-audit-*")
	if err != nil {
		return nil, "", fmt.Errorf("mktemp: %w", err)
	}

	cloneURL := fmt.Sprintf("https://github.com/%s.git", repo)
	cloneCmd := exec.Command("git", "clone", "--depth=50", "--quiet", cloneURL, tmpDir)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", fmt.Errorf("git clone failed: %s", strings.TrimSpace(string(out)))
	}

	ref := shIn(tmpDir, "unknown", "git rev-parse --short HEAD")

	ctx := &auditContext{
		Meta: auditMeta{
			Date: time.Now().UTC().Format(time.RFC3339),
			Repo: repo,
			Ref:  ref,
		},
		CICD: auditCICD{
			UnpinnedActions: shIn(tmpDir, "none",
				"grep -rn 'uses:.*@v[0-9]' .github/workflows/ 2>/dev/null || echo 'none'"),
			Zizmor: shIn(tmpDir, "zizmor not installed — skipped",
				"zizmor --format json .github/workflows/ 2>&1 || echo 'zizmor not installed — skipped'"),
			WorkflowList: shIn(tmpDir, "(none)",
				"ls .github/workflows/ 2>/dev/null || echo '(none)'"),
		},
		Code: auditCode{
			EvalUsage: shIn(tmpDir, "none",
				"grep -rn 'eval(' --include='*.ts' --include='*.js' . | grep -v node_modules | grep -v '\\.test\\.' | head -40 || echo 'none'"),
			MathRandom: shIn(tmpDir, "none",
				"grep -rn 'Math\\.random()' --include='*.ts' --include='*.js' . | grep -v node_modules | grep -v '\\.test\\.' | head -20 || echo 'none'"),
			RawSqlCalls: shIn(tmpDir, "none",
				"grep -rn '\\.raw(' --include='*.ts' . | grep -v node_modules | grep -v '\\.test\\.' | head -40 || echo 'none'"),
			XPoweredByHeader: shIn(tmpDir, "none",
				"grep -rn 'X-Powered-By\\|x-powered-by' --include='*.ts' --include='*.go' . | grep -v node_modules | head -20 || echo 'none'"),
			HardcodedSecretHints: shIn(tmpDir, "none",
				`grep -rEn "(password|secret|api_key)\s*=\s*[\"'][^\"']{4,}[\"']" --include='*.ts' --include='*.go' . | grep -v node_modules | grep -v '\.test\.' | head -20 || echo 'none'`),
			WeakCrypto: shIn(tmpDir, "none",
				"grep -rn 'createHash.*md5\\|createHash.*sha1\\|md5\\.New\\|sha1\\.New' --include='*.ts' --include='*.go' . | grep -v node_modules | head -20 || echo 'none'"),
			ProcessExitCalls: shIn(tmpDir, "none",
				"grep -rn 'process\\.exit\\|os\\.Exit' --include='*.ts' --include='*.go' . | grep -v node_modules | grep -v '\\.test\\.' | head -20 || echo 'none'"),
		},
		Infra: auditInfra{
			HelmLint: shIn(tmpDir, "helm not installed — skipped",
				"helm lint helm/*/  2>&1 || echo 'no helm chart or helm not installed'"),
			HelmSecretTemplate: shIn(tmpDir, "(not found)",
				"find . -path '*/helm/*/templates/secret.yaml' | head -1 | xargs cat 2>/dev/null || echo '(not found)'"),
			HelmValues: shIn(tmpDir, "(not found)",
				"find . -path '*/helm/*/values.yaml' | head -1 | xargs cat 2>/dev/null || echo '(not found)'"),
			Dockerfile: shIn(tmpDir, "(not found)",
				"cat Dockerfile 2>/dev/null || echo '(not found)'"),
		},
		Dependencies: auditDeps{
			PnpmAudit: shIn(tmpDir, "pnpm not available — skipped",
				"pnpm audit --json 2>&1 | head -300 || npm audit --json 2>&1 | head -300 || echo 'no package manager available'"),
			WorkspaceOverrides: shIn(tmpDir, "none",
				"grep -A 40 '^overrides:' pnpm-workspace.yaml 2>/dev/null || echo 'none'"),
		},
		Git: auditGit{
			RecentCommits: shIn(tmpDir, "(unavailable)",
				"git log --oneline -30 2>/dev/null"),
			RecentlyChangedFiles: shIn(tmpDir, "(unavailable)",
				"git diff HEAD~10..HEAD --name-only 2>/dev/null | head -60 || echo '(unavailable)'"),
		},
	}

	// GitHub API: open issues, open PRs, secret-scanning alerts
	ctx.GitHub = fetchGitHubContext(repo, ghToken)

	return ctx, tmpDir, nil
}

// fetchGitHubContext calls the GitHub REST API to get open issues, PRs, and
// secret-scanning alerts. ghToken may be empty (public repos only, rate-limited).
func fetchGitHubContext(repo, ghToken string) auditGitHub {
	fetch := func(url string) (interface{}, error) {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if ghToken != "" {
			req.Header.Set("Authorization", "Bearer "+ghToken)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var v interface{}
		json.NewDecoder(resp.Body).Decode(&v)
		return v, nil
	}

	base := "https://api.github.com/repos/" + repo

	issues, _ := fetch(base + "/issues?state=open&per_page=50")
	prs, _ := fetch(base + "/pulls?state=open&per_page=20")

	// secret-scanning requires token + security-events permission
	alerts := "(no token or insufficient permissions)"
	if ghToken != "" {
		req, _ := http.NewRequest("GET", base+"/secret-scanning/alerts?per_page=20", nil)
		req.Header.Set("Authorization", "Bearer "+ghToken)
		req.Header.Set("Accept", "application/vnd.github+json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			alerts = string(body)
		}
	}

	return auditGitHub{
		OpenIssues:     issues,
		OpenPRs:        prs,
		SecurityAlerts: alerts,
	}
}

// ── Generate ─────────────────────────────────────────────────────────────────

const auditSystemPrompt = `You are a senior DevSecOps engineer producing a formal, peer-reviewable security audit report ` +
	`for a GitHub repository. Your output is a single, complete Markdown document with no surrounding commentary.

Non-negotiable principles:

1. ROOT CAUSE — explain WHY the issue exists, not just what it is.
2. IMPACT CHAIN — trace the realistic path from finding to harm.
3. CALIBRATED SEVERITY — Critical = RCE / auth bypass / privilege escalation / secret disclosure. ` +
	`An informational header exposure is Low, not High. Over-rating severity destroys reviewer trust.
4. METHODOLOGY TRANSPARENCY — for categories with no findings, write: ` +
	`"No <X> paths identified during static review. Method: <what grep pattern, which paths were searched>." ` +
	`Never write "X — LOW RISK" — auditors cannot prove a negative.
5. VERIFICATION COMMANDS — every actionable finding must include concrete, copy-paste shell commands ` +
	`(curl, grep, kubectl, helm) that a reviewer can run to confirm the fix.
6. SYNTHESISE, do not dump — a finding is: root cause + impact chain + fix + verification. ` +
	`Raw tool output belongs in a raw log, not in an audit report.
7. PRIORITY vs SEVERITY — P0/P1/P2 labels denote fix urgency, not CVSS severity bands. ` +
	`State CVSS severity (Critical / High / Medium / Low / Informational) separately per finding.
8. OPEN ISSUES & PRS — surface any security-relevant open GitHub issues or PRs as a dedicated section. ` +
	`Assess their risk and flag any that may introduce new vulnerabilities before merge.
9. SHIFT-LEFT — close with a table mapping each manual verification step to an automated CI guardrail.`

func buildUserPrompt(ctx *auditContext) string {
	dateShort := ctx.Meta.Date[:10]
	ctxJSON, _ := json.MarshalIndent(ctx, "", "  ")

	return fmt.Sprintf(`Generate a complete DevSecOps audit report for the scan results below.

Repository: %s
Commit: %s
Scan date: %s

## Collected security context

`+"```json\n%s\n```"+`

## Required document structure

Produce the following sections in order. Do not omit any.

1. **Metadata table** — date, repository, commit, auditor ("Automated — Claude Opus"), status
2. **Scope** — what was checked (files, tools, GitHub API calls)
3. **Methodology** — tools used, static vs dynamic distinction, known limitations
4. **Findings Summary** — table: ID | Priority | Severity | Title | OWASP 2021 | Status
5. **Per-finding sections** (one H3 per finding) — each must contain:
   - OWASP, CWE, Severity metadata
   - Description
   - Root Cause
   - Impact Chain
   - Fix (code or config snippet where applicable)
   - Verification (shell commands)
6. **Open GitHub Issues & PRs** — security-relevant items with risk assessment
7. **P2 Recommendations** — backlog items not immediately critical
8. **Remediation Status table** — all findings with commit or PR reference where fixed
9. **Verification Checklist** — numbered list of copy-paste commands, one per finding
10. **Shift-left guardrails** — table: Finding | Manual check | Automated CI gate
11. **Appendix: Full Application Security Assessment** — one H3 subsection per category `+
		`(SQL Injection, Authentication, Authorisation, Deserialization, SSRF, XXE, Path Traversal, `+
		`Cryptography, Rate Limiting, Dependencies, HTTP Headers, Container, Kubernetes/Helm). `+
		`Each subsection must start with the methodology note before listing observations.`,
		ctx.Meta.Repo, ctx.Meta.Ref, dateShort, string(ctxJSON))
}

// ── Claude API ───────────────────────────────────────────────────────────────

type claudeSystemBlock struct {
	Type         string               `json:"type"`
	Text         string               `json:"text"`
	CacheControl *claudeCacheControl  `json:"cache_control,omitempty"`
}

type claudeCacheControl struct {
	Type string `json:"type"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeRequest struct {
	Model     string              `json:"model"`
	MaxTokens int                 `json:"max_tokens"`
	System    []claudeSystemBlock `json:"system"`
	Messages  []claudeMessage     `json:"messages"`
}

type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens          int `json:"input_tokens"`
		CacheReadInputTokens int `json:"cache_read_input_tokens"`
		OutputTokens         int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// generateReport calls the Claude API and returns the Markdown report plus token counts.
func generateReport(ctx *auditContext, apiKey string) (report string, inputTokens, outputTokens int, err error) {
	payload := claudeRequest{
		Model:     "claude-opus-4-8",
		MaxTokens: 8192,
		System: []claudeSystemBlock{
			{
				Type:         "text",
				Text:         auditSystemPrompt,
				CacheControl: &claudeCacheControl{Type: "ephemeral"},
			},
		},
		Messages: []claudeMessage{
			{Role: "user", Content: buildUserPrompt(ctx)},
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, 0, fmt.Errorf("claude API request failed: %w", err)
	}
	defer resp.Body.Close()

	var cr claudeResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", 0, 0, fmt.Errorf("claude API decode failed: %w", err)
	}
	if cr.Error != nil {
		return "", 0, 0, fmt.Errorf("claude API error %s: %s", cr.Error.Type, cr.Error.Message)
	}
	if len(cr.Content) == 0 {
		return "", 0, 0, fmt.Errorf("claude API returned empty content")
	}

	return cr.Content[0].Text, cr.Usage.InputTokens, cr.Usage.OutputTokens, nil
}

// ── Runner ───────────────────────────────────────────────────────────────────

// runAudit is meant to be called in a goroutine. It collects context, calls
// Claude, and updates the DB with the result (or error).
func runAudit(db interface{ // use *sql.DB in practice — see db.go
}, id, repo, ghToken, anthropicKey string) {
	dbUpdateAuditRunning(db, id)

	auditCtx, tmpDir, err := collectContext(repo, ghToken)
	if err != nil {
		dbUpdateAuditError(db, id, fmt.Sprintf("collect failed: %v", err))
		return
	}
	defer os.RemoveAll(tmpDir)

	report, inputTokens, outputTokens, err := generateReport(auditCtx, anthropicKey)
	if err != nil {
		dbUpdateAuditError(db, id, fmt.Sprintf("generate failed: %v", err))
		return
	}

	dbUpdateAuditDone(db, id, report, inputTokens, outputTokens)
}
````

**Important:** Replace the `db interface{...}` signature in `runAudit` with `*sql.DB` once you have added the DB
functions in Step 2. Also add `"database/sql"` to the imports.

---

## Step 2 — Modify `db.go`

### 2a. Add the `auditRow` struct

Add after the existing `scanResultRow` struct:

```go
type auditRow struct {
	ID           string
	Repo         string
	Status       string // pending | running | done | error
	CreatedAt    time.Time
	CompletedAt  *time.Time
	Report       *string
	Error        *string
	InputTokens  *int
	OutputTokens *int
}
```

### 2b. Add the `audits` table to `openDB()`

Inside `openDB()`, after the existing `CREATE TABLE IF NOT EXISTS scans` and `CREATE TABLE IF NOT EXISTS scan_results`
statements, add:

```go
const auditSchema = `
CREATE TABLE IF NOT EXISTS audits (
    id            TEXT    NOT NULL PRIMARY KEY,
    repo          TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'pending',
    created_at    DATETIME NOT NULL,
    completed_at  DATETIME,
    report        TEXT,
    error         TEXT,
    input_tokens  INTEGER,
    output_tokens INTEGER
);`
if _, err := db.Exec(auditSchema); err != nil {
    return nil, fmt.Errorf("create audits table: %w", err)
}
```

### 2c. Add CRUD functions

Append to `db.go`:

```go
func dbCreateAudit(db *sql.DB, id, repo string) error {
	_, err := db.Exec(
		`INSERT INTO audits (id, repo, status, created_at) VALUES (?, ?, 'pending', ?)`,
		id, repo, time.Now().UTC(),
	)
	return err
}

func dbUpdateAuditRunning(db *sql.DB, id string) error {
	_, err := db.Exec(`UPDATE audits SET status='running' WHERE id=?`, id)
	return err
}

func dbUpdateAuditDone(db *sql.DB, id, report string, inputTokens, outputTokens int) error {
	_, err := db.Exec(
		`UPDATE audits SET status='done', completed_at=?, report=?, input_tokens=?, output_tokens=? WHERE id=?`,
		time.Now().UTC(), report, inputTokens, outputTokens, id,
	)
	return err
}

func dbUpdateAuditError(db *sql.DB, id, errMsg string) error {
	_, err := db.Exec(
		`UPDATE audits SET status='error', completed_at=?, error=? WHERE id=?`,
		time.Now().UTC(), errMsg, id,
	)
	return err
}

func dbListAudits(db *sql.DB) ([]auditRow, error) {
	rows, err := db.Query(
		`SELECT id, repo, status, created_at, completed_at, error, input_tokens, output_tokens
		 FROM audits ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.ID, &a.Repo, &a.Status, &a.CreatedAt,
			&a.CompletedAt, &a.Error, &a.InputTokens, &a.OutputTokens); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func dbGetAudit(db *sql.DB, id string) (*auditRow, error) {
	var a auditRow
	err := db.QueryRow(
		`SELECT id, repo, status, created_at, completed_at, report, error, input_tokens, output_tokens
		 FROM audits WHERE id=?`, id,
	).Scan(&a.ID, &a.Repo, &a.Status, &a.CreatedAt,
		&a.CompletedAt, &a.Report, &a.Error, &a.InputTokens, &a.OutputTokens)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func dbDeleteAudit(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM audits WHERE id=?`, id)
	return err
}
```

---

## Step 3 — Modify `server.go`

### 3a. Register routes

In the `http.HandleFunc` block (alongside the existing `/api/scans` routes), add:

```go
http.HandleFunc("POST /api/audits",        s.handleCreateAudit)
http.HandleFunc("GET /api/audits",         s.handleListAudits)
http.HandleFunc("GET /api/audits/{id}",    s.handleGetAudit)
http.HandleFunc("DELETE /api/audits/{id}", s.handleDeleteAudit)
```

### 3b. Add handler methods

Append to `server.go`. The server struct already has a `db *sql.DB` field:

```go
type createAuditRequest struct {
	Repo           string `json:"repo"`            // e.g. "owner/name"
	GithubToken    string `json:"github_token"`    // optional
}

func (s *server) handleCreateAudit(w http.ResponseWriter, r *http.Request) {
	var req createAuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Repo == "" {
		http.Error(w, "invalid request body — repo is required", http.StatusBadRequest)
		return
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		http.Error(w, "ANTHROPIC_API_KEY not set on server", http.StatusServiceUnavailable)
		return
	}

	id := uuid.New().String()
	if err := dbCreateAudit(s.db, id, req.Repo); err != nil {
		http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	go runAudit(s.db, id, req.Repo, req.GithubToken, apiKey)

	a, _ := dbGetAudit(s.db, id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(a)
}

func (s *server) handleListAudits(w http.ResponseWriter, r *http.Request) {
	audits, err := dbListAudits(s.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if audits == nil {
		audits = []auditRow{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(audits)
}

func (s *server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := dbGetAudit(s.db, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a)
}

func (s *server) handleDeleteAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := dbDeleteAudit(s.db, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

Add `"github.com/google/uuid"` to imports (already in `go.mod` as an indirect dep — just needs to be used directly
here).

---

## Step 4 — Modify `frontend/package.json`

Add `react-markdown` to `dependencies`:

```json
"dependencies": {
  "react": "^19.0.0",
  "react-dom": "^19.0.0",
  "react-router-dom": "^6.28.0",
  "react-markdown": "^9.0.1"
}
```

Run `npm install` inside `frontend/` after this change.

---

## Step 5 — Modify `frontend/src/api.ts`

Add the following types and API calls (append to the existing file):

```typescript
// ── Audit ────────────────────────────────────────────────────────────────────

export type AuditStatus = 'pending' | 'running' | 'done' | 'error';

export interface Audit {
	id: string;
	repo: string;
	status: AuditStatus;
	created_at: string;
	completed_at: string | null;
	report: string | null;
	error: string | null;
	input_tokens: number | null;
	output_tokens: number | null;
}

export interface CreateAuditParams {
	repo: string;
	github_token?: string;
}
```

And inside the `api` object, add:

```typescript
  listAudits: () => request<Audit[]>('GET', '/api/audits'),
  getAudit: (id: string) => request<Audit>('GET', `/api/audits/${id}`),
  createAudit: (params: CreateAuditParams) => request<Audit>('POST', '/api/audits', params),
  deleteAudit: (id: string) => request<void>('DELETE', `/api/audits/${id}`),
```

---

## Step 6 — Create `frontend/src/pages/AuditPage.tsx`

```tsx
import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, Audit, AuditStatus } from '../api';
import StatusBadge from '../components/StatusBadge';

function formatDate(s: string) {
	return new Date(s).toLocaleString();
}

function costEstimate(inputTokens: number | null, outputTokens: number | null): string {
	if (!inputTokens && !outputTokens) return '—';
	const input = ((inputTokens ?? 0) / 1_000_000) * 15;
	const output = ((outputTokens ?? 0) / 1_000_000) * 75;
	return `~$${(input + output).toFixed(3)}`;
}

export default function AuditPage() {
	const navigate = useNavigate();
	const [audits, setAudits] = useState<Audit[]>([]);
	const [repo, setRepo] = useState('');
	const [token, setToken] = useState('');
	const [submitting, setSubmitting] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const load = useCallback(async () => {
		try {
			const data = await api.listAudits();
			setAudits(data);
		} catch (e) {
			setError(String(e));
		}
	}, []);

	useEffect(() => {
		load();
	}, [load]);

	// Poll while any audit is pending or running
	useEffect(() => {
		const active = audits.some((a) => a.status === 'pending' || a.status === 'running');
		if (!active) return;
		const id = setInterval(load, 5000);
		return () => clearInterval(id);
	}, [audits, load]);

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();
		if (!repo.trim()) return;
		setSubmitting(true);
		setError(null);
		try {
			await api.createAudit({ repo: repo.trim(), github_token: token || undefined });
			setRepo('');
			setToken('');
			load();
		} catch (e) {
			setError(String(e));
		} finally {
			setSubmitting(false);
		}
	}

	async function deleteAudit(e: React.MouseEvent, id: string) {
		e.stopPropagation();
		await api.deleteAudit(id);
		setAudits((prev) => prev.filter((a) => a.id !== id));
	}

	return (
		<div className="container">
			<div className="card">
				<h2>New Audit</h2>
				<form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
					<label>
						<span style={{ fontSize: 13, color: 'var(--muted)' }}>Target repository (owner/name)</span>
						<input
							type="text"
							className="input"
							placeholder="e.g. directus/directus"
							value={repo}
							onChange={(e) => setRepo(e.target.value)}
							required
							style={{ marginTop: 4 }}
						/>
					</label>
					<label>
						<span style={{ fontSize: 13, color: 'var(--muted)' }}>
							GitHub token{' '}
							<span style={{ fontWeight: 400 }}>(optional — needed for secret-scanning alerts and private repos)</span>
						</span>
						<input
							type="password"
							className="input"
							placeholder="ghp_…"
							value={token}
							onChange={(e) => setToken(e.target.value)}
							style={{ marginTop: 4 }}
						/>
					</label>
					{error && <p className="error-msg">{error}</p>}
					<button type="submit" className="btn btn-primary" disabled={submitting || !repo.trim()}>
						{submitting ? 'Starting…' : 'Run Audit'}
					</button>
				</form>
				<p style={{ fontSize: 12, color: 'var(--muted)', marginTop: 8 }}>
					Clones the repo, runs static analysis, calls Claude Opus. Typical cost: $0.50–$1.50 per run. Requires{' '}
					<code>ANTHROPIC_API_KEY</code> to be set on the server.
				</p>
			</div>

			<div className="card">
				<h2>Audit History</h2>
				{audits.length === 0 ? (
					<p className="empty">No audits yet. Run one above.</p>
				) : (
					<div className="table-wrap">
						<table className="scans-table">
							<thead>
								<tr>
									<th>Repository</th>
									<th>Started</th>
									<th>Completed</th>
									<th>Status</th>
									<th>API Cost</th>
									<th></th>
								</tr>
							</thead>
							<tbody>
								{audits.map((a) => (
									<tr key={a.id} className="scan-row" onClick={() => navigate(`/audits/${a.id}`)}>
										<td>
											<code>{a.repo}</code>
										</td>
										<td>{formatDate(a.created_at)}</td>
										<td>{a.completed_at ? formatDate(a.completed_at) : '—'}</td>
										<td>
											<StatusBadge status={a.status as AuditStatus} />
										</td>
										<td>{costEstimate(a.input_tokens, a.output_tokens)}</td>
										<td>
											<button className="btn btn-danger" onClick={(e) => deleteAudit(e, a.id)}>
												Delete
											</button>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</div>
		</div>
	);
}
```

---

## Step 7 — Create `frontend/src/pages/AuditDetail.tsx`

```tsx
import { useEffect, useState, useCallback, useRef } from 'react';
import { Link, useParams } from 'react-router-dom';
import Markdown from 'react-markdown';
import { api, Audit } from '../api';
import StatusBadge from '../components/StatusBadge';

export default function AuditDetail() {
	const { id } = useParams<{ id: string }>();
	const [audit, setAudit] = useState<Audit | null>(null);
	const [error, setError] = useState<string | null>(null);
	const prevStatus = useRef<string | null>(null);

	const load = useCallback(async () => {
		if (!id) return;
		try {
			const a = await api.getAudit(id);
			prevStatus.current = a.status;
			setAudit(a);
		} catch (e) {
			setError(String(e));
		}
	}, [id]);

	useEffect(() => {
		load();
	}, [load]);

	// Poll while pending or running
	useEffect(() => {
		if (!audit || (audit.status !== 'pending' && audit.status !== 'running')) return;
		const timer = setInterval(load, 3000);
		return () => clearInterval(timer);
	}, [audit, load]);

	function downloadReport() {
		if (!audit?.report) return;
		const blob = new Blob([audit.report], { type: 'text/markdown' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `audit-${audit.repo.replace('/', '-')}-${audit.created_at.slice(0, 10)}.md`;
		a.click();
		URL.revokeObjectURL(url);
	}

	return (
		<div className="container">
			<Link to="/audits" className="back-link">
				← Back to audits
			</Link>

			{error && <p className="error-msg">{error}</p>}

			{audit && (
				<>
					<div className="card">
						<div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
							<h2 style={{ margin: 0 }}>
								Audit: <code>{audit.repo}</code>
							</h2>
							<StatusBadge status={audit.status} />
						</div>

						<div className="detail-meta">
							<span className="meta-item">
								<span className="meta-label">Started:</span>
								{new Date(audit.created_at).toLocaleString()}
							</span>
							{audit.completed_at && (
								<span className="meta-item">
									<span className="meta-label">Completed:</span>
									{new Date(audit.completed_at).toLocaleString()}
								</span>
							)}
							{audit.input_tokens != null && (
								<span className="meta-item">
									<span className="meta-label">Tokens in/out:</span>
									{audit.input_tokens.toLocaleString()} / {(audit.output_tokens ?? 0).toLocaleString()}
								</span>
							)}
						</div>

						{(audit.status === 'pending' || audit.status === 'running') && (
							<p style={{ color: 'var(--muted)', fontSize: 13 }}>
								{audit.status === 'pending'
									? 'Waiting to start…'
									: 'Cloning repo and running analysis — this takes 1–3 minutes…'}
							</p>
						)}
						{audit.status === 'error' && <p className="error-msg">Error: {audit.error}</p>}
						{audit.status === 'done' && (
							<button className="btn btn-primary" onClick={downloadReport} style={{ marginTop: 8 }}>
								Download .md
							</button>
						)}
					</div>

					{audit.status === 'done' && audit.report && (
						<div className="card audit-report">
							<Markdown>{audit.report}</Markdown>
						</div>
					)}
				</>
			)}
		</div>
	);
}
```

Add a small CSS rule in `frontend/src/index.css` for readable report rendering:

```css
.audit-report {
	max-width: 100%;
	overflow-x: auto;
}
.audit-report h1,
.audit-report h2,
.audit-report h3 {
	margin-top: 1.5rem;
}
.audit-report table {
	border-collapse: collapse;
	width: 100%;
	font-size: 13px;
}
.audit-report th,
.audit-report td {
	border: 1px solid var(--border);
	padding: 6px 10px;
	text-align: left;
}
.audit-report code {
	background: var(--code-bg, #1e1e2e);
	padding: 1px 5px;
	border-radius: 3px;
	font-size: 12px;
}
.audit-report pre {
	background: var(--code-bg, #1e1e2e);
	padding: 12px;
	border-radius: 6px;
	overflow-x: auto;
}
```

---

## Step 8 — Modify `frontend/src/App.tsx`

### 8a. Add imports

Add these imports at the top of `App.tsx`:

```tsx
import AuditPage from './pages/AuditPage';
import AuditDetail from './pages/AuditDetail';
```

### 8b. Add nav link

In the `AppHeader` component, alongside the existing `<Link to="/">Scans</Link>` and
`<Link to="/trending">Trending</Link>` links, add:

```tsx
<Link to="/audits">Audit</Link>
```

### 8c. Add routes

In the `<Routes>` block, add:

```tsx
<Route path="/audits" element={<AuditPage />} />
<Route path="/audits/:id" element={<AuditDetail />} />
```

---

## Step 9 — Environment variable

The server reads `ANTHROPIC_API_KEY` from the environment at request time (see `handleCreateAudit`). Set it before
starting the server:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./ossf-scout
```

Or add it to `docker-compose.yml`:

```yaml
environment:
  - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
```

---

## Step 10 — Build & verify

```bash
# Install new frontend dep
cd frontend && npm install && cd ..

# Rebuild frontend and embed into Go binary
make build        # or: cd frontend && npm run build && cd .. && go build .

# Start server
ANTHROPIC_API_KEY=sk-ant-... ./ossf-scout --serve

# In another terminal — smoke test the API
curl -s -X POST http://localhost:7878/api/audits \
  -H 'Content-Type: application/json' \
  -d '{"repo":"nagyonmarci/ossf-scout"}' | jq .

# Poll until done
AUDIT_ID=$(curl -s http://localhost:7878/api/audits | jq -r '.[0].id')
watch -n 3 "curl -s http://localhost:7878/api/audits/$AUDIT_ID | jq '{status,error}'"
```

---

## Summary of new files

```
audit.go                              ← new
frontend/src/pages/AuditPage.tsx      ← new
frontend/src/pages/AuditDetail.tsx    ← new
```

## Summary of modified files

```
db.go                                 ← add auditRow struct + schema + 7 functions
server.go                             ← add 4 handlers + uuid import
frontend/package.json                 ← add react-markdown
frontend/src/api.ts                   ← add Audit types + 4 api calls
frontend/src/App.tsx                  ← add Audit nav link + 2 routes
frontend/src/index.css                ← add .audit-report styles
```
