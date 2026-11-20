---
name: dpdp-compliance-auditor
description: Audits Python/JS/TS repositories and SQL schemas for India DPDP Act 2023 (Sec 5, 6, 8(5), 8(7), 9) and DPDP Rules 2025 personal-data leaks — Aadhaar, PAN, phone, email, UPI, health/financial data in logs, DB schemas, consent UIs and outbound LLM prompts — and produces verified remediation patches. Use when auditing a repo, PR diff or schema for PII/DPDP compliance.
---

# DPDP Compliance Auditor

Neuro-symbolic workflow: **deterministic detection first, LLM reasoning second, verification last.**
The LLM never decides *whether* a leak exists — only *how to explain and fix* a leak the scanner proved.

## Progressive Disclosure

| Level | What | When loaded |
|---|---|---|
| 1 | This YAML frontmatter | Always (agent startup) |
| 2 | This markdown workflow | When the task matches the description |
| 3 | `scripts/scan_pii_ast.py`, `scripts/verify_patch.py`, `references/dpdp_2026_rules.json` | Only at the step that needs them |

Do **not** read `references/dpdp_2026_rules.json` in full up front. The scanner already attaches the
matching `rule_id` to each finding; look up only those rule IDs.

## Workflow

### Step 1 — Deterministic scan (zero hallucination)
```bash
python .agent/skills/dpdp-compliance-auditor/scripts/scan_pii_ast.py <target_dir> --format json --out scan.json
```
Output: list of findings `{rule_id, file, line, sink_type, pii_entity, snippet, severity, dpdp_section}`.
Exit code `1` if any `critical`/`high` finding exists (usable as a CI gate).

### Step 2 — Regulatory mapping
For each distinct `rule_id` in `scan.json`, read only that entry from `references/dpdp_2026_rules.json`
(`dpdp_section`, `obligation`, `penalty_ref`, `remediation_pattern`). Cite every finding as
`file:line → DPDP Sec X — obligation`. Never cite a section not present in the rule entry.

### Step 3 — Remediation patch
Generate a minimal unified diff per finding using the rule's `remediation_pattern`:
- `mask_before_log` → wrap value with a masking helper (`mask_aadhaar`, `mask_phone`, …).
- `redact_before_llm` → pass prompt through a redaction function (Gemma sidecar / regex fallback).
- `add_retention_column` → SQL migration adding `retention_purge_at` + purge job.
- `unchecked_consent` → default consent controls to unchecked; add purpose text (Sec 5 notice).

### Step 4 — Verification gate
```bash
python .agent/skills/dpdp-compliance-auditor/scripts/verify_patch.py <target_dir> --baseline scan.json
```
Re-scans the patched tree. A patch is accepted only if (a) the targeted findings disappear,
(b) no new findings are introduced, and (c) every changed Python file still compiles.
Only accepted patches may be proposed as a Pull Request.

## Output contract
Return JSON with: `summary` (risk score 0–100, counts by severity), `findings[]` (with DPDP citation),
`patches[]` (unified diffs, `verified: true|false`).
