# Sentinel-DPDP

**Shift-Left Compliance-as-Code & Auto-Remediation Platform for India's DPDP Act 2023.**

Modern startups ship 5x faster with AI coding agents (Cursor, Copilot, Antigravity), which routinely introduce silent Personal Data (PII) leaks in 40%–90% of generated code (CWE-200, CWE-532). Under India's **Digital Personal Data Protection (DPDP) Act 2023** (penalties up to **₹250 Crore**), a single unreviewed commit creates massive legal liability and stalls B2B enterprise deals.

**Sentinel-DPDP** is a **Neuro-Symbolic DevSecOps Control Plane** that pairs deterministic static analysis (`scan_pii_ast.py`, Semgrep, Gitleaks) with **Google Gemini** (`responseSchema`) + **Progressive Disclosure Agent Skills (`SKILL.md`)** to catch PII leaks at `file:line`, map them to exact DPDP sections, verify fixes in a sandbox (`verify_patch.py`), and open **1-click Auto-Fix Pull Requests**.

---

## Repository Structure

| Path | Purpose |
|---|---|
| [`.agent/skills/dpdp-compliance-auditor/`](.agent/skills/dpdp-compliance-auditor/SKILL.md) | Google Agent Skills (`SKILL.md`) with Progressive Disclosure, `dpdp_2026_rules.json`, deterministic `scan_pii_ast.py`, and `verify_patch.py` gate |
| [`demo_vulnerable_app/`](demo_vulnerable_app/README.md) | "PaisaFlow" test target with 4 planted DPDP violations + 2 clean controls |
| [`design/`](design/dashboard.png) | Stitch-generated Control Plane UI (`dashboard.png`, `dashboard.html`) & interactive workflow diagram (`architecture_workflow.html`) |
| [`docs/`](docs/ARCHITECTURE_WORKFLOW.md) | System architecture, startup workflow, and [Startup & Technical Report (PDF)](docs/Sentinel-DPDP_Startup_Report.pdf) |
| [`DESIGN.md`](DESIGN.md) | Full design system tokens, component states, WCAG AA accessibility, and API contract |

---

## Quick Test (Deterministic Scanner)

```bash
python .agent/skills/dpdp-compliance-auditor/scripts/scan_pii_ast.py demo_vulnerable_app
```
