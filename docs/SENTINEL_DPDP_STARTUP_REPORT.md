# Sentinel-DPDP — Startup, Product & Technical Report

**Date:** November 20, 2026  
**Event:** Google Cloud Startup Buildathon (IMC Churchgate, Mumbai)  
**Repository:** `https://github.com/Aayush-pixel29/Sentinel-DPDP`

---

## 1. What Our Startup Is (Category & Identity)

- **Category:** **B2B SaaS DevSecOps & AI Governance Platform** (Compliance-as-Code Service).
- **Delivery Form:** A **Web Control Plane** (Next.js/React on Cloud Run) + **GitHub App PR Reviewer** + **In-VPC Privacy Sidecar** (Gemma) + **Portable Agent Skill** (`SKILL.md`).
- **One-Liner:** *Sentinel-DPDP is the automated DPDP compliance engineer in your GitHub Pull Requests—detecting personal-data leaks deterministically and opening verified fix PRs before code ever merges to `main`.*

---

## 2. The Problem We Are Solving ("AI Velocity vs. Privacy Debt")

1. **AI Coding Agents Leak PII Silently:** Startups use Cursor, Copilot, and Antigravity to ship 5x faster, but LLMs optimize for *functional correctness*, not regulatory privacy.
2. **Empirical Proof (Peer-Reviewed Research):**
   - **Stanford University (Perry et al., ACM CCS '23):** AI-assisted developers wrote significantly less secure code on 4/5 tasks (e.g., 3% vs. 21% secure on ECDSA signing; 36% vs. 7% SQL injection) and had a *false sense of security*.
   - **Morkonda et al. (`arXiv:2605.23091`, May 2026):** Across 7 leading LLMs, **73%–90%** of generated snippets contained vulnerabilities (**98% High/Critical**), with **CWE-200 (Sensitive Information Exposure)** as the #1 flaw (381 instances).
   - **Yuan et al. (`arXiv:2610.15482`, Oct 2026 SLR):** Synthesizing 141 papers (40%–65% vulnerable outputs), recommending Zero-Trust on AI code, hybrid static+dynamic controls, and auditability.
   - **SecReason (`arXiv:2610.14453`, Oct 2026):** Proves our exact architecture—combining deterministic static analysis (`Tree-sitter`/`Semgrep`) with LLM self-repair raises secure & functional delivery from **<15% to 72.8%–98.1%** with only **0.1%–3.2% overhead**.
3. **Massive Legal & Commercial Impact:** India's **DPDP Act 2023** carries fines up to **₹250 Crore** (Sec 8(5) security safeguards). A single unmasked Aadhaar/PAN log or unredacted LLM prompt stalls enterprise B2B sales deals for months.

---

## 3. Target Market & Differentiation

- **Target Users:** CTOs, Engineering Leads, and DPOs at **Indian Startups, FinTechs, SaaS companies, and Dev Agencies**.
- **Pricing Wedge:** **₹1,999/mo (Startup)** and **₹7,999/mo (Agency)** vs. **Vanta ($20k/yr)**, **Drata ($24.9k/yr)**, and **Sprinto ($15k/yr)**.
- **Why We Beat Competitors:**
  - *Cloud GRC (Vanta/Drata/Sprinto)* only check cloud infra/HR checkboxes, don't natively enforce DPDP in code, and never write fix PRs.
  - *Generic SAST (Snyk/Semgrep/CodeRabbit)* lack Indian DPDP regulatory context (`Sec 5, 6, 8(5), 8(7), 9`).

---

## 4. Startup Trust & Zero-Data-Leakage Architecture

Why startups trust Sentinel-DPDP with their source code:
1. **Deterministic First (Zero Hallucination):** AST + Semgrep + Gitleaks run *inside* the isolated scan sandbox; only minimal `file:line` snippets + rule IDs are reasoned over.
2. **In-VPC Gemma Redaction Sidecar:** Raw PII/secrets are stripped locally (<15ms) before any payload touches external LLM APIs.
3. **Ephemeral, Zero-Retention Processing:** Repos are scanned in isolated containers with no training on customer code; only structured compliance metadata and audit hashes persist in Cloud SQL / BigQuery.
4. **Verification Gate (`verify_patch.py`):** Every generated PR must pass (a) baseline finding resolved, (b) zero new leaks introduced, and (c) clean compilation before a PR is offered.

---

## 5. What We Have Built So Far (Phase 1 — Verified)

1. **Progressive Disclosure Agent Skill (`.agent/skills/dpdp-compliance-auditor/`):**
   - `SKILL.md` (Level 1 YAML + Level 2 workflow)
   - `references/dpdp_2026_rules.json` (DPDP Sec 5, 6(1), 8(2), 8(5), 8(7), 9 + Rules 2025)
   - `scripts/scan_pii_ast.py` (Python AST taint + JS/TS + SQL + Verhoeff Aadhaar/PAN/Phone/UPI)
   - `scripts/verify_patch.py` (Patch verification gate)
   - **Verified Result:** Caught **4/4** planted violations on `demo_vulnerable_app` with **0 false positives**; verified patch dropped risk from **80/100 → 0/100**; rejected broken patch.
2. **Live Test Target (`demo_vulnerable_app/`):** Realistic FinTech app ("PaisaFlow") with 4 DPDP violations + 2 clean controls.
3. **UI Blueprint & Workflow (`DESIGN.md`, `design/dashboard.png`, `design/dashboard.html`, `design/architecture_workflow.html`):** Generated via **Google Stitch MCP**; includes GitHub repo selector, Risk Gauge, Diff Viewer, DPDP Citation Card, Auto-Fix PR Panel, and Gemini Live Auditor drawer.

---

## 6. Full Platform Roadmap (Phases 2–4)

- **Phase 2 (Core Platform Backend):** FastAPI on Cloud Run + GitHub OAuth & PR Webhook + Gemini (`responseSchema`) patch synthesis + `verify_patch.py` gate + BigQuery telemetry + Cloud SQL audit logs + Gemma redaction + Gemini Live Q&A.
- **Phase 3 (Live Control Plane Frontend):** Next.js/React dashboard built from `DESIGN.md` wired to live `/api/*` endpoints.
- **Phase 4 (Cloud Run Launch & Scale):** Public HTTPS deployment (`us-central1`), GitHub Marketplace App, and modular `SKILL.md` packs for **GDPR, PDPA, HIPAA, and EU AI Act**.
