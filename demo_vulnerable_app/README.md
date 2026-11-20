# demo_vulnerable_app — "PaisaFlow" (live test target)

> [!CAUTION]
> Intentionally vulnerable. Never deploy. Contains no real personal data.

A tiny Indian FinTech app (FastAPI + React) written the way an AI coding agent would write it:
works fine, but silently breaks India's DPDP Act. Sentinel-DPDP must catch all 4 planted violations
and must **not** flag the clean controls (`fx_rates` table, `/health` endpoint).

| # | File | Violation | DPDP | Rule |
|---|------|-----------|------|------|
| 1 | `backend/main.py` | Raw Aadhaar + PAN in `logger.info()` | Sec 8(5) | DPDP-LOG-001 |
| 2 | `backend/main.py` | Unredacted phone → OpenAI API (via taint: `req.phone → customer_phone → prompt`) | Sec 8(2), 8(5) | DPDP-LLM-002 |
| 3 | `backend/db/schema.sql` | `customers` table holds Aadhaar/PAN/phone with no retention/erasure | Sec 8(7) | DPDP-RET-003 |
| 4 | `frontend/components/SignupConsent.tsx` | Pre-checked bundled marketing consent | Sec 6(1) | DPDP-CON-004 |

```bash
python .agent/skills/dpdp-compliance-auditor/scripts/scan_pii_ast.py demo_vulnerable_app
```
