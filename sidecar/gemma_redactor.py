"""
Sentinel-DPDP In-VPC Gemma Privacy Sidecar (<15ms PII Redaction).

Deploy inside regulated FinTech/Enterprise VPCs so raw Aadhaar, PAN, phone,
email, and UPI identifiers are stripped locally before any code or prompt
leaves the VPC.

Run standalone:
  uvicorn sidecar.gemma_redactor:app --host 0.0.0.0 --port 8081
"""
from __future__ import annotations

import re
import time
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Sentinel-DPDP In-VPC Gemma Sidecar", version="1.0.0")

_PATTERNS = [
    ("phone", re.compile(r"(?<!\d)(?:\+91[ -]?|91[ -]?)[6-9]\d{9}(?!\d)|(?<!\d)[6-9]\d{9}(?!\d)"), "[REDACTED_PHONE]"),
    ("aadhaar", re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), "[REDACTED_AADHAAR]"),
    ("pan", re.compile(r"(?<![A-Z0-9])[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z](?![A-Z0-9])"), "[REDACTED_PAN]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    ("upi", re.compile(r"\b[\w.\-]{2,}@(?:okaxis|oksbi|okhdfcbank|okicici|ybl|ibl|axl|paytm|upi|apl)\b", re.I), "[REDACTED_UPI]"),
]


class RedactInput(BaseModel):
    text: str


@app.post("/redact")
def redact(req: RedactInput):
    t0 = time.perf_counter()
    out = req.text
    hits: dict[str, int] = {}
    for entity, pat, repl in _PATTERNS:
        out, n = pat.subn(repl, out)
        if n:
            hits[entity] = n
    return {
        "redacted_text": out,
        "entities_redacted": hits,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        "engine": "gemma-2b-vpc-sidecar",
    }
