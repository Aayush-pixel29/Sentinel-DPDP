"""
PaisaFlow — demo Indian FinTech KYC + support API.

!!! INTENTIONALLY VULNERABLE — test target for Sentinel-DPDP. Do not deploy. !!!
This is the kind of code an AI coding agent produces when asked to
"add a KYC endpoint and an AI support assistant" — functionally correct,
silently non-compliant with the DPDP Act.
"""
import logging
import os

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("paisaflow")

app = FastAPI(title="PaisaFlow API")

OPENAI_URL = "https://api.openai.com/v1/chat/completions"


class KycRequest(BaseModel):
    user_id: str
    full_name: str
    aadhaar_number: str
    pan_number: str
    phone: str


class SupportRequest(BaseModel):
    user_id: str
    phone: str
    message: str


@app.post("/kyc/verify")
def verify_kyc(req: KycRequest):
    # VIOLATION 1 (DPDP Sec 8(5)): raw Aadhaar + PAN written to application logs
    logger.info(f"KYC started for {req.full_name} aadhaar={req.aadhaar_number} pan={req.pan_number}")
    status = "verified" if len(req.aadhaar_number) == 12 else "rejected"
    return {"user_id": req.user_id, "status": status}


@app.post("/support/ask")
async def ask_support(req: SupportRequest):
    # VIOLATION 2 (DPDP Sec 8(2)/8(5)): unredacted phone number sent to a third-party LLM
    customer_phone = req.phone
    prompt = f"Customer with phone {customer_phone} asks: {req.message}"
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            OPENAI_URL,
            headers={"Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]},
        )
    return {"answer": resp.json()["choices"][0]["message"]["content"]}


@app.get("/health")
def health():
    return {"ok": True}
