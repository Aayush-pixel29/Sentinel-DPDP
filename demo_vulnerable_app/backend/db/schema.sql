-- PaisaFlow schema  (INTENTIONALLY VULNERABLE — Sentinel-DPDP test target)

-- VIOLATION 3 (DPDP Sec 8(7)): personal data stored with no retention / erasure column or purge logic
CREATE TABLE customers (
    id             UUID PRIMARY KEY,
    full_name      TEXT NOT NULL,
    aadhaar_number VARCHAR(12) NOT NULL,
    pan_number     VARCHAR(10),
    phone          VARCHAR(15) NOT NULL,
    email          TEXT,
    created_at     TIMESTAMPTZ DEFAULT now()
);

-- Non-personal table: should NOT be flagged
CREATE TABLE fx_rates (
    currency   CHAR(3) PRIMARY KEY,
    rate_inr   NUMERIC(12, 4) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);
