# TrustVault 🔐

> **Ultra-secure document sharing platform** with cryptographically verifiable audit trails and server-enforced object-level access control (ABAC/ALAC).

---

## Security Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                     CLIENT REQUEST                          │
└───────────────────────────┬─────────────────────────────────┘
                            │ Bearer JWT
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  1. get_current_user()  ← Live DB: user active? session OK? │
└───────────────────────────┬─────────────────────────────────┘
                            │ AuthenticatedUser
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  2. enforce_document_access() ← Live DB permission query    │
│     PolicyEngine.evaluate()   ← Default DENY               │
└───────────────────────────┬─────────────────────────────────┘
                            │ ALLOW or DENY
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  3. audit_service.record() ← Transactional HMAC chain write │
│     (Both SUCCESS and DENIED — BEFORE data is returned)     │
└───────────────────────────┬─────────────────────────────────┘
                            │
                 ALLOW ─────┴───── DENY
                   │                  │
                   ▼                  ▼
            Document Data          HTTP 404
                                (anti-enumeration)
```

---

## Project Structure

```
trustvault/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI app + security middleware stack
│   │   ├── core/
│   │   │   └── config.py              # Pydantic settings (env-based secrets)
│   │   ├── auth/
│   │   │   └── jwt_handler.py         # JWT create/decode (identity only, not authorization)
│   │   ├── db/
│   │   │   └── session.py             # Async SQLAlchemy session factory
│   │   ├── middleware/
│   │   │   └── authorization.py       # ★ CORE: PolicyEngine + enforce_document_access
│   │   ├── models/
│   │   │   └── domain.py              # ORM models + Pydantic schemas
│   │   └── services/
│   │       └── audit_service.py       # ★ CORE: HMAC-chained append-only audit logger
│   ├── database/
│   │   ├── schema.sql                 # Full PostgreSQL schema with RLS + triggers
│   │   └── seed.sql                   # Test data for all 3 roles
│   ├── tests/
│   │   ├── conftest.py                # Pytest fixtures + test user factory
│   │   ├── test_security.py           # ★ 10 security integration tests
│   │   └── pytest.ini                 # Pytest configuration
│   └── requirements.txt               # Python dependencies
└── docs/
    ├── THREATS.md                     # ★ Full threat model (6 vectors, STRIDE/CWE)
    └── PROMPTS.md                     # AI usage log + security review checklist
```

---

## Five Security Hard Rules (Enforced in Code)

| # | Rule | Implementation |
|---|------|----------------|
| 1 | **Server-Side Zero Trust** | `enforce_document_access()` called on every route — no shortcuts | 
| 2 | **Immediate Revocation** | `revoked_at` checked live per request; ephemeral stream tokens max 25s |
| 3 | **Tamper-Evident Audit** | HMAC-SHA256 chain, DB-level UPDATE/DELETE triggers on `audit_logs` |
| 4 | **Anti-Enumeration** | 404 for BOTH "not found" AND "forbidden" (never 403 on resource probes) |
| 5 | **Admin ≠ Data Access** | ADMIN role explicitly blocked from document content without grant |

---

## Role Permission Matrix

| Action | VIEWER (no grant) | VIEWER (READ grant) | VIEWER (EDIT grant) | OWNER | ADMIN |
|--------|:-----------------:|:-------------------:|:-------------------:|:-----:|:-----:|
| Download binary | ❌ | ✅ | ✅ | ✅ | ❌* |
| Read metadata | ❌ | ✅ | ✅ | ✅ | ✅ |
| Edit document | ❌ | ❌ | ✅ | ✅ | ❌ |
| Delete document | ❌ | ❌ | ❌ | ✅ | ❌ |
| Grant access | ❌ | ❌ | ❌ | ✅ | ❌ |
| Revoke access | ❌ | ❌ | ❌ | ✅ | ❌ |
| View audit logs | ❌ | ❌ | ❌ | Own docs | System-wide |
| Manage users | ❌ | ❌ | ❌ | ❌ | ✅ |

> *ADMIN can download only with an explicit READ grant from the document owner.

---

## Security Test Coverage

| Test ID | Scenario | Expected Result |
|---------|----------|----------------|
| TC-01 | Cross-tenant IDOR probe | HTTP 404 + `READ_DENIED` audit entry |
| TC-02 | Access after immediate revocation | HTTP 404 on next request post-revoke |
| TC-03 | Admin downloads ungranted document | HTTP 404 + `READ_DENIED` as ADMIN |
| TC-04 | Middleware detached from route | Test FAILS → security regression caught |
| TC-05 | DELETE on `audit_logs` | DB trigger exception raised |
| TC-06 | Tampered audit hash | `verify_chain()` returns `(False, entry_id)` |
| TC-07 | Non-existent document probe | HTTP 404 (not 403) |
| TC-08 | Expired permission grant | HTTP 404 (expired = revoked) |
| TC-09 | Path traversal filename upload | Sanitized to safe name, no `..` |
| TC-10 | Deactivated user authenticates | `is_active=False` → 401 |

---

## Quick Start (Development)

```bash
# 1. Clone and enter directory
cd trustvault/backend

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment (copy and edit)
copy .env.example .env
# Edit .env: set JWT_SECRET, AUDIT_HMAC_KEY, STREAM_SECRET, DATABASE_URL

# 5. Initialize database
psql -U postgres -c "CREATE DATABASE trustvault;"
psql -U postgres -d trustvault -f database/schema.sql
psql -U postgres -d trustvault -f database/seed.sql

# 6. Run tests
pytest tests/ -v

# 7. Start development server
uvicorn app.main:app --reload --port 8000
```

---

## Cryptographic Audit Chain

Each `audit_logs` row is HMAC-linked to the previous:

```
Entry N:
  previous_hash = current_hash of Entry N-1
  payload       = JSON({ts, actor, action, resource, ip, ua, prev, ctx})
  current_hash  = HMAC-SHA256(AUDIT_HMAC_KEY, previous_hash + payload)

Entry 1 (genesis):
  previous_hash = "GENESIS"
  current_hash  = HMAC-SHA256(AUDIT_HMAC_KEY, "GENESIS" + payload)
```

**Tamper detection**: Any modification to any row (or deletion) breaks the chain.
Run `audit_service.verify_chain(logs)` to check integrity.

---

## Threat Model Summary

See [`docs/THREATS.md`](docs/THREATS.md) for the full STRIDE analysis.

| Threat | Severity | Mitigated |
|--------|----------|-----------|
| IDOR / BOLA on file routes | CRITICAL | ✅ |
| Stale token after revocation | HIGH | ✅ |
| Admin privilege escalation | HIGH | ✅ |
| Audit log tampering | HIGH | ✅ |
| Metadata enumeration | HIGH | ✅ |
| Malicious payload upload | HIGH | ✅ |

---

## AI Usage Log

All AI-generated code is tracked in [`docs/PROMPTS.md`](docs/PROMPTS.md) per security policy.
Every AI-generated security-critical component must have a corresponding review entry.

---

*TrustVault — Security Engineering | Classification: INTERNAL*

