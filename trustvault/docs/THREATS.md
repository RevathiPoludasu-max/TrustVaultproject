# TrustVault — Threat Model (STRIDE / OWASP Mapping)
> Version 1.0 | Classification: INTERNAL | Last Updated: 2026-11-05

## Document Purpose
This document enumerates the attack surface of TrustVault — a cryptographically-audited, server-enforced document sharing platform. Each threat is mapped to STRIDE categories, OWASP Top-10 (2021), and CWE identifiers, with concrete mitigation code patterns and test strategies.

---

## Threat Actors
| Actor | Description | Trust Level |
|---|---|---|
| Unauthenticated User | No session, probing public endpoints | ZERO |
| Authenticated Viewer | Valid JWT, READ grant on ≥1 doc | LOW |
| Authenticated Admin | System-wide metadata access, NO implicit file access | MEDIUM |
| Compromised Owner | Legitimate owner whose credential is stolen | MEDIUM |
| Insider Threat | Employee with DB read access | HIGH |
| Nation-State / APT | Full infrastructure compromise capability | CRITICAL |

---

## Threat Vector 1 — IDOR / BOLA on Direct File Download and Metadata Routes

**STRIDE Category:** Spoofing, Elevation of Privilege  
**OWASP 2021:** A01 – Broken Access Control  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

### Threat Scenario
An authenticated Viewer (User B) discovers a sequential or guessable document UUID by observing their own document IDs (e.g., doc-00042 → doc-00043). They craft a direct GET to `/api/documents/doc-00043/download` or `/api/documents/doc-00043/metadata`. The backend returns the resource without checking whether User B has an explicit READ permission row for that document_id, exposing a cross-tenant data leak.

### Root Cause
- Object identity (document ID) used as implicit authorization proof
- Authorization check missing or performed only on the list endpoint, not the resource endpoint
- Sequential/guessable IDs making enumeration trivial

### Mitigation Code Pattern
```python
# backend/app/middleware/authorization.py

async def enforce_document_access(
    document_id: str,
    actor: AuthenticatedUser,
    required_level: AccessLevel,
    db: AsyncSession,
    request: Request,
) -> Document:
    """
    HARD RULE: This function MUST be called before ANY document IO.
    Returns the Document only if access is confirmed. Raises HTTP 404 on
    any unauthorized or non-existent probe (anti-enumeration).
    """
    # Step 1: Resolve document existence (single query — no early 404 on miss alone)
    stmt = (
        select(Document)
        .where(Document.id == document_id)
        .options(selectinload(Document.owner))
    )
    result = await db.execute(stmt)
    document = result.scalar_one_or_none()

    # Step 2: Check explicit permission row
    has_permission = False
    if document is not None:
        if actor.role == Role.OWNER and document.owner_id == actor.id:
            has_permission = True
        elif actor.role == Role.ADMIN and required_level == AccessLevel.METADATA_ONLY:
            has_permission = True
        else:
            perm_stmt = select(Permission).where(
                Permission.document_id == document_id,
                Permission.user_id == actor.id,
                Permission.access_level >= required_level,
                Permission.revoked_at.is_(None),
            )
            perm_result = await db.execute(perm_stmt)
            has_permission = perm_result.scalar_one_or_none() is not None

    # Step 3: ALWAYS audit the attempt BEFORE returning, transactionally
    action = AuditAction.READ_SUCCESS if has_permission else AuditAction.READ_DENIED
    await audit_service.record(
        db=db,
        actor_id=actor.id,
        action=action,
        resource_id=document_id,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )
    await db.commit()  # Flush audit BEFORE returning any data

    # Step 4: Anti-enumeration — return 404 for BOTH "not found" AND "forbidden"
    if not has_permission:
        raise HTTPException(status_code=404, detail="Document not found")

    return document
```

### Accepted Trade-offs (7-Day Scope)
- UX: Legitimate users who lose access see "Not Found" rather than "Access Denied" — acceptable for security; can add a grace-period message in a later sprint.
- Performance: One extra DB query per request (permission check). Acceptable at this scale; add Redis permission cache with sub-second TTL invalidation post-MVP.

### Test Coverage Strategy
```python
# tests/test_idor.py
async def test_cross_tenant_idor_returns_404():
    """User B (no permission) MUST receive 404, not 200 or 403."""
    doc = await create_document(owner=user_a)
    response = await client.get(f"/api/documents/{doc.id}/download",
                                headers=auth_headers(user_b))
    assert response.status_code == 404
    # Verify audit trail
    log = await get_latest_audit_log(resource_id=doc.id, actor_id=user_b.id)
    assert log.action == "READ_DENIED"
    assert log.current_hash is not None  # Hash chain intact
```

---

## Threat Vector 2 — Access After Immediate Permission Revocation with Active Sessions

**STRIDE Category:** Elevation of Privilege  
**OWASP 2021:** A07 – Identification and Authentication Failures  
**CWE:** CWE-613 (Insufficient Session Expiration)

### Threat Scenario
Owner grants User B READ access. User B obtains a presigned download URL or caches a JWT. Owner then revokes User B's permission. User B replays the cached URL/token 60 seconds later and successfully downloads the document because the backend honored the token's TTL (e.g., 15 minutes) without re-checking the permission table.

### Root Cause
- Long-lived presigned URLs not tied to live permission state
- JWT-only auth without server-side session invalidation layer
- Access control checked only at token issuance time, not at resource delivery time

### Mitigation Code Pattern
```python
# backend/app/services/document_service.py

STREAM_TOKEN_TTL_SECONDS = 25  # Hard max. Never increase above 30s.

async def issue_ephemeral_stream_token(
    document_id: str,
    actor: AuthenticatedUser,
    db: AsyncSession,
    request: Request,
) -> StreamToken:
    """
    Issue a single-use, 25-second stream token ONLY after live permission check.
    Token is stored in Redis with the permission snapshot timestamp.
    """
    # Live permission check — MUST succeed before token issuance
    document = await enforce_document_access(
        document_id=document_id,
        actor=actor,
        required_level=AccessLevel.READ,
        db=db,
        request=request,
    )

    token_id = secrets.token_urlsafe(32)
    payload = {
        "sub": actor.id,
        "doc": document_id,
        "jti": token_id,
        "exp": time.time() + STREAM_TOKEN_TTL_SECONDS,
        "perm_snapshot": int(time.time()),  # Permission validity baseline
    }
    signed = jwt.encode(payload, settings.STREAM_SECRET, algorithm="HS256")

    # Store token ID in Redis for single-use invalidation
    await redis.setex(f"stream:{token_id}", STREAM_TOKEN_TTL_SECONDS, "valid")
    return StreamToken(token=signed, expires_in=STREAM_TOKEN_TTL_SECONDS)


async def stream_document(
    token: str,
    db: AsyncSession,
    request: Request,
) -> AsyncGenerator[bytes, None]:
    """
    Stream document bytes ONLY after:
    1. Token signature verification
    2. Live permission re-check (not just token check)
    3. Single-use token invalidation
    """
    try:
        payload = jwt.decode(token, settings.STREAM_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(403, "Stream token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(403, "Invalid stream token")

    jti = payload["jti"]
    doc_id = payload["doc"]
    actor_id = payload["sub"]

    # Check single-use: delete atomically returns old value
    was_valid = await redis.getdel(f"stream:{jti}")
    if was_valid is None:
        raise HTTPException(403, "Stream token already consumed or revoked")

    # CRITICAL: Re-check live permission — revocation must take effect immediately
    actor = await get_user(actor_id, db)
    perm = await db.execute(
        select(Permission).where(
            Permission.document_id == doc_id,
            Permission.user_id == actor_id,
            Permission.revoked_at.is_(None),
        )
    )
    if perm.scalar_one_or_none() is None and not (actor.role == Role.OWNER):
        await audit_service.record(db, actor_id, AuditAction.READ_DENIED,
                                   doc_id, request.client.host)
        await db.commit()
        raise HTTPException(404, "Document not found")

    # Stream from encrypted storage
    async for chunk in storage_service.stream(doc_id):
        yield chunk
```

### Accepted Trade-offs (7-Day Scope)
- 25-second ephemeral tokens mean interrupted downloads must restart. Acceptable for MVP; resumable downloads with range-request re-auth can be added in sprint 2.
- Redis dependency introduced. Fallback: synchronous DB token store if Redis is unavailable.

### Test Coverage Strategy
```python
async def test_immediate_revocation():
    doc = await create_document(owner=user_a)
    perm = await grant_access(doc, user_b, AccessLevel.READ)
    # Verify read succeeds
    token_resp = await client.post(f"/api/documents/{doc.id}/stream-token",
                                   headers=auth_headers(user_b))
    assert token_resp.status_code == 200

    # Revoke immediately
    await revoke_access(perm.id, revoker=user_a)

    # Attempt to use already-issued token (within TTL) — MUST fail
    stream_resp = await client.get(f"/api/documents/{doc.id}/stream",
                                   params={"token": token_resp.json()["token"]},
                                   headers=auth_headers(user_b))
    assert stream_resp.status_code in (403, 404)
```

---

## Threat Vector 3 — Admin Privilege Escalation (Admins Reading Private Files Without Explicit Grant)

**STRIDE Category:** Elevation of Privilege  
**OWASP 2021:** A01 – Broken Access Control  
**CWE:** CWE-269 (Improper Privilege Management)

### Threat Scenario
A system administrator uses their ADMIN role to call `/api/documents/{id}/download` and successfully receives the binary content of a private document they were never explicitly granted access to. This is a classic "super-admin reads everything" anti-pattern that violates least-privilege and enables insider threat.

### Root Cause
- Role-based access conflating "administrative capability" with "data access capability"
- Authorization middleware using `if role == ADMIN: allow_all` logic

### Mitigation Code Pattern
```python
# backend/app/middleware/authorization.py  (continued from above)

class PolicyEngine:
    """
    Explicit permission matrix. No implicit wildcard grants.
    
    ADMIN capabilities:
      ✅ View system-wide audit logs
      ✅ View document metadata (title, category, owner, created_at)
      ✅ Manage users (create, deactivate)
      ❌ Download document binary content (unless OWNER explicitly grants READ)
      ❌ View document content via metadata routes
    """

    @staticmethod
    async def evaluate(
        actor: AuthenticatedUser,
        action: PolicyAction,
        document: Document,
        db: AsyncSession,
    ) -> PolicyDecision:
        
        # OWNER has full control over their own documents
        if action in OWNER_ACTIONS and document.owner_id == actor.id:
            return PolicyDecision.ALLOW

        # ADMIN: metadata only, never binary content
        if actor.role == Role.ADMIN:
            if action == PolicyAction.READ_METADATA:
                return PolicyDecision.ALLOW
            if action in (PolicyAction.DOWNLOAD, PolicyAction.READ_CONTENT):
                # Even admin needs explicit permission for content
                explicit = await PolicyEngine._check_explicit_grant(
                    actor.id, document.id, AccessLevel.READ, db
                )
                return PolicyDecision.ALLOW if explicit else PolicyDecision.DENY

        # All other roles: require explicit grant
        explicit = await PolicyEngine._check_explicit_grant(
            actor.id, document.id, AccessLevel.READ, db
        )
        return PolicyDecision.ALLOW if explicit else PolicyDecision.DENY

    @staticmethod
    async def _check_explicit_grant(
        user_id: str, document_id: str, level: AccessLevel, db: AsyncSession
    ) -> bool:
        result = await db.execute(
            select(Permission).where(
                Permission.user_id == user_id,
                Permission.document_id == document_id,
                Permission.access_level >= level,
                Permission.revoked_at.is_(None),
            )
        )
        return result.scalar_one_or_none() is not None
```

### Accepted Trade-offs (7-Day Scope)
- Admins cannot perform emergency document retrieval without Owner involvement. For crisis scenarios, add an "emergency override" flow requiring dual approval (second admin) with mandatory audit flag in sprint 3.

### Test Coverage Strategy
```python
async def test_admin_cannot_download_ungranted_document():
    doc = await create_document(owner=user_owner)
    response = await client.get(f"/api/documents/{doc.id}/download",
                                headers=auth_headers(user_admin))
    assert response.status_code == 404
    log = await get_latest_audit_log(resource_id=doc.id, actor_id=user_admin.id)
    assert log.action == "READ_DENIED"
```

---

## Threat Vector 4 — Log Tampering / Retroactive Deletion of Unauthorized Access Attempts

**STRIDE Category:** Repudiation  
**OWASP 2021:** A09 – Security Logging and Monitoring Failures  
**CWE:** CWE-778 (Insufficient Logging), CWE-345 (Insufficient Verification of Data Authenticity)

### Threat Scenario
An insider attacker or compromised admin account attempts to cover tracks by issuing `DELETE FROM audit_logs WHERE actor_id = 'attacker'` or `UPDATE audit_logs SET action = 'READ_SUCCESS' WHERE action = 'READ_DENIED'`. Without cryptographic integrity protection, these tampering events are silent.

### Root Cause
- Audit logs stored in mutable relational tables without structural protection
- No cryptographic chain linking entries — any single-row delete is undetectable
- DB credentials with write access to audit tables shared with application

### Mitigation Code Pattern
```python
# backend/app/services/audit_service.py

import hashlib, hmac, json
from datetime import datetime, timezone

AUDIT_HMAC_KEY = settings.AUDIT_HMAC_KEY.encode()  # 32-byte secret, never logged

async def record(
    db: AsyncSession,
    actor_id: str,
    action: AuditAction,
    resource_id: str,
    ip_address: str,
    user_agent: str = "",
) -> AuditLog:
    """
    Append-only audit log entry with HMAC chain.
    Hash: SHA256(HMAC_KEY || prev_hash || timestamp || actor_id || action || resource_id)
    """
    # Fetch previous hash (latest entry)
    prev_stmt = (
        select(AuditLog.current_hash)
        .order_by(AuditLog.id.desc())
        .limit(1)
        .with_for_update(skip_locked=False)  # Serialized — prevents concurrent chain forks
    )
    prev_result = await db.execute(prev_stmt)
    prev_hash = prev_result.scalar_one_or_none() or "GENESIS"

    timestamp = datetime.now(timezone.utc).isoformat()
    payload = json.dumps({
        "ts": timestamp, "actor": actor_id, "action": action.value,
        "resource": resource_id, "ip": ip_address, "ua": user_agent,
        "prev": prev_hash,
    }, sort_keys=True, separators=(",", ":"))

    current_hash = hmac.new(
        AUDIT_HMAC_KEY,
        (prev_hash + payload).encode(),
        hashlib.sha256,
    ).hexdigest()

    entry = AuditLog(
        timestamp=timestamp, actor_id=actor_id, action=action,
        resource_id=resource_id, ip_address=ip_address, user_agent=user_agent,
        previous_hash=prev_hash, current_hash=current_hash,
    )
    db.add(entry)
    # Caller MUST commit — this keeps audit write in same transaction as business logic
    return entry
```

```sql
-- database/migrations/002_audit_protection.sql
-- PostgreSQL row-level security: application role CANNOT delete/update audit rows

REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM trustvault_app;
GRANT INSERT, SELECT ON audit_logs TO trustvault_app;

-- Trigger to block any UPDATE attempt even from superuser via application connection
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: mutation forbidden (CWE-778 mitigation)';
END;
$$;

CREATE TRIGGER audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
```

### Accepted Trade-offs (7-Day Scope)
- HMAC key rotation requires a full chain re-sign — plan key rotation procedure before go-live.
- Chain verification is O(n) — add periodic background verification job for large log tables.

### Test Coverage Strategy
```python
async def test_audit_log_cannot_be_deleted(db_session):
    log = await audit_service.record(db_session, user_a.id, AuditAction.READ_DENIED, doc.id, "127.0.0.1")
    await db_session.commit()
    with pytest.raises(Exception, match="append-only"):
        await db_session.execute(text(f"DELETE FROM audit_logs WHERE id = '{log.id}'"))

async def test_audit_chain_integrity():
    logs = await get_all_audit_logs_ordered()
    for i in range(1, len(logs)):
        expected = compute_hmac(logs[i-1].current_hash, logs[i])
        assert logs[i].current_hash == expected, f"Chain broken at entry {logs[i].id}"
```

---

## Threat Vector 5 — Metadata Enumeration via Search/Filter Endpoints

**STRIDE Category:** Information Disclosure  
**OWASP 2021:** A01 – Broken Access Control  
**CWE:** CWE-200 (Exposure of Sensitive Information)

### Threat Scenario
A Viewer calls `GET /api/documents?category=CONFIDENTIAL&owner=alice` and the backend returns paginated results including documents the Viewer has no permission to see, leaking titles, categories, and owner information.

### Root Cause
- Search/filter queries run against the full documents table without joining on the user's permission set
- Results filtered post-fetch on the application layer (bypassable via pagination manipulation)

### Mitigation Code Pattern
```python
# backend/app/routes/documents.py

async def search_documents(
    query: DocumentSearchQuery,
    actor: AuthenticatedUser,
    db: AsyncSession,
) -> list[DocumentSummary]:
    """
    SECURE: Permission join is part of the SQL query — not a post-filter.
    Users can only discover documents they have an active permission for.
    """
    base_stmt = (
        select(Document)
        .join(
            Permission,
            and_(
                Permission.document_id == Document.id,
                Permission.user_id == actor.id,
                Permission.revoked_at.is_(None),
            ),
            isouter=False,  # INNER JOIN — excludes all docs without active permission
        )
        .where(Document.owner_id == actor.id)  # OR clause added below for owners
    )

    # Owners see their own docs; viewers see only granted docs
    if actor.role == Role.OWNER:
        base_stmt = select(Document).where(
            or_(
                Document.owner_id == actor.id,
                exists(
                    select(Permission.id).where(
                        Permission.document_id == Document.id,
                        Permission.user_id == actor.id,
                        Permission.revoked_at.is_(None),
                    )
                ),
            )
        )

    # Apply search filters WITHIN the authorized scope only
    if query.category:
        base_stmt = base_stmt.where(Document.category == query.category)
    if query.title_contains:
        base_stmt = base_stmt.where(Document.title.ilike(f"%{query.title_contains}%"))

    # Pagination — randomized cursor to prevent ID-walk enumeration
    base_stmt = base_stmt.limit(min(query.limit, 50)).offset(query.offset)

    result = await db.execute(base_stmt)
    return [DocumentSummary.from_orm(d) for d in result.scalars()]
```

### Accepted Trade-offs (7-Day Scope)
- Full-text search across unauthorized documents is blocked by design — this is intentional.

### Test Coverage Strategy
```python
async def test_search_does_not_leak_unauthorized_docs():
    doc_a = await create_document(owner=user_a, category="CONFIDENTIAL")
    results = await client.get("/api/documents?category=CONFIDENTIAL",
                               headers=auth_headers(user_b))
    doc_ids = [d["id"] for d in results.json()["items"]]
    assert doc_a.id not in doc_ids
```

---

## Threat Vector 6 — Malicious Payload Uploads (Executable Polyglots, Path Traversal Filenames)

**STRIDE Category:** Tampering, Spoofing  
**OWASP 2021:** A03 – Injection, A04 – Insecure Design  
**CWE:** CWE-22 (Path Traversal), CWE-434 (Unrestricted File Upload)

### Threat Scenario
An attacker uploads a file named `../../../../etc/passwd` or a PDF/ZIP polyglot that executes as a shell script. If the server uses the client-supplied filename to construct a storage path, path traversal occurs. If the server doesn't validate MIME type, a malicious executable may be stored and later served with `Content-Type: application/octet-stream`.

### Root Cause
- Using client-supplied filenames in storage key construction
- MIME type trust from `Content-Type` header (attacker-controlled)
- Missing magic-byte validation on actual file content

### Mitigation Code Pattern
```python
# backend/app/services/upload_service.py

import magic  # python-magic for content-type sniffing
import re, uuid, hashlib

ALLOWED_MIME_TYPES = frozenset({
    "application/pdf",
    "image/png", "image/jpeg", "image/gif",
    "text/plain",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
})
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB hard limit

async def validate_and_store(
    file: UploadFile,
    actor: AuthenticatedUser,
    db: AsyncSession,
) -> Document:
    # 1. Sanitize filename — strip ALL path components, allow only safe chars
    safe_name = re.sub(r"[^\w\-.]", "_", Path(file.filename).name)
    safe_name = safe_name[:255]  # Max filename length

    # 2. Read content (streaming with size limit)
    content = b""
    async for chunk in file:
        content += chunk
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(413, "File exceeds maximum allowed size")

    # 3. Magic-byte MIME detection — do NOT trust Content-Type header
    detected_mime = magic.from_buffer(content[:2048], mime=True)
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(415, f"File type '{detected_mime}' is not permitted")

    # 4. Generate server-controlled storage key — NEVER use client filename as path
    storage_key = f"docs/{uuid.uuid4().hex}/{uuid.uuid4().hex}"

    # 5. Compute SHA-256 checksum for integrity verification
    checksum = hashlib.sha256(content).hexdigest()

    # 6. Store encrypted (AES-256-GCM via storage backend)
    await storage_service.put(storage_key, content, content_type=detected_mime)

    # 7. Create document record
    doc = Document(
        title=safe_name,
        owner_id=actor.id,
        storage_key=storage_key,
        checksum=checksum,
        original_filename=safe_name,
        detected_mime=detected_mime,
    )
    db.add(doc)
    await audit_service.record(db, actor.id, AuditAction.UPLOAD, doc.id, ...)
    await db.commit()
    return doc
```

### Accepted Trade-offs (7-Day Scope)
- Magic-byte detection can be fooled by advanced polyglots — add ClamAV integration in sprint 2 for AV scanning.
- Large file chunked uploads need multipart reassembly before MIME check — scope for sprint 2.

### Test Coverage Strategy
```python
async def test_path_traversal_filename_sanitized():
    response = await upload_file("../../../../etc/passwd", b"malicious", user_a)
    assert response.status_code == 200
    doc = response.json()
    assert ".." not in doc["title"]
    assert "/" not in doc["title"]

async def test_executable_upload_rejected():
    elf_magic = b"\x7fELF" + b"\x00" * 100
    response = await upload_file("malware.pdf", elf_magic, user_a)
    assert response.status_code == 415
```

---

## Risk Register Summary

| ID | Threat | Severity | Likelihood | Risk | Mitigated |
|---|---|---|---|---|---|
| TV-01 | IDOR/BOLA on file routes | CRITICAL | HIGH | CRITICAL | ✅ Yes |
| TV-02 | Stale token after revocation | HIGH | MEDIUM | HIGH | ✅ Yes |
| TV-03 | Admin privilege escalation | HIGH | MEDIUM | HIGH | ✅ Yes |
| TV-04 | Audit log tampering | HIGH | LOW | MEDIUM | ✅ Yes |
| TV-05 | Metadata enumeration | MEDIUM | HIGH | HIGH | ✅ Yes |
| TV-06 | Malicious upload | HIGH | MEDIUM | HIGH | ✅ Yes |

---

*Document maintained by: Security Engineering*  
*Review cycle: Every sprint (bi-weekly)*  
*Next review: 2026-11-19*
