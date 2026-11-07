"""
TrustVault Authorization Middleware & Policy Engine
====================================================

SECURITY CONTRACT (enforced by this module):
--------------------------------------------
1. ZERO TRUST: Every request resolves permissions from the database in real time.
   No caching of permission decisions. No trust in JWTs alone for authorization.

2. ANTI-ENUMERATION: Unauthorized or non-existent resource probes return HTTP 404,
   never HTTP 403. This prevents resource ID enumeration by timing or status code.

3. FAIL SECURE: Any exception during the authorization pipeline MUST result in
   denial, not passage. The default decision is DENY.

4. AUDIT ON BOTH OUTCOMES: Both ALLOWED and DENIED access attempts are recorded
   transactionally before any data is returned or error is raised.

5. ADMIN ≠ DATA ACCESS: ADMIN role grants system metadata access only.
   Binary document content requires an explicit Permission row even for ADMINs.

NEVER:
- Remove the `await enforce_document_access(...)` call from a route handler.
- Add an `if settings.TESTING: skip_auth()` bypass.
- Return HTTP 403 for resource probes (always use 404).
- Commit the audit log separately from the business transaction.
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy import and_, exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.domain import (
    AccessLevel,
    AuditAction,
    AuthenticatedUser,
    Document,
    DocumentStatus,
    Permission,
    PolicyAction,
    PolicyDecision,
    UserRole,
)
from app.services import audit_service
from app.db.session import get_db
from app.auth.jwt_handler import decode_access_token

logger = logging.getLogger(__name__)

# Actions that only an OWNER can perform on their own documents
OWNER_ONLY_ACTIONS = frozenset({
    PolicyAction.DELETE,
    PolicyAction.GRANT_ACCESS,
    PolicyAction.REVOKE_ACCESS,
})

# Actions that an ADMIN can perform on any document (metadata only, no content)
ADMIN_METADATA_ACTIONS = frozenset({
    PolicyAction.READ_METADATA,
    PolicyAction.VIEW_AUDIT,
})


# ===========================================================================
# JWT → AuthenticatedUser resolution
# ===========================================================================

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthenticatedUser:
    """
    FastAPI dependency: Resolve and validate the authenticated user from the
    Authorization Bearer token.

    Security steps:
    1. Extract Bearer token from Authorization header.
    2. Verify JWT signature and expiry.
    3. Load user from DB to verify account is still active (not deactivated).
    4. Verify session is still valid (not revoked).

    Raises HTTP 401 for any authentication failure.
    Does NOT raise HTTP 403 — unauthenticated requests get 401, not 403.
    """
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.removeprefix("Bearer ").strip()

    try:
        payload = decode_access_token(token)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    session_id = payload.get("sid")

    if not user_id or not session_id:
        raise HTTPException(status_code=401, detail="Malformed token claims")

    # Live user check — must be active in DB (catches deactivated accounts)
    from app.models.domain import User, Session
    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(user_id),
            User.is_active == True,
        )
    )
    db_user = user_result.scalar_one_or_none()
    if db_user is None:
        raise HTTPException(status_code=401, detail="User not found or deactivated")

    # Live session check — catches immediately revoked sessions
    from datetime import datetime, timezone
    session_result = await db.execute(
        select(Session).where(
            Session.id == uuid.UUID(session_id),
            Session.user_id == db_user.id,
            Session.revoked_at.is_(None),
            Session.expires_at > datetime.now(timezone.utc),
        )
    )
    db_session = session_result.scalar_one_or_none()
    if db_session is None:
        raise HTTPException(
            status_code=401,
            detail="Session expired or revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return AuthenticatedUser(
        id=db_user.id,
        email=db_user.email,
        role=db_user.role,
        session_id=uuid.UUID(session_id),
        is_active=db_user.is_active,
    )


# ===========================================================================
# Policy Engine
# ===========================================================================

class PolicyEngine:
    """
    Explicit permission matrix for TrustVault.

    Decision table:
    ┌─────────────┬──────────────────┬──────────────────────────────────────┐
    │ Actor Role  │ Action           │ Decision                              │
    ├─────────────┼──────────────────┼──────────────────────────────────────┤
    │ OWNER       │ Any on own doc   │ ALLOW                                 │
    │ ADMIN       │ READ_METADATA    │ ALLOW (system-wide)                   │
    │ ADMIN       │ VIEW_AUDIT       │ ALLOW (system-wide)                   │
    │ ADMIN       │ DOWNLOAD/CONTENT │ DENY unless explicit Permission row   │
    │ VIEWER      │ DOWNLOAD/READ    │ ALLOW only with active Permission row │
    │ VIEWER      │ EDIT             │ ALLOW only with EDIT Permission row   │
    │ ANY         │ OWNER_ONLY acts  │ DENY unless actor is document owner   │
    └─────────────┴──────────────────┴──────────────────────────────────────┘
    """

    @staticmethod
    async def evaluate(
        actor: AuthenticatedUser,
        action: PolicyAction,
        document: Document,
        db: AsyncSession,
    ) -> PolicyDecision:
        """
        Evaluate whether `actor` is permitted to perform `action` on `document`.

        DESIGN: Default return is DENY. Only explicit matching conditions return ALLOW.
        This "default deny" posture is intentional and must not be changed.
        """
        # --- OWNER: full control over their own documents ---
        if document.owner_id == actor.id:
            # Owners can do everything on their own documents
            return PolicyDecision.ALLOW

        # --- OWNER-ONLY actions: no other role can perform these ---
        if action in OWNER_ONLY_ACTIONS:
            return PolicyDecision.DENY

        # --- ADMIN: metadata and audit only, never binary content ---
        if actor.role == UserRole.ADMIN:
            if action in ADMIN_METADATA_ACTIONS:
                return PolicyDecision.ALLOW
            # Admin downloading content requires an explicit grant (same as any user)
            if action in (PolicyAction.DOWNLOAD, PolicyAction.READ_CONTENT):
                has_grant = await PolicyEngine._has_active_permission(
                    actor.id, document.id, AccessLevel.READ, db
                )
                return PolicyDecision.ALLOW if has_grant else PolicyDecision.DENY
            return PolicyDecision.DENY  # Default deny for ADMIN on other actions

        # --- VIEWER / other roles: require explicit active permission ---
        if action in (PolicyAction.READ_CONTENT, PolicyAction.DOWNLOAD, PolicyAction.READ_METADATA):
            has_grant = await PolicyEngine._has_active_permission(
                actor.id, document.id, AccessLevel.READ, db
            )
            return PolicyDecision.ALLOW if has_grant else PolicyDecision.DENY

        if action == PolicyAction.EDIT:
            has_grant = await PolicyEngine._has_active_permission(
                actor.id, document.id, AccessLevel.EDIT, db
            )
            return PolicyDecision.ALLOW if has_grant else PolicyDecision.DENY

        # Default: deny anything not explicitly handled
        return PolicyDecision.DENY

    @staticmethod
    async def _has_active_permission(
        user_id: uuid.UUID,
        document_id: uuid.UUID,
        required_level: AccessLevel,
        db: AsyncSession,
    ) -> bool:
        """
        Check for an active, non-expired, non-revoked permission row.
        
        SECURITY: This queries the live database — not a cache.
        Revocation is immediate because revoked_at is set instantly.
        """
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        # Build query matching the required or higher access level
        level_values = [AccessLevel.READ]
        if required_level == AccessLevel.READ:
            level_values = [AccessLevel.READ, AccessLevel.EDIT]  # EDIT implies READ
        else:
            level_values = [AccessLevel.EDIT]

        stmt = select(Permission).where(
            and_(
                Permission.user_id == user_id,
                Permission.document_id == document_id,
                Permission.access_level.in_(level_values),
                Permission.revoked_at.is_(None),
                # Also check expiry
                (Permission.expires_at.is_(None)) | (Permission.expires_at > now),
            )
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None


# ===========================================================================
# Core Authorization Enforcer
# ===========================================================================

async def enforce_document_access(
    document_id: uuid.UUID,
    actor: AuthenticatedUser,
    action: PolicyAction,
    db: AsyncSession,
    request: Request,
    *,
    required_level: AccessLevel = AccessLevel.READ,
    context: Optional[dict] = None,
) -> Document:
    """
    Gate function: MUST be called before any document IO operation.

    This function:
    1. Loads the document from the database.
    2. Evaluates the policy engine decision.
    3. Writes a transactional audit log entry (SUCCESS or DENIED).
    4. Returns the Document on ALLOW or raises HTTP 404 on DENY.

    ANTI-ENUMERATION: Both "not found" and "forbidden" return HTTP 404.
    This prevents an attacker from distinguishing existing-but-forbidden
    documents from non-existent ones.

    Args:
        document_id: The UUID of the document to access.
        actor: The authenticated user attempting the action.
        action: The PolicyAction being attempted.
        db: Active database session (must be in a transaction).
        request: FastAPI Request object for IP/User-Agent extraction.
        required_level: Minimum AccessLevel required (READ or EDIT).
        context: Additional JSON context for the audit log.

    Returns:
        Document ORM instance if access is granted.

    Raises:
        HTTPException(404): If document does not exist OR if access is denied
                            (anti-enumeration: never returns 403).
        HTTPException(423): If document is quarantined.
    """
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")

    # ----- Step 1: Resolve document (DO NOT raise 404 here — do it after audit) -----
    doc_stmt = (
        select(Document)
        .where(Document.id == document_id)
        .options(selectinload(Document.owner))
    )
    doc_result = await db.execute(doc_stmt)
    document = doc_result.scalar_one_or_none()

    # ----- Step 2: Evaluate policy -----
    # We evaluate even for non-existent documents to avoid timing attacks.
    # For non-existent docs, we always deny.
    if document is None or document.status == DocumentStatus.DELETED:
        decision = PolicyDecision.DENY
        audit_action = AuditAction.READ_DENIED
    elif document.status == DocumentStatus.QUARANTINED:
        decision = PolicyDecision.DENY
        audit_action = AuditAction.READ_DENIED
    else:
        decision = await PolicyEngine.evaluate(actor, action, document, db)
        if action == PolicyAction.READ_METADATA and actor.role == UserRole.ADMIN:
            audit_action = AuditAction.ADMIN_METADATA_READ
        elif decision == PolicyDecision.ALLOW:
            audit_action = AuditAction.READ_SUCCESS
        else:
            audit_action = AuditAction.READ_DENIED

    # ----- Step 3: Write audit entry BEFORE returning any data -----
    # This is a hard requirement: audit MUST precede data delivery.
    try:
        await audit_service.record(
            db=db,
            actor_id=actor.id,
            action=audit_action,
            resource_id=document_id,
            ip_address=ip,
            actor_email=actor.email,
            actor_role=actor.role,
            user_agent=ua,
            resource_type="document",
            context={
                "policy_action": action.value,
                "decision": decision.value,
                **(context or {}),
            },
        )
        # Flush the audit entry to the transaction (but don't commit yet)
        await db.flush()
    except Exception as e:
        # FAIL SECURE: If audit write fails, deny access rather than proceeding without a log
        logger.critical(
            "AUDIT WRITE FAILURE — denying access as fail-secure measure. "
            "document_id=%s actor_id=%s error=%s",
            document_id, actor.id, str(e)
        )
        raise HTTPException(
            status_code=503,
            detail="Audit system unavailable — access denied for security (fail-secure)",
        )

    # ----- Step 4: Enforce decision — 404 for both not-found AND forbidden -----
    if decision == PolicyDecision.DENY:
        # Anti-enumeration: 404 for BOTH "doesn't exist" AND "forbidden"
        await db.commit()  # Commit the DENIED audit entry before raising
        raise HTTPException(status_code=404, detail="Document not found")

    if document is not None and document.status == DocumentStatus.QUARANTINED:
        await db.commit()
        raise HTTPException(status_code=423, detail="Document is locked")

    return document


# ===========================================================================
# Permission Management
# ===========================================================================

async def grant_permission(
    document_id: uuid.UUID,
    target_user_id: uuid.UUID,
    access_level: AccessLevel,
    granter: AuthenticatedUser,
    db: AsyncSession,
    request: Request,
) -> Permission:
    """
    Grant access to a document. Only the OWNER of the document can grant access.
    Transactionally records a GRANT audit entry.
    """
    # Verify granter is the document owner
    doc = await enforce_document_access(
        document_id=document_id,
        actor=granter,
        action=PolicyAction.GRANT_ACCESS,
        db=db,
        request=request,
    )

    # Check for existing active permission (idempotency)
    existing_stmt = select(Permission).where(
        Permission.document_id == document_id,
        Permission.user_id == target_user_id,
        Permission.revoked_at.is_(None),
    )
    existing = (await db.execute(existing_stmt)).scalar_one_or_none()
    if existing:
        # Update access level if different
        if existing.access_level != access_level:
            existing.access_level = access_level
        return existing

    perm = Permission(
        document_id=document_id,
        user_id=target_user_id,
        access_level=access_level,
        granted_by=granter.id,
    )
    db.add(perm)

    await audit_service.record(
        db=db,
        actor_id=granter.id,
        action=AuditAction.GRANT,
        resource_id=document_id,
        ip_address=request.client.host if request.client else "unknown",
        actor_email=granter.email,
        actor_role=granter.role,
        context={
            "target_user_id": str(target_user_id),
            "access_level": access_level.value,
        },
    )
    await db.commit()
    return perm


async def revoke_permission(
    permission_id: uuid.UUID,
    revoker: AuthenticatedUser,
    db: AsyncSession,
    request: Request,
) -> None:
    """
    Revoke an active permission. Revocation is IMMEDIATE — the revoked_at
    timestamp is set, and all subsequent requests re-check this column.
    """
    from datetime import datetime, timezone

    perm_stmt = select(Permission).where(
        Permission.id == permission_id,
        Permission.revoked_at.is_(None),
    )
    perm = (await db.execute(perm_stmt)).scalar_one_or_none()
    if perm is None:
        raise HTTPException(status_code=404, detail="Permission not found or already revoked")

    # Only the document owner can revoke
    doc_stmt = select(Document).where(Document.id == perm.document_id)
    doc = (await db.execute(doc_stmt)).scalar_one_or_none()
    if doc is None or doc.owner_id != revoker.id:
        # Anti-enumeration: return 404 not 403
        raise HTTPException(status_code=404, detail="Document not found")

    perm.revoked_at = datetime.now(timezone.utc)
    perm.revoked_by = revoker.id

    await audit_service.record(
        db=db,
        actor_id=revoker.id,
        action=AuditAction.REVOKE,
        resource_id=perm.document_id,
        ip_address=request.client.host if request.client else "unknown",
        actor_email=revoker.email,
        actor_role=revoker.role,
        context={
            "revoked_permission_id": str(permission_id),
            "affected_user_id": str(perm.user_id),
        },
    )
    await db.commit()
