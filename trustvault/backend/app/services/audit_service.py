"""
TrustVault Audit Service
========================
Provides cryptographically chained, append-only audit logging.

SECURITY DESIGN:
- Every audit entry is HMAC-SHA256 chained to the previous entry.
- Hash: HMAC(KEY, prev_hash || JSON_payload) where payload is deterministically serialized.
- The chain is serialized via SELECT ... FOR UPDATE to prevent concurrent forks.
- This service NEVER commits — the caller must commit to keep audit writes
  in the same transaction as the business action they record.

NEVER:
- Call this service outside of a live database transaction.
- Skip calling this service on DENIED access attempts.
- Allow the AUDIT_HMAC_KEY to be logged or returned to clients.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.domain import AuditLog, AuditAction, UserRole
from app.core.config import settings


# ---------------------------------------------------------------------------
# Chain integrity helpers
# ---------------------------------------------------------------------------

def _build_payload(
    *,
    timestamp: str,
    actor_id: Optional[str],
    action: str,
    resource_id: Optional[str],
    ip_address: Optional[str],
    user_agent: Optional[str],
    prev_hash: str,
    context: dict,
) -> str:
    """
    Build a deterministic JSON payload string for HMAC computation.
    Keys are sorted to ensure reproducibility across Python versions.
    """
    return json.dumps(
        {
            "ts": timestamp,
            "actor": str(actor_id) if actor_id else None,
            "action": action,
            "resource": str(resource_id) if resource_id else None,
            "ip": ip_address,
            "ua": user_agent,
            "prev": prev_hash,
            "ctx": context,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def compute_audit_hash(prev_hash: str, payload: str) -> str:
    """
    Compute HMAC-SHA256(AUDIT_HMAC_KEY, prev_hash + payload).
    Returns hex digest (64 characters).
    
    SECURITY: Uses constant-time comparison key from settings.
    Key must be at least 32 bytes of cryptographic randomness.
    """
    key = settings.AUDIT_HMAC_KEY.encode("utf-8")
    message = (prev_hash + payload).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_chain(logs: list[AuditLog]) -> tuple[bool, Optional[int]]:
    """
    Verify the cryptographic integrity of a sequence of audit log entries.
    
    Returns:
        (True, None) if chain is intact.
        (False, broken_at_id) if chain is broken at the given log entry ID.
    
    Usage: Run periodically as a background job or on-demand by security team.
    """
    if not logs:
        return True, None

    for i, log in enumerate(logs):
        if i == 0:
            # First entry must reference GENESIS
            if log.previous_hash != "GENESIS":
                return False, log.id
        else:
            prev = logs[i - 1]
            # Reconstruct the payload for the previous entry to verify current entry's prev_hash
            if log.previous_hash != prev.current_hash:
                return False, log.id

        # Reconstruct payload and verify current_hash
        payload = _build_payload(
            timestamp=log.timestamp.isoformat() if isinstance(log.timestamp, datetime) else log.timestamp,
            actor_id=str(log.actor_id) if log.actor_id else None,
            action=log.action.value if hasattr(log.action, "value") else log.action,
            resource_id=str(log.resource_id) if log.resource_id else None,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            prev_hash=log.previous_hash,
            context=log.context or {},
        )
        expected_hash = compute_audit_hash(log.previous_hash, payload)
        if log.current_hash != expected_hash:
            return False, log.id

    return True, None


# ---------------------------------------------------------------------------
# Core audit recording function
# ---------------------------------------------------------------------------

async def record(
    db: AsyncSession,
    actor_id: Optional[uuid.UUID],
    action: AuditAction,
    resource_id: Optional[uuid.UUID],
    ip_address: Optional[str],
    *,
    actor_email: Optional[str] = None,
    actor_role: Optional[UserRole] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[uuid.UUID] = None,
    resource_type: str = "document",
    context: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """
    Append a new audit log entry with HMAC chain linkage.

    CRITICAL RULES:
    1. This function acquires a row-level lock (FOR UPDATE) on the last audit entry
       to serialize concurrent inserts and prevent chain forks.
    2. The caller MUST commit the session after calling this function.
       DO NOT commit inside this function — keep audit in the same transaction
       as the business operation.
    3. This function MUST be called for BOTH successful and denied access attempts.
    4. Never catch exceptions from this function silently — a failed audit write
       must fail the entire request (fail-secure).

    Args:
        db: Active async database session (uncommitted transaction).
        actor_id: UUID of the user performing the action.
        action: AuditAction enum value.
        resource_id: UUID of the document or resource being acted upon.
        ip_address: Client IP address from request.
        actor_email: Snapshot of actor's email (preserved if user is deleted).
        actor_role: Snapshot of actor's role at time of action.
        user_agent: HTTP User-Agent header.
        request_id: Correlation ID for request tracing.
        resource_type: 'document', 'user', 'permission', etc.
        context: Additional structured JSON context.

    Returns:
        The created AuditLog ORM instance (not yet committed).

    Raises:
        RuntimeError: If the AUDIT_HMAC_KEY is not configured.
        Exception: Propagates DB errors — do not suppress.
    """
    if not settings.AUDIT_HMAC_KEY or len(settings.AUDIT_HMAC_KEY) < 32:
        raise RuntimeError(
            "AUDIT_HMAC_KEY must be at least 32 characters. "
            "Refusing to write audit log with weak key."
        )

    # Acquire the previous hash with a serializing lock to prevent concurrent chain forks
    prev_stmt = (
        select(AuditLog.current_hash, AuditLog.id)
        .order_by(AuditLog.id.desc())
        .limit(1)
        .with_for_update()  # Row-level exclusive lock for chain serialization
    )
    prev_result = await db.execute(prev_stmt)
    prev_row = prev_result.first()
    prev_hash = prev_row[0] if prev_row else "GENESIS"

    timestamp = datetime.now(timezone.utc).isoformat()
    ctx = context or {}

    payload = _build_payload(
        timestamp=timestamp,
        actor_id=str(actor_id) if actor_id else None,
        action=action.value,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=ip_address,
        user_agent=user_agent,
        prev_hash=prev_hash,
        context=ctx,
    )

    current_hash = compute_audit_hash(prev_hash, payload)

    entry = AuditLog(
        timestamp=datetime.now(timezone.utc),
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        action=action,
        resource_id=resource_id,
        resource_type=resource_type,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        context=ctx,
        previous_hash=prev_hash,
        current_hash=current_hash,
    )
    db.add(entry)

    # NOTE: DO NOT call db.commit() here.
    # The caller is responsible for committing to keep audit in the same transaction.
    return entry
