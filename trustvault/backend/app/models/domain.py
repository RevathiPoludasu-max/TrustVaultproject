"""
TrustVault Domain Models
========================
Pydantic models and SQLAlchemy ORM definitions for all core entities.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Enum, ForeignKey,
    Integer, String, Text, UniqueConstraint, event
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    OWNER = "OWNER"
    VIEWER = "VIEWER"


class AccessLevel(str, enum.Enum):
    READ = "READ"
    EDIT = "EDIT"

    def __ge__(self, other: "AccessLevel") -> bool:
        order = {AccessLevel.READ: 0, AccessLevel.EDIT: 1}
        return order[self] >= order[other]

    def __gt__(self, other: "AccessLevel") -> bool:
        order = {AccessLevel.READ: 0, AccessLevel.EDIT: 1}
        return order[self] > order[other]


class AuditAction(str, enum.Enum):
    UPLOAD = "UPLOAD"
    READ_SUCCESS = "READ_SUCCESS"
    READ_DENIED = "READ_DENIED"
    EDIT_SUCCESS = "EDIT_SUCCESS"
    EDIT_DENIED = "EDIT_DENIED"
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    DELETE = "DELETE"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    TOKEN_ISSUED = "TOKEN_ISSUED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    ADMIN_METADATA_READ = "ADMIN_METADATA_READ"
    UPLOAD_REJECTED = "UPLOAD_REJECTED"


class DocumentStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DELETED = "DELETED"
    QUARANTINED = "QUARANTINED"


class PolicyAction(str, enum.Enum):
    DOWNLOAD = "DOWNLOAD"
    READ_CONTENT = "READ_CONTENT"
    READ_METADATA = "READ_METADATA"
    EDIT = "EDIT"
    DELETE = "DELETE"
    GRANT_ACCESS = "GRANT_ACCESS"
    REVOKE_ACCESS = "REVOKE_ACCESS"
    VIEW_AUDIT = "VIEW_AUDIT"


class PolicyDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


# ---------------------------------------------------------------------------
# SQLAlchemy ORM Base
# ---------------------------------------------------------------------------

class Base(AsyncAttrs, DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"), nullable=False, default=UserRole.VIEWER
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    totp_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    deactivated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45))
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Relationships
    documents: Mapped[list["Document"]] = relationship(
        "Document", back_populates="owner", foreign_keys="Document.owner_id"
    )
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission", back_populates="user", foreign_keys="Permission.user_id"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(100))

    user: Mapped["User"] = relationship("User")


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(100))
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    storage_key: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    detected_mime: Mapped[str] = mapped_column(String(127), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[DocumentStatus] = mapped_column(
        Enum(DocumentStatus, name="document_status"),
        nullable=False,
        default=DocumentStatus.ACTIVE,
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    owner: Mapped["User"] = relationship(
        "User", back_populates="documents", foreign_keys=[owner_id]
    )
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission", back_populates="document"
    )


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    access_level: Mapped[AccessLevel] = mapped_column(
        Enum(AccessLevel, name="access_level"), nullable=False
    )
    granted_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id")
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="permissions")
    user: Mapped["User"] = relationship("User", back_populates="permissions", foreign_keys=[user_id])
    granter: Mapped["User"] = relationship("User", foreign_keys=[granted_by])


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_email: Mapped[Optional[str]] = mapped_column(String(254))
    actor_role: Mapped[Optional[UserRole]] = mapped_column(
        Enum(UserRole, name="user_role")
    )
    action: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction, name="audit_action"), nullable=False
    )
    resource_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    resource_type: Mapped[Optional[str]] = mapped_column(String(50))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    request_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True))
    context: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    previous_hash: Mapped[str] = mapped_column(Text, nullable=False)
    current_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)


# ---------------------------------------------------------------------------
# Pydantic Schemas (API layer)
# ---------------------------------------------------------------------------

class AuthenticatedUser(BaseModel):
    """Decoded JWT payload — represents the currently authenticated request actor."""
    id: uuid.UUID
    email: EmailStr
    role: UserRole
    session_id: uuid.UUID
    is_active: bool = True

    class Config:
        from_attributes = True


class DocumentSummary(BaseModel):
    """Safe document representation — never exposes storage_key or checksum."""
    id: uuid.UUID
    title: str
    category: Optional[str]
    owner_id: uuid.UUID
    detected_mime: str
    file_size_bytes: int
    created_at: datetime
    status: DocumentStatus

    class Config:
        from_attributes = True


class StreamToken(BaseModel):
    token: str
    expires_in: int
    document_id: uuid.UUID


class DocumentSearchQuery(BaseModel):
    category: Optional[str] = None
    title_contains: Optional[str] = None
    limit: int = Field(default=20, ge=1, le=50)
    offset: int = Field(default=0, ge=0)

    @field_validator("title_contains")
    @classmethod
    def sanitize_search(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Strip SQL wildcards and control chars from search input
        return v.replace("%", "").replace("_", "").strip()[:100]
