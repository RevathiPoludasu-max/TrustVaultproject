"""
TrustVault Test Configuration & Fixtures
=========================================
Provides reusable pytest fixtures for integration tests.
Uses an in-memory SQLite database (via aiosqlite) for speed,
with a PostgreSQL fixture available via pytest-postgresql for full-stack tests.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.models.domain import (
    AccessLevel,
    AuditAction,
    AuditLog,
    Base,
    Document,
    DocumentStatus,
    Permission,
    Session as DBSession,
    User,
    UserRole,
)
from app.core.config import settings

# ---------------------------------------------------------------------------
# Override settings for test environment
# ---------------------------------------------------------------------------
settings.AUDIT_HMAC_KEY = "test-hmac-key-must-be-32-chars-xx"
settings.JWT_SECRET = "test-jwt-secret-must-be-32-chars-x"
settings.STREAM_SECRET = "test-stream-secret-32-chars-xxxxx"
settings.TESTING = True

# ---------------------------------------------------------------------------
# Async test infrastructure
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop for all async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create a fresh in-memory SQLite engine per test function."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a fresh database session per test, rolled back after each test."""
    async_session = async_sessionmaker(
        db_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session
        await session.rollback()


# ---------------------------------------------------------------------------
# Test User Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def user_admin(db_session: AsyncSession) -> User:
    """ADMIN role user — system metadata access, NO implicit file access."""
    user = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        email="admin@test.local",
        display_name="Test Admin",
        role=UserRole.ADMIN,
        password_hash="$argon2id$test",
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def user_owner(db_session: AsyncSession) -> User:
    """OWNER role user — creates and manages documents."""
    user = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
        email="owner@test.local",
        display_name="Alice Owner",
        role=UserRole.OWNER,
        password_hash="$argon2id$test",
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def user_viewer_a(db_session: AsyncSession) -> User:
    """VIEWER role — will have explicit grants on some documents."""
    user = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000003"),
        email="viewer_a@test.local",
        display_name="Bob Viewer A",
        role=UserRole.VIEWER,
        password_hash="$argon2id$test",
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def user_viewer_b(db_session: AsyncSession) -> User:
    """VIEWER role — NO grants (used for negative/IDOR tests)."""
    user = User(
        id=uuid.UUID("00000000-0000-0000-0000-000000000004"),
        email="viewer_b@test.local",
        display_name="Carol Viewer B",
        role=UserRole.VIEWER,
        password_hash="$argon2id$test",
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


# ---------------------------------------------------------------------------
# Test Document Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def document_owned_by_alice(
    db_session: AsyncSession, user_owner: User
) -> Document:
    """A CONFIDENTIAL document owned by Alice (user_owner)."""
    doc = Document(
        id=uuid.UUID("10000000-0000-0000-0000-000000000001"),
        title="Q4 Financial Report",
        category="CONFIDENTIAL",
        owner_id=user_owner.id,
        storage_key=f"docs/test/{uuid.uuid4().hex}",
        checksum="a" * 64,
        detected_mime="application/pdf",
        original_filename="Q4_Financial_Report.pdf",
        file_size_bytes=204800,
        status=DocumentStatus.ACTIVE,
    )
    db_session.add(doc)
    await db_session.flush()
    return doc


# ---------------------------------------------------------------------------
# Auth Token Helper
# ---------------------------------------------------------------------------

def make_auth_headers(user: User, session_id: uuid.UUID = None) -> dict:
    """Generate JWT auth headers for a test user."""
    from app.auth.jwt_handler import create_access_token
    sid = session_id or uuid.uuid4()
    token = create_access_token(
        subject=str(user.id),
        session_id=str(sid),
        role=user.role.value,
    )
    return {"Authorization": f"Bearer {token}"}


async def create_test_session(
    db: AsyncSession, user: User, session_id: uuid.UUID = None
) -> DBSession:
    """Create a valid DB session record for a test user."""
    sid = session_id or uuid.uuid4()
    session = DBSession(
        id=sid,
        user_id=user.id,
        token_hash=f"test_hash_{sid}",
        ip_address="127.0.0.1",
        user_agent="pytest/1.0",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(session)
    await db.flush()
    return session
