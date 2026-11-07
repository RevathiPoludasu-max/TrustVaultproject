"""
TrustVault — FastAPI Application Entry Point
=============================================

SECURITY CONFIGURATION:
- All routes require authentication (Bearer JWT + live session check).
- Document routes require enforce_document_access() — NEVER skip this gate.
- Audit logging is synchronous and transactional — no async fire-and-forget.
- 404 is returned for both "not found" and "forbidden" (anti-enumeration).
- CORS is restricted to explicit allowlist (empty by default).
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trustvault")


# ---------------------------------------------------------------------------
# Application Lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("TrustVault starting up — validating security configuration...")

    # Validate critical secrets are not default/weak values
    if "dev-" in settings.AUDIT_HMAC_KEY and not settings.TESTING:
        logger.critical(
            "SECURITY WARNING: AUDIT_HMAC_KEY appears to be a development default. "
            "Set a production secret before deployment."
        )

    if "dev-" in settings.JWT_SECRET and not settings.TESTING:
        logger.critical(
            "SECURITY WARNING: JWT_SECRET appears to be a development default."
        )

    logger.info("TrustVault startup complete.")
    yield
    logger.info("TrustVault shutting down.")


# ---------------------------------------------------------------------------
# Application Instance
# ---------------------------------------------------------------------------

app = FastAPI(
    title="TrustVault API",
    version=settings.APP_VERSION,
    description=(
        "Ultra-secure document sharing platform with cryptographically "
        "verifiable audit trails and server-enforced object-level access control."
    ),
    docs_url="/api/docs" if settings.DEBUG else None,  # Disable Swagger in production
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Security Middleware Stack
# ---------------------------------------------------------------------------

# 1. Trusted Host (prevents Host header attacks)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "trustvault.local", "*.trustvault.io"],
)

# 2. CORS — restrictive by default (empty allowlist = no cross-origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)


# ---------------------------------------------------------------------------
# Request ID Middleware (for audit correlation)
# ---------------------------------------------------------------------------

@app.middleware("http")
async def attach_request_id(request: Request, call_next) -> Response:
    """Attach a unique X-Request-ID to every request for audit correlation."""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = uuid.UUID(request_id) if _is_valid_uuid(request_id) else uuid.uuid4()
    response = await call_next(request)
    response.headers["X-Request-ID"] = str(request.state.request_id)
    return response


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    """Add security headers to every response."""
    response = await call_next(request)
    if settings.SECURE_HEADERS:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Never cache document responses
        if "/documents/" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
    return response


# ---------------------------------------------------------------------------
# Global Exception Handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all exception handler.
    SECURITY: Never expose internal error details to clients.
    Log internally, return generic error externally.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        "Unhandled exception: request_id=%s path=%s error=%s",
        request_id, request.url.path, str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred", "request_id": str(request_id)},
    )


# ---------------------------------------------------------------------------
# Health Check (unauthenticated — no sensitive data)
# ---------------------------------------------------------------------------

@app.get("/health", include_in_schema=False)
async def health_check():
    """Basic health check endpoint. Returns 200 if the app is running."""
    return {"status": "healthy", "version": settings.APP_VERSION}


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False

