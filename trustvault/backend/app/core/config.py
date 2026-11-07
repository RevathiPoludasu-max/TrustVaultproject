"""
TrustVault Application Configuration
=====================================
Environment-based settings using pydantic-settings.
All secrets must be injected via environment variables — never hardcoded.
"""
from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ---------------------------------------------------------------------------
    # Application
    # ---------------------------------------------------------------------------
    APP_NAME: str = "TrustVault"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    TESTING: bool = False

    # ---------------------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------------------
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://trustvault_app:CHANGE_ME@localhost:5432/trustvault",
        description="Async PostgreSQL connection URL",
    )

    # ---------------------------------------------------------------------------
    # JWT Authentication
    # ---------------------------------------------------------------------------
    JWT_SECRET: str = Field(
        min_length=32,
        description="HMAC-SHA256 signing key for JWT access tokens. Min 32 bytes.",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ---------------------------------------------------------------------------
    # Stream Token (ephemeral document download tokens)
    # ---------------------------------------------------------------------------
    STREAM_SECRET: str = Field(
        min_length=32,
        description="Signing key for ephemeral stream tokens. Max TTL: 30s.",
    )
    STREAM_TOKEN_TTL_SECONDS: int = Field(
        default=25,
        ge=10,
        le=30,
        description="Ephemeral stream token TTL. Hard max 30s per security policy.",
    )

    # ---------------------------------------------------------------------------
    # Audit HMAC Key
    # ---------------------------------------------------------------------------
    AUDIT_HMAC_KEY: str = Field(
        min_length=32,
        description=(
            "HMAC-SHA256 key for audit log chain integrity. "
            "NEVER log this value. NEVER return it in API responses. "
            "Rotation requires full chain re-signing procedure."
        ),
    )

    # ---------------------------------------------------------------------------
    # Redis (for stream token single-use invalidation)
    # ---------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"

    # ---------------------------------------------------------------------------
    # Storage Backend
    # ---------------------------------------------------------------------------
    STORAGE_BACKEND: str = "local"  # 'local' | 's3' | 'gcs'
    STORAGE_LOCAL_PATH: str = "/var/trustvault/documents"
    STORAGE_S3_BUCKET: str = ""
    STORAGE_ENCRYPTION_KEY: str = Field(
        default="",
        description="AES-256-GCM key for at-rest document encryption (hex-encoded 32 bytes).",
    )

    # ---------------------------------------------------------------------------
    # Upload Limits
    # ---------------------------------------------------------------------------
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB

    # ---------------------------------------------------------------------------
    # Rate Limiting
    # ---------------------------------------------------------------------------
    RATE_LIMIT_AUTH_PER_MINUTE: int = 10
    RATE_LIMIT_DOWNLOAD_PER_MINUTE: int = 30

    # ---------------------------------------------------------------------------
    # Security Headers
    # ---------------------------------------------------------------------------
    CORS_ORIGINS: list[str] = []
    SECURE_HEADERS: bool = True

    @field_validator("JWT_SECRET", "STREAM_SECRET", "AUDIT_HMAC_KEY", mode="before")
    @classmethod
    def secrets_must_not_be_default(cls, v: str, info) -> str:
        dangerous_defaults = {
            "changeme", "secret", "password", "default", "test",
            "trustvault", "CHANGE_ME",
        }
        if any(d in v.lower() for d in dangerous_defaults):
            import warnings
            warnings.warn(
                f"WARNING: {info.field_name} appears to use a default/weak value. "
                "Set a cryptographically random value in production.",
                stacklevel=2,
            )
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


# Singleton settings instance
# Import this everywhere: `from app.core.config import settings`
settings = Settings(
    # Provide safe defaults for development — override via environment in production
    JWT_SECRET="dev-jwt-secret-change-in-production-xx",
    STREAM_SECRET="dev-stream-secret-change-in-prod-xx",
    AUDIT_HMAC_KEY="dev-audit-key-change-in-production-xx",
)
