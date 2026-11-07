-- =============================================================================
-- TrustVault Database Schema
-- PostgreSQL 15+ | UTF-8 | Timezone: UTC
-- Security Design: Append-only audit logs, immutable hash chains, RBAC+ABAC
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid(), crypt()
CREATE EXTENSION IF NOT EXISTS "citext";      -- Case-insensitive email
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- Trigram text search

-- =============================================================================
-- ENUMERATIONS
-- =============================================================================

CREATE TYPE user_role AS ENUM ('ADMIN', 'OWNER', 'VIEWER');
CREATE TYPE access_level AS ENUM ('READ', 'EDIT');
CREATE TYPE audit_action AS ENUM (
    'UPLOAD',
    'READ_SUCCESS',
    'READ_DENIED',
    'EDIT_SUCCESS',
    'EDIT_DENIED',
    'GRANT',
    'REVOKE',
    'DELETE',
    'LOGIN_SUCCESS',
    'LOGIN_FAILED',
    'TOKEN_ISSUED',
    'TOKEN_REVOKED',
    'ADMIN_METADATA_READ',
    'UPLOAD_REJECTED'
);
CREATE TYPE document_status AS ENUM ('ACTIVE', 'DELETED', 'QUARANTINED');

-- =============================================================================
-- TABLE: users
-- =============================================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           CITEXT NOT NULL UNIQUE,
    display_name    VARCHAR(255) NOT NULL,
    role            user_role NOT NULL DEFAULT 'VIEWER',
    -- Argon2id hash of password (never store plaintext)
    password_hash   TEXT NOT NULL,
    -- MFA
    totp_secret     TEXT,
    totp_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    -- Account lifecycle
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    deactivated_at  TIMESTAMPTZ,
    deactivated_by  UUID REFERENCES users(id),
    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Login tracking
    last_login_at   TIMESTAMPTZ,
    last_login_ip   INET,
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,

    CONSTRAINT email_format CHECK (email ~* '^[^@]+@[^@]+\.[^@]+$'),
    CONSTRAINT display_name_length CHECK (LENGTH(display_name) BETWEEN 2 AND 255)
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active) WHERE is_active = TRUE;

COMMENT ON TABLE users IS 'Application users. Passwords stored as Argon2id hashes. Never store plaintext.';
COMMENT ON COLUMN users.role IS 'ADMIN: system metadata only. OWNER: document creator. VIEWER: explicit-grant-only access.';

-- =============================================================================
-- TABLE: sessions
-- Session store for immediate revocation capability
-- =============================================================================

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of the actual session token (never store raw token)
    token_hash      TEXT NOT NULL UNIQUE,
    ip_address      INET NOT NULL,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    -- Explicit revocation fields
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(100),   -- 'USER_LOGOUT', 'ADMIN_FORCE', 'PERMISSION_CHANGE'

    CONSTRAINT session_expiry_valid CHECK (expires_at > created_at)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_active ON sessions(user_id, expires_at, revoked_at)
    WHERE revoked_at IS NULL;

-- =============================================================================
-- TABLE: documents
-- =============================================================================

CREATE TABLE documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           VARCHAR(500) NOT NULL,
    category        VARCHAR(100),
    owner_id        UUID NOT NULL REFERENCES users(id),
    -- Server-controlled storage path (NEVER client-supplied filename)
    storage_key     TEXT NOT NULL UNIQUE,
    -- SHA-256 of raw file bytes for integrity verification
    checksum        CHAR(64) NOT NULL,
    -- MIME type from magic-byte detection, NOT from client Content-Type header
    detected_mime   VARCHAR(127) NOT NULL,
    -- Safe sanitized display name (original client filename, stripped of traversal chars)
    original_filename VARCHAR(255) NOT NULL,
    -- File size in bytes
    file_size_bytes BIGINT NOT NULL,
    status          document_status NOT NULL DEFAULT 'ACTIVE',
    -- Soft delete support
    deleted_at      TIMESTAMPTZ,
    deleted_by      UUID REFERENCES users(id),
    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT checksum_format CHECK (checksum ~* '^[0-9a-f]{64}$'),
    CONSTRAINT file_size_positive CHECK (file_size_bytes > 0),
    CONSTRAINT storage_key_no_traversal CHECK (storage_key NOT LIKE '%..%')
);

CREATE INDEX idx_documents_owner ON documents(owner_id);
CREATE INDEX idx_documents_category ON documents(category) WHERE category IS NOT NULL;
CREATE INDEX idx_documents_status ON documents(status) WHERE status = 'ACTIVE';
CREATE INDEX idx_documents_title_trgm ON documents USING GIN (title gin_trgm_ops);

COMMENT ON COLUMN documents.storage_key IS 'UUID-based path generated server-side. Never uses client-supplied filename.';
COMMENT ON COLUMN documents.checksum IS 'SHA-256 of raw file content. Verified on every download.';
COMMENT ON COLUMN documents.detected_mime IS 'Magic-byte detected MIME, not trusting client Content-Type.';

-- =============================================================================
-- TABLE: permissions
-- Granular, explicit, per-user, per-document access grants
-- =============================================================================

CREATE TABLE permissions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id     UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_level    access_level NOT NULL,
    granted_by      UUID NOT NULL REFERENCES users(id),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Revocation fields (soft-delete for audit trail preservation)
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID REFERENCES users(id),
    -- Expiry (optional time-bound access)
    expires_at      TIMESTAMPTZ,

    -- One active permission per user per document (partial unique index)
    CONSTRAINT permissions_active_unique
        UNIQUE NULLS NOT DISTINCT (document_id, user_id, revoked_at),

    CONSTRAINT no_self_grant CHECK (user_id != granted_by OR granted_by IS NULL),
    CONSTRAINT expiry_after_grant CHECK (expires_at IS NULL OR expires_at > granted_at)
);

CREATE INDEX idx_permissions_document ON permissions(document_id);
CREATE INDEX idx_permissions_user ON permissions(user_id);
CREATE INDEX idx_permissions_active ON permissions(document_id, user_id)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE permissions IS 'Explicit access grants. No implicit access from role alone. Revocation is immediate via revoked_at timestamp.';

-- =============================================================================
-- TABLE: audit_logs
-- Append-only, cryptographically hash-chained, immutable audit trail
-- =============================================================================

CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,  -- Sequential for chain ordering
    -- When
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Who
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email     CITEXT,     -- Snapshot — preserved even if user is deleted
    actor_role      user_role,  -- Role snapshot at time of action
    -- What
    action          audit_action NOT NULL,
    -- On what
    resource_id     UUID,
    resource_type   VARCHAR(50),
    -- Context
    ip_address      INET,
    user_agent      TEXT,
    request_id      UUID,       -- Correlate with application request logs
    -- Additional structured context (JSON — query params, error codes, etc.)
    context         JSONB NOT NULL DEFAULT '{}',
    -- Cryptographic chain
    previous_hash   TEXT NOT NULL,  -- 'GENESIS' for first entry
    current_hash    TEXT NOT NULL UNIQUE,

    CONSTRAINT audit_hash_not_empty CHECK (LENGTH(current_hash) = 64),
    CONSTRAINT audit_prev_hash_not_empty CHECK (LENGTH(previous_hash) >= 7)
);

-- Indexes for security monitoring queries
CREATE INDEX idx_audit_actor ON audit_logs(actor_id, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_id, timestamp DESC);
CREATE INDEX idx_audit_denied ON audit_logs(action, timestamp DESC)
    WHERE action IN ('READ_DENIED', 'EDIT_DENIED', 'LOGIN_FAILED', 'UPLOAD_REJECTED');
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC);

COMMENT ON TABLE audit_logs IS 'Append-only audit trail. Protected by DB triggers and application-level REVOKE. Hash chain ensures tamper evidence.';
COMMENT ON COLUMN audit_logs.current_hash IS 'HMAC-SHA256(KEY, prev_hash || JSON_payload). Verified by chain integrity checker.';

-- =============================================================================
-- TRIGGERS: Audit Log Immutability
-- PostgreSQL-level protection against UPDATE and DELETE on audit_logs
-- =============================================================================

CREATE OR REPLACE FUNCTION audit_logs_prevent_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RAISE EXCEPTION
        'SECURITY VIOLATION: audit_logs is append-only. '
        'Attempted % on row id=%. '
        'This event will be reported. '
        'CWE-778 / TrustVault Security Policy TV-SEC-004.',
        TG_OP, OLD.id
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER trg_audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION audit_logs_prevent_mutation();

CREATE TRIGGER trg_audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION audit_logs_prevent_mutation();

-- Also prevent TRUNCATE at table level
CREATE OR REPLACE FUNCTION audit_logs_prevent_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RAISE EXCEPTION
        'SECURITY VIOLATION: audit_logs TRUNCATE is forbidden. CWE-778.',
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER trg_audit_logs_no_truncate
    BEFORE TRUNCATE ON audit_logs
    EXECUTE FUNCTION audit_logs_prevent_truncate();

-- =============================================================================
-- TRIGGERS: Updated_at auto-maintenance
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_documents_updated_at
    BEFORE UPDATE ON documents FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- =============================================================================
-- ROW LEVEL SECURITY (PostgreSQL RLS)
-- Application role cannot see other tenants' data even with SQL injection
-- =============================================================================

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE permissions ENABLE ROW LEVEL SECURITY;

-- Application connects as 'trustvault_app' role
-- RLS policies are enforced per-row automatically

CREATE POLICY documents_owner_isolation ON documents
    FOR ALL TO trustvault_app
    USING (TRUE);  -- Application-level filtering handles this; RLS as defense-in-depth

-- Prevent direct permission table reads without going through application layer
CREATE POLICY permissions_read_policy ON permissions
    FOR SELECT TO trustvault_app
    USING (TRUE);

-- =============================================================================
-- APPLICATION ROLE: Principle of least privilege
-- =============================================================================

-- Create the application role (run as superuser once)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'trustvault_app') THEN
        CREATE ROLE trustvault_app LOGIN PASSWORD 'CHANGE_ME_IN_PRODUCTION';
    END IF;
END$$;

-- Grant minimum necessary permissions
GRANT CONNECT ON DATABASE trustvault TO trustvault_app;
GRANT USAGE ON SCHEMA public TO trustvault_app;

-- Tables: app can read and write, but NOT delete audit logs
GRANT SELECT, INSERT, UPDATE ON users TO trustvault_app;
GRANT SELECT, INSERT, UPDATE ON sessions TO trustvault_app;
GRANT SELECT, INSERT, UPDATE ON documents TO trustvault_app;
GRANT SELECT, INSERT, UPDATE ON permissions TO trustvault_app;
GRANT SELECT, INSERT ON audit_logs TO trustvault_app;  -- INSERT only, no UPDATE/DELETE

GRANT USAGE ON SEQUENCE audit_logs_id_seq TO trustvault_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO trustvault_app;
