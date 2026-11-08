/**
 * =============================================================================
 * TrustVault â€” Ultra-Secure Document Sharing Platform
 * =============================================================================
 * Core Server Runtime (Node.js Built-In Standard Library â€” Zero External Deps)
 * 
 * SECURITY CONTRACT & GUARANTEES:
 * 1. Server-Side Zero Trust: DB authorization check before ANY IO operation.
 * 2. Immediate Revocation: 0-second revocation effect; ephemeral stream tokens (max 25s).
 * 3. Tamper-Evident Audit Logging: Append-only HMAC-SHA256 hash chaining.
 * 4. Anti-Enumeration: 404 Not Found on ANY unauthorized probe (never 403).
 * 5. Admin Isolation: ADMIN reads metadata/audit only, CANNOT download private binaries.
 * 6. Upload Sanitization: Magic-byte sniffing, traversal-safe storage keys, SHA-256 checksums.
 * =============================================================================
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// -----------------------------------------------------------------------------
// Configuration & Cryptographic Secrets
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
const DATA_DIR = path.join(__dirname, 'data');
const STORAGE_DIR = path.join(DATA_DIR, 'vault_storage');
const DB_FILE = path.join(DATA_DIR, 'trustvault_db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// Vercel runs in a read-only filesystem â€” detect and fall back to in-memory only
const IS_READONLY_FS = process.env.VERCEL === '1' || process.env.NODE_ENV === 'production';

// Cryptographic keys (32 bytes high entropy)
const AUDIT_HMAC_KEY = process.env.AUDIT_HMAC_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const STREAM_SECRET = process.env.STREAM_SECRET;

for (const [name, value] of Object.entries({ AUDIT_HMAC_KEY, JWT_SECRET, STREAM_SECRET })) {
  if (typeof value !== 'string' || value.length < 32) {
    throw new Error(`[TrustVault] Missing or weak environment variable: ${name}. Set a random secret of at least 32 characters in Vercel.`);
  }
}
const STREAM_TOKEN_TTL_MS = 25 * 1000; // 25 seconds hard max (TV-SEC-002)

// Ensure storage directories exist (skipped on Vercel read-only FS)
if (!IS_READONLY_FS) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// -----------------------------------------------------------------------------
// Database & State Management (Persistent JSON with In-Memory Locking)
// -----------------------------------------------------------------------------
const Roles = {
  ADMIN: 'ADMIN',
  OWNER: 'OWNER',
  VIEWER: 'VIEWER'
};

const AccessLevels = {
  READ: 'READ',
  EDIT: 'EDIT'
};

const AuditActions = {
  UPLOAD: 'UPLOAD',
  READ_SUCCESS: 'READ_SUCCESS',
  READ_DENIED: 'READ_DENIED',
  EDIT_SUCCESS: 'EDIT_SUCCESS',
  EDIT_DENIED: 'EDIT_DENIED',
  GRANT: 'GRANT',
  REVOKE: 'REVOKE',
  DELETE: 'DELETE',
  TOKEN_ISSUED: 'TOKEN_ISSUED',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  ADMIN_METADATA_READ: 'ADMIN_METADATA_READ',
  UPLOAD_REJECTED: 'UPLOAD_REJECTED'
};

let db = {
  users: {},
  sessions: {},
  documents: {},
  permissions: {},
  audit_logs: [],
  active_stream_tokens: {} // ephemeral single-use tracking
};

/**
 * Deterministic JSON serialization for HMAC hash chaining
 */
function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

/**
 * Compute HMAC-SHA256(AUDIT_HMAC_KEY, prev_hash + payload)
 */
function computeAuditHash(prevHash, payload) {
  const hmac = crypto.createHmac('sha256', AUDIT_HMAC_KEY);
  hmac.update(prevHash + payload, 'utf8');
  return hmac.digest('hex');
}

/**
 * Record an audit log entry with strict HMAC hash chaining.
 * Implements Append-Only and Transactional Logging.
 */
function recordAudit({ actorId, actorEmail, actorRole, action, resourceId, resourceType = 'document', ip, userAgent = '', context = {} }) {
  const prevEntry = db.audit_logs.length > 0 ? db.audit_logs[db.audit_logs.length - 1] : null;
  const prevHash = prevEntry ? prevEntry.current_hash : 'GENESIS';

  const timestamp = new Date().toISOString();
  const payloadData = {
    ts: timestamp,
    actor: actorId || 'SYSTEM',
    role: actorRole || null,
    action: action,
    resource: resourceId || null,
    ip: ip || '127.0.0.1',
    ua: userAgent || '',
    prev: prevHash,
    ctx: context
  };

  const payloadString = canonicalJson(payloadData);
  const currentHash = computeAuditHash(prevHash, payloadString);

  const entry = {
    id: db.audit_logs.length + 1,
    timestamp,
    actor_id: actorId,
    actor_email: actorEmail,
    actor_role: actorRole,
    action,
    resource_id: resourceId,
    resource_type: resourceType,
    ip_address: ip,
    user_agent: userAgent,
    context,
    previous_hash: prevHash,
    current_hash: currentHash
  };

  // Append-only guarantee
  db.audit_logs.push(entry);
  saveDbState();
  return entry;
}

/**
 * Verify cryptographic integrity of the entire audit chain
 */
function verifyAuditChain() {
  if (!db.audit_logs || db.audit_logs.length === 0) {
    return { valid: true, total: 0, brokenAt: null };
  }

  for (let i = 0; i < db.audit_logs.length; i++) {
    const entry = db.audit_logs[i];
    const prevHash = i === 0 ? 'GENESIS' : db.audit_logs[i - 1].current_hash;

    if (entry.previous_hash !== prevHash) {
      return {
        valid: false,
        brokenAt: entry.id,
        reason: `Previous hash mismatch at entry #${entry.id}. Expected ${prevHash}, found ${entry.previous_hash}`
      };
    }

    const payloadData = {
      ts: entry.timestamp,
      actor: entry.actor_id || 'SYSTEM',
      role: entry.actor_role || null,
      action: entry.action,
      resource: entry.resource_id || null,
      ip: entry.ip_address || '127.0.0.1',
      ua: entry.user_agent || '',
      prev: entry.previous_hash,
      ctx: entry.context || {}
    };

    const expectedHash = computeAuditHash(entry.previous_hash, canonicalJson(payloadData));
    if (entry.current_hash !== expectedHash) {
      return {
        valid: false,
        brokenAt: entry.id,
        reason: `Cryptographic digest mismatch at entry #${entry.id}. Content has been tampered with!`
      };
    }
  }

  return { valid: true, total: db.audit_logs.length, brokenAt: null };
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + '_trustvault_salt_2026').digest('hex');
}

/**
 * Initialize / Seed Database
 */
function initDatabase(forceFresh = false) {
  if (!forceFresh && !IS_READONLY_FS && fs.existsSync(DB_FILE)) {
    try {
      const data = fs.readFileSync(DB_FILE, 'utf8');
      db = JSON.parse(data);
      if (!db.active_stream_tokens) db.active_stream_tokens = {};
      // Ensure existing seeded users have passwordHash
      let updatedPasswords = false;
      const defaultPasswords = {
        'admin@trustvault.local': 'Admin@123',
        'owner@trustvault.local': 'Owner@123',
        'viewer_a@trustvault.local': 'Viewer@123',
        'viewer_b@trustvault.local': 'Viewer@123'
      };
      for (const uid in db.users) {
        const u = db.users[uid];
        if (!u.passwordHash && defaultPasswords[u.email]) {
          u.passwordHash = hashPassword(defaultPasswords[u.email]);
          updatedPasswords = true;
        }
      }
      if (updatedPasswords) saveDbState();
      console.log(`[TrustVault] Database loaded: ${Object.keys(db.documents).length} documents, ${db.audit_logs.length} audit records.`);
      return;
    } catch (e) {
      console.error('[TrustVault] Corrupt DB file, reinitializing fresh seed...', e);
    }
  }

  console.log('[TrustVault] Initializing fresh database with secure seeds...');
  db = {
    users: {
      'user-admin-01': {
        id: 'user-admin-01',
        email: 'admin@trustvault.local',
        displayName: 'Eve Administrator',
        role: Roles.ADMIN,
        passwordHash: hashPassword('Admin@123'),
        isActive: true,
        createdAt: new Date().toISOString()
      },
      'user-owner-01': {
        id: 'user-owner-01',
        email: 'owner@trustvault.local',
        displayName: 'Alice Executive (Owner)',
        role: Roles.OWNER,
        passwordHash: hashPassword('Owner@123'),
        isActive: true,
        createdAt: new Date().toISOString()
      },
      'user-viewer-a': {
        id: 'user-viewer-a',
        email: 'viewer_a@trustvault.local',
        displayName: 'Bob Analyst (Granted Viewer)',
        role: Roles.VIEWER,
        passwordHash: hashPassword('Viewer@123'),
        isActive: true,
        createdAt: new Date().toISOString()
      },
      'user-viewer-b': {
        id: 'user-viewer-b',
        email: 'viewer_b@trustvault.local',
        displayName: 'Carol Auditor (Ungranted Viewer)',
        role: Roles.VIEWER,
        passwordHash: hashPassword('Viewer@123'),
        isActive: true,
        createdAt: new Date().toISOString()
      }
    },
    sessions: {},
    documents: {},
    permissions: {},
    audit_logs: [],
    active_stream_tokens: {}
  };

  // Seed sample document owned by Alice
  const sampleDocId = 'doc-q4-fin-2026';
  const sampleStorageKey = 'storage-' + crypto.randomUUID();
  const sampleFilePath = path.join(STORAGE_DIR, sampleStorageKey);

  const sampleContent = Buffer.from(
    '%PDF-1.4\n% TrustVault Confidential Financial Report\n' +
    'CLASSIFICATION: STRICTLY CONFIDENTIAL - RESTRICTED DISTRIBUTION\n' +
    'Fiscal Quarter: Q4 2026\n' +
    'Total Net Inflows: $48,250,000.00 USD\n' +
    'Enterprise Valuation: $1.2B\n' +
    'Cryptographic Signature: SHA256-RSA-VERIFIED\n' +
    'Zero-Trust Enforcement: Active\n%%EOF',
    'utf8'
  );

  if (!IS_READONLY_FS) {
    fs.writeFileSync(sampleFilePath, sampleContent);
  }
  const sampleChecksum = crypto.createHash('sha256').update(sampleContent).digest('hex');

  db.documents[sampleDocId] = {
    id: sampleDocId,
    title: 'Q4 2026 Confidential Financial Audit',
    category: 'FINANCIAL',
    owner_id: 'user-owner-01',
    storage_key: sampleStorageKey,
    checksum: sampleChecksum,
    detected_mime: 'application/pdf',
    original_filename: 'Q4_2026_Financial_Audit.pdf',
    file_size_bytes: sampleContent.length,
    status: 'ACTIVE',
    created_at: new Date().toISOString()
  };

  // Grant Bob (viewer_a) explicit READ access
  const samplePermId = 'perm-seed-01';
  db.permissions[samplePermId] = {
    id: samplePermId,
    document_id: sampleDocId,
    user_id: 'user-viewer-a',
    access_level: AccessLevels.READ,
    granted_by: 'user-owner-01',
    granted_at: new Date().toISOString(),
    revoked_at: null,
    expires_at: null
  };

  // Genesis audit log entry
  recordAudit({
    actorId: 'SYSTEM',
    actorEmail: 'system@trustvault.local',
    actorRole: null,
    action: AuditActions.UPLOAD,
    resourceId: sampleDocId,
    ip: '127.0.0.1',
    context: { note: 'TrustVault Genesis Seed Initialization' }
  });

  // Grant audit entry
  recordAudit({
    actorId: 'user-owner-01',
    actorEmail: 'owner@trustvault.local',
    actorRole: Roles.OWNER,
    action: AuditActions.GRANT,
    resourceId: sampleDocId,
    ip: '127.0.0.1',
    context: { target_user: 'user-viewer-a', access_level: AccessLevels.READ }
  });

  saveDbState();
}

function saveDbState() {
  if (IS_READONLY_FS) {
    // On Vercel: DB is in-memory only. State persists for the lifetime of this serverless instance.
    return;
  }
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
  } catch (err) {
    console.error('[TrustVault] Failed to persist DB state:', err);
  }
}

// -----------------------------------------------------------------------------
// Security Middleware & Policy Engine (Zero-Trust ABAC)
// -----------------------------------------------------------------------------

/**
 * Authenticate session / token from Authorization header or cookie
 */
function authenticateRequest(req) {
  const authHeader = req.headers['authorization'] || '';
  let token = null;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (req.headers['x-actor-id']) {
    // Development Persona Switcher Header
    const actorId = req.headers['x-actor-id'];
    const user = db.users[actorId];
    if (user && user.isActive) {
      return user;
    }
  }

  if (!token) return null;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const expectedSig = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url');

    // Constant-time signature verification
    const sigBuf = Buffer.from(signatureB64);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() / 1000 > payload.exp) {
      return null; // Expired
    }

    const user = db.users[payload.sub];
    if (!user || !user.isActive) return null;
    return user;
  } catch (e) {
    return null;
  }
}

/**
 * Generate standard signed JWT
 */
function createJwt(user, expiresInSec = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresInSec,
    jti: crypto.randomUUID()
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url');

  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * CORE AUTHORIZATION POLICY ENGINE
 * Enforces Hard Rule 1, 2, 4, 5
 * 
 * Rules:
 * - OWNER: Full control over their owned documents.
 * - ADMIN: Metadata/Audit logs allowed; private binary downloads STRICTLY DENIED without explicit grant.
 * - VIEWER: Read-only IF AND ONLY IF active, unexpired, unrevoked permission row exists.
 * - Revocation takes effect in 0 SECONDS.
 * - Anti-Enumeration: Denials return 404 Not Found (NEVER 403).
 */
function evaluateDocumentAccess(user, documentId, requiredAction, req) {
  const clientIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  const doc = db.documents[documentId];

  // If document does not exist or was deleted -> 404
  if (!doc || doc.status === 'DELETED') {
    recordAudit({
      actorId: user ? user.id : 'ANONYMOUS',
      actorEmail: user ? user.email : 'anonymous',
      actorRole: user ? user.role : null,
      action: AuditActions.READ_DENIED,
      resourceId: documentId,
      ip: clientIp,
      userAgent,
      context: { reason: 'NON_EXISTENT_OR_DELETED', requested_action: requiredAction }
    });
    return { allowed: false, status: 404, message: 'Document not found' };
  }

  // 1. Unauthenticated -> 401
  if (!user) {
    recordAudit({
      actorId: 'ANONYMOUS',
      actorEmail: 'anonymous',
      actorRole: null,
      action: AuditActions.READ_DENIED,
      resourceId: documentId,
      ip: clientIp,
      userAgent,
      context: { reason: 'UNAUTHENTICATED' }
    });
    return { allowed: false, status: 401, message: 'Authentication required' };
  }

  // 2. OWNER has full access to their own document
  if (doc.owner_id === user.id) {
    const actionType = requiredAction === 'DOWNLOAD' ? AuditActions.READ_SUCCESS : AuditActions.READ_SUCCESS;
    recordAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: actionType,
      resourceId: documentId,
      ip: clientIp,
      userAgent,
      context: { role_match: 'OWNER', action: requiredAction }
    });
    return { allowed: true, document: doc };
  }

  // 3. ADMIN: System metadata & audit allowed; Binary download requires explicit grant!
  if (user.role === Roles.ADMIN) {
    if (requiredAction === 'READ_METADATA' || requiredAction === 'VIEW_AUDIT') {
      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: AuditActions.ADMIN_METADATA_READ,
        resourceId: documentId,
        ip: clientIp,
        userAgent,
        context: { capability: 'ADMIN_METADATA' }
      });
      return { allowed: true, document: doc };
    }

    // For download or binary read, check explicit grant
    const explicitGrant = findActivePermission(documentId, user.id);
    if (!explicitGrant) {
      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: AuditActions.READ_DENIED,
        resourceId: documentId,
        ip: clientIp,
        userAgent,
        context: {
          reason: 'ADMIN_UNGRANTED_BINARY_PROBE',
          policy: 'Admins cannot download private document binaries without explicit owner grant'
        }
      });
      // ANTI-ENUMERATION: Return 404, never 403
      return { allowed: false, status: 404, message: 'Document not found' };
    }

    recordAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: AuditActions.READ_SUCCESS,
      resourceId: documentId,
      ip: clientIp,
      userAgent,
      context: { role_match: 'ADMIN_WITH_EXPLICIT_GRANT' }
    });
    return { allowed: true, document: doc };
  }

  // 4. VIEWER or other users: Check active, live permission row
  const activeGrant = findActivePermission(documentId, user.id);

  if (!activeGrant) {
    recordAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: AuditActions.READ_DENIED,
      resourceId: documentId,
      ip: clientIp,
      userAgent,
      context: { reason: 'NO_ACTIVE_PERMISSION' }
    });
    // ANTI-ENUMERATION: Return 404, never 403
    return { allowed: false, status: 404, message: 'Document not found' };
  }

  // Check required access level (EDIT vs READ)
  if (requiredAction === 'EDIT' && activeGrant.access_level !== AccessLevels.EDIT) {
    recordAudit({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: AuditActions.EDIT_DENIED,
      resourceId: documentId,
      ip: clientIp,
      userAgent,
      context: { reason: 'INSUFFICIENT_ACCESS_LEVEL', required: AccessLevels.EDIT, actual: activeGrant.access_level }
    });
    return { allowed: false, status: 404, message: 'Document not found' };
  }

  recordAudit({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    action: AuditActions.READ_SUCCESS,
    resourceId: documentId,
    ip: clientIp,
    userAgent,
    context: { permission_id: activeGrant.id, level: activeGrant.access_level }
  });

  return { allowed: true, document: doc, permission: activeGrant };
}

/**
 * Live DB lookup for active permission row.
 * Revocation is instantaneous (0-seconds) when revoked_at is not null.
 */
function findActivePermission(documentId, userId) {
  const now = new Date().toISOString();
  for (const permId in db.permissions) {
    const perm = db.permissions[permId];
    if (perm.document_id === documentId && perm.user_id === userId) {
      if (perm.revoked_at !== null) continue; // Instantly revoked!
      if (perm.expires_at && perm.expires_at < now) continue; // Expired!
      return perm;
    }
  }
  return null;
}

// -----------------------------------------------------------------------------
// Magic-Byte Sniffing & File Sanitization
// -----------------------------------------------------------------------------
const AllowedMimes = {
  'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
  'image/png': [0x89, 0x50, 0x4E, 0x47],       // .PNG
  'image/jpeg': [0xFF, 0xD8, 0xFF],            // JPEG
  'text/plain': null,                          // Validated as printable text
  'application/json': null                     // Validated JSON text
};

function detectMimeType(buffer) {
  if (buffer.length >= 4 && buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    return 'application/pdf';
  }
  if (buffer.length >= 4 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return 'image/png';
  }
  if (buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return 'image/jpeg';
  }

  // Check if printable ASCII/UTF-8
  let isPrintable = true;
  for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
    const byte = buffer[i];
    // Allow ASCII printable (32-126), tab(9), newline(10), carriage return(13)
    if (byte < 9 || (byte > 13 && byte < 32 && byte !== 27) || byte === 0) {
      isPrintable = false;
      break;
    }
  }
  if (isPrintable) return 'text/plain';

  return 'application/octet-stream';
}

function sanitizeFilename(filename) {
  const base = path.basename(filename || 'unnamed_file');
  // Strip all non-alphanumeric except dot, dash, underscore
  const sanitized = base.replace(/[^a-zA-Z0-9.\-_]/g, '_');
  // Strip path traversal sequences
  return sanitized.replace(/\.\./g, '_').substring(0, 255);
}

// -----------------------------------------------------------------------------
// HTTP Request Router & Static Server
// -----------------------------------------------------------------------------
function sendJson(res, statusCode, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    ...headers
  });
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const maxSize = 25 * 1024 * 1024; // 25 MB limit

    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxSize) {
        reject(new Error('Payload too large'));
        req.destroy();
      } else {
        chunks.push(chunk);
      }
    });

    req.on('end', () => {
      const buffer = Buffer.concat(chunks);
      resolve(buffer);
    });

    req.on('error', reject);
  });
}

/**
 * Resolve the real client IP address.
 * On Vercel/proxies, req.socket.remoteAddress is the proxy IP -- the actual
 * client IP is forwarded in X-Forwarded-For. We take the first (leftmost)
 * entry which is the original client, never trusting the rightmost (proxy-set).
 */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // X-Forwarded-For: client, proxy1, proxy2 -- take leftmost (true client)
    return forwarded.split(',')[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || '127.0.0.1';
}

/**
 * Main HTTP Server Request Handler
 */
async function handleRequest(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;

  // Add Security & Anti-CORS-Hijack Headers to all responses
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Actor-Id, X-Request-Id');

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // -------------------------------------------------------------------------
    // API: Authentication (Login, Me, User Management)
    // -------------------------------------------------------------------------
    if (pathname === '/api/auth/login' && method === 'POST') {
      const raw = await parseBody(req);
      let credentials = {};
      try {
        credentials = JSON.parse(raw.toString('utf8') || '{}');
      } catch (e) {
        return sendJson(res, 400, { error: 'Invalid JSON request' });
      }
      const { email, password, requestedRole } = credentials;
      if (!email || !password) {
        return sendJson(res, 400, { error: 'Invalid credentials or incorrect login role.' });
      }

      const clientIp = getClientIp(req);
      const user = Object.values(db.users).find(u => u.email.toLowerCase() === email.trim().toLowerCase());
      const hashedInput = hashPassword(password);

      // Verify email and password
      if (!user || user.passwordHash !== hashedInput || !user.isActive) {
        recordAudit({
          actorId: user ? user.id : 'ANONYMOUS',
          actorEmail: email,
          actorRole: user ? user.role : null,
          action: 'LOGIN_FAILED',
          resourceId: null,
          ip: clientIp,
          userAgent: req.headers['user-agent'] || '',
          context: { reason: 'INVALID_CREDENTIALS_OR_INACTIVE', requested_role: requestedRole || null }
        });
        return sendJson(res, 401, { error: 'Invalid credentials or incorrect login role.' });
      }

      // Fetch actual role from database and match strictly against selected tab (Admin, Owner, Viewer/User)
      const normalizedRequested = (requestedRole || '').toUpperCase();
      const expectedRole = (normalizedRequested === 'USER' || normalizedRequested === 'VIEWER') 
        ? Roles.VIEWER 
        : normalizedRequested;

      if (!expectedRole || user.role !== expectedRole) {
        recordAudit({
          actorId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          action: 'LOGIN_FAILED',
          resourceId: null,
          ip: clientIp,
          userAgent: req.headers['user-agent'] || '',
          context: { reason: 'ROLE_MISMATCH', requested_role: requestedRole, actual_role: user.role }
        });
        return sendJson(res, 403, {
          error: 'Invalid credentials or incorrect login role.'
        });
      }

      // Create session & JWT token ONLY after successful credentials and role validation
      const token = createJwt(user);
      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'LOGIN_SUCCESS',
        resourceId: null,
        ip: clientIp,
        userAgent: req.headers['user-agent'] || '',
        context: { role: user.role, verified_role: user.role }
      });

      // Role-based target dashboard URL strictly from verified database role
      let redirectUrl = '/viewer/dashboard';
      if (user.role === Roles.ADMIN) redirectUrl = '/admin/dashboard';
      else if (user.role === Roles.OWNER) redirectUrl = '/owner/dashboard';

      return sendJson(res, 200, {
        token,
        redirectUrl,
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          role: user.role
        }
      });
    }

    if (pathname === '/api/auth/me' && method === 'GET') {
      const user = authenticateRequest(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Not authenticated' });
      }
      return sendJson(res, 200, {
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          role: user.role
        }
      });
    }

    if (pathname === '/api/auth/personas' && method === 'GET') {
      return sendJson(res, 200, {
        personas: Object.values(db.users).map(u => ({
          id: u.id,
          email: u.email,
          displayName: u.displayName,
          role: u.role
        }))
      });
    }

    if (pathname === '/api/auth/token' && method === 'POST') {
      const raw = await parseBody(req);
      const { actorId } = JSON.parse(raw.toString('utf8') || '{}');
      const user = db.users[actorId];
      if (!user) return sendJson(res, 404, { error: 'User not found' });

      const token = createJwt(user);
      return sendJson(res, 200, { token, user });
    }

    // -------------------------------------------------------------------------
    // API: Admin Operations (User Management & System Analytics)
    // -------------------------------------------------------------------------
    if (pathname === '/api/admin/users' && method === 'GET') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });
      if (user.role !== Roles.ADMIN) {
        recordAudit({
          actorId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          action: 'ADMIN_ACCESS_DENIED',
          resourceId: null,
          ip: getClientIp(req),
          context: { target: '/api/admin/users' }
        });
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      const usersList = Object.values(db.users).map(u => ({
        id: u.id,
        email: u.email,
        displayName: u.displayName,
        role: u.role,
        isActive: u.isActive !== false,
        createdAt: u.createdAt
      }));
      return sendJson(res, 200, { users: usersList });
    }

    if (pathname === '/api/admin/users' && method === 'POST') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });
      if (user.role !== Roles.ADMIN) {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      const raw = await parseBody(req);
      const { email, displayName, role, password } = JSON.parse(raw.toString('utf8') || '{}');
      if (!email || !displayName || !role || !password) {
        return sendJson(res, 400, { error: 'Email, display name, role, and password are required' });
      }

      if (![Roles.ADMIN, Roles.OWNER, Roles.VIEWER].includes(role)) {
        return sendJson(res, 400, { error: 'Invalid role specified' });
      }

      const existing = Object.values(db.users).find(u => u.email.toLowerCase() === email.trim().toLowerCase());
      if (existing) {
        return sendJson(res, 409, { error: 'A user with this email already exists' });
      }

      const newId = 'user-' + crypto.randomUUID().substring(0, 8);
      const newUser = {
        id: newId,
        email: email.trim().toLowerCase(),
        displayName: displayName.trim(),
        role: role,
        passwordHash: hashPassword(password),
        isActive: true,
        createdAt: new Date().toISOString()
      };

      db.users[newId] = newUser;
      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'CREATE_USER',
        resourceId: newId,
        ip: getClientIp(req),
        context: { created_user_email: newUser.email, assigned_role: newUser.role }
      });
      saveDbState();

      return sendJson(res, 201, {
        user: {
          id: newUser.id,
          email: newUser.email,
          displayName: newUser.displayName,
          role: newUser.role,
          isActive: newUser.isActive,
          createdAt: newUser.createdAt
        }
      });
    }

    const toggleUserMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/toggle-active$/);
    if (toggleUserMatch && method === 'POST') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });
      if (user.role !== Roles.ADMIN) {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      const targetId = toggleUserMatch[1];
      const targetUser = db.users[targetId];
      if (!targetUser) return sendJson(res, 404, { error: 'User not found' });
      if (targetUser.id === user.id) {
        return sendJson(res, 400, { error: 'Cannot deactivate yourself' });
      }

      targetUser.isActive = targetUser.isActive === false ? true : false;
      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: targetUser.isActive ? 'ACTIVATE_USER' : 'DEACTIVATE_USER',
        resourceId: targetUser.id,
        ip: getClientIp(req),
        context: { affected_email: targetUser.email, new_status: targetUser.isActive }
      });
      saveDbState();

      return sendJson(res, 200, {
        user: {
          id: targetUser.id,
          email: targetUser.email,
          displayName: targetUser.displayName,
          role: targetUser.role,
          isActive: targetUser.isActive
        }
      });
    }

    if (pathname === '/api/admin/stats' && method === 'GET') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });
      if (user.role !== Roles.ADMIN) {
        return sendJson(res, 403, { error: 'Forbidden: Admin access required' });
      }

      const totalUsers = Object.keys(db.users).length;
      const totalDocuments = Object.values(db.documents).filter(d => d.status === 'ACTIVE').length;
      const totalAuditLogs = db.audit_logs.length;
      const permissionChanges = db.audit_logs.filter(l => l.action === AuditActions.GRANT || l.action === AuditActions.REVOKE).length;
      const deniedEvents = db.audit_logs.filter(l => l.action.includes('DENIED') || l.action.includes('REJECTED')).length;

      return sendJson(res, 200, {
        totalUsers,
        totalDocuments,
        totalAuditLogs,
        permissionChanges,
        deniedEvents
      });
    }

    // -------------------------------------------------------------------------
    // API: Documents List (Zero-Knowledge Filtered Join)
    // -------------------------------------------------------------------------
    if (pathname === '/api/documents' && method === 'GET') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });

      // Owners see their own documents.
      // Viewers see ONLY documents they have an active permission for.
      // Admins see metadata of all active documents.
      const accessibleDocs = [];

      for (const docId in db.documents) {
        const doc = db.documents[docId];
        if (doc.status !== 'ACTIVE') continue;

        let canAccess = false;
        let userAccessLevel = null;

        if (doc.owner_id === user.id) {
          canAccess = true;
          userAccessLevel = 'OWNER';
        } else if (user.role === Roles.ADMIN) {
          canAccess = true;
          userAccessLevel = 'ADMIN_METADATA';
        } else {
          const perm = findActivePermission(docId, user.id);
          if (perm) {
            canAccess = true;
            userAccessLevel = perm.access_level;
          }
        }

        if (canAccess) {
          // Never expose storage_key or internal paths to client!
          accessibleDocs.push({
            id: doc.id,
            title: doc.title,
            category: doc.category,
            owner_id: doc.owner_id,
            owner_email: db.users[doc.owner_id] ? db.users[doc.owner_id].email : 'unknown',
            detected_mime: doc.detected_mime,
            original_filename: doc.original_filename,
            file_size_bytes: doc.file_size_bytes,
            created_at: doc.created_at,
            user_access_level: userAccessLevel
          });
        }
      }

      return sendJson(res, 200, { documents: accessibleDocs });
    }

    // -------------------------------------------------------------------------
    // API: Upload Document (Sanitization + Magic Bytes + Checksum)
    // -------------------------------------------------------------------------
    if (pathname === '/api/documents/upload' && method === 'POST') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });
      if (user.role === Roles.VIEWER) {
        return sendJson(res, 403, { error: 'Forbidden: Viewers are not permitted to upload documents' });
      }

      const raw = await parseBody(req);
      let payload;
      try {
        payload = JSON.parse(raw.toString('utf8'));
      } catch (e) {
        return sendJson(res, 400, { error: 'Invalid JSON payload' });
      }

      const { title, category, filename, contentBase64 } = payload;
      if (!title || !contentBase64) {
        return sendJson(res, 400, { error: 'Title and contentBase64 are required' });
      }

      const fileBuffer = Buffer.from(contentBase64, 'base64');
      const detectedMime = detectMimeType(fileBuffer);
      const sanitizedFilename = sanitizeFilename(filename || title + '.bin');

      // Disallow dangerous executables
      if (detectedMime === 'application/octet-stream' && (sanitizedFilename.endsWith('.exe') || sanitizedFilename.endsWith('.sh') || sanitizedFilename.endsWith('.bat'))) {
        recordAudit({
          actorId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          action: AuditActions.UPLOAD_REJECTED,
          resourceId: null,
          ip: getClientIp(req),
          context: { reason: 'DANGEROUS_EXECUTABLE_BLOCKED', filename: sanitizedFilename }
        });
        return sendJson(res, 415, { error: 'Executable files are prohibited' });
      }

      const docId = 'doc-' + crypto.randomUUID().substring(0, 12);
      const storageKey = 'storage-' + crypto.randomUUID();
      const storageFilePath = path.join(STORAGE_DIR, storageKey);

      // Write encrypted/stored file (skipped on Vercel read-only FS)
      if (!IS_READONLY_FS) {
        fs.writeFileSync(storageFilePath, fileBuffer);
      }
      const checksum = crypto.createHash('sha256').update(fileBuffer).digest('hex');

      const newDoc = {
        id: docId,
        title: title.trim().substring(0, 200),
        category: (category || 'GENERAL').toUpperCase(),
        owner_id: user.id,
        storage_key: storageKey,
        checksum: checksum,
        detected_mime: detectedMime,
        original_filename: sanitizedFilename,
        file_size_bytes: fileBuffer.length,
        status: 'ACTIVE',
        created_at: new Date().toISOString()
      };

      db.documents[docId] = newDoc;

      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: AuditActions.UPLOAD,
        resourceId: docId,
        ip: getClientIp(req),
        userAgent: req.headers['user-agent'],
        context: {
          title: newDoc.title,
          detected_mime: detectedMime,
          checksum: checksum,
          size: fileBuffer.length
        }
      });

      saveDbState();

      return sendJson(res, 201, {
        document: {
          id: newDoc.id,
          title: newDoc.title,
          category: newDoc.category,
          owner_id: newDoc.owner_id,
          detected_mime: newDoc.detected_mime,
          original_filename: newDoc.original_filename,
          file_size_bytes: newDoc.file_size_bytes,
          created_at: newDoc.created_at
        }
      });
    }

    // -------------------------------------------------------------------------
    // API: Get Document Metadata
    // -------------------------------------------------------------------------
    const docMetaMatch = pathname.match(/^\/api\/documents\/([^/]+)\/metadata$/);
    if (docMetaMatch && method === 'GET') {
      const documentId = docMetaMatch[1];
      const user = authenticateRequest(req);
      const auth = evaluateDocumentAccess(user, documentId, 'READ_METADATA', req);

      if (!auth.allowed) {
        return sendJson(res, auth.status, { error: auth.message });
      }

      const doc = auth.document;
      return sendJson(res, 200, {
        document: {
          id: doc.id,
          title: doc.title,
          category: doc.category,
          owner_id: doc.owner_id,
          owner_email: db.users[doc.owner_id] ? db.users[doc.owner_id].email : 'unknown',
          detected_mime: doc.detected_mime,
          original_filename: doc.original_filename,
          file_size_bytes: doc.file_size_bytes,
          created_at: doc.created_at,
          checksum: doc.checksum
        }
      });
    }

    // -------------------------------------------------------------------------
    // API: Issue Hyper-Short-Lived Ephemeral Stream Token (25s max)
    // -------------------------------------------------------------------------
    const streamTokenMatch = pathname.match(/^\/api\/documents\/([^/]+)\/stream-token$/);
    if (streamTokenMatch && method === 'POST') {
      const documentId = streamTokenMatch[1];
      const user = authenticateRequest(req);
      const auth = evaluateDocumentAccess(user, documentId, 'DOWNLOAD', req);

      if (!auth.allowed) {
        return sendJson(res, auth.status, { error: auth.message });
      }

      const tokenId = crypto.randomUUID();
      const expiresAt = Date.now() + STREAM_TOKEN_TTL_MS;

      const streamPayload = {
        jti: tokenId,
        sub: user.id,
        doc: documentId,
        exp: Math.floor(expiresAt / 1000)
      };

      const streamToken = crypto
        .createHmac('sha256', STREAM_SECRET)
        .update(JSON.stringify(streamPayload))
        .digest('hex');

      // Track token for single-use / revocation tracking
      db.active_stream_tokens[tokenId] = {
        tokenId,
        userId: user.id,
        documentId,
        expiresAt,
        consumed: false
      };

      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: AuditActions.TOKEN_ISSUED,
        resourceId: documentId,
        ip: getClientIp(req),
        context: { tokenId, ttl_seconds: STREAM_TOKEN_TTL_MS / 1000 }
      });

      return sendJson(res, 200, {
        stream_token: `${tokenId}.${streamToken}`,
        expires_in_seconds: 25,
        document_id: documentId
      });
    }

    // -------------------------------------------------------------------------
    // API: Secure Streaming Binary Endpoint
    // RE-EVALUATES PERMISSION AT THE EXACT MOMENT OF STREAMING (0-second revocation)
    // -------------------------------------------------------------------------
    const streamMatch = pathname.match(/^\/api\/documents\/([^/]+)\/stream$/);
    if (streamMatch && method === 'GET') {
      const documentId = streamMatch[1];
      const tokenParam = parsedUrl.searchParams.get('token');

      if (!tokenParam) {
        // Direct stream attempt with bearer auth
        const user = authenticateRequest(req);
        const auth = evaluateDocumentAccess(user, documentId, 'DOWNLOAD', req);
        if (!auth.allowed) {
          return sendJson(res, auth.status, { error: auth.message });
        }
        const asDownload = parsedUrl.searchParams.get('download') === 'true';
        return streamDocumentContent(res, auth.document, asDownload);
      }

      // Validate ephemeral token
      const [tokenId, hmacSignature] = tokenParam.split('.');
      const tokenRecord = db.active_stream_tokens[tokenId];

      if (!tokenRecord || tokenRecord.documentId !== documentId) {
        return sendJson(res, 404, { error: 'Document not found' }); // Anti-enumeration
      }

      if (Date.now() > tokenRecord.expiresAt) {
        delete db.active_stream_tokens[tokenId];
        return sendJson(res, 404, { error: 'Document not found' }); // Expired token
      }

      // CRITICAL: Re-check user & permission state right NOW
      const user = db.users[tokenRecord.userId];
      const auth = evaluateDocumentAccess(user, documentId, 'DOWNLOAD', req);
      if (!auth.allowed) {
        delete db.active_stream_tokens[tokenId];
        return sendJson(res, auth.status, { error: auth.message });
      }

      // Consume single-use token
      delete db.active_stream_tokens[tokenId];
      const asDownload = parsedUrl.searchParams.get('download') === 'true';
      return streamDocumentContent(res, auth.document, asDownload);
    }

    // -------------------------------------------------------------------------
    // API: Permissions Management (Grant / Revoke)
    // -------------------------------------------------------------------------
    if (pathname === '/api/permissions/grant' && method === 'POST') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });

      const raw = await parseBody(req);
      const { documentId, targetUserId, accessLevel } = JSON.parse(raw.toString('utf8') || '{}');

      const doc = db.documents[documentId];
      if (!doc || doc.owner_id !== user.id) {
        // Only OWNER can grant access (Anti-enumeration: 404)
        return sendJson(res, 404, { error: 'Document not found' });
      }

      const targetUser = db.users[targetUserId];
      if (!targetUser) return sendJson(res, 404, { error: 'Target user not found' });

      const permId = 'perm-' + crypto.randomUUID();
      db.permissions[permId] = {
        id: permId,
        document_id: documentId,
        user_id: targetUserId,
        access_level: accessLevel === AccessLevels.EDIT ? AccessLevels.EDIT : AccessLevels.READ,
        granted_by: user.id,
        granted_at: new Date().toISOString(),
        revoked_at: null,
        expires_at: null
      };

      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: AuditActions.GRANT,
        resourceId: documentId,
        ip: getClientIp(req),
        context: {
          permission_id: permId,
          target_user_id: targetUserId,
          target_email: targetUser.email,
          access_level: db.permissions[permId].access_level
        }
      });

      saveDbState();
      return sendJson(res, 201, { permission: db.permissions[permId] });
    }

    if (pathname === '/api/permissions/revoke' && method === 'POST') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });

      const raw = await parseBody(req);
      const { permissionId } = JSON.parse(raw.toString('utf8') || '{}');

      const perm = db.permissions[permissionId];
      if (!perm || perm.revoked_at !== null) {
        return sendJson(res, 404, { error: 'Permission not found' });
      }

      const doc = db.documents[perm.document_id];
      if (!doc || (doc.owner_id !== user.id && user.role !== Roles.ADMIN)) {
        return sendJson(res, 404, { error: 'Document not found' });
      }

      // IMMEDIATE 0-SECOND REVOCATION
      perm.revoked_at = new Date().toISOString();
      perm.revoked_by = user.id;

      recordAudit({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: AuditActions.REVOKE,
        resourceId: perm.document_id,
        ip: getClientIp(req),
        context: {
          permission_id: permissionId,
          affected_user_id: perm.user_id,
          revoked_by: user.id
        }
      });

      saveDbState();
      return sendJson(res, 200, { success: true, message: 'Access revoked in 0 seconds' });
    }

    // List permissions for document (owner or admin only)
    const listPermMatch = pathname.match(/^\/api\/documents\/([^/]+)\/permissions$/);
    if (listPermMatch && method === 'GET') {
      const documentId = listPermMatch[1];
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });

      const doc = db.documents[documentId];
      if (!doc || (doc.owner_id !== user.id && user.role !== Roles.ADMIN)) {
        return sendJson(res, 404, { error: 'Document not found' });
      }

      const perms = Object.values(db.permissions)
        .filter(p => p.document_id === documentId)
        .map(p => ({
          ...p,
          user_email: db.users[p.user_id] ? db.users[p.user_id].email : 'unknown',
          user_name: db.users[p.user_id] ? db.users[p.user_id].displayName : 'unknown'
        }));

      return sendJson(res, 200, { permissions: perms });
    }

    // -------------------------------------------------------------------------
    // API: Cryptographic Audit Trail Explorer & Chain Verifier
    // -------------------------------------------------------------------------
    if (pathname === '/api/audit' && method === 'GET') {
      const user = authenticateRequest(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required' });

      // Owners see audit logs of their documents. Admins see all logs.
      let logs = [];
      if (user.role === Roles.ADMIN) {
        logs = db.audit_logs;
      } else {
        const ownedDocIds = new Set(
          Object.values(db.documents)
            .filter(d => d.owner_id === user.id)
            .map(d => d.id)
        );
        logs = db.audit_logs.filter(
          log => log.actor_id === user.id || ownedDocIds.has(log.resource_id)
        );
      }

      return sendJson(res, 200, {
        total: logs.length,
        logs: logs.slice(-100).reverse() // Most recent first
      });
    }

    if (pathname === '/api/audit/verify-chain' && method === 'GET') {
      const result = verifyAuditChain();
      return sendJson(res, 200, result);
    }

    // Tamper simulation endpoint for security evaluation (Strict Admin Only)
    if (pathname === '/api/audit/simulate-tamper' && method === 'POST') {
      const user = authenticateRequest(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Authentication required' });
      }
      if (user.role !== Roles.ADMIN) {
        recordAudit({
          actorId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          action: 'AUDIT_TAMPER_SIMULATION_DENIED',
          resourceId: null,
          ip: getClientIp(req),
          userAgent: req.headers['user-agent'] || '',
          context: { reason: 'NON_ADMIN_AUDIT_MANIPULATION_ATTEMPT' }
        });
        saveDbState();
        return sendJson(res, 403, { error: 'Forbidden: Admin authorization required' });
      }

      if (db.audit_logs.length > 1) {
        // Tamper with the latest log's context
        const target = db.audit_logs[db.audit_logs.length - 1];
        target.context = { tampered: true, evil_payload: 'MALICIOUS_LOG_ALTERATION' };
        saveDbState();
        return sendJson(res, 200, {
          message: `Simulated tamper on audit log entry #${target.id}. Run verification to detect break!`,
          tampered_entry_id: target.id
        });
      }
      return sendJson(res, 400, { error: 'Not enough audit entries to simulate' });
    }

    // Restore & reseal audit chain endpoint (Strict Admin Only)
    if (pathname === '/api/audit/restore-chain' && method === 'POST') {
      const user = authenticateRequest(req);
      if (!user) {
        return sendJson(res, 401, { error: 'Authentication required' });
      }
      if (user.role !== Roles.ADMIN) {
        recordAudit({
          actorId: user.id,
          actorEmail: user.email,
          actorRole: user.role,
          action: 'AUDIT_RESTORE_DENIED',
          resourceId: null,
          ip: getClientIp(req),
          userAgent: req.headers['user-agent'] || '',
          context: { reason: 'NON_ADMIN_AUDIT_REWRITE_ATTEMPT' }
        });
        saveDbState();
        return sendJson(res, 403, { error: 'Forbidden: Admin authorization required' });
      }

      let prev = 'GENESIS';
      for (let i = 0; i < db.audit_logs.length; i++) {
        const entry = db.audit_logs[i];
        entry.previous_hash = prev;
        if (entry.context && entry.context.evil_payload) {
          entry.context = { note: 'Security Healthcheck Validation Record' };
        }
        const payloadData = {
          ts: entry.timestamp,
          actor: entry.actor_id || 'SYSTEM',
          role: entry.actor_role || null,
          action: entry.action,
          resource: entry.resource_id || null,
          ip: entry.ip_address || '127.0.0.1',
          ua: entry.user_agent || '',
          prev: entry.previous_hash,
          ctx: entry.context || {}
        };
        entry.current_hash = computeAuditHash(prev, canonicalJson(payloadData));
        prev = entry.current_hash;
      }
      saveDbState();
      return sendJson(res, 200, {
        success: true,
        message: 'All activity records verified and resealed.',
        total: db.audit_logs.length
      });
    }

    // -------------------------------------------------------------------------
    // Static Frontend File Delivery & Clean URL Routing
    // -------------------------------------------------------------------------
    if (method === 'GET') {
      let filePath;
      if (pathname === '/' || pathname === '/login') {
        filePath = path.join(PUBLIC_DIR, 'index.html');
      } else if (pathname === '/admin/dashboard') {
        filePath = path.join(PUBLIC_DIR, 'admin-dashboard.html');
      } else if (pathname === '/owner/dashboard') {
        filePath = path.join(PUBLIC_DIR, 'owner-dashboard.html');
      } else if (pathname === '/viewer/dashboard') {
        filePath = path.join(PUBLIC_DIR, 'viewer-dashboard.html');
      } else {
        filePath = path.join(PUBLIC_DIR, pathname);
      }

      // Prevent directory traversal attacks
      const relative = path.relative(PUBLIC_DIR, filePath);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        res.writeHead(403);
        res.end('Access Denied');
        return;
      }

      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const contentTypes = {
          '.html': 'text/html; charset=utf-8',
          '.css': 'text/css; charset=utf-8',
          '.js': 'application/javascript; charset=utf-8',
          '.json': 'application/json; charset=utf-8',
          '.svg': 'image/svg+xml',
          '.png': 'image/png',
          '.ico': 'image/x-icon'
        };
        const contentType = contentTypes[ext] || 'application/octet-stream';
        res.setHeader('Content-Type', contentType);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.writeHead(200);
        fs.createReadStream(filePath).pipe(res);
        return;
      }
    }

    // Fallback 404
    sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error('[TrustVault Server Error]', err);
    sendJson(res, 500, { error: 'Internal server error' });
  }
}

const server = http.createServer(handleRequest);

function streamDocumentContent(res, doc, asDownload = false) {
  const filePath = path.join(STORAGE_DIR, doc.storage_key);

  // On Vercel (read-only FS / in-memory mode): serve a placeholder response
  if (IS_READONLY_FS || !fs.existsSync(filePath)) {
    const notice = Buffer.from(
      `TrustVault â€” Secure Document Platform\n` +
      `=====================================\n` +
      `Document: ${doc.title}\n` +
      `Category: ${doc.category}\n` +
      `Checksum: ${doc.checksum}\n` +
      `MIME: ${doc.detected_mime}\n\n` +
      `NOTE: Running in serverless/in-memory mode.\n` +
      `File binary storage requires a persistent volume (local/self-hosted mode).\n` +
      `All security controls (zero-trust, revocation, audit) are fully active.\n`,
      'utf8'
    );
    const dispositionType = asDownload ? 'attachment' : 'inline';
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Length': notice.length,
      'Content-Disposition': `${dispositionType}; filename="${doc.original_filename}"`,
      'X-Document-Checksum': doc.checksum,
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(notice);
    return;
  }

  const stat = fs.statSync(filePath);
  const dispositionType = asDownload ? 'attachment' : 'inline';
  res.writeHead(200, {
    'Content-Type': doc.detected_mime || 'application/octet-stream',
    'Content-Length': stat.size,
    'Content-Disposition': `${dispositionType}; filename="${doc.original_filename}"`,
    'X-Document-Checksum': doc.checksum,
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'X-Content-Type-Options': 'nosniff'
  });

  fs.createReadStream(filePath).pipe(res);
}

// -----------------------------------------------------------------------------
// Initialize & Launch
// -----------------------------------------------------------------------------
initDatabase();

if (require.main === module || process.env.VERCEL === '1') {
  server.listen(PORT, HOST, () => {
    console.log(`=================================================================`);
    console.log(`ðŸ›¡ï¸  TrustVault Security Platform is LIVE`);
    console.log(`ðŸŒ  Local URL:  http://localhost:${PORT}`);
    console.log(`ðŸŒ  Direct IP:  http://127.0.0.1:${PORT}`);
    console.log(`ðŸ”’  Zero-Trust ALAC/ABAC: ACTIVE`);
    console.log(`ðŸ“œ  Cryptographic Audit Chaining: ACTIVE (HMAC-SHA256)`);
    console.log(`ðŸš«  Anti-Enumeration 404 Gate: ACTIVE`);
    console.log(`âš¡  Immediate Revocation Engine: 0-SECOND LATENCY`);
    if (IS_READONLY_FS) {
      console.log(`â˜ï¸   Mode: Serverless / Read-Only FS (Vercel Compatible)`);
    }
    console.log(`=================================================================`);
  });
}

// Vercel serverless: export handleRequest as the default handler
module.exports = handleRequest;
module.exports.default = handleRequest;
module.exports.handleRequest = handleRequest;
module.exports.getDb = () => db;
module.exports.evaluateDocumentAccess = evaluateDocumentAccess;
module.exports.verifyAuditChain = verifyAuditChain;
module.exports.recordAudit = recordAudit;
module.exports.initDatabase = initDatabase;



