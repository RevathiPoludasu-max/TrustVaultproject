/**
 * =============================================================================
 * TrustVault — Server Automated Security Test Suite
 * =============================================================================
 * Executed via Node.js Native Test Runner (node --test tests/server.test.js)
 * Tests run completely in-process (Sandbox compliant, zero TCP network dependencies).
 */

const test = require('node:test');
const assert = require('node:assert');
const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');

const { handleRequest, getDb, verifyAuditChain, initDatabase } = require('../server.js');

/**
 * In-memory HTTP Request/Response Dispatcher
 */
function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const method = options.method || 'GET';
    const headers = options.headers || {};
    const body = options.body;

    const chunks = [];
    if (body) {
      const serialized = typeof body === 'string' ? body : JSON.stringify(body);
      chunks.push(Buffer.from(serialized, 'utf8'));
    }

    const req = Readable.from(chunks);
    req.method = method;
    req.url = path;
    req.headers = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
    );
    req.socket = { remoteAddress: '127.0.0.1' };

    const res = new EventEmitter();
    let resBuffer = Buffer.alloc(0);
    res.statusCode = 200;
    res.headers = {};

    res.setHeader = (key, val) => {
      res.headers[key.toLowerCase()] = val;
    };
    res.getHeader = (key) => res.headers[key.toLowerCase()];

    res.writeHead = (statusCode, hdrs = {}) => {
      res.statusCode = statusCode;
      for (const k in hdrs) {
        res.setHeader(k, hdrs[k]);
      }
    };

    res.write = (chunk) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');
      resBuffer = Buffer.concat([resBuffer, buf]);
    };

    res.end = (chunk) => {
      if (chunk) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');
        resBuffer = Buffer.concat([resBuffer, buf]);
      }

      const bodyStr = resBuffer.toString('utf8');
      let json = null;
      try {
        json = JSON.parse(bodyStr);
      } catch (e) {
        json = bodyStr;
      }

      resolve({
        status: res.statusCode,
        headers: res.headers,
        data: json,
        raw: resBuffer
      });
    };

    handleRequest(req, res).catch(reject);
  });
}

test('TrustVault Core Zero-Trust Security Verification', async (t) => {
  // Reset database state to pristine seeds for deterministic testing
  initDatabase(true);

  await t.test('TC-01: Cross-Tenant IDOR probe returns 404 (Anti-Enumeration) & logs READ_DENIED', async () => {
    const targetDocId = 'doc-q4-fin-2026';

    // Carol (user-viewer-b) probes Alice's document without permission
    const res = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'X-Actor-Id': 'user-viewer-b' }
    });

    // Anti-enumeration: MUST be 404, NEVER 403
    assert.strictEqual(res.status, 404, 'IDOR probe must return 404 Not Found to conceal resource existence');

    // Verify audit log has recorded READ_DENIED
    const db = getDb();
    const latestLog = db.audit_logs[db.audit_logs.length - 1];
    assert.strictEqual(latestLog.action, 'READ_DENIED', 'Denied attempt must be audited');
    assert.strictEqual(latestLog.actor_id, 'user-viewer-b');
    assert.strictEqual(latestLog.resource_id, targetDocId);
    assert.ok(latestLog.current_hash, 'Audit entry must have valid HMAC hash');
  });

  await t.test('TC-02: Immediate Revocation terminates access in 0 seconds', async () => {
    const targetDocId = 'doc-q4-fin-2026';

    // 1. Alice grants Carol READ permission
    const grantRes = await request('/api/permissions/grant', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Actor-Id': 'user-owner-01'
      },
      body: {
        documentId: targetDocId,
        targetUserId: 'user-viewer-b',
        accessLevel: 'READ'
      }
    });
    assert.strictEqual(grantRes.status, 201, 'Grant should succeed');
    const permId = grantRes.data.permission.id;

    // 2. Carol can now read metadata
    const readBefore = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'X-Actor-Id': 'user-viewer-b' }
    });
    assert.strictEqual(readBefore.status, 200, 'Permitted read should succeed');

    // 3. Alice revokes Carol immediately
    const revokeRes = await request('/api/permissions/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Actor-Id': 'user-owner-01'
      },
      body: { permissionId: permId }
    });
    assert.strictEqual(revokeRes.status, 200, 'Revoke should succeed');

    // 4. Carol attempts access on the VERY NEXT request -> Must fail immediately with 404
    const readAfter = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'X-Actor-Id': 'user-viewer-b' }
    });
    assert.strictEqual(readAfter.status, 404, 'Post-revocation access must immediately return 404 in 0 seconds');

    // Verify revoke was recorded in audit log
    const db = getDb();
    const revokeLog = db.audit_logs.find(l => l.action === 'REVOKE' && l.context && l.context.permission_id === permId);
    assert.ok(revokeLog, 'Revocation must be recorded in audit log');
  });

  await t.test('TC-03: Admin Privilege Isolation blocks ungranted file download', async () => {
    const targetDocId = 'doc-q4-fin-2026';

    // Admin can read metadata (System management role)
    const metaRes = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'X-Actor-Id': 'user-admin-01' }
    });
    assert.strictEqual(metaRes.status, 200, 'Admin can read document metadata');

    // Admin CANNOT download private document binary without explicit owner grant
    const streamRes = await request(`/api/documents/${targetDocId}/stream`, {
      headers: { 'X-Actor-Id': 'user-admin-01' }
    });
    assert.strictEqual(streamRes.status, 404, 'Admin private file download without explicit grant must be blocked with 404');

    // Verify READ_DENIED audit log for admin
    const db = getDb();
    const adminDeniedLog = db.audit_logs[db.audit_logs.length - 1];
    assert.strictEqual(adminDeniedLog.action, 'READ_DENIED');
    assert.strictEqual(adminDeniedLog.actor_role, 'ADMIN');
  });

  await t.test('TC-04: Path traversal filename is sanitized & stored under isolated UUID key', async () => {
    const maliciousFilename = '../../../../etc/passwd';
    const testContent = Buffer.from('Confidential audit test file 2026').toString('base64');

    const uploadRes = await request('/api/documents/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Actor-Id': 'user-owner-01'
      },
      body: {
        title: 'Security Sanitization Test',
        category: 'SECURITY',
        filename: maliciousFilename,
        contentBase64: testContent
      }
    });

    assert.strictEqual(uploadRes.status, 201, 'Upload should succeed after sanitization');
    const doc = uploadRes.data.document;
    assert.ok(!doc.original_filename.includes('..'), 'Filename must not contain path traversal sequence');
    assert.ok(!doc.original_filename.includes('/'), 'Filename must not contain directory slashes');

    // Verify internal storage key does not contain traversal
    const db = getDb();
    const storedDoc = db.documents[doc.id];
    assert.ok(storedDoc, 'Uploaded document must exist in database');
    assert.ok(!storedDoc.storage_key.includes('..'), 'Storage key must be isolated UUID');
  });

  await t.test('TC-05: Cryptographic HMAC chain is mathematically valid', async () => {
    const verification = verifyAuditChain();
    assert.strictEqual(verification.valid, true, 'Audit chain must be completely intact');
    assert.ok(verification.total >= 5, 'Audit chain must hold entries from tests');
  });

  await t.test('TC-06: Zero-Knowledge Metadata Filtering (Search does not leak unauthorized files)', async () => {
    // Query documents as Carol (Viewer B - has no permissions)
    const res = await request('/api/documents', {
      headers: { 'X-Actor-Id': 'user-viewer-b' }
    });

    assert.strictEqual(res.status, 200);
    const docs = res.data.documents || [];
    const leakedDoc = docs.find(d => d.id === 'doc-q4-fin-2026');
    assert.strictEqual(leakedDoc, undefined, 'Unauthorized documents must never appear in document list');
  });

  await t.test('TC-07: Audit Ledger Rewrite & Tamper Protection (Strict Admin Authorization)', async () => {
    // 1. Unauthenticated requests to /api/audit/restore-chain must be rejected with 401
    const unauthRestore = await request('/api/audit/restore-chain', { method: 'POST' });
    assert.strictEqual(unauthRestore.status, 401, 'Unauthenticated restore-chain must return 401');

    // 2. Unauthenticated requests to /api/audit/simulate-tamper must be rejected with 401
    const unauthTamper = await request('/api/audit/simulate-tamper', { method: 'POST' });
    assert.strictEqual(unauthTamper.status, 401, 'Unauthenticated simulate-tamper must return 401');

    // 3. Non-admin (Viewer) requests must be rejected with 403
    const viewerRestore = await request('/api/audit/restore-chain', {
      method: 'POST',
      headers: { 'X-Actor-Id': 'user-viewer-a' }
    });
    assert.strictEqual(viewerRestore.status, 403, 'Viewer cannot restore/reseal audit chain (403 required)');

    const viewerTamper = await request('/api/audit/simulate-tamper', {
      method: 'POST',
      headers: { 'X-Actor-Id': 'user-viewer-a' }
    });
    assert.strictEqual(viewerTamper.status, 403, 'Viewer cannot trigger tamper simulation (403 required)');

    // 4. Non-admin (Owner) requests must be rejected with 403
    const ownerRestore = await request('/api/audit/restore-chain', {
      method: 'POST',
      headers: { 'X-Actor-Id': 'user-owner-01' }
    });
    assert.strictEqual(ownerRestore.status, 403, 'Owner cannot rewrite audit chain (403 required)');

    // 5. Admin request succeeds
    const adminRestore = await request('/api/audit/restore-chain', {
      method: 'POST',
      headers: { 'X-Actor-Id': 'user-admin-01' }
    });
    assert.strictEqual(adminRestore.status, 200, 'Admin can restore and reseal audit chain');
    assert.strictEqual(adminRestore.data.success, true);
  });
});
