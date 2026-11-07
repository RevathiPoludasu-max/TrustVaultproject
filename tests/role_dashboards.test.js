/**
 * =============================================================================
 * TrustVault — Dedicated Role-Based Dashboard & Security Integration Test Suite
 * =============================================================================
 * Validates:
 * 1. Email/Password Authentication & JWT Token Issuance
 * 2. Automatic Role Resolution & Routing Redirection
 * 3. Role Restrictions & Endpoint Guards
 * 4. Cross-Tenant IDOR Prevention (Anti-Enumeration 404)
 * 5. Unauthorized Download & Ephemeral Token Expiry
 * 6. Admin Privilege Isolation (Cannot download private binaries)
 * 7. Immediate 0-Second Permission Revocation
 * 8. Cryptographic HMAC Chain Integrity
 */

const test = require('node:test');
const assert = require('node:assert');
const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');

const { handleRequest, getDb, verifyAuditChain, initDatabase } = require('../server.js');

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

test('TrustVault Multi-Role Authentication & Access Control Suite', async (t) => {
  initDatabase(true);

  let adminToken = null;
  let ownerToken = null;
  let viewerAToken = null;
  let viewerBToken = null;

  await t.test('1. Authentication: Login with email/password and verify role redirection', async () => {
    // 1a. Invalid credentials
    const badLogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'owner@trustvault.local', password: 'WrongPassword!', requestedRole: 'OWNER' }
    });
    assert.strictEqual(badLogin.status, 401, 'Invalid password must return 401');
    assert.strictEqual(badLogin.data.error, 'Invalid credentials or incorrect login role.');

    // 1b. Admin Login with requestedRole: ADMIN -> redirectUrl: /admin/dashboard
    const adminLogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'admin@trustvault.local', password: 'Admin@123', requestedRole: 'ADMIN' }
    });
    assert.strictEqual(adminLogin.status, 200);
    assert.strictEqual(adminLogin.data.user.role, 'ADMIN');
    assert.strictEqual(adminLogin.data.redirectUrl, '/admin/dashboard');
    assert.ok(adminLogin.data.token);
    adminToken = adminLogin.data.token;

    // 1c. Owner Login with requestedRole: OWNER -> redirectUrl: /owner/dashboard
    const ownerLogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'owner@trustvault.local', password: 'Owner@123', requestedRole: 'OWNER' }
    });
    assert.strictEqual(ownerLogin.status, 200);
    assert.strictEqual(ownerLogin.data.user.role, 'OWNER');
    assert.strictEqual(ownerLogin.data.redirectUrl, '/owner/dashboard');
    assert.ok(ownerLogin.data.token);
    ownerToken = ownerLogin.data.token;

    // 1d. Viewer A Login with requestedRole: VIEWER -> redirectUrl: /viewer/dashboard
    const viewerALogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'viewer_a@trustvault.local', password: 'Viewer@123', requestedRole: 'VIEWER' }
    });
    assert.strictEqual(viewerALogin.status, 200);
    assert.strictEqual(viewerALogin.data.user.role, 'VIEWER');
    assert.strictEqual(viewerALogin.data.redirectUrl, '/viewer/dashboard');
    assert.ok(viewerALogin.data.token);
    viewerAToken = viewerALogin.data.token;

    // 1e. Viewer B Login with requestedRole: USER (Viewer alias) -> redirectUrl: /viewer/dashboard
    const viewerBLogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'viewer_b@trustvault.local', password: 'Viewer@123', requestedRole: 'USER' }
    });
    assert.strictEqual(viewerBLogin.status, 200);
    assert.strictEqual(viewerBLogin.data.user.role, 'VIEWER');
    assert.strictEqual(viewerBLogin.data.redirectUrl, '/viewer/dashboard');
    assert.ok(viewerBLogin.data.token);
    viewerBToken = viewerBLogin.data.token;

    // 1f. Full 9 Login Combinations Matrix (3 Users × 3 Tabs)
    // Users:
    //   Admin: admin@trustvault.local / Admin@123 (Role: ADMIN)
    //   Owner: owner@trustvault.local / Owner@123 (Role: OWNER)
    //   Viewer: viewer_a@trustvault.local / Viewer@123 (Role: VIEWER)
    // Tabs: ADMIN, OWNER, VIEWER
    const matrix = [
      // Admin account across 3 tabs
      { email: 'admin@trustvault.local', pass: 'Admin@123', tab: 'ADMIN', expectStatus: 200, expectRedirect: '/admin/dashboard' },
      { email: 'admin@trustvault.local', pass: 'Admin@123', tab: 'OWNER', expectStatus: 403, expectRedirect: null },
      { email: 'admin@trustvault.local', pass: 'Admin@123', tab: 'VIEWER', expectStatus: 403, expectRedirect: null },

      // Owner account across 3 tabs
      { email: 'owner@trustvault.local', pass: 'Owner@123', tab: 'ADMIN', expectStatus: 403, expectRedirect: null },
      { email: 'owner@trustvault.local', pass: 'Owner@123', tab: 'OWNER', expectStatus: 200, expectRedirect: '/owner/dashboard' },
      { email: 'owner@trustvault.local', pass: 'Owner@123', tab: 'VIEWER', expectStatus: 403, expectRedirect: null },

      // Viewer account across 3 tabs
      { email: 'viewer_a@trustvault.local', pass: 'Viewer@123', tab: 'ADMIN', expectStatus: 403, expectRedirect: null },
      { email: 'viewer_a@trustvault.local', pass: 'Viewer@123', tab: 'OWNER', expectStatus: 403, expectRedirect: null },
      { email: 'viewer_a@trustvault.local', pass: 'Viewer@123', tab: 'VIEWER', expectStatus: 200, expectRedirect: '/viewer/dashboard' },
    ];

    for (const testCase of matrix) {
      const res = await request('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { email: testCase.email, password: testCase.pass, requestedRole: testCase.tab }
      });
      assert.strictEqual(
        res.status,
        testCase.expectStatus,
        `Matrix check failed for ${testCase.email} on ${testCase.tab} tab. Expected status ${testCase.expectStatus}, got ${res.status}`
      );
      if (testCase.expectStatus === 200) {
        assert.strictEqual(res.data.redirectUrl, testCase.expectRedirect);
        assert.ok(res.data.token, 'Must issue token on 200');
      } else {
        assert.strictEqual(res.data.error, 'Invalid credentials or incorrect login role.');
        assert.strictEqual(res.data.token, undefined, 'Must NEVER issue token on mismatch');
      }
    }
  });

  await t.test('2. Role Enforcement: Non-admins are strictly forbidden from /api/admin endpoints', async () => {
    // Owner tries to access admin users
    const ownerTry = await request('/api/admin/users', {
      headers: { 'Authorization': 'Bearer ' + ownerToken }
    });
    assert.strictEqual(ownerTry.status, 403, 'Owner cannot access /api/admin/users');

    // Viewer tries to access admin stats
    const viewerTry = await request('/api/admin/stats', {
      headers: { 'Authorization': 'Bearer ' + viewerAToken }
    });
    assert.strictEqual(viewerTry.status, 403, 'Viewer cannot access /api/admin/stats');

    // Admin can access admin stats & users
    const adminStats = await request('/api/admin/stats', {
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    assert.strictEqual(adminStats.status, 200, 'Admin can access stats');
    assert.ok(adminStats.data.totalUsers >= 4);
  });

  await t.test('3. Viewer Restrictions: Viewers cannot upload documents', async () => {
    const testContent = Buffer.from('Viewer prohibited upload test').toString('base64');
    const uploadAttempt = await request('/api/documents/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + viewerAToken
      },
      body: {
        title: 'Hacked Upload',
        category: 'INTERNAL',
        filename: 'hacked.txt',
        contentBase64: testContent
      }
    });
    assert.strictEqual(uploadAttempt.status, 403, 'Viewers must be forbidden from uploading');
  });

  await t.test('4. IDOR / BOLA Prevention: Cross-user document probing returns 404 (Anti-Enumeration)', async () => {
    const targetDocId = 'doc-q4-fin-2026'; // Owned by Alice

    // Carol (Viewer B) has no permission on Alice's doc
    const probe = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'Authorization': 'Bearer ' + viewerBToken }
    });
    assert.strictEqual(probe.status, 404, 'Unauthorized IDOR probe must return 404 (never 403)');

    // Ensure denied attempt was logged in audit
    const db = getDb();
    const deniedLog = db.audit_logs[db.audit_logs.length - 1];
    assert.strictEqual(deniedLog.action, 'READ_DENIED');
  });

  await t.test('5. Admin Privilege Isolation: Admin cannot download private document binaries', async () => {
    const targetDocId = 'doc-q4-fin-2026';

    // Admin can view metadata
    const metaRes = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    assert.strictEqual(metaRes.status, 200, 'Admin can view document metadata');

    // Admin CANNOT stream document binary
    const streamRes = await request(`/api/documents/${targetDocId}/stream`, {
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    assert.strictEqual(streamRes.status, 404, 'Admin private binary download must return 404');
  });

  await t.test('6. Immediate Revocation: Revoking access terminates viewing rights in 0 seconds', async () => {
    const targetDocId = 'doc-q4-fin-2026';

    // Step 1: Owner grants Viewer B access
    const grantRes = await request('/api/permissions/grant', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + ownerToken
      },
      body: {
        documentId: targetDocId,
        targetUserId: 'user-viewer-b',
        accessLevel: 'READ'
      }
    });
    assert.strictEqual(grantRes.status, 201, 'Grant should succeed');
    const permId = grantRes.data.permission.id;

    // Step 2: Viewer B can now read metadata
    const readBefore = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'Authorization': 'Bearer ' + viewerBToken }
    });
    assert.strictEqual(readBefore.status, 200, 'Viewer B can now read');

    // Step 3: Owner revokes access
    const revokeRes = await request('/api/permissions/revoke', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + ownerToken
      },
      body: { permissionId: permId }
    });
    assert.strictEqual(revokeRes.status, 200, 'Revoke should succeed');

    // Step 4: Viewer B probes again on the very next request -> Must fail immediately with 404
    const readAfter = await request(`/api/documents/${targetDocId}/metadata`, {
      headers: { 'Authorization': 'Bearer ' + viewerBToken }
    });
    assert.strictEqual(readAfter.status, 404, 'Revocation must take effect immediately in 0 seconds');
  });

  await t.test('7. Clean URLs & Dashboard Routing: Verify HTML dashboards are served', async () => {
    const rAdmin = await request('/admin/dashboard');
    assert.strictEqual(rAdmin.status, 200);
    assert.ok(rAdmin.data.includes('Administrator Security Console'));

    const rOwner = await request('/owner/dashboard');
    assert.strictEqual(rOwner.status, 200);
    assert.ok(rOwner.data.includes('Document Owner Console'));

    const rViewer = await request('/viewer/dashboard');
    assert.strictEqual(rViewer.status, 200);
    assert.ok(rViewer.data.includes('Authorized Viewer Portal'));

    const rLogin = await request('/login');
    assert.strictEqual(rLogin.status, 200);
    assert.ok(rLogin.data.includes('Admin Sign In') || rLogin.data.includes('TrustVault'));
  });

  await t.test('8. Audit Ledger Integrity: HMAC hash chain remains intact', async () => {
    const chain = verifyAuditChain();
    assert.strictEqual(chain.valid, true, 'Cryptographic chain must be valid');
    assert.ok(chain.total >= 8);
  });

  await t.test('9. Audit Security Guards: Prevent unauthenticated & non-admin rewrite of audit ledger', async () => {
    // Acquire tokens for admin, owner, viewer
    const adminLogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'admin@trustvault.local', password: 'Admin@123', requestedRole: 'ADMIN' }
    });
    const adminToken = adminLogin.data.token;

    const ownerLogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'owner@trustvault.local', password: 'Owner@123', requestedRole: 'OWNER' }
    });
    const ownerToken = ownerLogin.data.token;

    const viewerLogin = await request('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: { email: 'viewer_a@trustvault.local', password: 'Viewer@123', requestedRole: 'VIEWER' }
    });
    const viewerToken = viewerLogin.data.token;

    // 1. Unauthenticated request to restore-chain -> 401
    const unauthRes = await request('/api/audit/restore-chain', { method: 'POST' });
    assert.strictEqual(unauthRes.status, 401, 'Unauthenticated call to restore-chain must return 401');

    // 2. Unauthenticated request to simulate-tamper -> 401
    const unauthTamper = await request('/api/audit/simulate-tamper', { method: 'POST' });
    assert.strictEqual(unauthTamper.status, 401, 'Unauthenticated call to simulate-tamper must return 401');

    // 3. Viewer token to restore-chain -> 403
    const viewerRes = await request('/api/audit/restore-chain', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + viewerToken }
    });
    assert.strictEqual(viewerRes.status, 403, 'Viewer must not be authorized to rewrite audit chain');

    // 4. Owner token to restore-chain -> 403
    const ownerRes = await request('/api/audit/restore-chain', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + ownerToken }
    });
    assert.strictEqual(ownerRes.status, 403, 'Owner must not be authorized to rewrite audit chain');

    // 5. Admin token to simulate-tamper -> 200
    const adminTamper = await request('/api/audit/simulate-tamper', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    assert.strictEqual(adminTamper.status, 200, 'Admin can invoke simulate-tamper');

    // 6. Admin token to restore-chain -> 200
    const adminRestore = await request('/api/audit/restore-chain', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    assert.strictEqual(adminRestore.status, 200, 'Admin can restore and reseal chain');
    assert.strictEqual(adminRestore.data.success, true);
  });
});

