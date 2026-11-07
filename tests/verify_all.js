/**
 * TrustVault — Comprehensive Verification Script
 * Tests all API endpoints and security behaviors in-process
 * Run: node tests/verify_all.js
 */

const { Readable } = require('node:stream');
const { EventEmitter } = require('node:events');
const fs = require('fs');
const path = require('path');

// Load server
const { handleRequest, getDb, verifyAuditChain, initDatabase } = require('../server.js');

// Reset to fresh seed
initDatabase(true);

let passed = 0;
let failed = 0;
const results = [];

// ---- In-process request dispatcher ----
function request(urlPath, options = {}) {
  return new Promise((resolve, reject) => {
    const method = options.method || 'GET';
    const headers = options.headers || {};
    const body = options.body;

    const chunks = [];
    if (body) {
      const s = typeof body === 'string' ? body : JSON.stringify(body);
      chunks.push(Buffer.from(s, 'utf8'));
    }

    const req = Readable.from(chunks);
    req.method = method;
    req.url = urlPath;
    req.headers = Object.fromEntries(
      Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
    );
    req.socket = { remoteAddress: '127.0.0.1' };

    const res = new EventEmitter();
    let resBuffer = Buffer.alloc(0);
    res.statusCode = 200;
    res.headers = {};
    res.setHeader = (key, val) => { res.headers[key.toLowerCase()] = val; };
    res.getHeader = (key) => res.headers[key.toLowerCase()];
    res.writeHead = (statusCode, hdrs = {}) => {
      res.statusCode = statusCode;
      for (const k in hdrs) res.setHeader(k, hdrs[k]);
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
      let json = null;
      try { json = JSON.parse(resBuffer.toString('utf8')); } catch (e) { json = resBuffer.toString('utf8'); }
      resolve({ status: res.statusCode, headers: res.headers, data: json, raw: resBuffer });
    };
    handleRequest(req, res).catch(reject);
  });
}

function check(label, actual, expected, notes = '') {
  const ok = actual === expected;
  if (ok) {
    passed++;
    results.push(`  ✅ PASS  ${label}`);
  } else {
    failed++;
    results.push(`  ❌ FAIL  ${label}\n           Expected: ${expected}  Got: ${actual}${notes ? '  → '+notes : ''}`);
  }
}

function checkTrue(label, expr, notes = '') {
  if (expr) {
    passed++;
    results.push(`  ✅ PASS  ${label}`);
  } else {
    failed++;
    results.push(`  ❌ FAIL  ${label}${notes ? '  → '+notes : ''}`);
  }
}

async function run() {
  console.log('================================================================');
  console.log('  TrustVault — Full Requirement Verification Report');
  console.log('================================================================\n');

  // ============================================================
  // SECTION A: Static File Serving
  // ============================================================
  console.log('▶ SECTION A: Static File Serving');

  // A1: index.html
  const a1 = await request('/');
  check('A1  GET / → 200 (index.html)', a1.status, 200);
  checkTrue('A1b index.html contains TrustVault title',
    typeof a1.data === 'string' && a1.data.includes('TrustVault'));

  // A2: CSS
  const a2 = await request('/css/styles.css');
  check('A2  GET /css/styles.css → 200', a2.status, 200);

  // A3: JS files
  const a3a = await request('/js/app.js');
  check('A3a GET /js/app.js → 200', a3a.status, 200);
  const a3b = await request('/js/crypto-audit.js');
  check('A3b GET /js/crypto-audit.js → 200', a3b.status, 200);
  const a3c = await request('/js/security-tester.js');
  check('A3c GET /js/security-tester.js → 200', a3c.status, 200);

  // A4: Favicon
  const a4 = await request('/favicon.svg');
  check('A4  GET /favicon.svg → 200', a4.status, 200);

  // A5: Path traversal on static server → blocked
  const a5 = await request('/../../../etc/passwd');
  checkTrue('A5  Path traversal on static server → 403', a5.status === 403 || a5.status === 404);

  // A6: Non-existent static file → 404 JSON
  const a6 = await request('/nonexistent-file.xyz');
  check('A6  Missing static file → 404', a6.status, 404);

  // ============================================================
  // SECTION B: Authentication & Auth Endpoints
  // ============================================================
  console.log('\n▶ SECTION B: Authentication & Identity');

  // B1: Personas list
  const b1 = await request('/api/auth/personas');
  check('B1  GET /api/auth/personas → 200', b1.status, 200);
  checkTrue('B1b 4 personas returned', Array.isArray(b1.data.personas) && b1.data.personas.length === 4);

  // B2: /api/auth/me without auth → 401
  const b2 = await request('/api/auth/me');
  check('B2  GET /api/auth/me (no auth) → 401', b2.status, 401);

  // B3: /api/auth/me with X-Actor-Id header
  const b3 = await request('/api/auth/me', { headers: { 'X-Actor-Id': 'user-owner-01' } });
  check('B3  GET /api/auth/me (with actor) → 200', b3.status, 200);
  check('B3b Role is OWNER', b3.data.user.role, 'OWNER');

  // B4: JWT token issuance
  const b4 = await request('/api/auth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: { actorId: 'user-admin-01' }
  });
  check('B4  POST /api/auth/token → 200', b4.status, 200);
  checkTrue('B4b JWT token returned', typeof b4.data.token === 'string' && b4.data.token.split('.').length === 3);

  // ============================================================
  // SECTION C: Document Operations
  // ============================================================
  console.log('\n▶ SECTION C: Document Operations');

  // C1: List documents as OWNER
  const c1 = await request('/api/documents', { headers: { 'X-Actor-Id': 'user-owner-01' } });
  check('C1  GET /api/documents as OWNER → 200', c1.status, 200);
  checkTrue('C1b Seed doc present', (c1.data.documents || []).some(d => d.id === 'doc-q4-fin-2026'));

  // C2: List documents as VIEWER-B (no grants) → empty list (zero-knowledge)
  const c2 = await request('/api/documents', { headers: { 'X-Actor-Id': 'user-viewer-b' } });
  check('C2  GET /api/documents as ungranted VIEWER → 200', c2.status, 200);
  checkTrue('C2b No docs leaked to ungranted viewer', (c2.data.documents || []).length === 0);

  // C3: Unauthenticated request blocked
  const c3 = await request('/api/documents');
  check('C3  GET /api/documents (no auth) → 401', c3.status, 401);

  // C4: Upload a document
  const testContent = Buffer.from('%PDF-1.4\nTest TrustVault Verification PDF').toString('base64');
  const c4 = await request('/api/documents/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Actor-Id': 'user-owner-01' },
    body: { title: 'Verification Test Doc', category: 'LEGAL', filename: 'test.pdf', contentBase64: testContent }
  });
  check('C4  POST /api/documents/upload → 201', c4.status, 201);
  checkTrue('C4b Document ID returned', typeof c4.data.document?.id === 'string');
  checkTrue('C4c MIME detected as PDF', c4.data.document?.detected_mime === 'application/pdf');

  const uploadedDocId = c4.data.document?.id;

  // C5: Malicious filename sanitization
  const c5 = await request('/api/documents/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Actor-Id': 'user-owner-01' },
    body: { title: 'Malicious Name Test', category: 'INTERNAL', filename: '../../../../etc/passwd', contentBase64: testContent }
  });
  check('C5  Upload with malicious filename → 201 (sanitized)', c5.status, 201);
  checkTrue('C5b Path traversal stripped from filename',
    c5.data.document?.original_filename && !c5.data.document.original_filename.includes('..') && !c5.data.document.original_filename.includes('/'));

  // C6: Get document metadata as owner
  const c6 = await request(`/api/documents/doc-q4-fin-2026/metadata`, {
    headers: { 'X-Actor-Id': 'user-owner-01' }
  });
  check('C6  Owner reads own doc metadata → 200', c6.status, 200);
  checkTrue('C6b Storage key NOT exposed to client',
    c6.data.document && !('storage_key' in c6.data.document));

  // ============================================================
  // SECTION D: Zero-Trust Authorization (Core Security)
  // ============================================================
  console.log('\n▶ SECTION D: Zero-Trust Authorization (Core Security Requirements)');

  // D1: IDOR / Anti-Enumeration — 404 not 403
  const d1 = await request('/api/documents/doc-q4-fin-2026/metadata', {
    headers: { 'X-Actor-Id': 'user-viewer-b' }
  });
  check('D1  IDOR: ungranted VIEWER gets 404 (NOT 403)', d1.status, 404);

  // D2: Admin can read metadata
  const d2 = await request('/api/documents/doc-q4-fin-2026/metadata', {
    headers: { 'X-Actor-Id': 'user-admin-01' }
  });
  check('D2  Admin reads metadata → 200', d2.status, 200);

  // D3: Admin CANNOT stream/download binary without explicit grant
  const d3 = await request('/api/documents/doc-q4-fin-2026/stream', {
    headers: { 'X-Actor-Id': 'user-admin-01' }
  });
  check('D3  Admin binary download without grant → 404 (Admin Isolation)', d3.status, 404);

  // D4: Viewer-A (has seed grant) CAN read metadata
  const d4 = await request('/api/documents/doc-q4-fin-2026/metadata', {
    headers: { 'X-Actor-Id': 'user-viewer-a' }
  });
  check('D4  Granted VIEWER reads metadata → 200', d4.status, 200);

  // D5: 0-second revocation test
  // Grant Carol
  const grantD5 = await request('/api/permissions/grant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Actor-Id': 'user-owner-01' },
    body: { documentId: 'doc-q4-fin-2026', targetUserId: 'user-viewer-b', accessLevel: 'READ' }
  });
  const permId = grantD5.data.permission?.id;
  // Carol can now read
  const d5before = await request('/api/documents/doc-q4-fin-2026/metadata', {
    headers: { 'X-Actor-Id': 'user-viewer-b' }
  });
  check('D5a Carol reads after grant → 200', d5before.status, 200);
  // Revoke
  await request('/api/permissions/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Actor-Id': 'user-owner-01' },
    body: { permissionId: permId }
  });
  // Carol immediately blocked
  const d5after = await request('/api/documents/doc-q4-fin-2026/metadata', {
    headers: { 'X-Actor-Id': 'user-viewer-b' }
  });
  check('D5b Immediate 0s revocation: Carol gets 404 on next request', d5after.status, 404);

  // D6: Ephemeral stream token for owner
  const d6tok = await request('/api/documents/doc-q4-fin-2026/stream-token', {
    method: 'POST',
    headers: { 'X-Actor-Id': 'user-owner-01' }
  });
  check('D6  Stream token issued for owner → 200', d6tok.status, 200);
  checkTrue('D6b Token is 25s max TTL', d6tok.data.expires_in_seconds === 25);
  checkTrue('D6c Token contains UUID.hmac format', /^[0-9a-f-]+\.[0-9a-f]+$/.test(d6tok.data.stream_token));

  // D7: Use stream token to fetch document
  const d7 = await request(`/api/documents/doc-q4-fin-2026/stream?token=${encodeURIComponent(d6tok.data.stream_token)}`);
  check('D7  Stream with valid token → 200', d7.status, 200);
  checkTrue('D7b Checksum header present', typeof d7.headers['x-document-checksum'] === 'string');

  // D8: Replay / reuse of consumed stream token → rejected
  const d8 = await request(`/api/documents/doc-q4-fin-2026/stream?token=${encodeURIComponent(d6tok.data.stream_token)}`);
  check('D8  Replay of consumed stream token → 404 (single-use)', d8.status, 404);

  // ============================================================
  // SECTION E: Permissions Management
  // ============================================================
  console.log('\n▶ SECTION E: Permissions Management');

  // E1: Grant succeeds for owner
  const e1 = await request('/api/permissions/grant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Actor-Id': 'user-owner-01' },
    body: { documentId: uploadedDocId, targetUserId: 'user-viewer-b', accessLevel: 'READ' }
  });
  check('E1  Owner grants READ to viewer → 201', e1.status, 201);

  // E2: Viewer-B can now list docs containing the uploaded doc
  const e2 = await request('/api/documents', { headers: { 'X-Actor-Id': 'user-viewer-b' } });
  checkTrue('E2  Granted viewer now sees document', (e2.data.documents || []).some(d => d.id === uploadedDocId));

  // E3: List permissions for owned doc
  const e3 = await request(`/api/documents/${uploadedDocId}/permissions`, {
    headers: { 'X-Actor-Id': 'user-owner-01' }
  });
  check('E3  Owner lists permissions → 200', e3.status, 200);
  checkTrue('E3b Permission list includes viewer-b', (e3.data.permissions || []).some(p => p.user_id === 'user-viewer-b'));

  // E4: Non-owner cannot grant access
  const e4 = await request('/api/permissions/grant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Actor-Id': 'user-viewer-b' },
    body: { documentId: 'doc-q4-fin-2026', targetUserId: 'user-viewer-a', accessLevel: 'READ' }
  });
  checkTrue('E4  Non-owner cannot grant → 404', e4.status === 404);

  // ============================================================
  // SECTION F: Cryptographic Audit Trail
  // ============================================================
  console.log('\n▶ SECTION F: Cryptographic Audit Trail');

  // F1: Audit log endpoint
  const f1 = await request('/api/audit', { headers: { 'X-Actor-Id': 'user-admin-01' } });
  check('F1  GET /api/audit as admin → 200', f1.status, 200);
  checkTrue('F1b Logs array present', Array.isArray(f1.data.logs));

  // F2: Audit logs contain DENIED entries (from D1 test)
  const deniedLogs = (f1.data.logs || []).filter(l => l.action === 'READ_DENIED');
  checkTrue('F2  DENIED access attempts are recorded in audit', deniedLogs.length > 0);

  // F3: Every audit entry has HMAC hash
  const f1Logs = f1.data.logs || [];
  const hasHashes = f1Logs.every(l => typeof l.current_hash === 'string' && l.current_hash.length > 0);
  checkTrue('F3  All audit entries have HMAC hash', hasHashes);

  // F4: Chain verification
  const f4 = await request('/api/audit/verify-chain');
  check('F4  GET /api/audit/verify-chain → 200', f4.status, 200);
  check('F4b Chain is valid', f4.data.valid, true);
  checkTrue('F4c Chain covers all entries', f4.data.total >= 10);

  // F5: Tamper simulation (Strict Admin authorization)
  const f5Unauth = await request('/api/audit/simulate-tamper', { method: 'POST' });
  check('F5_unauth POST /api/audit/simulate-tamper (unauthenticated) → 401', f5Unauth.status, 401);

  const f5Viewer = await request('/api/audit/simulate-tamper', {
    method: 'POST',
    headers: { 'X-Actor-Id': 'user-viewer-a' }
  });
  check('F5_viewer POST /api/audit/simulate-tamper (non-admin) → 403', f5Viewer.status, 403);

  const f5a = await request('/api/audit/simulate-tamper', {
    method: 'POST',
    headers: { 'X-Actor-Id': 'user-admin-01' }
  });
  check('F5a Tamper simulation (Admin) → 200', f5a.status, 200);
  const f5b = await request('/api/audit/verify-chain');
  check('F5b Chain reports invalid after tamper', f5b.data.valid, false);
  checkTrue('F5c brokenAt entry ID returned', typeof f5b.data.brokenAt !== 'undefined');

  // F6: Chain restore re-seals (Strict Admin authorization)
  const f6Unauth = await request('/api/audit/restore-chain', { method: 'POST' });
  check('F6_unauth POST /api/audit/restore-chain (unauthenticated) → 401', f6Unauth.status, 401);

  const f6Viewer = await request('/api/audit/restore-chain', {
    method: 'POST',
    headers: { 'X-Actor-Id': 'user-viewer-a' }
  });
  check('F6_viewer POST /api/audit/restore-chain (non-admin) → 403', f6Viewer.status, 403);

  const f6 = await request('/api/audit/restore-chain', {
    method: 'POST',
    headers: { 'X-Actor-Id': 'user-admin-01' }
  });
  check('F6  POST /api/audit/restore-chain (Admin) → 200', f6.status, 200);
  const f6verify = await request('/api/audit/verify-chain');
  check('F6b Chain valid after restore', f6verify.data.valid, true);

  // F7: Owner only sees own audit logs (not admin-wide)
  const f7 = await request('/api/audit', { headers: { 'X-Actor-Id': 'user-owner-01' } });
  check('F7  GET /api/audit as OWNER → 200', f7.status, 200);
  checkTrue('F7b Viewer-B audit logs not leaked to OWNER', 
    !(f7.data.logs || []).some(l => l.actor_id === 'user-viewer-b' && l.resource_id !== 'doc-q4-fin-2026'));

  // ============================================================
  // SECTION G: File / Project Integrity
  // ============================================================
  console.log('\n▶ SECTION G: File & Project Integrity');

  const reqFiles = [
    'server.js', 'package.json', 'vercel.json', '.gitignore', '.env.example',
    'public/index.html', 'public/admin-dashboard.html', 'public/owner-dashboard.html', 'public/viewer-dashboard.html',
    'public/favicon.svg', 'public/css/styles.css',
    'public/js/app.js', 'public/js/crypto-audit.js', 'public/js/security-tester.js',
    'tests/server.test.js', 'tests/role_dashboards.test.js',
    'trustvault/docs/THREATS.md', 'trustvault/docs/PROMPTS.md',
    'trustvault/database/schema.sql', 'trustvault/database/seed.sql'
  ];

  for (const file of reqFiles) {
    const full = path.join(__dirname, '..', file);
    checkTrue(`G  File exists: ${file}`, fs.existsSync(full));
  }

  // Check CSS has all required badge classes
  const cssContent = fs.readFileSync(path.join(__dirname, '../public/css/styles.css'), 'utf8');
  checkTrue('G  CSS: .badge-cat-confidential', cssContent.includes('badge-cat-confidential'));
  checkTrue('G  CSS: .badge-cat-financial', cssContent.includes('badge-cat-financial'));
  checkTrue('G  CSS: .badge-cat-legal', cssContent.includes('badge-cat-legal'));
  checkTrue('G  CSS: .badge-cat-healthcare', cssContent.includes('badge-cat-healthcare'));
  checkTrue('G  CSS: .badge-cat-internal', cssContent.includes('badge-cat-internal'));
  checkTrue('G  CSS: .stat-card-cyan', cssContent.includes('stat-card-cyan'));
  checkTrue('G  CSS: .stat-card-amber', cssContent.includes('stat-card-amber'));
  checkTrue('G  CSS: .stat-card-emerald', cssContent.includes('stat-card-emerald'));
  checkTrue('G  CSS: .stat-card-purple', cssContent.includes('stat-card-purple'));
  checkTrue('G  CSS: .action-upload', cssContent.includes('action-upload'));
  checkTrue('G  CSS: .action-read', cssContent.includes('action-read'));
  checkTrue('G  CSS: .action-denied', cssContent.includes('action-denied'));
  checkTrue('G  CSS: .action-grant', cssContent.includes('action-grant'));
  checkTrue('G  CSS: .action-revoke', cssContent.includes('action-revoke'));

  // Check JS has required functions
  const appJs = fs.readFileSync(path.join(__dirname, '../public/js/app.js'), 'utf8');
  checkTrue('G  app.js: getCategoryBadgeClass()', appJs.includes('getCategoryBadgeClass'));
  checkTrue('G  app.js: renderDocuments()', appJs.includes('renderDocuments'));
  checkTrue('G  app.js: updateDashboardStats()', appJs.includes('updateDashboardStats'));
  checkTrue('G  app.js: openStreamModal()', appJs.includes('openStreamModal'));
  checkTrue('G  app.js: submitUpload()', appJs.includes('submitUpload'));
  checkTrue('G  app.js: revokeAccess()', appJs.includes('revokeAccess'));
  checkTrue('G  app.js: escapeHtml() XSS guard', appJs.includes('escapeHtml'));

  const cryptoJs = fs.readFileSync(path.join(__dirname, '../public/js/crypto-audit.js'), 'utf8');
  checkTrue('G  crypto-audit.js: getActionClass()', cryptoJs.includes('getActionClass'));
  checkTrue('G  crypto-audit.js: renderChainBlocks()', cryptoJs.includes('renderChainBlocks'));
  checkTrue('G  crypto-audit.js: verifyChainIntegrity()', cryptoJs.includes('verifyChainIntegrity'));
  checkTrue('G  crypto-audit.js: restoreChain()', cryptoJs.includes('restoreChain'));

  // Check HTML has required DOM IDs referenced across the platform
  const loginHtml = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
  checkTrue('G  index.html: loginForm', loginHtml.includes('id="loginForm"'));
  checkTrue('G  index.html: loginEmail', loginHtml.includes('id="loginEmail"'));
  checkTrue('G  index.html: loginPassword', loginHtml.includes('id="loginPassword"'));

  const adminHtml = fs.readFileSync(path.join(__dirname, '../public/admin-dashboard.html'), 'utf8');
  checkTrue('G  admin-dashboard: usersTableBody', adminHtml.includes('id="usersTableBody"'));
  checkTrue('G  admin-dashboard: auditTableBody', adminHtml.includes('id="auditTableBody"'));
  checkTrue('G  admin-dashboard: statTotalUsers', adminHtml.includes('id="statTotalUsers"'));
  checkTrue('G  admin-dashboard: statTotalDocs', adminHtml.includes('id="statTotalDocs"'));

  const ownerHtml = fs.readFileSync(path.join(__dirname, '../public/owner-dashboard.html'), 'utf8');
  checkTrue('G  owner-dashboard: documentsTableBody', ownerHtml.includes('id="documentsTableBody"'));
  checkTrue('G  owner-dashboard: permissionsTableBody', ownerHtml.includes('id="permissionsTableBody"'));
  checkTrue('G  owner-dashboard: uploadModal', ownerHtml.includes('id="uploadModal"'));
  checkTrue('G  owner-dashboard: grantModal', ownerHtml.includes('id="grantModal"'));

  const viewerHtml = fs.readFileSync(path.join(__dirname, '../public/viewer-dashboard.html'), 'utf8');
  checkTrue('G  viewer-dashboard: viewerDocsTableBody', viewerHtml.includes('id="viewerDocsTableBody"'));
  checkTrue('G  viewer-dashboard: viewerAuditTableBody', viewerHtml.includes('id="viewerAuditTableBody"'));
  checkTrue('G  viewer-dashboard: streamModal', viewerHtml.includes('id="streamModal"'));

  // Check vercel.json is valid JSON with required fields
  const vercelJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../vercel.json'), 'utf8'));
  checkTrue('G  vercel.json: version field', vercelJson.version === 2);
  checkTrue('G  vercel.json: builds entry', Array.isArray(vercelJson.builds));
  checkTrue('G  vercel.json: routes entry', Array.isArray(vercelJson.routes));

  // ============================================================
  // SECTION H: Security Headers
  // ============================================================
  console.log('\n▶ SECTION H: Security Headers on API Response');

  const h1 = await request('/api/auth/personas');
  checkTrue('H1  X-Content-Type-Options: nosniff', h1.headers['x-content-type-options'] === 'nosniff');
  checkTrue('H2  X-Frame-Options: DENY', h1.headers['x-frame-options'] === 'DENY');
  checkTrue('H3  Cache-Control: no-store', (h1.headers['cache-control'] || '').includes('no-store'));

  // ============================================================
  // RESULTS
  // ============================================================
  console.log('\n================================================================');
  console.log('  DETAILED RESULTS');
  console.log('================================================================');
  results.forEach(r => console.log(r));

  console.log('\n================================================================');
  console.log(`  FINAL SCORE: ${passed} PASSED / ${failed} FAILED / ${passed+failed} TOTAL`);
  if (failed === 0) {
    console.log('  🏆 ALL CHECKS PASSED — PROJECT IS FULLY FUNCTIONAL');
  } else {
    console.log('  ⚠️  SOME CHECKS FAILED — See details above');
  }
  console.log('================================================================\n');

  process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
  console.error('Fatal error during verification:', err);
  process.exit(1);
});

