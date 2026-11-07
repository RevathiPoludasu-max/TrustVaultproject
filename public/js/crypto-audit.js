/**
 * =============================================================================
 * TrustVault — Activity History & Tamper-Proof Chain Explorer
 * =============================================================================
 */

const CryptoAudit = {
  /**
   * Translate technical action codes to clear, common English words
   */
  formatActionLabel(action) {
    const map = {
      'UPLOAD': '⬆️ Uploaded File',
      'READ_SUCCESS': '👁️ Viewed File',
      'READ_DENIED': '🚫 Blocked Stranger',
      'EDIT_SUCCESS': '✏️ Modified File',
      'EDIT_DENIED': '🚫 Blocked Edit',
      'GRANT': '🔑 Shared Access',
      'REVOKE': '⚡ Cancelled Access',
      'DELETE': '🗑️ Deleted File',
      'ADMIN_METADATA_READ': 'ℹ️ Admin Checked Info',
      'TOKEN_ISSUED': '🔗 Safe Link Created',
      'TOKEN_REVOKED': '⚡ Link Cancelled',
      'UPLOAD_REJECTED': '❌ Blocked Risky Upload'
    };
    return map[action] || action;
  },

  /**
   * Deterministic canonical JSON matching backend serialization
   */
  canonicalJson(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map(CryptoAudit.canonicalJson).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + CryptoAudit.canonicalJson(obj[k])).join(',') + '}';
  },

  /**
   * Render audit log records into the table
   */
  renderAuditLogs(logs, filter = 'ALL') {
    const tbody = document.getElementById('auditTableBody');
    if (!tbody) return;

    tbody.innerHTML = '';

    const filtered = logs.filter(log => {
      if (filter === 'DENIED') return log.action.includes('DENIED') || log.action.includes('REJECTED');
      if (filter === 'GRANTS') return log.action === 'GRANT' || log.action === 'REVOKE';
      if (filter === 'UPLOADS') return log.action === 'UPLOAD';
      return true;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 2rem; color: var(--text-muted);">No activity matches this filter.</td></tr>`;
      return;
    }

    filtered.forEach(log => {
      const tr = document.createElement('tr');

      let badgeClass = 'badge-success';
      if (log.action.includes('DENIED') || log.action.includes('REJECTED')) {
        badgeClass = 'badge-denied';
      } else if (log.action === 'GRANT' || log.action === 'REVOKE') {
        badgeClass = 'badge-grant';
      } else if (log.action === 'ADMIN_METADATA_READ') {
        badgeClass = 'badge-admin';
      }

      const formattedDate = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const prevHashShort = log.previous_hash === 'GENESIS' ? '🌟 GENESIS' : log.previous_hash.substring(0, 10) + '...';
      const currHashShort = log.current_hash ? log.current_hash.substring(0, 10) + '...' : 'UNKNOWN';

      let userRoleFriendly = log.actor_role || 'SYSTEM';
      if (userRoleFriendly === 'OWNER') userRoleFriendly = 'File Owner';
      else if (userRoleFriendly === 'VIEWER') userRoleFriendly = 'Viewer';
      else if (userRoleFriendly === 'ADMIN') userRoleFriendly = 'System Admin';

      tr.innerHTML = `
        <td style="font-family: var(--font-mono); font-weight: bold; color: var(--text-muted);">#${log.id}</td>
        <td style="white-space: nowrap; font-size: 0.8rem;">${formattedDate}</td>
        <td>
          <div style="font-weight: 600;">${log.actor_email || 'Automated System'}</div>
          <div style="font-size: 0.72rem; color: var(--text-faint);">${userRoleFriendly}</div>
        </td>
        <td>
          <span class="badge ${badgeClass}">${CryptoAudit.formatActionLabel(log.action)}</span>
          <div style="font-size:0.65rem; color:var(--text-faint); margin-top:2px; font-family:var(--font-mono);">${log.action}</div>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${log.resource_id ? log.resource_id.substring(0, 12) : '-'}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem;">${log.ip_address || '127.0.0.1'}</td>
        <td><span class="hash-snippet" title="Chain link to previous entry: ${log.previous_hash}">${prevHashShort}</span></td>
        <td><span class="hash-snippet" title="Cryptographic seal of this entry: ${log.current_hash}">${currHashShort}</span></td>
      `;
      tbody.appendChild(tr);
    });

    CryptoAudit.renderChainBlocks(logs.slice(0, 8));
  },

  /**
   * Map an audit action string to a chain-block CSS class
   */
  getActionClass(action) {
    if (!action) return 'action-system';
    const a = action.toUpperCase();
    if (a === 'UPLOAD') return 'action-upload';
    if (a.includes('READ_SUCCESS') || a.includes('ADMIN_METADATA')) return 'action-read';
    if (a.includes('DENIED') || a.includes('REJECTED')) return 'action-denied';
    if (a === 'GRANT' || a.includes('TOKEN_ISSUED')) return 'action-grant';
    if (a === 'REVOKE' || a.includes('TOKEN_REVOKED')) return 'action-revoke';
    if (a === 'DELETE') return 'action-delete';
    return 'action-system';
  },

  /**
   * Render visual block flow for the top entries
   */
  renderChainBlocks(blocks) {
    const container = document.getElementById('chainBlockContainer');
    if (!container) return;

    container.innerHTML = '';
    const reversed = [...blocks].reverse(); // from genesis/older to latest

    reversed.forEach(block => {
      const card = document.createElement('div');
      const isGenesis = block.previous_hash === 'GENESIS';
      const actionClass = isGenesis ? 'genesis' : CryptoAudit.getActionClass(block.action);
      card.className = `chain-block-card ${actionClass}`;
      
      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span style="font-size: 0.75rem; font-weight:700; color:${isGenesis ? 'var(--accent-amber)' : 'var(--accent-cyan)'}">
            ${isGenesis ? '🌟 START OF HISTORY' : '🔗 ENTRY #' + block.id}
          </span>
          <span class="badge badge-success" style="font-size:0.65rem;">SEALED</span>
        </div>
        <div style="font-size: 0.8rem; font-weight:600; color:var(--text-main); margin-top:2px;">
          ${CryptoAudit.formatActionLabel(block.action)}
        </div>
        <div style="font-size: 0.7rem; color: var(--text-muted);">By: ${block.actor_email || 'SYSTEM'}</div>
        <div style="font-size: 0.65rem; color: var(--text-faint); font-family: var(--font-mono); word-break: break-all;">
          Seal: ${block.current_hash ? block.current_hash.substring(0, 16) + '...' : 'N/A'}
        </div>
      `;
      container.appendChild(card);
    });
  },

  /**
   * Verify chain integrity against server
   */
  async verifyChainIntegrity() {
    const statusBox = document.getElementById('chainIntegrityStatus');
    if (statusBox) {
      statusBox.innerHTML = `<span style="color:var(--accent-cyan);">⏳ Checking digital seals on all activity entries...</span>`;
    }

    try {
      const res = await fetch('/api/audit/verify-chain');
      const data = await res.json();

      if (data.valid) {
        if (statusBox) {
          statusBox.innerHTML = `
            <span style="color:var(--accent-emerald); font-weight:700;">
              ✅ 100% Genuine: All ${data.total} history entries have been mathematically verified. No record has been deleted or secretly changed!
            </span>
          `;
        }
        App.showToast('All activity records verified: 100% genuine & untampered!', 'success');
      } else {
        if (statusBox) {
          statusBox.innerHTML = `
            <span style="color:var(--accent-rose); font-weight:700;">
              ❌ SECURITY ALERT: Altered Entry Detected at #${data.brokenAt}! ${data.reason}
            </span>
          `;
        }
        App.showToast('Security Alert: A log entry was tampered with!', 'error');
      }
    } catch (e) {
      if (statusBox) {
        statusBox.innerHTML = `<span style="color:var(--accent-rose);">Error connecting to history verification engine.</span>`;
      }
    }
  },

  /**
   * Simulate a tampering attack on the ledger to prove tamper-evidence
   */
  async simulateTamper() {
    if (!confirm('Test Tamper Detection: This will simulate someone secretly changing the latest log entry to see if TrustVault catches it.')) return;
    try {
      const headers = { 'Content-Type': 'application/json' };
      const token = localStorage.getItem('tv_token');
      if (token) headers['Authorization'] = 'Bearer ' + token;
      else if (typeof App !== 'undefined' && App.currentActor) headers['X-Actor-Id'] = App.currentActor.id;

      const res = await fetch('/api/audit/simulate-tamper', { method: 'POST', headers });
      const data = await res.json();
      if (!res.ok) {
        App.showToast(data.error || 'Failed to simulate tamper test', 'error');
        return;
      }
      App.showToast(data.message || 'Tamper simulated!', 'error');
      await CryptoAudit.verifyChainIntegrity();
      await App.loadAuditLogs();
    } catch (e) {
      App.showToast('Failed to simulate tamper test', 'error');
    }
  },

  /**
   * Restore and reseal all activity records
   */
  async restoreChain() {
    try {
      const headers = { 'Content-Type': 'application/json' };
      const token = localStorage.getItem('tv_token');
      if (token) headers['Authorization'] = 'Bearer ' + token;
      else if (typeof App !== 'undefined' && App.currentActor) headers['X-Actor-Id'] = App.currentActor.id;

      const res = await fetch('/api/audit/restore-chain', { method: 'POST', headers });
      const data = await res.json();
      if (!res.ok) {
        App.showToast(data.error || 'Failed to restore history', 'error');
        return;
      }
      App.showToast(data.message || 'All activity records restored and verified!', 'success');
      await CryptoAudit.verifyChainIntegrity();
      await App.loadAuditLogs();
    } catch (e) {
      App.showToast('Failed to restore history', 'error');
    }
  }
};

window.CryptoAudit = CryptoAudit;
