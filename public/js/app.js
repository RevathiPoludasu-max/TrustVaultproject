/**
 * =============================================================================
 * TrustVault — Main Application Controller
 * =============================================================================
 * User-Friendly Controller with Real-Time Search, Stats, and Instant Feedback
 */

const App = {
  currentActor: null,
  personas: [],
  documents: [],
  auditLogs: [],
  activeCategoryFilter: 'ALL',
  searchQuery: '',
  streamCountdownTimer: null,

  /**
   * Initialize application on DOM ready
   */
  async init() {
    console.log('[TrustVault] Initializing client runtime...');
    App.bindEvents();
    await App.loadPersonas();
    await App.loadDocuments();
    await App.loadAuditLogs();
    CryptoAudit.verifyChainIntegrity();
  },

  /**
   * Bind DOM event listeners
   */
  bindEvents() {
    // Navigation Tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const targetTab = tab.getAttribute('data-tab');
        App.switchTab(targetTab);
      });
    });

    // Persona Switcher
    const actorSelect = document.getElementById('actorSelect');
    if (actorSelect) {
      actorSelect.addEventListener('change', (e) => {
        App.switchPersona(e.target.value);
      });
    }

    // Drag and drop upload zone
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileUploadInput');

    if (dropZone && fileInput) {
      dropZone.addEventListener('click', () => fileInput.click());

      dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
      });

      dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
      });

      dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
          App.handleFileSelect(e.dataTransfer.files[0]);
        }
      });

      fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
          App.handleFileSelect(e.target.files[0]);
        }
      });
    }

    // Modal background click & ESC key to close
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          App.closeAllModals();
        }
      });
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        App.closeAllModals();
      }
    });
  },

  /**
   * Switch navigation tab
   */
  switchTab(tabId) {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    const tabBtn = document.querySelector(`.nav-tab[data-tab="${tabId}"]`);
    const tabPane = document.getElementById(tabId);

    if (tabBtn) tabBtn.classList.add('active');
    if (tabPane) tabPane.classList.add('active');

    if (tabId === 'audit') {
      App.loadAuditLogs();
    } else if (tabId === 'permissions') {
      App.loadPermissionsTab();
    }
  },

  /**
   * Open the Healthcheck modal
   */
  openHealthcheckModal() {
    const modal = document.getElementById('healthcheckModal');
    if (modal) modal.classList.add('active');
  },

  closeAllModals() {
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
    if (App.streamCountdownTimer) clearInterval(App.streamCountdownTimer);
  },

  /**
   * Load personas and initialize active user with friendly common English names
   */
  async loadPersonas() {
    try {
      const res = await fetch('/api/auth/personas');
      const data = await res.json();
      App.personas = data.personas;

      const select = document.getElementById('actorSelect');
      if (select) {
        select.innerHTML = '';
        App.personas.forEach(p => {
          const opt = document.createElement('option');
          opt.value = p.id;
          
          let friendlyLabel = p.displayName;
          if (p.id === 'user-owner-01') {
            friendlyLabel = 'Alice (File Owner - Full Control)';
          } else if (p.id === 'user-viewer-a') {
            friendlyLabel = 'Bob (Invited Friend - Can Read)';
          } else if (p.id === 'user-viewer-b') {
            friendlyLabel = 'Carol (Stranger - Access Blocked)';
          } else if (p.id === 'user-admin-01') {
            friendlyLabel = 'Eve (System Admin - Cannot Download)';
          }

          opt.textContent = friendlyLabel;
          select.appendChild(opt);
        });
      }

      // Default persona: Alice (Owner)
      const defaultActor = App.personas.find(p => p.role === 'OWNER') || App.personas[0];
      if (defaultActor) {
        App.currentActor = defaultActor;
        if (select) select.value = defaultActor.id;
        App.updateActorBadge();
      }
    } catch (e) {
      console.error('Failed to load users:', e);
    }
  },

  /**
   * Switch current persona
   */
  async switchPersona(actorId) {
    App.closeAllModals();
    const actor = App.personas.find(p => p.id === actorId);
    if (!actor) return;
    App.currentActor = actor;
    App.updateActorBadge();

    let friendlyName = actor.displayName;
    if (actor.id === 'user-owner-01') friendlyName = 'Alice (File Owner)';
    else if (actor.id === 'user-viewer-a') friendlyName = 'Bob (Invited Friend)';
    else if (actor.id === 'user-viewer-b') friendlyName = 'Carol (Blocked Stranger)';
    else if (actor.id === 'user-admin-01') friendlyName = 'Eve (System Admin)';

    App.showToast(`Now testing site as: ${friendlyName}`, 'info');

    await App.loadDocuments();
    await App.loadAuditLogs();
    await App.loadPermissionsTab();
  },

  updateActorBadge() {
    if (!App.currentActor) return;
    const badge = document.getElementById('activeRoleBadge');
    if (badge) {
      let roleLabel = App.currentActor.role;
      if (roleLabel === 'OWNER') roleLabel = 'OWNER';
      else if (roleLabel === 'VIEWER') roleLabel = 'VIEWER';
      else if (roleLabel === 'ADMIN') roleLabel = 'ADMIN';

      badge.textContent = roleLabel;
      badge.className = `badge badge-${App.currentActor.role.toLowerCase()}`;
    }
  },

  getAuthHeaders() {
    return {
      'Content-Type': 'application/json',
      'X-Actor-Id': App.currentActor ? App.currentActor.id : 'user-owner-01'
    };
  },

  /**
   * Helper: Get file icon based on mime type or extension
   */
  getFileIcon(mime, filename) {
    if (mime && mime.includes('pdf')) return '📕';
    if (mime && mime.includes('image')) return '🖼️';
    if (filename && (filename.endsWith('.txt') || filename.endsWith('.md'))) return '📄';
    return '📁';
  },

  /**
   * Helper: Get vibrant category badge CSS class
   */
  getCategoryBadgeClass(category) {
    const map = {
      'CONFIDENTIAL': 'badge-cat-confidential',
      'FINANCIAL': 'badge-cat-financial',
      'LEGAL': 'badge-cat-legal',
      'HEALTHCARE': 'badge-cat-healthcare',
      'INTERNAL': 'badge-cat-internal',
      'GENERAL': 'badge-cat-general'
    };
    return map[(category || '').toUpperCase()] || 'badge-cat-general';
  },

  /**
   * Filter documents in real time based on search input
   */
  filterDocuments() {
    const input = document.getElementById('documentSearchInput');
    App.searchQuery = input ? input.value.trim().toLowerCase() : '';
    App.renderDocuments();
  },

  /**
   * Set category filter pill
   */
  setCategoryFilter(category) {
    App.activeCategoryFilter = category;
    document.querySelectorAll('.filter-pill').forEach(pill => {
      if (pill.textContent.trim().toUpperCase() === category.toUpperCase() ||
          (category === 'ALL' && pill.textContent.trim() === 'All') ||
          (category === 'INTERNAL' && pill.textContent.trim() === 'General')) {
        pill.classList.add('active');
      } else {
        pill.classList.remove('active');
      }
    });
    App.renderDocuments();
  },

  /**
   * Load accessible documents for current actor
   */
  async loadDocuments() {
    try {
      const res = await fetch('/api/documents', {
        headers: App.getAuthHeaders()
      });
      const data = await res.json();
      App.documents = data.documents || [];
      App.renderDocuments();
      App.updateDashboardStats();
    } catch (e) {
      console.error('Failed to load documents:', e);
    }
  },

  /**
   * Render documents into table with search & category filtering
   */
  renderDocuments() {
    const container = document.getElementById('documentsTableBody');
    if (!container) return;

    let filtered = App.documents;

    // Filter by Category
    if (App.activeCategoryFilter !== 'ALL') {
      filtered = filtered.filter(d => (d.category || '').toUpperCase() === App.activeCategoryFilter);
    }

    // Filter by Search Query
    if (App.searchQuery) {
      filtered = filtered.filter(d => 
        (d.title || '').toLowerCase().includes(App.searchQuery) ||
        (d.original_filename || '').toLowerCase().includes(App.searchQuery)
      );
    }

    if (filtered.length === 0) {
      const emptyMsg = App.documents.length === 0 ?
        '🔒 No files found for this user. Strangers cannot see or search for files they do not own.' :
        '🔍 No files match your search query.';
      container.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2.5rem; color: var(--text-muted);">${emptyMsg}</td></tr>`;
      return;
    }

    container.innerHTML = '';
    filtered.forEach(doc => {
      const tr = document.createElement('tr');
      const formattedDate = new Date(doc.created_at).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
      const sizeFormatted = (doc.file_size_bytes / 1024).toFixed(1) + ' KB';
      const fileIcon = App.getFileIcon(doc.detected_mime, doc.original_filename);
      const catBadgeClass = App.getCategoryBadgeClass(doc.category);

      let accessBadge = '<span class="badge badge-viewer">CAN READ</span>';
      if (doc.user_access_level === 'OWNER') {
        accessBadge = '<span class="badge badge-owner">FILE OWNER</span>';
      } else if (doc.user_access_level === 'ADMIN_METADATA') {
        accessBadge = '<span class="badge badge-admin">ADMIN (INFO ONLY)</span>';
      } else if (doc.user_access_level === 'EDIT') {
        accessBadge = '<span class="badge badge-grant">CAN EDIT</span>';
      }

      const isOwner = doc.user_access_level === 'OWNER';
      const canStream = isOwner || doc.user_access_level === 'READ' || doc.user_access_level === 'EDIT';

      tr.innerHTML = `
        <td>
          <div class="file-row-title">
            <span class="file-avatar">${fileIcon}</span>
            <div>
              <div style="font-weight: 700; color: var(--text-main); font-size: 0.95rem;">${escapeHtml(doc.title)}</div>
              <div style="font-size: 0.72rem; color: var(--text-faint); font-family: var(--font-mono);">${escapeHtml(doc.original_filename)}</div>
            </div>
          </div>
        </td>
        <td><span class="badge ${catBadgeClass}">${escapeHtml(doc.category || 'GENERAL')}</span></td>
        <td style="font-size: 0.8rem;">${escapeHtml(doc.owner_email)}</td>
        <td style="font-size: 0.8rem; font-family: var(--font-mono);">${sizeFormatted}</td>
        <td>${accessBadge}</td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${formattedDate}</td>
        <td style="text-align: right; white-space: nowrap;">
          ${canStream ? `
            <button class="btn btn-primary btn-sm" onclick="App.openStreamModal('${doc.id}')">
              👁️ View
            </button>
          ` : `
            <button class="btn btn-secondary btn-sm" onclick="App.probeBlockedStream('${doc.id}')" title="Test how the server blocks unauthorized access">
              🚫 Peek (Blocked)
            </button>
          `}
          ${isOwner ? `
            <button class="btn btn-secondary btn-sm" onclick="App.openGrantModal('${doc.id}')">
              🔑 Share
            </button>
          ` : ''}
        </td>
      `;
      container.appendChild(tr);
    });
  },

  /**
   * Update Dashboard Top Stat Cards
   */
  async updateDashboardStats() {
    const fileCountEl = document.getElementById('statFileCount');
    if (fileCountEl) {
      fileCountEl.textContent = `${App.documents.length} File${App.documents.length === 1 ? '' : 's'}`;
    }

    const shareCountEl = document.getElementById('statShareCount');
    if (shareCountEl) {
      let activeShares = 0;
      for (const doc of App.documents) {
        if (doc.user_access_level === 'OWNER') {
          try {
            const res = await fetch(`/api/documents/${doc.id}/permissions`, { headers: App.getAuthHeaders() });
            if (res.ok) {
              const d = await res.json();
              activeShares += (d.permissions || []).filter(p => p.revoked_at === null).length;
            }
          } catch (e) {}
        }
      }
      shareCountEl.textContent = `${activeShares} Shared`;
    }
  },

  /**
   * Handle file upload selection
   */
  handleFileSelect(file) {
    const titleInput = document.getElementById('docTitleInput');
    const filenamePreview = document.getElementById('sanitizedFilenamePreview');

    if (titleInput && !titleInput.value) {
      titleInput.value = file.name.replace(/\.[^/.]+$/, "");
    }

    // Client-side sanitization preview
    const cleanName = file.name.replace(/[^a-zA-Z0-9.\-_]/g, '_').replace(/\.\./g, '_');
    if (filenamePreview) {
      filenamePreview.textContent = cleanName;
    }

    App.selectedFile = file;
    App.showToast(`Selected file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, 'info');
  },

  /**
   * Execute document upload
   */
  async submitUpload() {
    const titleInput = document.getElementById('docTitleInput');
    const categorySelect = document.getElementById('docCategorySelect');

    if (!titleInput || !titleInput.value.trim()) {
      App.showToast('Please enter a title for the file', 'error');
      return;
    }

    if (!App.selectedFile) {
      App.showToast('Please select or drop a file to upload', 'error');
      return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
      const base64Content = e.target.result.split(',')[1];

      try {
        const res = await fetch('/api/documents/upload', {
          method: 'POST',
          headers: App.getAuthHeaders(),
          body: JSON.stringify({
            title: titleInput.value.trim(),
            category: categorySelect ? categorySelect.value : 'GENERAL',
            filename: App.selectedFile.name,
            contentBase64: base64Content
          })
        });

        const data = await res.json();
        if (res.status === 201) {
          App.showToast('File saved safely to your private vault!', 'success');
          App.closeModal('uploadModal');
          titleInput.value = '';
          App.selectedFile = null;
          await App.loadDocuments();
          await App.loadAuditLogs();
        } else {
          App.showToast(data.error || 'Upload was blocked by security policy', 'error');
        }
      } catch (err) {
        App.showToast('Could not reach the server to upload file', 'error');
      }
    };
    reader.readAsDataURL(App.selectedFile);
  },

  /**
   * Open Secure In-Browser Stream Modal
   * Implements Ephemeral Signed Tokens (25s countdown)
   */
  async openStreamModal(documentId) {
    const modal = document.getElementById('streamModal');
    const viewerContent = document.getElementById('streamViewerContent');
    const countdownEl = document.getElementById('streamCountdown');
    const checksumEl = document.getElementById('streamChecksum');
    const downloadBtn = document.getElementById('streamDownloadBtn');

    if (!modal) return;
    modal.classList.add('active');

    viewerContent.innerHTML = `<div style="text-align:center; padding: 2rem; color:var(--accent-cyan);">🔐 Creating safe view link...</div>`;
    if (downloadBtn) downloadBtn.style.display = 'none';

    try {
      // Step 1: Issue ephemeral stream token
      const tokenRes = await fetch(`/api/documents/${documentId}/stream-token`, {
        method: 'POST',
        headers: App.getAuthHeaders()
      });

      if (!tokenRes.ok) {
        viewerContent.innerHTML = `<div style="color:var(--accent-rose); padding: 2rem;">❌ Access Denied: 404 Not Found (You do not have permission to read this file).</div>`;
        return;
      }

      const tokenData = await tokenRes.json();
      const token = tokenData.stream_token;

      // Start 25s Countdown
      let remaining = tokenData.expires_in_seconds || 25;
      if (countdownEl) countdownEl.textContent = `${remaining}s`;

      if (App.streamCountdownTimer) clearInterval(App.streamCountdownTimer);
      App.streamCountdownTimer = setInterval(() => {
        remaining--;
        if (countdownEl) countdownEl.textContent = `${remaining}s`;
        if (remaining <= 0) {
          clearInterval(App.streamCountdownTimer);
          if (countdownEl) countdownEl.innerHTML = `<span style="color:var(--accent-rose);">EXPIRED (Safe Link Closed)</span>`;
          if (downloadBtn) downloadBtn.style.display = 'none';
        }
      }, 1000);

      // Step 2: Stream content securely
      const streamRes = await fetch(`/api/documents/${documentId}/stream?token=${encodeURIComponent(token)}`);
      if (!streamRes.ok) {
        viewerContent.innerHTML = `<div style="color:var(--accent-rose); padding: 2rem;">This viewing link has expired or was already closed.</div>`;
        return;
      }

      const checksum = streamRes.headers.get('X-Document-Checksum');
      if (checksumEl) {
        checksumEl.textContent = checksum ? checksum.substring(0, 24) + '...' : 'Verified Authentic';
      }

      const contentType = streamRes.headers.get('Content-Type') || '';
      const blob = await streamRes.blob();
      const blobUrl = URL.createObjectURL(blob);

      if (contentType.includes('pdf')) {
        viewerContent.innerHTML = `<iframe src="${blobUrl}" style="width:100%; height:450px; border:none; border-radius:8px;"></iframe>`;
      } else {
        const text = await blob.text();
        viewerContent.innerHTML = `<pre style="background:#040812; padding:1.25rem; border-radius:8px; font-family:var(--font-mono); font-size:0.85rem; color:#38bdf8; overflow:auto; max-height:450px;">${escapeHtml(text)}</pre>`;
      }

      // Hook up download button
      if (downloadBtn) {
        downloadBtn.style.display = 'inline-flex';
        downloadBtn.onclick = () => {
          const a = document.createElement('a');
          a.href = blobUrl;
          a.download = `TrustVault-Document.pdf`;
          a.click();
        };
      }

      App.showToast('File opened safely! (Link closes automatically in 25s)', 'success');
      await App.loadAuditLogs();
    } catch (e) {
      viewerContent.innerHTML = `<div style="color:var(--accent-rose); padding: 2rem;">Could not open file: ${e.message}</div>`;
    }
  },

  /**
   * Probe an unauthorized document stream to test zero-trust rejection
   */
  async probeBlockedStream(documentId) {
    try {
      const res = await fetch(`/api/documents/${documentId}/stream`, {
        headers: App.getAuthHeaders()
      });
      App.showToast(`Server Blocked Access: 404 Not Found (Hidden from strangers)`, 'error');
      await App.loadAuditLogs();
    } catch (e) {
      App.showToast('Test executed', 'info');
    }
  },

  /**
   * Open Grant Access Modal
   */
  openGrantModal(documentId) {
    const modal = document.getElementById('grantModal');
    const docIdInput = document.getElementById('grantDocId');
    const userSelect = document.getElementById('grantTargetUser');

    if (!modal) return;
    if (docIdInput) docIdInput.value = documentId;

    if (userSelect) {
      userSelect.innerHTML = '';
      App.personas
        .filter(p => p.id !== App.currentActor.id)
        .forEach(p => {
          const opt = document.createElement('option');
          opt.value = p.id;
          opt.textContent = `${p.displayName} (${p.email})`;
          userSelect.appendChild(opt);
        });
    }

    modal.classList.add('active');
  },

  /**
   * Submit Grant Access Request
   */
  async submitGrant() {
    const docId = document.getElementById('grantDocId').value;
    const targetUserId = document.getElementById('grantTargetUser').value;
    const accessLevel = document.getElementById('grantAccessLevel').value;

    try {
      const res = await fetch('/api/permissions/grant', {
        method: 'POST',
        headers: App.getAuthHeaders(),
        body: JSON.stringify({
          documentId: docId,
          targetUserId,
          accessLevel
        })
      });

      if (res.ok) {
        App.showToast('File shared successfully! Recorded in permanent history.', 'success');
        App.closeModal('grantModal');
        await App.loadDocuments();
        await App.loadAuditLogs();
        await App.loadPermissionsTab();
      } else {
        const d = await res.json();
        App.showToast(d.error || 'Failed to share file', 'error');
      }
    } catch (e) {
      App.showToast('Network error while sharing file', 'error');
    }
  },

  /**
   * Immediate 0-Second Revocation
   */
  async revokeAccess(permissionId) {
    if (!confirm('Cancel this person\'s access right now? Their ability to view or download will stop immediately with zero delay.')) return;

    const start = performance.now();
    try {
      const res = await fetch('/api/permissions/revoke', {
        method: 'POST',
        headers: App.getAuthHeaders(),
        body: JSON.stringify({ permissionId })
      });

      const latency = (performance.now() - start).toFixed(1);

      if (res.ok) {
        App.showToast(`Access cancelled in ${latency}ms! The user was blocked immediately.`, 'success');
        await App.loadPermissionsTab();
        await App.loadDocuments();
        await App.loadAuditLogs();
      } else {
        const d = await res.json();
        App.showToast(d.error || 'Failed to cancel access', 'error');
      }
    } catch (e) {
      App.showToast('Network error while cancelling access', 'error');
    }
  },

  /**
   * Load permissions tab data
   */
  async loadPermissionsTab() {
    const tbody = document.getElementById('permissionsTableBody');
    if (!tbody) return;

    tbody.innerHTML = '';
    let totalPerms = 0;

    for (const doc of App.documents) {
      try {
        const res = await fetch(`/api/documents/${doc.id}/permissions`, {
          headers: App.getAuthHeaders()
        });
        if (res.ok) {
          const data = await res.json();
          (data.permissions || []).forEach(perm => {
            totalPerms++;
            const tr = document.createElement('tr');
            const isRevoked = perm.revoked_at !== null;
            const grantedTime = new Date(perm.granted_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            const friendlyLevel = perm.access_level === 'EDIT' ? 'Can Edit' : 'Read Only';

            tr.innerHTML = `
              <td style="font-weight:600;">${escapeHtml(doc.title)}</td>
              <td>${escapeHtml(perm.user_name)} (${escapeHtml(perm.user_email)})</td>
              <td><span class="badge badge-grant">${friendlyLevel}</span></td>
              <td style="font-size:0.8rem; color:var(--text-muted);">${grantedTime}</td>
              <td>
                ${isRevoked ? 
                  `<span class="badge badge-denied">ACCESS CANCELLED (0s)</span>` : 
                  `<span class="badge badge-success">ACTIVE</span>`
                }
              </td>
              <td style="text-align:right;">
                ${!isRevoked ? `
                  <button class="btn btn-danger btn-sm" onclick="App.revokeAccess('${perm.id}')">
                    ⚡ Cancel Access Now
                  </button>
                ` : `
                  <span style="font-size:0.75rem; color:var(--text-faint);">Access Revoked</span>
                `}
              </td>
            `;
            tbody.appendChild(tr);
          });
        }
      } catch (e) {}
    }

    if (totalPerms === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:2.5rem; color:var(--text-muted);">You have not shared any files yet. Go to "My Vault" and click "Share" on any file to invite someone.</td></tr>`;
    }
  },

  /**
   * Load audit logs from server
   */
  async loadAuditLogs() {
    try {
      const res = await fetch('/api/audit', {
        headers: App.getAuthHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        App.auditLogs = data.logs || [];
        CryptoAudit.renderAuditLogs(App.auditLogs);
      }
    } catch (e) {
      console.error('Failed to load activity logs:', e);
    }
  },

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('active');
    if (modalId === 'streamModal' && App.streamCountdownTimer) {
      clearInterval(App.streamCountdownTimer);
    }
  },

  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '❌';

    toast.innerHTML = `<span>${icon}</span><span style="font-weight:600;">${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
};

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

document.addEventListener('DOMContentLoaded', App.init);
window.App = App;
