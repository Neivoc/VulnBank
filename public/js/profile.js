// ============================================================
// PROFILE.JS — Profile, XSS bio, insecure upload, support tickets
// ============================================================

(function init() {
    if (!checkAuth()) return;
    setupNav();
    loadProfile();
    loadTickets();
})();

async function loadProfile() {
    const user = getUser();
    const urlParams = new URLSearchParams(window.location.search);
    const pathParts = window.location.pathname.split('/');
    const pathId = (pathParts[1] === 'profile' && pathParts[2]) ? pathParts[2] : null;
    const targetId = pathId || urlParams.get('id') || user.id;
    try {
        const res = await fetch(`${API_BASE}/api/users/${targetId}`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        const data = await res.json();

        document.getElementById('profileName').textContent = data.full_name || data.username;
        document.getElementById('profileEmail').textContent = data.email;
        const roleEl = document.getElementById('profileRole');
        roleEl.textContent = data.role;
        roleEl.className = `role-badge ${data.role}`;

        document.getElementById('full_name').value = data.full_name || '';
        document.getElementById('email').value = data.email || '';
        document.getElementById('bio').value = data.bio || '';

        // VULNERABILITY: XSS — bio rendered with unsafeRender
        updateBioPreview(data.bio || '');

        const avatarEl = document.getElementById('avatarDisplay');
        if (data.avatar) {
            avatarEl.outerHTML = `<img id="avatarDisplay" class="avatar" src="${data.avatar}" alt="Avatar" onerror="this.outerHTML='<div id=\\'avatarDisplay\\' class=\\'avatar-placeholder\\'>${(data.username || '?')[0].toUpperCase()}</div>'">`;
        } else {
            avatarEl.textContent = (data.username || '?')[0].toUpperCase();
        }
    } catch (err) { console.error('Load profile error:', err); }
}

function updateBioPreview(bio) {
    const preview = document.getElementById('bioPreview');
    if (bio.trim()) {
        // VULNERABILITY: XSS — renders raw HTML + executes <script> tags
        unsafeRender(preview, bio);
    } else {
        preview.innerHTML = '<span class="text-muted">No bio set</span>';
    }
}

document.getElementById('bio').addEventListener('input', (e) => {
    updateBioPreview(e.target.value);
});

document.getElementById('profileForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = getUser();
    const full_name = document.getElementById('full_name').value;
    const email = document.getElementById('email').value;
    const bio = document.getElementById('bio').value;

    try {
        const res = await fetch(`${API_BASE}/api/users/${user.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getToken()}` },
            body: JSON.stringify({ full_name, email, bio })
        });
        const data = await res.json();
        if (!res.ok) { showAlert('alert', data.error); return; }

        const updatedUser = { ...user, full_name, email, bio };
        localStorage.setItem('user', JSON.stringify(updatedUser));
        showAlert('alert', 'Profile updated successfully!', 'success');
        loadProfile();
    } catch (err) { showAlert('alert', 'Failed to update profile: ' + err.message); }
});

// VULNERABILITY: Insecure File Upload — Validation is ONLY on frontend!
async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file) return;

    // FRONTEND VALIDATION ONLY — Backend remains vulnerable
    const validExtensions = ['png', 'jpg', 'jpeg'];
    const extension = file.name.split('.').pop().toLowerCase();

    if (!validExtensions.includes(extension)) {
        showAlert('alert', 'Invalid file type. Only PNG and JPG images are allowed.');
        fileInput.value = ''; // clear input
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${getToken()}` },
            body: formData
        });
        const data = await res.json();
        if (!res.ok) { showAlert('alert', data.error); return; }

        const resultDiv = document.getElementById('uploadResult');
        resultDiv.innerHTML = `
      <div class="alert alert-success" style="display:block;">
        ✅ File uploaded: <a href="${data.filePath}" target="_blank">${data.originalName}</a><br>
        <small class="text-muted">Server path: ${data.serverPath} | Size: ${data.size} bytes</small>
      </div>`;
        loadProfile();
    } catch (err) { showAlert('alert', 'Upload failed: ' + err.message); }
}

// Support tickets
document.getElementById('ticketForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const subject = document.getElementById('ticketSubject').value;
    const message = document.getElementById('ticketMessage').value;

    try {
        const res = await fetch(`${API_BASE}/api/tickets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getToken()}` },
            body: JSON.stringify({ subject, message })
        });
        const data = await res.json();
        if (!res.ok) { showAlert('alert', data.error); return; }

        showAlert('alert', 'Ticket submitted!', 'success');
        document.getElementById('ticketForm').reset();
        loadTickets();
    } catch (err) { showAlert('alert', 'Failed to submit ticket: ' + err.message); }
});

async function loadTickets() {
    try {
        const res = await fetch(`${API_BASE}/api/tickets`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        const tickets = await res.json();
        const container = document.getElementById('ticketsList');

        if (tickets.length === 0) {
            container.innerHTML = '<p class="text-muted text-center">No tickets yet</p>';
            return;
        }

        // VULNERABILITY: XSS — ticket subject & message rendered with unsafeRender
        let html = tickets.map(t => `
      <div style="padding:0.75rem; border-bottom:1px solid var(--border-color);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>${t.subject}</strong>
          <span class="badge ${t.status === 'open' ? 'badge-warning' : 'badge-success'}">${t.status}</span>
        </div>
        <div style="margin-top:0.5rem; font-size:0.9rem; color:var(--text-secondary);">${t.message}</div>
        <div class="text-muted" style="font-size:0.75rem; margin-top:0.25rem;">${new Date(t.created_at).toLocaleString()}</div>
      </div>`).join('');

        unsafeRender(container, html);
    } catch (err) { console.error('Load tickets error:', err); }
}
