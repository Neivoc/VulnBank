// ============================================================
// ADMIN.JS — Admin panel with JWT role escalation
// ============================================================

(function init() {
    if (!checkAuth()) return;
    setupNav();
    checkAdmin();
})();

async function checkAdmin() {
    try {
        const res = await fetch(`${API_BASE}/api/users`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });

        if (res.status === 403) {
            document.getElementById('accessDenied').style.display = 'block';
            document.getElementById('adminContent').style.display = 'none';
            return;
        }

        const users = await res.json();

        document.getElementById('adminContent').style.display = 'block';
        document.getElementById('accessDenied').style.display = 'none';
        document.getElementById('totalUsers').textContent = users.length;

        const tbody = document.getElementById('usersTable');
        tbody.innerHTML = users.map(u => {
            const date = new Date(u.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
            return `
        <tr>
          <td>${u.id}</td>
          <td><strong>${u.username}</strong></td>
          <td>${u.email}</td>
          <td>${u.full_name}</td>
          <td><span class="role-badge ${u.role}">${u.role}</span></td>
          <td class="text-muted">${date}</td>
        </tr>`;
        }).join('');

        loadAdminTickets();
        loadDebugInfo();
    } catch (err) {
        console.error('Admin check error:', err);
        document.getElementById('accessDenied').style.display = 'block';
    }
}

async function loadAdminTickets() {
    try {
        const res = await fetch(`${API_BASE}/api/tickets`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        const tickets = await res.json();
        document.getElementById('totalTickets').textContent = tickets.filter(t => t.status === 'open').length;
        const container = document.getElementById('allTickets');

        if (tickets.length === 0) {
            container.innerHTML = '<p class="text-muted text-center" style="padding:1rem;">No tickets</p>';
            return;
        }

        // VULNERABILITY: XSS — ticket content rendered with unsafeRender
        let html = tickets.map(t => `
      <div style="padding:1rem; border-bottom:1px solid var(--border-color);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>${t.subject}</strong>
            ${t.username ? `<span class="text-muted"> — by ${t.username}</span>` : ''}
          </div>
          <span class="badge ${t.status === 'open' ? 'badge-warning' : 'badge-success'}">${t.status}</span>
        </div>
        <div style="margin-top:0.5rem; font-size:0.9rem; color:var(--text-secondary);">${t.message}</div>
        <div class="text-muted" style="font-size:0.75rem; margin-top:0.25rem;">${new Date(t.created_at).toLocaleString()}</div>
      </div>`).join('');

        unsafeRender(container, html);
    } catch (err) { console.error('Load tickets error:', err); }
}

async function loadDebugInfo() {
    try {
        const res = await fetch(`${API_BASE}/api/debug`);
        const data = await res.json();
        document.getElementById('totalBalance').textContent = '—';
        document.getElementById('debugInfo').innerHTML =
            `<pre style="color: var(--text-secondary); font-size: 0.8rem; white-space: pre-wrap; overflow-x: auto;">${JSON.stringify(data, null, 2)}</pre>`;
    } catch (err) { console.error('Debug info error:', err); }
}
