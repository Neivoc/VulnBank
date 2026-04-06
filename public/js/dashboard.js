// ============================================================
// DASHBOARD.JS — Account overview and transaction display
// VULNERABILITY: Uses JWT userId (tamperable), stores data in localStorage, XSS
// ============================================================

(function init() {
    if (!checkAuth()) return;
    setupNav();
    loadDashboard();

    document.getElementById('welcomeName').textContent =
        getUser().full_name || getUser().username || 'User';
})();

async function loadDashboard() {
    try {
        const res = await fetch(`${API_BASE}/api/my-accounts`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        if (res.status === 401 || res.status === 403) { logout(); return; }

        const accounts = await res.json();
        // VULNERABILITY: Stores balance in localStorage
        localStorage.setItem('accounts', JSON.stringify(accounts));

        const grid = document.getElementById('accountsGrid');
        let totalBalance = 0;
        const colors = ['accent-blue', 'accent-green', 'accent-purple', 'accent-gold'];
        const icons = ['💳', '🏦', '💎', '🪙'];

        grid.innerHTML = accounts.map((acc, i) => {
            totalBalance += acc.balance;
            return `
        <div class="stat-card ${colors[i % colors.length]}">
          <div class="stat-icon">${icons[i % icons.length]}</div>
          <div class="stat-label">${acc.account_type.toUpperCase()} — ${acc.account_number}</div>
          <div class="stat-value">$${acc.balance.toLocaleString('en-US', { minimumFractionDigits: 2 })}</div>
        </div>`;
        }).join('');

        grid.innerHTML += `
      <div class="stat-card accent-gold">
        <div class="stat-icon">📊</div>
        <div class="stat-label">TOTAL BALANCE</div>
        <div class="stat-value">$${totalBalance.toLocaleString('en-US', { minimumFractionDigits: 2 })}</div>
      </div>`;

        localStorage.setItem('totalBalance', totalBalance);

        if (accounts.length > 0) loadTransactions(accounts[0].id);
    } catch (err) { console.error('Dashboard error:', err); }
}

async function loadTransactions(accountId) {
    try {
        const res = await fetch(`${API_BASE}/api/transactions/${accountId}`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        const transactions = await res.json();
        const tbody = document.getElementById('transactionsTable');

        if (transactions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted" style="padding:2rem;">No transactions yet</td></tr>';
            return;
        }

        // VULNERABILITY: Stored XSS — description rendered with unsafeRender
        let html = transactions.map(t => {
            const date = new Date(t.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
            return `
        <tr>
          <td>${date}</td>
          <td>${t.description}</td>
          <td>${t.from_account_number || '-'}</td>
          <td>${t.to_account_number || '-'}</td>
          <td class="amount-negative">$${t.amount.toFixed(2)}</td>
        </tr>`;
        }).join('');

        unsafeRender(tbody, html);
    } catch (err) { console.error('Transactions error:', err); }
}


