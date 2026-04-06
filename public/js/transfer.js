// ============================================================
// TRANSFER.JS — Money transfers with Stored XSS in description
// ============================================================

(function init() {
    if (!checkAuth()) return;
    setupNav();
    loadAccounts();
})();

async function loadAccounts() {
    try {
        const res = await fetch(`${API_BASE}/api/my-accounts`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        if (res.status === 401 || res.status === 403) { logout(); return; }

        const accounts = await res.json();
        const select = document.getElementById('fromAccount');
        select.innerHTML = accounts.map(a =>
            `<option value="${a.id}">${a.account_number} (${a.account_type}) — $${a.balance.toFixed(2)}</option>`
        ).join('');

        if (accounts.length > 0) loadTransferHistory(accounts[0].id);
    } catch (err) { console.error('Load accounts error:', err); }
}

async function loadTransferHistory(accountId) {
    try {
        const res = await fetch(`${API_BASE}/api/transactions/${accountId}`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        const transactions = await res.json();
        const container = document.getElementById('transferHistory');

        if (transactions.length === 0) {
            container.innerHTML = '<p class="text-muted text-center" style="padding:2rem;">No transfers yet</p>';
            return;
        }

        // VULNERABILITY: Stored XSS — description rendered via unsafeRender
        let html = transactions.map(t => {
            const date = new Date(t.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            return `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:0.75rem 0; border-bottom:1px solid var(--border-color);">
          <div>
            <div style="font-weight:600; font-size:0.9rem;">${t.description}</div>
            <div class="text-muted" style="font-size:0.8rem;">${date} · ${t.from_account_number} → ${t.to_account_number}</div>
          </div>
          <div style="font-weight:700; font-size:1rem;" class="amount-negative">-$${t.amount.toFixed(2)}</div>
        </div>`;
        }).join('');

        unsafeRender(container, html);
    } catch (err) { console.error('Transfer history error:', err); }
}

document.getElementById('transferForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const fromAccountId = document.getElementById('fromAccount').value;
    const toAccountNumber = document.getElementById('toAccount').value;
    const amount = parseFloat(document.getElementById('amount').value);
    const description = document.getElementById('description').value;

    if (amount <= 0) { showAlert('alert', 'Amount must be greater than zero'); return; }

    try {
        const res = await fetch(`${API_BASE}/api/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getToken()}` },
            body: JSON.stringify({ fromAccountId, toAccountNumber, amount, description })
        });
        const data = await res.json();
        if (!res.ok) { showAlert('alert', data.error); return; }

        showAlert('alert', `Transfer of $${amount.toFixed(2)} sent successfully!`, 'success');
        document.getElementById('transferForm').reset();
        loadAccounts();
    } catch (err) { showAlert('alert', 'Transfer failed: ' + err.message); }
});
