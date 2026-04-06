// ============================================================
// SEARCH.JS — Transaction search with SQL Injection
// ============================================================

(function init() {
    if (!checkAuth()) return;
    setupNav();

    // Check for reflected XSS via URL params
    const urlParams = new URLSearchParams(window.location.search);
    const q = urlParams.get('q');
    if (q) {
        document.getElementById('searchInput').value = q;
        searchTransactions();
    }
})();

document.getElementById('searchInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') searchTransactions();
});

async function searchTransactions() {
    const query = document.getElementById('searchInput').value;
    const errorDetails = document.getElementById('errorDetails');
    const errorPre = document.getElementById('errorPre');
    errorDetails.style.display = 'none';

    if (!query.trim()) { showAlert('alert', 'Please enter a search term', 'warning'); return; }

    try {
        const res = await fetch(`${API_BASE}/api/transactions/search?q=${encodeURIComponent(query)}`, {
            headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        const data = await res.json();

        if (!res.ok) {
            showAlert('alert', `Error: ${data.error}`);
            errorDetails.style.display = 'block';
            errorPre.textContent = JSON.stringify(data, null, 2);
            return;
        }

        const tbody = document.getElementById('searchResults');

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted" style="padding:2rem;">No results found</td></tr>';
            return;
        }

        showAlert('alert', `Found ${data.length} result(s)`, 'success');

        // VULNERABILITY: XSS — description rendered via unsafeRender
        let html = data.map(t => {
            const date = t.created_at ? new Date(t.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '-';
            return `
        <tr>
          <td>${t.id}</td>
          <td>${t.from_account_number || '-'}</td>
          <td>${t.to_account_number || '-'}</td>
          <td class="amount-positive">$${(t.amount || 0).toFixed(2)}</td>
          <td>${t.description || '-'}</td>
          <td class="text-muted">${date}</td>
        </tr>`;
        }).join('');

        unsafeRender(tbody, html);
    } catch (err) { showAlert('alert', 'Search error: ' + err.message); }
}
