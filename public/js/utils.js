// ============================================================
// UTILS.JS — Shared utilities for VulnBank
// Contains the intentionally unsafe HTML renderer for XSS demos
// ============================================================

const API_BASE = '';

function getToken() { return localStorage.getItem('token'); }
function getUser() { return JSON.parse(localStorage.getItem('user') || '{}'); }

function logout() {
    localStorage.clear();
    window.location.href = '/index.html';
}

function checkAuth() {
    if (!getToken()) {
        window.location.href = '/index.html';
        return false;
    }
    return true;
}

function setupNav() {
    const user = getUser();
    const navUsername = document.getElementById('navUsername');
    const navRole = document.getElementById('navRole');
    if (navUsername) navUsername.textContent = user.username || 'User';
    if (navRole) {
        navRole.textContent = user.role || 'user';
        navRole.className = `role-badge ${user.role || 'user'}`;
    }
    // VULNERABILITY: Role check based on localStorage (client-side, tamperable)
    const adminLink = document.getElementById('adminLink');
    if (adminLink && (user.role === 'admin' || localStorage.getItem('isAdmin') === 'true')) {
        adminLink.style.display = '';
    }
}

function showAlert(containerId, message, type = 'error') {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.className = `alert alert-${type}`;
    el.textContent = message;
    el.style.display = 'block';
    setTimeout(() => { el.style.display = 'none'; }, 6000);
}

// ============================================================
// VULNERABILITY: Unsafe HTML renderer — executes <script> tags
// Browsers block script execution via innerHTML by design.
// This function bypasses that for educational XSS demonstration.
// ============================================================
function unsafeRender(element, htmlString) {
    // Set the HTML content
    element.innerHTML = htmlString;

    // Find all script tags and execute them (innerHTML normally blocks this)
    const scripts = element.querySelectorAll('script');
    scripts.forEach(oldScript => {
        const newScript = document.createElement('script');
        // Copy attributes
        Array.from(oldScript.attributes).forEach(attr => {
            newScript.setAttribute(attr.name, attr.value);
        });
        // Copy content
        newScript.textContent = oldScript.textContent;
        // Replace old non-executing script with a new one that WILL execute
        oldScript.parentNode.replaceChild(newScript, oldScript);
    });
}
