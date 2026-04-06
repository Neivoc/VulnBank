// ============================================================
// AUTH.JS — Login & Registration Logic
// VULNERABILITY: Stores sensitive data in localStorage
// ============================================================

const API_BASE = '';

// Check if already logged in
(function checkAuth() {
    const token = localStorage.getItem('token');
    if (token && !window.location.pathname.includes('register')) {
        window.location.href = '/dashboard.html';
    }
})();

function showAlert(message, type = 'error') {
    const alert = document.getElementById('alert');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    alert.style.display = 'block';
    setTimeout(() => { alert.style.display = 'none'; }, 5000);
}

// LOGIN
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const btn = document.getElementById('loginBtn');

        btn.disabled = true;
        btn.textContent = 'Signing in...';

        try {
            const res = await fetch(`${API_BASE}/api/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();

            if (!res.ok) {
                // VULNERABILITY: Server returns specific error messages enabling user enumeration
                showAlert(data.error);
                btn.disabled = false;
                btn.textContent = 'Sign In';
                return;
            }

            // VULNERABILITY: Sensitive Data in Local Storage
            // Storing token, user object, role, and other sensitive info in localStorage
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            localStorage.setItem('userId', data.user.id);
            localStorage.setItem('username', data.user.username);
            localStorage.setItem('role', data.user.role);
            localStorage.setItem('email', data.user.email);
            localStorage.setItem('isAdmin', data.user.role === 'admin' ? 'true' : 'false');

            showAlert('Login successful! Redirecting...', 'success');
            setTimeout(() => { window.location.href = '/dashboard.html'; }, 800);
        } catch (err) {
            showAlert('Connection error: ' + err.message);
            btn.disabled = false;
            btn.textContent = 'Sign In';
        }
    });
}

// REGISTER
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const full_name = document.getElementById('full_name').value;
        const email = document.getElementById('email').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const btn = document.getElementById('registerBtn');

        btn.disabled = true;
        btn.textContent = 'Creating account...';

        try {
            const res = await fetch(`${API_BASE}/api/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, email, full_name })
            });

            const data = await res.json();

            if (!res.ok) {
                // VULNERABILITY: Reveals if username already exists — user enumeration
                showAlert(data.error);
                btn.disabled = false;
                btn.textContent = 'Create Account';
                return;
            }

            // VULNERABILITY: Shows internal userId and account number
            showAlert(`Account created! Your ID: ${data.userId}, Account: ${data.accountNumber}. Redirecting to login...`, 'success');
            setTimeout(() => { window.location.href = '/index.html'; }, 2000);
        } catch (err) {
            showAlert('Connection error: ' + err.message);
            btn.disabled = false;
            btn.textContent = 'Create Account';
        }
    });
}
