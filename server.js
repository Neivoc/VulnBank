const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { db, initializeDatabase } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY: Weak JWT secret — easily brute-forceable
const JWT_SECRET = 'secret123';

// VULNERABILITY: Information Disclosure — server version in headers
app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'Express 4.18.2');
    res.setHeader('X-Server-Version', 'VulnBank/1.0.0');
    res.setHeader('X-Debug-Mode', 'enabled');
    next();
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// VULNERABILITY: Insecure File Upload — no file type or size restrictions
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    originalname: (req, file, cb) => cb(null, file.originalname) // keep original name
});
// No fileFilter, no limits
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, 'uploads/'),
        filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
    })
});

// Serve uploaded files statically — VULNERABILITY: allows execution of uploaded scripts
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ============================================================
// JWT MIDDLEWARE
// VULNERABILITY: Weak secret, trusts userId and role from token
// ============================================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        // VULNERABILITY: JWT signature is NOT VERIFIED at all (None Algorithm/Trust decode)
        const decoded = jwt.decode(token);
        if (!decoded) throw new Error("Invalid token format");

        req.user = decoded; // userId, username, role all come from token — tamperable
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
}

// ============================================================
// AUTH ROUTES
// ============================================================

// VULNERABILITY: User Enumeration — different messages for each case
app.post('/api/register', (req, res) => {
    try {
        const { username, password, email, full_name } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // VULNERABILITY: Tells attacker if username exists
        const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existingUser) {
            return res.status(409).json({ error: `Username '${username}' is already registered` });
        }

        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = db.prepare(
            'INSERT INTO users (username, password, email, full_name, role) VALUES (?, ?, ?, ?, ?)'
        ).run(username, hashedPassword, email || '', full_name || username, 'user');

        // Create a checking account for the new user
        const accountNumber = `VB-${String(result.lastInsertRowid).padStart(4, '0')}-0001`;
        db.prepare(
            'INSERT INTO accounts (user_id, account_number, balance, account_type) VALUES (?, ?, ?, ?)'
        ).run(result.lastInsertRowid, accountNumber, 1000.00, 'checking');

        // VULNERABILITY: Returns userId in response — info disclosure
        res.status(201).json({
            message: 'Registration successful',
            userId: result.lastInsertRowid,
            accountNumber: accountNumber
        });
    } catch (err) {
        // VULNERABILITY: Information Disclosure — full error stack
        res.status(500).json({ error: 'Registration failed', details: err.message, stack: err.stack });
    }
});

// VULNERABILITY: User Enumeration in login
app.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

        // VULNERABILITY: Different error for non-existent user vs wrong password
        if (!user) {
            return res.status(404).json({ error: `User '${username}' not found in our system` });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Incorrect password for this account' });
        }

        // VULNERABILITY: Token includes role and userId — both are trusted by the server
        const token = jwt.sign(
            {
                userId: user.id,
                username: user.username,
                role: user.role,
                email: user.email
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // VULNERABILITY: Returns too much user info including internal ID and role
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                full_name: user.full_name,
                role: user.role,
                bio: user.bio,
                avatar: user.avatar
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Login failed', details: err.message, stack: err.stack });
    }
});

// ============================================================
// USER ROUTES
// ============================================================

// VULNERABILITY: IDOR — any authenticated user can view any user's profile
app.get('/api/users/:id', authenticateToken, (req, res) => {
    try {
        // NO ownership check — IDOR
        const user = db.prepare('SELECT id, username, email, full_name, role, bio, avatar, created_at FROM users WHERE id = ?').get(req.params.id);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch user', details: err.message });
    }
});

// Get all users (admin only — but role check is JWT-based so bypassable)
app.get('/api/users', authenticateToken, (req, res) => {
    try {
        // VULNERABILITY: Role check uses JWT-provided role which can be tampered
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        const users = db.prepare('SELECT id, username, email, full_name, role, created_at FROM users').all();
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch users', details: err.message });
    }
});

// Update user profile
app.put('/api/users/:id', authenticateToken, (req, res) => {
    try {
        const { bio, full_name, email } = req.body;
        // VULNERABILITY: IDOR — no ownership check, can update any user
        db.prepare('UPDATE users SET bio = ?, full_name = ?, email = ? WHERE id = ?')
            .run(bio || '', full_name || '', email || '', req.params.id);

        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update profile', details: err.message });
    }
});

// ============================================================
// ACCOUNT ROUTES
// ============================================================

// VULNERABILITY: IDOR — any authenticated user can view any account
app.get('/api/accounts/:id', authenticateToken, (req, res) => {
    try {
        const account = db.prepare(`
      SELECT a.*, u.username, u.full_name 
      FROM accounts a 
      JOIN users u ON a.user_id = u.id 
      WHERE a.id = ?
    `).get(req.params.id);

        if (!account) {
            return res.status(404).json({ error: 'Account not found' });
        }

        res.json(account);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch account', details: err.message });
    }
});

// Get accounts by user — uses JWT userId (tamperable)
app.get('/api/my-accounts', authenticateToken, (req, res) => {
    try {
        // VULNERABILITY: Uses userId from JWT which can be tampered
        const accounts = db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.user.userId);
        res.json(accounts);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch accounts', details: err.message });
    }
});

// ============================================================
// TRANSACTION ROUTES
// ============================================================

// Transfer money
app.post('/api/transfer', authenticateToken, (req, res) => {
    try {
        const { fromAccountId, toAccountNumber, amount, description } = req.body;

        if (!fromAccountId || !toAccountNumber || !amount) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const fromAccount = db.prepare('SELECT * FROM accounts WHERE id = ?').get(fromAccountId);
        const toAccount = db.prepare('SELECT * FROM accounts WHERE account_number = ?').get(toAccountNumber);

        if (!fromAccount) return res.status(404).json({ error: 'Source account not found' });
        if (!toAccount) return res.status(404).json({ error: 'Destination account not found' });

        // VULNERABILITY: No ownership check on fromAccount — IDOR
        if (fromAccount.balance < amount) {
            return res.status(400).json({ error: 'Insufficient funds' });
        }

        db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?').run(amount, fromAccount.id);
        db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?').run(amount, toAccount.id);

        // VULNERABILITY: Description stored without sanitization — Stored XSS
        db.prepare(
            'INSERT INTO transactions (from_account_id, to_account_id, amount, description, transaction_type) VALUES (?, ?, ?, ?, ?)'
        ).run(fromAccount.id, toAccount.id, amount, description || 'Transfer', 'transfer');

        res.json({
            message: 'Transfer successful',
            amount,
            from: fromAccount.account_number,
            to: toAccount.account_number
        });
    } catch (err) {
        res.status(500).json({ error: 'Transfer failed', details: err.message, stack: err.stack });
    }
});

// VULNERABILITY: SQL Injection in search
// IMPORTANT: This route MUST come BEFORE /api/transactions/:accountId
app.get('/api/transactions/search', authenticateToken, (req, res) => {
    try {
        const query = req.query.q || '';
        // VULNERABILITY: Direct string concatenation in SQL query
        const sql = `SELECT t.*, 
                        fa.account_number as from_account_number,
                        ta.account_number as to_account_number
                 FROM transactions t
                 LEFT JOIN accounts fa ON t.from_account_id = fa.id
                 LEFT JOIN accounts ta ON t.to_account_id = ta.id
                 WHERE t.description LIKE '%${query}%'
                 ORDER BY t.created_at DESC`;

        const transactions = db.prepare(sql).all();
        res.json(transactions);
    } catch (err) {
        // VULNERABILITY: Info Disclosure — returns SQL error details
        res.status(500).json({
            error: 'Search failed',
            details: err.message,
            query: `Query attempted: ${req.query.q}`,
            stack: err.stack
        });
    }
});

// Get transactions for an account
app.get('/api/transactions/:accountId', authenticateToken, (req, res) => {
    try {
        // VULNERABILITY: IDOR — no ownership check
        const transactions = db.prepare(`
      SELECT t.*, 
             fa.account_number as from_account_number,
             ta.account_number as to_account_number
      FROM transactions t
      LEFT JOIN accounts fa ON t.from_account_id = fa.id
      LEFT JOIN accounts ta ON t.to_account_id = ta.id
      WHERE t.from_account_id = ? OR t.to_account_id = ?
      ORDER BY t.created_at DESC
    `).all(req.params.accountId, req.params.accountId);

        res.json(transactions);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch transactions', details: err.message });
    }
});

// VULNERABILITY: Reflected XSS — renders user input directly in HTML response
app.get('/api/reflected', (req, res) => {
    const name = req.query.name || 'Guest';
    // VULNERABILITY: User input reflected directly in HTML without sanitization
    res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>VulnBank - Welcome</title>
    <link rel="stylesheet" href="/css/style.css">
    </head>
    <body style="display:flex;align-items:center;justify-content:center;min-height:100vh;">
      <div class="card" style="max-width:500px;padding:2rem;text-align:center;">
        <h2>Welcome to VulnBank</h2>
        <p style="margin-top:1rem;font-size:1.1rem;">Hello, <strong>${name}</strong>!</p>
        <p class="text-muted" style="margin-top:0.5rem;">Your session has been registered.</p>
        <a href="/dashboard.html" class="btn btn-primary" style="margin-top:1rem;">Go to Dashboard</a>
      </div>
    </body>
    </html>
    `);
});

// ============================================================
// SUPPORT TICKETS (XSS target)
// ============================================================

app.post('/api/tickets', authenticateToken, (req, res) => {
    try {
        const { subject, message } = req.body;
        // VULNERABILITY: Stored XSS — no sanitization on subject/message
        db.prepare('INSERT INTO support_tickets (user_id, subject, message) VALUES (?, ?, ?)')
            .run(req.user.userId, subject, message);

        res.status(201).json({ message: 'Ticket created successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create ticket', details: err.message });
    }
});

app.get('/api/tickets', authenticateToken, (req, res) => {
    try {
        let tickets;
        if (req.user.role === 'admin') {
            // Admin sees all tickets
            tickets = db.prepare(`
        SELECT t.*, u.username 
        FROM support_tickets t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC
      `).all();
        } else {
            tickets = db.prepare('SELECT * FROM support_tickets WHERE user_id = ? ORDER BY created_at DESC')
                .all(req.user.userId);
        }
        res.json(tickets);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch tickets', details: err.message });
    }
});

// ============================================================
// FILE UPLOAD
// ============================================================

// VULNERABILITY: Insecure File Upload — no validation on file type/size
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Update user avatar path
        const filePath = `/uploads/${req.file.filename}`;
        db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(filePath, req.user.userId);

        // VULNERABILITY: Returns full server file path
        res.json({
            message: 'File uploaded successfully',
            filePath: filePath,
            originalName: req.file.originalname,
            serverPath: req.file.path,
            size: req.file.size
        });
    } catch (err) {
        res.status(500).json({ error: 'Upload failed', details: err.message, stack: err.stack });
    }
});

// ============================================================
// DEBUG / INFO DISCLOSURE
// ============================================================

// VULNERABILITY: Information Disclosure — exposes internal system details
app.get('/api/debug', (req, res) => {
    const tables = db.prepare("SELECT name, sql FROM sqlite_master WHERE type='table'").all();
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    const envInfo = {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        cwd: process.cwd(),
        env: {
            NODE_ENV: process.env.NODE_ENV || 'development',
            PORT: process.env.PORT || 3000
        }
    };

    res.json({
        application: 'VulnBank',
        version: '1.0.0',
        database: {
            type: 'SQLite3',
            tables: tables,
            totalUsers: userCount.count
        },
        server: envInfo,
        jwtSecret: JWT_SECRET, // VULNERABILITY: Exposes JWT secret!
        endpoints: [
            'POST /api/register',
            'POST /api/login',
            'GET /api/users/:id',
            'GET /api/users',
            'PUT /api/users/:id',
            'GET /api/accounts/:id',
            'GET /api/my-accounts',
            'POST /api/transfer',
            'GET /api/transactions/:accountId',
            'GET /api/transactions/search?q=',
            'POST /api/tickets',
            'GET /api/tickets',
            'POST /api/upload',
            'GET /api/debug'
        ]
    });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// VULNERABILITY: Reflected XSS via search page
app.get('/search-page', (req, res) => {
    const q = req.query.q || '';
    // VULNERABILITY: Reflects query parameter directly into page HTML
    res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>VulnBank - Search Results</title>
    <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
      <nav class="navbar">
        <a href="/dashboard.html" class="navbar-brand"><div class="brand-icon">🏦</div><span>VulnBank</span></a>
      </nav>
      <main class="main-content">
        <div class="card" style="padding:2rem;">
          <h2>🔍 Search Results</h2>
          <p style="margin:1rem 0;">Showing results for: <strong>${q}</strong></p>
          <p class="text-muted">No transactions found matching your query.</p>
          <a href="/search.html" class="btn btn-outline" style="margin-top:1rem;">Back to Search</a>
        </div>
      </main>
    </body>
    </html>
    `);
});

// ============================================================
// PROFILE ROUTES (For SPA realism)
// ============================================================
app.get(['/profile', '/profile/:id'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// ============================================================
// ADMIN ROUTE (For SPA realism)
// ============================================================
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ============================================================
// CATCH-ALL FOR SPA
// ============================================================
app.get('*', (req, res) => {
    // If request is for an API route, return 404
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'Endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// START SERVER
// ============================================================
initializeDatabase();

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║     ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗             ║
  ║     ██║   ██║██║   ██║██║     ████╗  ██║             ║
  ║     ██║   ██║██║   ██║██║     ██╔██╗ ██║             ║
  ║     ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║             ║
  ║      ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║             ║
  ║       ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝             ║
  ║                 B A N K                               ║
  ║                                                      ║
  ║   Deliberately Vulnerable Banking Application        ║
  ║   FOR EDUCATIONAL PURPOSES ONLY                      ║
  ║                                                      ║
  ║   Server running on: http://localhost:${PORT}           ║
  ║                                                      ║
  ║   Default Users:                                     ║
  ║     admin  / admin123  (admin role)                   ║
  ║     carlos / carlos123 (user role)                    ║
  ║     maria  / maria123  (user role)                    ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
