const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'vulnbank.db');
const db = new Database(dbPath);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

function initializeDatabase() {
  // Create users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      full_name TEXT,
      role TEXT DEFAULT 'user',
      bio TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create accounts table
  db.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      account_number TEXT UNIQUE NOT NULL,
      balance REAL DEFAULT 0,
      account_type TEXT DEFAULT 'checking',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Create transactions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_account_id INTEGER,
      to_account_id INTEGER,
      amount REAL NOT NULL,
      description TEXT,
      transaction_type TEXT DEFAULT 'transfer',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (from_account_id) REFERENCES accounts(id),
      FOREIGN KEY (to_account_id) REFERENCES accounts(id)
    )
  `);

  // Create support_tickets table (for XSS demo)
  db.exec(`
    CREATE TABLE IF NOT EXISTS support_tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT DEFAULT 'open',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Seed users if table is empty
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count === 0) {
    console.log('[VulnBank] Seeding database with initial users...');

    const insertUser = db.prepare(`
      INSERT INTO users (username, password, email, full_name, role, bio) 
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const insertAccount = db.prepare(`
      INSERT INTO accounts (user_id, account_number, balance, account_type) 
      VALUES (?, ?, ?, ?)
    `);

    const insertTransaction = db.prepare(`
      INSERT INTO transactions (from_account_id, to_account_id, amount, description, transaction_type) 
      VALUES (?, ?, ?, ?, ?)
    `);

    // VULNERABILITY: Passwords hashed with bcrypt but weak passwords
    // Admin user
    const adminHash = bcrypt.hashSync('admin123', 10);
    insertUser.run('admin', adminHash, 'admin@vulnbank.com', 'Administrator', 'admin', 'System administrator with full access');
    insertAccount.run(1, 'VB-1000-0001', 50000.00, 'checking');
    insertAccount.run(1, 'VB-1000-0002', 150000.00, 'savings');

    // Carlos user
    const carlosHash = bcrypt.hashSync('carlos123', 10);
    insertUser.run('carlos', carlosHash, 'carlos@email.com', 'Carlos Rodriguez', 'user', 'Regular banking customer');
    insertAccount.run(2, 'VB-2000-0001', 5000.00, 'checking');
    insertAccount.run(2, 'VB-2000-0002', 12000.00, 'savings');

    // Maria user
    const mariaHash = bcrypt.hashSync('maria123', 10);
    insertUser.run('maria', mariaHash, 'maria@email.com', 'Maria Santos', 'user', 'Premium banking customer');
    insertAccount.run(3, 'VB-3000-0001', 2500.00, 'checking');
    insertAccount.run(3, 'VB-3000-0002', 8500.00, 'savings');

    // Seed some transactions
    insertTransaction.run(2, 1, 500.00, 'Monthly payment', 'transfer');
    insertTransaction.run(1, 3, 1200.00, 'Salary deposit', 'transfer');
    insertTransaction.run(3, 2, 300.00, 'Shared expense', 'transfer');
    insertTransaction.run(1, 2, 2500.00, 'Bonus payment', 'transfer');
    insertTransaction.run(2, 3, 150.00, 'Dinner reimbursement', 'transfer');

    console.log('[VulnBank] Database seeded successfully!');
    console.log('[VulnBank] Users: admin/admin123, carlos/carlos123, maria/maria123');
  }
}

module.exports = { db, initializeDatabase };
