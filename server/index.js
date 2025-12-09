require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:8080", "http://localhost:3000"],
  credentials: true
}));

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION_super_secret_key';
const JWT_EXPIRY = '24h';

// PostgreSQL connection with SSL
const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: process.env.PGPORT || 5432,
  user: process.env.PGUSER || 'app_user',
  password: process.env.PGPASSWORD || 'AppPass456!',
  database: process.env.PGDATABASE || 'postgres',
  ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error("❌ Database connection error:", err.stack);
  } else {
    console.log("✅ Connected to PostgreSQL database");
    client.query("SHOW ssl", (err, result) => {
      release();
      if (!err) {
        console.log("🔒 SSL Status:", result.rows[0].ssl);
      }
    });
  }
});

// ================== VALIDATION HELPERS ==================
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email) && email.length <= 100;
}

function validateUsername(username) {
  return username && username.length >= 3 && username.length <= 50 && /^[a-zA-Z0-9_]+$/.test(username);
}

function validatePassword(password) {
  return password && password.length >= 8;
}

// ================== AUTHENTICATION MIDDLEWARE ==================
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: "Access token required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Set PostgreSQL session variable for RLS
    await pool.query('SELECT set_current_user($1)', [decoded.user_id]);
    
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return res.status(403).json({ success: false, message: "Invalid or expired token" });
  }
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: "Admin access required" });
  }
  next();
}

// ================== AUTH ROUTES ==================

// Register new user
app.post("/api/auth/register", async (req, res) => {
  const { username, full_name, email, password } = req.body;

  // Input validation
  if (!validateUsername(username)) {
    return res.status(400).json({ success: false, message: "Username must be 3-50 alphanumeric characters" });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ success: false, message: "Invalid email format" });
  }
  if (!validatePassword(password)) {
    return res.status(400).json({ success: false, message: "Password must be at least 8 characters" });
  }
  if (!full_name || full_name.length > 100) {
    return res.status(400).json({ success: false, message: "Full name required (max 100 chars)" });
  }

  try {
    const password_hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, email, full_name, password_hash, role)
       VALUES ($1, $2, $3, $4, 'standard')
       RETURNING user_id, username, full_name, email, role`,
      [username, email, full_name, password_hash]
    );

    res.status(201).json({ 
      success: true, 
      message: "Account created successfully",
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Registration error:', err);
    if (err.code === "23505") {
      if (err.constraint === 'users_username_key') {
        return res.status(409).json({ success: false, message: "Username already taken" });
      } else if (err.constraint === 'users_email_key') {
        return res.status(409).json({ success: false, message: "Email already registered" });
      }
    }
    res.status(500).json({ success: false, message: "Registration failed" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ success: false, message: "Email/username and password required" });
  }

  try {
    const result = await pool.query(
      `SELECT user_id, username, email, password_hash, role, full_name, is_active, locked_until
       FROM users
       WHERE username = $1 OR email = $1`,
      [identifier]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const user = result.rows[0];

    // Check if account is active
    if (!user.is_active) {
      return res.status(403).json({ success: false, message: "Account is disabled" });
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(403).json({
        success: false,
        message: "Account locked due to failed login attempts",
        locked_until: user.locked_until
      });
    }

    // Verify password
    const match = await bcrypt.compare(password, user.password_hash);
    
    if (!match) {
      await pool.query('SELECT increment_failed_login($1)', [user.username]);
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // Reset failed login attempts
    await pool.query('SELECT reset_failed_login($1)', [user.user_id]);

    // Generate JWT token
    const token = jwt.sign(
      { 
        user_id: user.user_id, 
        username: user.username, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({ 
      success: true, 
      token,
      user: {
        user_id: user.user_id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        role: user.role
      }
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

// ================== USER ROUTES ==================

// Get user's own accounts
app.get("/api/user/accounts", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT account_id, account_number, balance, status, created_at
       FROM accounts
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.user_id]
    );
    res.json({ success: true, accounts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get user's transactions for a specific account
app.get("/api/user/transactions/:accountId", authenticateToken, async (req, res) => {
  const accountId = parseInt(req.params.accountId);
  if (isNaN(accountId)) return res.status(400).json({ success: false, message: "Invalid account ID" });

  try {
    // Ensure this account belongs to the logged-in user
    const accountCheck = await pool.query(
      `SELECT account_id FROM accounts WHERE account_id = $1 AND user_id = $2`,
      [accountId, req.user.user_id]
    );

    if (accountCheck.rows.length === 0) {
      return res.status(403).json({ success: false, message: "Unauthorized access to this account" });
    }

    const result = await pool.query(
      `SELECT transaction_id, transaction_type, amount, transaction_date, description, balance_after
       FROM transactions
       WHERE account_id = $1
       ORDER BY transaction_date DESC`,
      [accountId]
    );

    res.json({ success: true, transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get user's analytics
app.get("/api/user/analytics", authenticateToken, async (req, res) => {
  try {
    const totalResult = await pool.query(
      `SELECT COUNT(*) as total
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       WHERE a.user_id = $1`,
      [req.user.user_id]
    );

    const depositResult = await pool.query(
      `SELECT COALESCE(SUM(amount),0) as total_deposits
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       WHERE a.user_id = $1 AND transaction_type = 'deposit'`,
      [req.user.user_id]
    );

    const withdrawalResult = await pool.query(
      `SELECT COALESCE(SUM(amount),0) as total_withdrawals
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       WHERE a.user_id = $1 AND transaction_type = 'withdrawal'`,
      [req.user.user_id]
    );

    const typeResult = await pool.query(
      `SELECT transaction_type, COUNT(*) as count, SUM(amount) as total_amount
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       WHERE a.user_id = $1
       GROUP BY transaction_type`,
      [req.user.user_id]
    );

    const recentResult = await pool.query(
      `SELECT t.*, a.account_number
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       WHERE a.user_id = $1
       ORDER BY t.transaction_date DESC
       LIMIT 10`,
      [req.user.user_id]
    );

    res.json({
      success: true,
      analytics: {
        totalTransactions: parseInt(totalResult.rows[0].total),
        totalDeposits: parseFloat(depositResult.rows[0].total_deposits),
        totalWithdrawals: parseFloat(withdrawalResult.rows[0].total_withdrawals),
        byType: typeResult.rows,
        recentTransactions: recentResult.rows
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// Create new account
app.post("/api/user/accounts/create", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `INSERT INTO accounts (user_id, balance, status)
       VALUES ($1, 0, 'active')
       RETURNING account_id, account_number, balance, status, created_at`,
      [req.user.user_id]
    );

    res.status(201).json({
      success: true,
      account: result.rows[0]
    });

  } catch (err) {
    console.error("Account creation error:", err);
    res.status(500).json({ success: false, message: "Could not create account" });
  }
});

// Deposit into account
app.post("/api/user/accounts/:id/deposit", authenticateToken, async (req, res) => {
  const accountId = parseInt(req.params.id);
  const { amount } = req.body;

  if (!amount || amount <= 0)
    return res.status(400).json({ success: false, message: "Invalid amount" });

  try {
    // Ensure account belongs to user
    const accountCheck = await pool.query(
      "SELECT balance FROM accounts WHERE account_id = $1 AND user_id = $2",
      [accountId, req.user.user_id]
    );

    if (accountCheck.rowCount === 0)
      return res.status(403).json({ success: false, message: "Unauthorized" });

    const newBalance = parseFloat(accountCheck.rows[0].balance) + amount;

    // Update balance
    await pool.query(
      "UPDATE accounts SET balance = $1 WHERE account_id = $2",
      [newBalance, accountId]
    );

    // Add transaction
    const tx = await pool.query(
      `INSERT INTO transactions (account_id, transaction_type, amount, balance_after)
       VALUES ($1, 'deposit', $2, $3)
       RETURNING *`,
      [accountId, amount, newBalance]
    );

    res.json({ success: true, transaction: tx.rows[0], newBalance });

  } catch (err) {
    console.error("Deposit error:", err);
    res.status(500).json({ success: false, message: "Deposit failed" });
  }
});

// Withdraw from account
app.post("/api/user/accounts/:id/withdraw", authenticateToken, async (req, res) => {
  const accountId = parseInt(req.params.id);
  const { amount } = req.body;

  if (!amount || amount <= 0)
    return res.status(400).json({ success: false, message: "Invalid amount" });

  try {
    // Ensure account belongs to user
    const accountCheck = await pool.query(
      "SELECT balance FROM accounts WHERE account_id = $1 AND user_id = $2",
      [accountId, req.user.user_id]
    );

    if (accountCheck.rowCount === 0)
      return res.status(403).json({ success: false, message: "Unauthorized" });

    const balance = parseFloat(accountCheck.rows[0].balance);

    if (balance < amount)
      return res.status(400).json({ success: false, message: "Insufficient funds" });

    const newBalance = balance - amount;

    // Update balance
    await pool.query(
      "UPDATE accounts SET balance = $1 WHERE account_id = $2",
      [newBalance, accountId]
    );

    // Add transaction
    const tx = await pool.query(
      `INSERT INTO transactions (account_id, transaction_type, amount, balance_after)
       VALUES ($1, 'withdrawal', $2, $3)
       RETURNING *`,
      [accountId, amount, newBalance]
    );

    res.json({ success: true, transaction: tx.rows[0], newBalance });

  } catch (err) {
    console.error("Withdraw error:", err);
    res.status(500).json({ success: false, message: "Withdrawal failed" });
  }
});



// ================== ADMIN ROUTES ==================

// Get all users (admin only)
app.get("/api/admin/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT user_id, username, email, full_name, role, is_active, created_at 
       FROM users 
       ORDER BY created_at DESC`
    );
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get all accounts (admin only)
app.get("/api/admin/accounts", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.account_id, a.account_number, a.balance, a.status, 
              u.username, u.full_name, a.created_at
       FROM accounts a
       JOIN users u ON a.user_id = u.user_id
       ORDER BY a.created_at DESC`
    );
    res.json({ success: true, accounts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get all transactions (admin only)
app.get("/api/admin/transactions", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.transaction_id, t.transaction_type, t.amount, 
              t.transaction_date, t.description, t.balance_after,
              a.account_number, u.username
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       JOIN users u ON a.user_id = u.user_id
       ORDER BY t.transaction_date DESC
       LIMIT 100`
    );
    res.json({ success: true, transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get system statistics (admin only)
app.get("/api/admin/stats", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userCount = await pool.query("SELECT COUNT(*) FROM users");
    const accountCount = await pool.query("SELECT COUNT(*) FROM accounts");
    const activeAccountCount = await pool.query("SELECT COUNT(*) FROM accounts WHERE status = 'active'");
    const transactionCount = await pool.query("SELECT COUNT(*) FROM transactions");

    res.json({
      success: true,
      stats: {
        totalUsers: parseInt(userCount.rows[0].count),
        totalAccounts: parseInt(accountCount.rows[0].count),
        activeAccounts: parseInt(activeAccountCount.rows[0].count),
        totalTransactions: parseInt(transactionCount.rows[0].count)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get system-wide analytics (admin only)
app.get("/api/admin/analytics", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const totalResult = await pool.query("SELECT COUNT(*) as total FROM transactions");
    
    const depositResult = await pool.query(
      "SELECT COALESCE(SUM(amount), 0) as total_deposits FROM transactions WHERE transaction_type = 'deposit'"
    );
    
    const withdrawalResult = await pool.query(
      "SELECT COALESCE(SUM(amount), 0) as total_withdrawals FROM transactions WHERE transaction_type = 'withdrawal'"
    );
    
    const typeResult = await pool.query(
      `SELECT transaction_type, COUNT(*) as count, SUM(amount) as total_amount
       FROM transactions
       GROUP BY transaction_type`
    );

    const recentResult = await pool.query(
      `SELECT t.*, a.account_number, u.username
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       JOIN users u ON a.user_id = u.user_id
       ORDER BY t.transaction_date DESC
       LIMIT 10`
    );

    const analytics = {
      totalTransactions: parseInt(totalResult.rows[0].total),
      totalDeposits: parseFloat(depositResult.rows[0].total_deposits) || 0,
      totalWithdrawals: parseFloat(withdrawalResult.rows[0].total_withdrawals) || 0,
      byType: typeResult.rows,
      recentTransactions: recentResult.rows
    };

    res.json({ success: true, analytics });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== LEGACY ROUTES (for backward compatibility) ==================

// Old signup route (redirects to new endpoint)
app.post("/signup", async (req, res) => {
  req.url = '/api/auth/register';
  return app._router.handle(req, res);
});

// Old login route (redirects to new endpoint)
app.post("/login", async (req, res) => {
  req.url = '/api/auth/login';
  return app._router.handle(req, res);
});

// ================== TEST ROUTES ==================

app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ 
      success: true,
      message: "🏦 Secure Banking API Server",
      time: result.rows[0].now,
      endpoints: {
        auth: ["/api/auth/register", "/api/auth/login"],
        user: ["/api/user/accounts", "/api/user/transactions/:accountId", "/api/user/analytics"],
        admin: ["/api/admin/users", "/api/admin/accounts", "/api/admin/transactions", "/api/admin/stats", "/api/admin/analytics"]
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Database connection failed" });
  }
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "healthy", database: "connected" });
  } catch (err) {
    res.status(503).json({ status: "unhealthy", database: "disconnected" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 API Documentation: http://localhost:${PORT}/`);
});