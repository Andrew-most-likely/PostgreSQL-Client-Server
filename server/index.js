require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const fs = require("fs");

const app = express();
app.use(express.json());
app.use(cors({
  origin: "http://localhost:8080",
  credentials: true
}));

// PostgreSQL connection with SSL
const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : false
});

// Test database connection and log SSL status
pool.connect((err, client, release) => {
  if (err) {
    console.error("❌ Database connection error:", err.stack);
  } else {
    console.log(" Connected to PostgreSQL database");
    client.query("SHOW ssl", (err, result) => {
      release();
      if (!err) {
        console.log(" SSL Status:", result.rows[0].ssl);
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
function authenticate(req, res, next) {
  const userId = req.headers['x-user-id'];
  if (!userId) {
    return res.status(401).json({ success: false, message: "Authentication required" });
  }
  req.userId = parseInt(userId);
  next();
}

// ================== AUTH ROUTES ==================

// Signup route
app.post("/signup", async (req, res) => {
  const { username, full_name, email, password, role } = req.body;

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
    const hashedPassword = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (username, email, full_name, password, role)
       VALUES ($1, $2, $3, $4, $5)`,
      [username, email, full_name, hashedPassword, role || 'standard']
    );

    res.json({ success: true, message: "User created" });
  } catch (err) {
    if (err.code === "23505") {
      res.status(400).json({ success: false, message: "Username or email already exists" });
    } else {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password required" });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, email, password, role, full_name
       FROM users
       WHERE username = $1 OR email = $1`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    
    if (!match) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const { password: pw, ...userData } = user;
    res.json({ success: true, user: userData });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== USER ROUTES ==================

// Get all users (admin only)
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, full_name, role, created_at 
       FROM users 
       ORDER BY created_at DESC`
    );
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== ACCOUNT ROUTES ==================

// Get user's accounts
app.get("/api/accounts/:userId", authenticate, async (req, res) => {
  const userId = parseInt(req.params.userId);

  // Validate numeric input
  if (isNaN(userId)) {
    return res.status(400).json({ success: false, message: "Invalid user ID" });
  }

  try {
    const result = await pool.query(
      `SELECT account_id, account_number, balance, status 
       FROM accounts 
       WHERE id = $1`,
      [userId]
    );
    res.json({ success: true, accounts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get all accounts (admin)
app.get("/api/accounts", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT a.account_id, a.account_number, a.balance, a.status, 
              u.username, u.full_name
       FROM accounts a
       JOIN users u ON a.id = u.id
       ORDER BY a.account_id`
    );
    res.json({ success: true, accounts: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== TRANSACTION ROUTES ==================

// Get transactions for an account
app.get("/api/transactions/:accountId", authenticate, async (req, res) => {
  const accountId = parseInt(req.params.accountId);

  if (isNaN(accountId)) {
    return res.status(400).json({ success: false, message: "Invalid account ID" });
  }

  try {
    const result = await pool.query(
      `SELECT transaction_id, transaction_type, amount, transaction_date, description
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

// Get all transactions (admin)
app.get("/api/transactions", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.transaction_id, t.transaction_type, t.amount, 
              t.transaction_date, t.description,
              a.account_number, u.username
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       JOIN users u ON a.id = u.id
       ORDER BY t.transaction_date DESC
       LIMIT 100`
    );
    res.json({ success: true, transactions: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== JSON API ENDPOINT (Part Two - Part D) ==================

// Secure JSON endpoint - returns sample data (authenticated users only)
app.get("/api/data/sample", authenticate, async (req, res) => {
  try {
    const sampleData = {
      timestamp: new Date().toISOString(),
      environment: "secure",
      status: "operational",
      statistics: {
        totalUsers: 0,
        activeAccounts: 0,
        totalTransactions: 0
      }
    };

    // Get real statistics
    const userCount = await pool.query("SELECT COUNT(*) FROM users");
    const accountCount = await pool.query("SELECT COUNT(*) FROM accounts WHERE status = 'active'");
    const transactionCount = await pool.query("SELECT COUNT(*) FROM transactions");

    sampleData.statistics.totalUsers = parseInt(userCount.rows[0].count);
    sampleData.statistics.activeAccounts = parseInt(accountCount.rows[0].count);
    sampleData.statistics.totalTransactions = parseInt(transactionCount.rows[0].count);

    res.json({ success: true, data: sampleData });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================== CSV ANALYTICS ENDPOINT (Part Two - Part E) ==================

// CSV analytics - secure transaction analytics (authenticated users only)
app.get("/api/analytics/transactions", authenticate, async (req, res) => {
  try {
    // Total transactions
    const totalResult = await pool.query("SELECT COUNT(*) as total FROM transactions");
    
    // Total deposit volume
    const depositResult = await pool.query(
      "SELECT SUM(amount) as total_deposits FROM transactions WHERE transaction_type = 'deposit'"
    );
    
    // Total withdrawal volume
    const withdrawalResult = await pool.query(
      "SELECT SUM(amount) as total_withdrawals FROM transactions WHERE transaction_type = 'withdrawal'"
    );
    
    // Transactions by type
    const typeResult = await pool.query(
      `SELECT transaction_type, COUNT(*) as count, SUM(amount) as total_amount
       FROM transactions
       GROUP BY transaction_type`
    );

    // Recent transactions (last 10)
    const recentResult = await pool.query(
      `SELECT t.*, a.account_number, u.username
       FROM transactions t
       JOIN accounts a ON t.account_id = a.account_id
       JOIN users u ON a.id = u.id
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

// ================== TEST ROUTES ==================

// Test database connection
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ 
      success: true,
      message: "Server is running",
      time: result.rows[0].now 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Database connection failed" });
  }
});

// Health check
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
  console.log(`Server running on port ${PORT}`);
});