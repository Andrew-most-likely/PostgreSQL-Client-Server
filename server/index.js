require("dotenv").config(); // load .env first
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());
app.use(cors({
  origin: "http://localhost:8080",
  credentials: true
}));

// PostgreSQL connection
const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE
});

// Signup route
app.post("/signup", async (req, res) => {
  const { username, full_name, email, password, role } = req.body;

  if (!username || !full_name || !email || !password || !role)
    return res.status(400).json({ success: false, message: "All fields required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (username, email, full_name, password, role)
       VALUES ($1, $2, $3, $4, $5)`,
      [username, email, full_name, hashedPassword, role]
    );

    res.json({ success: true, message: "User created" });
  } catch (err) {
    if (err.code === "23505")
      res.status(400).json({ success: false, message: "Username or email already exists" });
    else {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
});


// Login route (username or email)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ success: false, message: "Username/email and password required" });

  try {
    const result = await pool.query(
      `SELECT id, username, email, password, role, full_name
       FROM users
       WHERE username = $1 OR email = $1`,
      [email]
    );

    if (result.rows.length === 0)
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const { password: pw, ...userData } = user;

    res.json({ success: true, user: userData });


  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// Test route
app.get("/", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ time: result.rows[0].now });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Start server
app.listen(3000, "0.0.0.0", () => console.log("Server running on port 3000"));
