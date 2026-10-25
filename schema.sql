
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "20kb" }));

const {
  DATABASE_URL,
  JWT_SECRET,
  PORT = 3000
} = process.env;

if (!DATABASE_URL || !JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("Configure DATABASE_URL and a strong JWT_SECRET");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const { email, password, phone } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 254 ||
      password.length < 12 ||
      password.length > 128 ||
      (phone != null &&
        (typeof phone !== "string" || phone.length > 24))
    ) {
      return res.status(400).json({
        error: "Invalid registration details"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({ error: "Invalid email" });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, phone)
       VALUES ($1, $2, $3)
       RETURNING id, email, phone`,
      [normalizedEmail, hash, phone || null]
    );

    return res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Account already exists"
      });
    }

    console.error("Registration failed");
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 254 ||
      password.length > 128
    ) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const result = await pool.query(
      `SELECT id, email, password_hash
       FROM users WHERE email = $1`,
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const accessToken = jwt.sign(
      { sub: String(user.id) },
      JWT_SECRET,
      { expiresIn: "30m", issuer: "vicky-flix" }
    );

    return res.json({
      accessToken,
      tokenType: "Bearer",
      expiresIn: 1800,
      user: { id: user.id, email: user.email }
    });
  } catch (error) {
    console.error("Login failed");
    return res.status(500).json({ error: "Server error" });
  }
});

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer (.+)$/);

  if (!match) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  try {
    req.user = jwt.verify(match[1], JWT_SECRET, {
      issuer: "vicky-flix"
    });
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

app.get("/api/movies", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, description, category, poster_url
       FROM movies
       ORDER BY title
       LIMIT 100`
    );

    res.json({ movies: result.rows });
  } catch (error) {
    console.error("Movie query failed");
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/movies/:id", requireAuth, async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) {
    return res.status(400).json({ error: "Invalid movie ID" });
  }

  try {
    const result = await pool.query(
      `SELECT id, title, description, category, poster_url
       FROM movies WHERE id = $1`,
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Movie not found" });
    }

    res.json({ movie: result.rows[0] });
  } catch (error) {
    console.error("Movie details query failed");
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(Number(PORT), "0.0.0.0", () => {
  console.log(`Vicky flix API listening on ${PORT}`);
});
  
