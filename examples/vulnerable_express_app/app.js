 /**
 * Intentionally Vulnerable Express App — for FixProof testing only.
 *
 * DO NOT deploy this to production. Every endpoint here is deliberately
 * insecure so that FixProof can detect and demonstrate its checks.
 */

const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = 3000;

// --- In-memory SQLite database ---
const db = new Database(":memory:");
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT);
  INSERT INTO users VALUES (1, 'admin', 'admin@local.test');
  INSERT INTO users VALUES (2, 'alice', 'alice@local.test');
  INSERT INTO users VALUES (3, 'bob',   'bob@local.test');
`);

app.use(express.urlencoded({ extended: true }));

// --- Deliberately missing security headers ---
// (No CSP, no X-Frame-Options, no HSTS, etc.)

// --- Insecure cookie ---
app.use((req, res, next) => {
  res.cookie("session_id", "demo_session_value", {
    // Missing HttpOnly, Secure, SameSite
  });
  next();
});

// --- Home page ---
app.get("/", (req, res) => {
  res.send(`
    <html>
    <head><title>Vuln App</title></head>
    <body>
      <h1>Vulnerable Demo App</h1>
      <ul>
        <li><a href="/search?q=test">Search (XSS)</a></li>
        <li><a href="/users?id=1">User Lookup (SQLi)</a></li>
        <li><a href="/login">Login Form (CSRF)</a></li>
        <li><a href="/comment">Comment Form (XSS)</a></li>
      </ul>
    </body>
    </html>
  `);
});

// --- Reflected XSS via GET parameter ---
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  // Deliberately reflects user input without encoding.
  res.send(`
    <html><head><title>Search</title></head><body>
    <h1>Search Results</h1>
    <p>You searched for: ${q}</p>
    <form action="/search" method="GET">
      <input type="text" name="q" value="${q}">
      <button type="submit">Search</button>
    </form>
    </body></html>
  `);
});

// --- SQL injection via GET parameter ---
app.get("/users", (req, res) => {
  const id = req.query.id || "1";
  try {
    // Deliberately uses string concatenation — vulnerable to SQLi.
    const rows = db.prepare(`SELECT * FROM users WHERE id = ${id}`).all();
    res.send(`
      <html><head><title>Users</title></head><body>
      <h1>User Lookup</h1>
      <pre>${JSON.stringify(rows, null, 2)}</pre>
      <form action="/users" method="GET">
        <input type="text" name="id" value="${id}">
        <button>Lookup</button>
      </form>
      </body></html>
    `);
  } catch (err) {
    // Deliberately leaks error messages.
    res.send(`<html><body><h1>Error</h1><pre>${err.message}</pre></body></html>`);
  }
});

// --- Login form without CSRF token ---
app.get("/login", (req, res) => {
  res.send(`
    <html><head><title>Login</title></head><body>
    <h1>Login</h1>
    <form action="/login" method="POST">
      <input type="text" name="username" placeholder="Username"><br>
      <input type="password" name="password" placeholder="Password"><br>
      <button type="submit">Login</button>
    </form>
    </body></html>
  `);
});

app.post("/login", (req, res) => {
  res.send(`<html><body><p>Logged in as ${req.body.username}</p></body></html>`);
});

// --- Comment form with reflected XSS ---
app.get("/comment", (req, res) => {
  res.send(`
    <html><head><title>Comment</title></head><body>
    <h1>Leave a Comment</h1>
    <form action="/comment" method="POST">
      <input type="hidden" name="post_id" value="42">
      <textarea name="body" rows="5" cols="40"></textarea><br>
      <button type="submit">Submit</button>
    </form>
    </body></html>
  `);
});

app.post("/comment", (req, res) => {
  // Reflects the comment body without encoding.
  res.send(`
    <html><body>
    <h1>Comment Posted</h1>
    <div class="comment">${req.body.body}</div>
    </body></html>
  `);
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Vulnerable app running at http://127.0.0.1:${PORT}`);
});