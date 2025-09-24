// Minimal Express auth server — binds to 0.0.0.0 so it can be reached from the network.
// Requires: express, sqlite3, bcrypt, jsonwebtoken, cors, helmet, dotenv
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const SECRET = process.env.JWT_SECRET || 'change_this_secret';

app.use(helmet());
app.use(cors()); // allow requests from anywhere (adjust for production)
app.use(express.json());
app.use(express.static(path.join(__dirname))); // serve index.html & dashboard.html

// sqlite DB
const db = new sqlite3.Database(path.join(__dirname, 'auth.db'));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    full_name TEXT,
    password_hash TEXT
  )`);
});

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '8h' });
}

// Signup
app.post('/api/signup', async (req, res) => {
  const { username, password, full_name } = req.body || {};
  if (!username || !password || !full_name) return res.status(400).json({ error: 'Missing username, password or full_name' });

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users(username, full_name, password_hash) VALUES (?, ?, ?)', [username, full_name, hash], function (err) {
      if (err) return res.status(409).json({ error: 'Username already taken' });
      const token = generateToken({ id: this.lastID, username });
      return res.json({ token });
    });
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken({ id: row.id, username: row.username });
    return res.json({ token });
  });
});

// Middleware to authenticate JWT
function authenticate(req, res, next) {
  const auth = req.get('Authorization') || req.get('authorization');
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Bad authorization header' });
  const token = parts[1];
  jwt.verify(token, SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  });
}

// Get current user (used by dashboard)
app.get('/api/me', authenticate, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
});

// Start server, listen on 0.0.0.0 for external access
app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`Accessible on network at http://<your-ip>:${PORT} (if firewall/router allow)`);
});
