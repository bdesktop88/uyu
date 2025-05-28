const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');


const app = express();
const PORT = 3000;

const db = new sqlite3.Database('./redirects.db', (err) => {
  if (err) return console.error('Database error:', err);
  console.log('Connected to SQLite database.');
});

// Create tables if not exist
db.run(`CREATE TABLE IF NOT EXISTS redirects (
  token TEXT PRIMARY KEY,
  destination TEXT NOT NULL
)`);

db.run(`CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
)`);

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
}));

// Home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Add redirect
app.post('/add-redirect', (req, res) => {
  const { destination } = req.body;
  if (!destination) return res.status(400).json({ message: 'Missing destination URL' });
  const token = uuidv4().slice(0, 8);
  db.run(`INSERT INTO redirects (token, destination) VALUES (?, ?)`, [token, destination], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to save redirect' });
    res.json({ redirectUrl: `${req.protocol}://${req.get('host')}/r/${token}` });
  });
});

// Serve dynamic reCAPTCHA page
app.get('/r/:token', (req, res) => {
  const token = req.params.token;

  db.get('SELECT value FROM settings WHERE key = ?', ['recaptcha_site_key'], (err, row) => {
    if (err || !row) return res.status(500).send('Missing reCAPTCHA site key');
    const siteKey = row.value;

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Verifying...</title>
        <script src="https://www.google.com/recaptcha/api.js?render=${siteKey}"></script>
        <style>
    /* Full page with blue border */
    html, body {
      height: 100%;
      margin: 0;
      padding: 0;
      background: white;
      border: 1px solid #007bff; /* bootstrap blue */
      box-sizing: border-box;
      justify-content: center;
      align-items: center;
      font-family: Arial, sans-serif;
      overflow: hidden;
    }

    .container {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh; /* Full screen height */
  background-color: #f0f8ff; /* Light blue background for the page */
}

.progress-bar {
  position: relative;
  height: 5px;
  background: #e0e0e0;
  border-radius: 2px;
  overflow: hidden;
  width: 1005%;
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
}


    /* Animated moving bar */
    .progress-bar::before {
      content: "";
      position: absolute;
      height: 100%;
      width: 50%;
      background: #007bff;
      animation: loading 1.5s linear infinite;
      border-radius: 5px;
      left: -50%;
    }

    @keyframes loading {
      0% { left: -50%; }
      100% { left: 100%; }
    }
  </style>
</head>
<body>
  <div class="loader-container">
    <div class="progress-bar"></div>
  </div>
        <script>
          grecaptcha.ready(async function () {
            const recaptchaToken = await grecaptcha.execute('${siteKey}', { action: 'redirect' });
            const token = window.location.pathname.split('/').pop();

            const response = await fetch('/verify-redirect', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ token, recaptchaToken })
            });

            const result = await response.json();
            if (result.destination) {
              window.location.href = result.destination;
            } else {
              document.body.innerHTML = '<p style="color:red; text-align:center; margin-top:20px;">Access denied: ' + result.message + '</p>';
            }
          });
        </script>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// reCAPTCHA verification + redirect
app.post('/verify-redirect', async (req, res) => {
  const { token, recaptchaToken } = req.body;
  if (!token || !recaptchaToken) return res.status(400).json({ message: 'Missing parameters' });

  db.get('SELECT value FROM settings WHERE key = ?', ['recaptcha_secret_key'], async (err, row) => {
    if (err || !row) return res.status(500).json({ message: 'reCAPTCHA key error' });

    try {
      const recaptchaSecret = row.value;
      const verify = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=${recaptchaSecret}&response=${recaptchaToken}`,
      });
      const data = await verify.json();
      if (!data.success || data.score < 0.5) return res.status(403).json({ message: 'reCAPTCHA failed' });

      db.get(`SELECT destination FROM redirects WHERE token = ?`, [token], (err, row) => {
        if (err || !row) return res.status(404).json({ message: 'Redirect token not found' });
        res.json({ destination: row.destination });
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({ message: 'Internal error' });
    }
  });
});

// Admin Login
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  db.get('SELECT value FROM settings WHERE key = ?', ['admin_password'], (err, row) => {
    if (err || !row || row.value !== password) return res.json({ success: false, message: 'Invalid password' });
    res.json({ success: true });
  });
});

// Admin Get Settings
app.get('/admin/settings', (req, res) => {
  db.all('SELECT key, value FROM settings', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false });
    const settings = {};
    rows.forEach(r => settings[r.key] = r.value);
    res.json(settings);
  });
});

// Admin Update Settings
app.post('/admin/settings', (req, res) => {
  const settings = req.body;
  const updates = Object.entries(settings);

  db.serialize(() => {
    const stmt = db.prepare('REPLACE INTO settings (key, value) VALUES (?, ?)');
    updates.forEach(([key, value]) => {
      stmt.run(key, value);
    });
    stmt.finalize();
  });

  res.json({ success: true });
});

// Admin Get Redirects
app.get('/admin/redirects', (req, res) => {
  db.all('SELECT token, destination FROM redirects', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Failed to fetch redirects' });
    res.json(rows);
  });
});

// Update redirect
app.post('/admin/update-redirect', (req, res) => {
  const { token, destination } = req.body;
  if (!token || !destination) return res.status(400).json({ success: false });

  db.run(`UPDATE redirects SET destination = ? WHERE token = ?`, [destination, token], function (err) {
    if (err || this.changes === 0) return res.status(500).json({ success: false });
    res.json({ success: true });
  });
});

// Delete redirect
app.post('/admin/delete-redirect', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ success: false });

  db.run(`DELETE FROM redirects WHERE token = ?`, [token], function (err) {
    if (err || this.changes === 0) return res.status(500).json({ success: false });
    res.json({ success: true });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
