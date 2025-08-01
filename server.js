const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database('users.db');

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    token TEXT,
    token_expires INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Email transporter setup (you'll need to configure this)
const transporter = nodemailer.createTransporter({
  host: 'smtp.gmail.com', // or your SMTP provider
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER, // your email
    pass: process.env.EMAIL_PASS  // your app password
  }
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/send-magic-link', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

  try {
    // Insert or update user
    db.run(
      'INSERT OR REPLACE INTO users (email, token, token_expires) VALUES (?, ?, ?)',
      [email, token, expires],
      async function(err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Database error' });
        }

        // Send magic link email
        const magicLink = `${req.protocol}://${req.get('host')}/login?token=${token}`;
        
        try {
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your Magic Link',
            html: `
              <h2>Login to Your Account</h2>
              <p>Click the link below to login:</p>
              <a href="${magicLink}">Login Here</a>
              <p>This link expires in 15 minutes.</p>
            `
          });

          res.json({ message: 'Magic link sent to your email!' });
        } catch (emailError) {
          console.error('Email error:', emailError);
          res.status(500).json({ error: 'Failed to send email' });
        }
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/login', (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).send('Invalid token');
  }

  db.get(
    'SELECT * FROM users WHERE token = ? AND token_expires > ?',
    [token, Date.now()],
    (err, user) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Database error');
      }

      if (!user) {
        return res.status(400).send('Invalid or expired token');
      }

      // Clear the token after use
      db.run('UPDATE users SET token = NULL, token_expires = NULL WHERE id = ?', [user.id]);

      // Get total user count
      db.get('SELECT COUNT(*) as count FROM users', (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Database error');
        }

        res.send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Profile</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
          </head>
          <body>
            <div style="padding: 20px; font-family: Arial, sans-serif;">
              <div style="position: absolute; top: 20px; left: 20px;">
                <strong>${user.email}</strong>
              </div>
              <div style="margin-top: 60px;">
                <h1>Welcome to your profile!</h1>
                <p>Total users: ${result.count}</p>
              </div>
            </div>
          </body>
          </html>
        `);
      });
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
