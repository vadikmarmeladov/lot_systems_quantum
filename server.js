require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session middleware
app.use(session({
secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
resave: false,
saveUninitialized: false,
cookie: { 
secure: false, // Set to true if using HTTPS
maxAge: 24 * 60 * 60 * 1000 // 24 hours
}
}));

// Initialize SQLite database
const db = new sqlite3.Database('./users.db', (err) => {
if (err) {
console.error('Error opening database:', err.message);
} else {
console.log('Connected to SQLite database.');

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT UNIQUE NOT NULL,
token TEXT,
token_expires INTEGER,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
last_login DATETIME
)`, (err) => {
if (err) {
console.error('Error creating users table:', err.message);
} else {
console.log('Users table created or already exists.');
}
});
}
});

// Email transporter configuration
const transporter = nodemailer.createTransporter({
service: 'gmail',
auth: {
user: 'lot.systems.quantum@gmail.com',
pass: process.env.keiarhaqoezamefb // Your Gmail app password
},
pool: true,
maxConnections: 5,
maxMessages: 100,
rateLimit: 14 // emails per second max
});

// Verify email configuration
transporter.verify((error, success) => {
if (error) {
console.error('Email transporter error:', error);
} else {
console.log('Email transporter is ready');
}
});

// Generate magic link token
function generateToken() {
return crypto.randomBytes(32).toString('hex');
}

// Routes

// Serve main page
app.get('/', (req, res) => {
if (req.session.user) {
// User is logged in, show profile
const userCount = new Promise((resolve, reject) => {
db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
if (err) reject(err);
else resolve(row.count);
});
});

userCount.then(count => {
const html = `
<!DOCTYPE html>
<html>
<head>
<title>Profile - LOT Systems Quantum</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
.container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #333; margin-bottom: 30px; }
.info { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
.logout-btn { background: #dc3545; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }
.logout-btn:hover { background: #c82333; }
</style>
</head>
<body>
<div class="container">
<p style="color: #666; margin: 0;">info@vadikmarmeladovlab.com</p>
<h1>Welcome to your profile!</h1>
<div class="info">
<p><strong>Total users:</strong> ${count}</p>
<p><strong>Login successful at:</strong> ${new Date().toLocaleString()}</p>
</div>
<a href="/logout" class="logout-btn">Logout</a>
</div>
</body>
</html>
`;
res.send(html);
}).catch(err => {
console.error('Error getting user count:', err);
res.status(500).send('Database error');
});
} else {
// User not logged in, show login form
res.sendFile(path.join(__dirname, 'public', 'index.html'));
}
});

// Send magic link
app.post('/send-magic-link', async (req, res) => {
const { email } = req.body;

if (!email) {
return res.status(400).json({ error: 'Email is required' });
}

try {
const token = generateToken();
const expires = Date.now() + (15 * 60 * 1000); // 15 minutes
const magicLink = `${req.protocol}://${req.get('host')}/login/${token}`;

// Store or update user with token
db.run(`INSERT OR REPLACE INTO users (email, token, token_expires) 
VALUES (?, ?, ?)`, 
[email, token, expires], 
function(err) {
if (err) {
console.error('Database error:', err);
return res.status(500).json({ error: 'Database error' });
}

// Send email
const mailOptions = {
from: 'lot.systems.quantum@gmail.com',
to: email,
subject: 'Your Magic Login Link - LOT Systems Quantum',
html: `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
<h2>LOT Systems Quantum - Login Link</h2>
<p>Click the link below to log into your account:</p>
<a href="${magicLink}" style="background: #00000; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
Login to Your Account
</a>
<p style="margin-top: 20px; color: #666; font-size: 14px;">
This link will expire in 15 minutes.<br>
If you didn't request this, please ignore this email.
</p>
<p style="color: #999; font-size: 12px;">
Link: ${magicLink}
</p>
</div>
`
};

transporter.sendMail(mailOptions, (error, info) => {
if (error) {
console.error('Email error:', error);
return res.status(500).json({ error: 'Failed to send email' });
}

console.log('Email sent:', info.messageId);
res.json({ 
success: true, 
message: 'Magic link sent to your email!',
directLink: magicLink // For testing - remove in production
});
});
});

} catch (error) {
console.error('Server error:', error);
res.status(500).json({ error: 'Server error' });
}
});

// Handle magic link login
app.get('/login/:token', (req, res) => {
const { token } = req.params;

db.get(`SELECT * FROM users WHERE token = ? AND token_expires > ?`, 
[token, Date.now()], 
(err, user) => {
if (err) {
console.error('Database error:', err);
return res.status(500).send('Database error');
}

if (!user) {
return res.status(400).send(`
<div style="font-family: Arial, sans-serif; text-align: center; margin-top: 100px;">
<h2>Invalid or Expired Link</h2>
<p>This magic link is either invalid or has expired.</p>
<a href="/" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
Request New Link
</a>
</div>
`);
}

// Update last login and clear token
db.run(`UPDATE users SET last_login = CURRENT_TIMESTAMP, token = NULL, token_expires = NULL 
WHERE id = ?`, 
[user.id], 
(err) => {
if (err) {
console.error('Error updating user:', err);
}
});

// Set session
req.session.user = {
id: user.id,
email: user.email
};

// Redirect to profile
res.redirect('/');
});
});

// Logout
app.get('/logout', (req, res) => {
req.session.destroy((err) => {
if (err) {
console.error('Session destroy error:', err);
}
res.redirect('/');
});
});

// API endpoint to get user info (for debugging)
app.get('/api/user', (req, res) => {
if (!req.session.user) {
return res.status(401).json({ error: 'Not authenticated' });
}
res.json(req.session.user);
});

// Start server
app.listen(PORT, () => {
console.log(`Server running on port ${PORT}`);
console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
console.log('Shutting down gracefully...');
db.close((err) => {
if (err) {
console.error('Error closing database:', err.message);
} else {
console.log('Database connection closed.');
}
process.exit(0);
});
});
