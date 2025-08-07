require(‘dotenv’).config();
const express = require(‘express’);
const sqlite3 = require(‘sqlite3’).verbose();
const crypto = require(‘crypto’);
const session = require(‘express-session’);
const path = require(‘path’);
const { Resend } = require(‘resend’);
const jwt = require(‘jsonwebtoken’);
const axios = require(‘axios’);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || ‘vbglDygJEu7dizNTO2YLfMxXWyD5rRCbSHaH8U453nE=’;

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(‘public’));

// Session configuration
app.use(session({
secret: crypto.randomBytes(32).toString(‘hex’),
resave: false,
saveUninitialized: false,
cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Initialize SQLite database
const db = new sqlite3.Database(’./users.db’);

// Create base tables
db.run(`CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, magic_token TEXT, token_expires INTEGER, login_count INTEGER DEFAULT 0, last_login DATETIME, location TEXT DEFAULT 'California', name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP )`);

db.run(`CREATE TABLE IF NOT EXISTS magic_links ( id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, token TEXT NOT NULL, expires_at INTEGER NOT NULL, used BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP )`);

db.run(`CREATE TABLE IF NOT EXISTS personal_notes ( id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, content TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id) )`);

// Add new columns to existing users table (ignore errors if they exist)
db.run(`ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0`, () => {});
db.run(`ALTER TABLE users ADD COLUMN last_login DATETIME`, () => {});
db.run(`ALTER TABLE users ADD COLUMN location TEXT DEFAULT 'California'`, () => {});
db.run(`ALTER TABLE users ADD COLUMN name TEXT`, () => {});

console.log(‘Server running on port’, PORT);
console.log(‘Environment:’, process.env.NODE_ENV);
console.log(‘Connected to SQLite database.’);
console.log(‘Resend API Key:’, process.env.RESEND_API_KEY ? ‘Configured ✅’ : ‘Missing ❌’);

// Token authentication middleware
function authenticateToken(req, res, next) {
const authHeader = req.headers[‘authorization’];
const token = authHeader && authHeader.split(’ ’)[1];

```
if (!token) {
    return res.status(401).json({ error: 'Access token required' });
}

jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
        return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
});
```

}

// Email function using Resend
async function sendMagicLinkEmail(email, magicLink) {
try {
console.log(‘📧 Sending magic link email to:’, email);

```
    const data = await resend.emails.send({
        from: process.env.FROM_EMAIL || 'onboarding@resend.dev',
        to: [email],
        subject: 'Your Login Link - IoT Systems Quantum',
        html: `
            <div style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                    <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 600;">IoT Systems Quantum</h1>
                    <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0;">Secure Dashboard Access</p>
                </div>
                
                <div style="padding: 40px 30px;">
                    <h2 style="color: #1f2937; margin: 0 0 20px 0;">Your Login Link is Ready</h2>
                    <p style="color: #4b5563; line-height: 1.6; margin: 0 0 30px 0;">
                        Click the button below to securely access your dashboard. This link expires in 15 minutes.
                    </p>
                    
                    <div style="text-align: center; margin: 35px 0;">
                        <a href="${magicLink}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 16px 32px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block;">
                            Access Dashboard →
                        </a>
                    </div>
                    
                    <div style="background: #f9fafb; padding: 20px; border-radius: 6px;">
                        <p style="color: #6b7280; font-size: 14px; margin: 0 0 8px 0;">Or copy this link:</p>
                        <code style="background: #e5e7eb; padding: 8px; border-radius: 4px; font-size: 13px; word-break: break-all; display: block;">${magicLink}</code>
                    </div>
                </div>
                
                <div style="background: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                        🔒 Expires in 15 minutes • If you didn't request this, ignore this email
                    </p>
                </div>
            </div>
        `,
        text: `IoT Systems Quantum - Login Link\n\nClick this link: ${magicLink}\n\nExpires in 15 minutes.`
    });

    console.log('✅ Email sent successfully!');
    console.log('📧 Message ID:', data.id);
    return { success: true, messageId: data.id };
    
} catch (error) {
    console.error('❌ Email error:', error);
    return { success: false, error: error.message };
}
```

}

// Routes
app.get(’/’, (req, res) => {
res.sendFile(path.join(__dirname, ‘public’, ‘index.html’));
});

app.post(’/send-magic-link’, async (req, res) => {
const { email } = req.body;

```
if (!email) {
    return res.status(400).json({ success: false, error: 'Email is required' });
}

try {
    const magicToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + (15 * 60 * 1000);
    const magicLink = `${req.protocol}://${req.get('host')}/verify-magic-link?token=${magicToken}&email=${encodeURIComponent(email)}`;
    
    console.log('🔗 Generated magic link for:', email);
    
    // Store or update user
    db.run(`INSERT OR IGNORE INTO users (email) VALUES (?)`, [email]);
    
    // Store magic link
    db.run(
        `INSERT OR REPLACE INTO magic_links (email, token, expires_at) VALUES (?, ?, ?)`,
        [email, magicToken, expiresAt],
        async function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }
            
            const emailResult = await sendMagicLinkEmail(email, magicLink);
            
            if (emailResult.success) {
                res.json({ 
                    success: true, 
                    message: 'Magic link sent! Check your email.',
                    messageId: emailResult.messageId 
                });
            } else {
                res.status(500).json({ 
                    success: false, 
                    error: 'Failed to send email: ' + emailResult.error 
                });
            }
        }
    );
    
} catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
}
```

});

app.get(’/verify-magic-link’, (req, res) => {
const { token, email } = req.query;

```
if (!token || !email) {
    return res.status(400).send('Invalid magic link');
}

db.get(
    `SELECT * FROM magic_links WHERE token = ? AND email = ? AND used = 0`,
    [token, email],
    (err, row) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Database error');
        }
        
        if (!row) {
            return res.status(400).send('Invalid or expired magic link');
        }
        
        if (Date.now() > row.expires_at) {
            return res.status(400).send('Magic link has expired');
        }
        
        // Mark link as used
        db.run(`UPDATE magic_links SET used = 1 WHERE id = ?`, [row.id]);
        
        // Get or create user
        db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Database error');
            }
            
            if (!user) {
                return res.status(400).send('User not found');
            }
            
            // Update login count and last login
            db.run(`
                UPDATE users 
                SET login_count = COALESCE(login_count, 0) + 1, 
                    last_login = CURRENT_TIMESTAMP,
                    name = COALESCE(name, ?)
                WHERE email = ?
            `, [email.split('@')[0], email]);
            
            // Generate JWT token
            const jwtToken = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email,
                    name: user.name || email.split('@')[0]
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            console.log('✅ Magic link verified for:', email);
            
            // Send HTML that stores token and redirects to profile
            res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login Successful</title>
                    <style>
                        body { font-family: system-ui, sans-serif; text-align: center; padding: 50px; background: #f9fafb; }
                        .container { max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                        h1 { color: #10b981; margin: 0 0 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>✅ Login Successful!</h1>
                        <p>Welcome to IoT Systems Quantum</p>
                        <p>Email: ${email}</p>
                        <p>Redirecting to your profile...</p>
                    </div>
                    <script>
                        localStorage.setItem('authToken', '${jwtToken}');
                        setTimeout(() => window.location.href = '/profile.html', 2000);
                    </script>
                </body>
                </html>
            `);
        });
    }
);
```

});

// Profile API Routes
app.get(’/api/user/profile’, authenticateToken, (req, res) => {
const userId = req.user.id;

```
db.get(`
    SELECT id, email, name, login_count, last_login, location, created_at 
    FROM users WHERE id = ?
`, [userId], (err, user) => {
    if (err) {
        return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Get total user count
    db.get('SELECT COUNT(*) as total FROM users', (err, countResult) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        res.json({
            user: {
                name: user.name || user.email.split('@')[0] || 'User',
                email: user.email,
                loginCount: user.login_count || 0,
                lastLogin: user.last_login,
                location: user.location || 'California'
            },
            stats: {
                totalUsers: countResult.total
            }
        });
    });
});
```

});

app.get(’/api/user/notes’, authenticateToken, (req, res) => {
const userId = req.user.id;

```
db.all(`
    SELECT id, content, created_at, updated_at 
    FROM personal_notes 
    WHERE user_id = ? 
    ORDER BY created_at DESC
`, [userId], (err, notes) => {
    if (err) {
        return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ notes: notes || [] });
});
```

});

app.post(’/api/user/notes’, authenticateToken, (req, res) => {
const userId = req.user.id;
const { content } = req.body;

```
if (!content || content.trim().length === 0) {
    return res.status(400).json({ error: 'Content is required' });
}

db.run(`
    INSERT INTO personal_notes (user_id, content) 
    VALUES (?, ?)
`, [userId, content.trim()], function(err) {
    if (err) {
        return res.status(500).json({ error: 'Database error' });
    }
    
    // Return the created note
    db.get(`
        SELECT id, content, created_at, updated_at 
        FROM personal_notes 
        WHERE id = ?
    `, [this.lastID], (err, note) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        res.status(201).json({ note });
    });
});
```

});

app.delete(’/api/user/notes/:id’, authenticateToken, (req, res) => {
const userId = req.user.id;
const noteId = req.params.id;

```
db.run(`
    DELETE FROM personal_notes 
    WHERE id = ? AND user_id = ?
`, [noteId, userId], function(err) {
    if (err) {
        return res.status(500).json({ error: 'Database error' });
    }
    
    if (this.changes === 0) {
        return res.status(404).json({ error: 'Note not found' });
    }
    
    res.json({ message: 'Note deleted successfully' });
});
```

});

app.get(’/api/weather/current’, authenticateToken, (req, res) => {
const userId = req.user.id;

```
// Get user location
db.get('SELECT location FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
        return res.status(500).json({ error: 'Database error' });
    }
    
    const location = user?.location || 'California';
    
    // Return mock weather data (you can integrate real API later)
    res.json({
        location: location,
        temperature: '75°F',
        humidity: '20% rH',
        description: 'Clear'
    });
});
```

});

// Legacy routes for backward compatibility
app.get(’/dashboard’, (req, res) => {
if (!req.session.authenticated) {
return res.redirect(’/’);
}

```
res.redirect('/profile.html');
```

});

app.get(’/logout’, (req, res) => {
req.session.destroy();
res.send(`<script> localStorage.removeItem('authToken'); window.location.href = '/'; </script>`);
});

app.get(’/health’, (req, res) => {
res.json({
status: ‘OK’,
timestamp: new Date().toISOString(),
resend: !!process.env.RESEND_API_KEY
});
});

app.listen(PORT, () => {
console.log(`🚀 Server running on port ${PORT}`);
console.log(`🌐 Visit: http://localhost:${PORT}`);
});
