cat > server.js << 'EOF'
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const session = require('express-session');
const path = require('path');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Initialize SQLite database
const db = new sqlite3.Database('./users.db');

// Create tables
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    magic_token TEXT,
    token_expires INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

db.run(`CREATE TABLE IF NOT EXISTS magic_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

console.log('Server running on port', PORT);
console.log('Environment:', process.env.NODE_ENV);
console.log('Connected to SQLite database.');
console.log('Resend API Key:', process.env.RESEND_API_KEY ? 'Configured ✅' : 'Missing ❌');

// Email function using Resend
async function sendMagicLinkEmail(email, magicLink) {
    try {
        console.log('📧 Sending magic link email to:', email);
        
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
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/send-magic-link', async (req, res) => {
    const { email } = req.body;
    
    if (!email || !email.includes('@')) {
        return res.status(400).json({ 
            success: false, 
            error: 'Valid email required' 
        });
    }

    try {
        const magicToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + (15 * 60 * 1000);
        const magicLink = `${req.protocol}://${req.get('host')}/verify-magic-link?token=${magicToken}&email=${encodeURIComponent(email)}`;
        
        console.log('🔗 Generated magic link for:', email);
        
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
});

app.get('/verify-magic-link', (req, res) => {
    const { token, email } = req.query;
    
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
            
            db.run(`UPDATE magic_links SET used = 1 WHERE id = ?`, [row.id]);
            
            req.session.user = { email: email };
            req.session.authenticated = true;
            
            console.log('✅ Magic link verified for:', email);
            
            res.send(`
                <html>
                <head><title>Login Successful</title></head>
                <body style="font-family: system-ui, sans-serif; text-align: center; padding: 50px;">
                    <h1 style="color: #10b981;">✅ Login Successful!</h1>
                    <p>Welcome to IoT Systems Quantum</p>
                    <p>Email: ${email}</p>
                    <script>setTimeout(() => window.location.href = '/dashboard', 2000);</script>
                </body>
                </html>
            `);
        }
    );
});

app.get('/dashboard', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/');
    }
    
    res.send(`
        <html>
        <head><title>IoT Dashboard</title></head>
        <body style="font-family: system-ui, sans-serif; padding: 20px;">
            <h1>🚀 IoT Systems Quantum Dashboard</h1>
            <p>Welcome, ${req.session.user.email}!</p>
            <p>Successfully logged in!</p>
            <a href="/logout">Logout</a>
        </body>
        </html>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        resend: !!process.env.RESEND_API_KEY
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Visit: http://localhost:${PORT}`);
});
EOF
