// Updated server.js - Replace your email configuration with this

require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const session = require('express-session');
const path = require('path');

// Replace nodemailer with Resend
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Initialize SQLite database
const db = new sqlite3.Database('./users.db');

// Create users table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    magic_token TEXT,
    token_expires INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Create magic_links table for tracking
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
console.log('Users table created or already exists.');

// Email sending function using Resend
async function sendMagicLinkEmail(email, magicLink) {
    try {
        console.log('Attempting to send magic link email to:', email);
        
        const data = await resend.emails.send({
            from: process.env.FROM_EMAIL || 'onboarding@resend.dev',
            to: [email],
            subject: 'Your Secure Login Link - IoT Systems Quantum',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>IoT Systems Quantum - Login Link</title>
                </head>
                <body style="margin: 0; padding: 0; background-color: #f8fafc; font-family: system-ui, -apple-system, sans-serif;">
                    <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; margin-top: 40px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);">
                        
                        <!-- Header -->
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center;">
                            <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 600;">
                                IoT Systems Quantum
                            </h1>
                            <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0; font-size: 16px;">
                                Secure Dashboard Access
                            </p>
                        </div>
                        
                        <!-- Content -->
                        <div style="padding: 40px 30px;">
                            <h2 style="color: #1f2937; margin: 0 0 20px 0; font-size: 24px;">
                                Your Login Link is Ready
                            </h2>
                            
                            <p style="color: #4b5563; font-size: 16px; line-height: 1.6; margin: 0 0 30px 0;">
                                Click the button below to securely access your IoT Systems Quantum dashboard. This link is valid for 15 minutes.
                            </p>
                            
                            <!-- CTA Button -->
                            <div style="text-align: center; margin: 35px 0;">
                                <a href="${magicLink}" 
                                   style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                          color: white; 
                                          padding: 16px 32px; 
                                          text-decoration: none; 
                                          border-radius: 8px; 
                                          font-weight: 600; 
                                          font-size: 16px;
                                          display: inline-block;
                                          box-shadow: 0 4px 14px 0 rgba(102, 126, 234, 0.39);">
                                    Access Dashboard →
                                </a>
                            </div>
                            
                            <!-- Alternative link -->
                            <div style="background-color: #f9fafb; padding: 20px; border-radius: 6px; margin: 30px 0;">
                                <p style="color: #6b7280; font-size: 14px; margin: 0 0 8px 0;">
                                    Or copy and paste this link:
                                </p>
                                <code style="background: #e5e7eb; padding: 8px 12px; border-radius: 4px; font-size: 13px; word-break: break-all; display: block; color: #374151;">
                                    ${magicLink}
                                </code>
                            </div>
                        </div>
                        
                        <!-- Footer -->
                        <div style="background-color: #f8fafc; padding: 30px; border-top: 1px solid #e5e7eb;">
                            <div style="text-align: center;">
                                <p style="color: #9ca3af; font-size: 13px; margin: 0; line-height: 1.5;">
                                    🔒 This link expires in 15 minutes for your security<br>
                                    If you didn't request this login, please ignore this email
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Footer note -->
                    <div style="text-align: center; margin: 30px 0;">
                        <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                            IoT Systems Quantum Dashboard
                        </p>
                    </div>
                </body>
                </html>
            `,
            text: `
IoT Systems Quantum - Secure Login

Click this link to access your dashboard:
${magicLink}

This link expires in 15 minutes for security.

If you didn't request this login, please ignore this email.
            `
        });

        console.log('✅ Email sent successfully via Resend');
        console.log('📧 Email ID:', data.id);
        console.log('📬 Sent to:', email);
        
        return { success: true, messageId: data.id };
        
    } catch (error) {
        console.error('❌ Resend email error:', error);
        return { success: false, error: error.message };
    }
}

// Generate magic link token
function generateMagicToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Route: Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route: Send magic link
app.post('/send-magic-link', async (req, res) => {
    const { email } = req.body;
    
    if (!email || !email.includes('@')) {
        return res.status(400).json({ 
            success: false, 
            error: 'Valid email address is required' 
        });
    }

    try {
        // Generate magic token
        const magicToken = generateMagicToken();
        const expiresAt = Date.now() + (15 * 60 * 1000); // 15 minutes
        
        // Create magic link URL
        const magicLink = `${req.protocol}://${req.get('host')}/verify-magic-link?token=${magicToken}&email=${encodeURIComponent(email)}`;
        
        console.log('🔗 Generated magic link for:', email);
        console.log('🎫 Token:', magicToken);
        console.log('⏰ Expires at:', new Date(expiresAt).toISOString());
        
        // Store in database
        db.run(
            `INSERT OR REPLACE INTO magic_links (email, token, expires_at) VALUES (?, ?, ?)`,
            [email, magicToken, expiresAt],
            async function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Database error' 
                    });
                }
                
                // Send email
                const emailResult = await sendMagicLinkEmail(email, magicLink);
                
                if (emailResult.success) {
                    res.json({ 
                        success: true, 
                        message: 'Magic link sent successfully! Check your email.',
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
        console.error('Error in /send-magic-link:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Internal server error' 
        });
    }
});

// Route: Verify magic link
app.get('/verify-magic-link', (req, res) => {
    const { token, email } = req.query;
    
    if (!token || !email) {
        return res.status(400).send('Invalid magic link');
    }
    
    // Check token in database
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
            
            // Check if expired
            if (Date.now() > row.expires_at) {
                return res.status(400).send('Magic link has expired');
            }
            
            // Mark as used
            db.run(
                `UPDATE magic_links SET used = 1 WHERE id = ?`,
                [row.id],
                (err) => {
                    if (err) {
                        console.error('Error marking token as used:', err);
                    }
                }
            );
            
            // Create session
            req.session.user = { email: email };
            req.session.authenticated = true;
            
            console.log('✅ Magic link verified for:', email);
            
            // Redirect to dashboard or send success response
            res.send(`
                <html>
                <head><title>Login Successful</title></head>
                <body style="font-family: system-ui, sans-serif; text-align: center; padding: 50px;">
                    <h1 style="color: #10b981;">✅ Login Successful!</h1>
                    <p>Welcome to IoT Systems Quantum Dashboard</p>
                    <p>Email: ${email}</p>
                    <script>
                        setTimeout(() => {
                            window.location.href = '/dashboard';
                        }, 2000);
                    </script>
                </body>
                </html>
            `);
        }
    );
});

// Route: Dashboard (protected)
app.get('/dashboard', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/');
    }
    
    res.send(`
        <html>
        <head><title>IoT Dashboard</title></head>
        <body style="font-family: system-ui, sans-serif; padding: 20px;">
            <h1>🚀 LOT Systems Quantum Dashboard</h1>
            <p>Welcome, ${req.session.user.email}!</p>
            <p>You are successfully logged in.</p>
            <a href="/logout">Logout</a>
        </body>
        </html>
    `);
});

// Route: Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Access your app at: http://localhost:${PORT}`);
    console.log(`📧 Using Resend for email delivery`);
});
