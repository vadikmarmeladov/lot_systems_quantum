// package.json
{
“name”: “iot-systems-quantum”,
“version”: “1.0.0”,
“type”: “module”,
“scripts”: {
“dev”: “nodemon src/server.js”,
“start”: “node src/server.js”,
“migrate”: “node src/database/migrate.js”
},
“dependencies”: {
“express”: “^4.18.2”,
“express-rate-limit”: “^7.1.5”,
“helmet”: “^7.1.0”,
“cors”: “^2.8.5”,
“dotenv”: “^16.3.1”,
“pg”: “^8.11.3”,
“redis”: “^4.6.10”,
“jsonwebtoken”: “^9.0.2”,
“bcrypt”: “^5.1.1”,
“joi”: “^17.11.0”,
“resend”: “^2.0.0”,
“axios”: “^1.6.0”,
“winston”: “^3.11.0”,
“compression”: “^1.7.4”,
“express-slow-down”: “^2.0.1”
},
“devDependencies”: {
“nodemon”: “^3.0.1”
}
}

// ============================================================================
// src/server.js - Main application entry point
// ============================================================================

import express from ‘express’;
import helmet from ‘helmet’;
import cors from ‘cors’;
import compression from ‘compression’;
import rateLimit from ‘express-rate-limit’;
import slowDown from ‘express-slow-down’;

import { config } from ‘./config/index.js’;
import { logger } from ‘./utils/logger.js’;
import { connectDB } from ‘./database/connection.js’;
import { connectRedis } from ‘./database/redis.js’;
import { errorHandler, notFound } from ‘./middleware/errorHandler.js’;

// Route imports
import authRoutes from ‘./routes/auth.js’;
import userRoutes from ‘./routes/user.js’;
import weatherRoutes from ‘./routes/weather.js’;

const app = express();

// Security middleware
app.use(helmet({
contentSecurityPolicy: {
directives: {
defaultSrc: [”‘self’”],
styleSrc: [”‘self’”, “‘unsafe-inline’”],
scriptSrc: [”‘self’”],
imgSrc: [”‘self’”, “data:”, “https:”],
},
},
}));

app.use(cors({
origin: config.isDevelopment ? ‘http://localhost:3000’ : config.frontendUrl,
credentials: true
}));

app.use(compression());

// Rate limiting
const limiter = rateLimit({
windowMs: 15 * 60 * 1000, // 15 minutes
max: 100, // limit each IP to 100 requests per windowMs
message: { error: ‘Too many requests from this IP’ }
});

const speedLimiter = slowDown({
windowMs: 15 * 60 * 1000, // 15 minutes
delayAfter: 50, // allow 50 requests per 15 minutes at full speed
delayMs: 500 // add 500ms of delay per request after delayAfter
});

app.use(limiter);
app.use(speedLimiter);

// Body parsing middleware
app.use(express.json({ limit: ‘10mb’ }));
app.use(express.urlencoded({ extended: true, limit: ‘10mb’ }));

// Static files
app.use(express.static(‘public’));

// Request logging
app.use((req, res, next) => {
logger.info(`${req.method} ${req.path}`, {
ip: req.ip,
userAgent: req.get(‘User-Agent’)
});
next();
});

// Routes
app.use(’/api/auth’, authRoutes);
app.use(’/api/user’, userRoutes);
app.use(’/api/weather’, weatherRoutes);

// Health check
app.get(’/health’, (req, res) => {
res.json({
status: ‘OK’,
timestamp: new Date().toISOString(),
version: process.env.npm_package_version,
environment: config.nodeEnv
});
});

// Error handling
app.use(notFound);
app.use(errorHandler);

// Graceful shutdown
process.on(‘SIGTERM’, () => {
logger.info(‘SIGTERM received, shutting down gracefully’);
process.exit(0);
});

async function startServer() {
try {
await connectDB();
await connectRedis();

```
app.listen(config.port, () => {
  logger.info(`🚀 Server running on port ${config.port}`);
  logger.info(`🌐 Environment: ${config.nodeEnv}`);
  logger.info(`📧 Email service: ${config.resendApiKey ? 'Configured ✅' : 'Missing ❌'}`);
});
```

} catch (error) {
logger.error(‘Failed to start server:’, error);
process.exit(1);
}
}

startServer();

// ============================================================================
// src/config/index.js - Configuration management
// ============================================================================

import dotenv from ‘dotenv’;
dotenv.config();

export const config = {
nodeEnv: process.env.NODE_ENV || ‘development’,
port: parseInt(process.env.PORT) || 3000,
isDevelopment: process.env.NODE_ENV === ‘development’,

// Database
database: {
host: process.env.DB_HOST || ‘localhost’,
port: parseInt(process.env.DB_PORT) || 5432,
name: process.env.DB_NAME || ‘iot_quantum’,
user: process.env.DB_USER || ‘postgres’,
password: process.env.DB_PASSWORD || ‘password’,
ssl: process.env.DB_SSL === ‘true’
},

// Redis
redis: {
url: process.env.REDIS_URL || ‘redis://localhost:6379’,
password: process.env.REDIS_PASSWORD
},

// JWT
jwtSecret: process.env.JWT_SECRET || ‘your-super-secret-key-change-in-production’,
jwtExpiresIn: process.env.JWT_EXPIRES_IN || ‘24h’,

// Email
resendApiKey: process.env.RESEND_API_KEY,
fromEmail: process.env.FROM_EMAIL || ‘noreply@yourdomain.com’,

// APIs
weatherApiKey: process.env.WEATHER_API_KEY,

// Frontend
frontendUrl: process.env.FRONTEND_URL || ‘https://yourdomain.com’
};

// ============================================================================
// src/database/connection.js - PostgreSQL connection
// ============================================================================

import pg from ‘pg’;
import { config } from ‘../config/index.js’;
import { logger } from ‘../utils/logger.js’;

const { Pool } = pg;

export const pool = new Pool({
host: config.database.host,
port: config.database.port,
database: config.database.name,
user: config.database.user,
password: config.database.password,
ssl: config.database.ssl ? { rejectUnauthorized: false } : false,
max: 20, // Maximum number of clients in the pool
idleTimeoutMillis: 30000,
connectionTimeoutMillis: 2000,
});

export async function connectDB() {
try {
const client = await pool.connect();
logger.info(‘✅ Connected to PostgreSQL database’);
client.release();
return pool;
} catch (error) {
logger.error(‘❌ Failed to connect to database:’, error);
throw error;
}
}

// ============================================================================
// src/database/redis.js - Redis connection
// ============================================================================

import { createClient } from ‘redis’;
import { config } from ‘../config/index.js’;
import { logger } from ‘../utils/logger.js’;

export const redis = createClient({
url: config.redis.url,
password: config.redis.password
});

redis.on(‘error’, (err) => logger.error(‘Redis Client Error’, err));
redis.on(‘connect’, () => logger.info(‘✅ Connected to Redis’));

export async function connectRedis() {
try {
await redis.connect();
return redis;
} catch (error) {
logger.error(‘❌ Failed to connect to Redis:’, error);
throw error;
}
}

// ============================================================================
// src/database/migrate.js - Database migrations
// ============================================================================

import { pool } from ‘./connection.js’;
import { logger } from ‘../utils/logger.js’;

const migrations = [
{
name: ‘001_initial_tables’,
sql: `
– Users table
CREATE TABLE IF NOT EXISTS users (
id SERIAL PRIMARY KEY,
email VARCHAR(255) UNIQUE NOT NULL,
name VARCHAR(255),
location VARCHAR(255) DEFAULT ‘California’,
login_count INTEGER DEFAULT 0,
last_login TIMESTAMP,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

```
  -- Magic links table
  CREATE TABLE IF NOT EXISTS magic_links (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at BIGINT NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  
  -- Personal notes table
  CREATE TABLE IF NOT EXISTS personal_notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  
  -- Indexes
  CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token);
  CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links(email);
  CREATE INDEX IF NOT EXISTS idx_personal_notes_user_id ON personal_notes(user_id);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
`
```

},
{
name: ‘002_updated_at_triggers’,
sql: `
– Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
NEW.updated_at = CURRENT_TIMESTAMP;
RETURN NEW;
END;
$$ language ‘plpgsql’;

```
  -- Triggers for updated_at
  DROP TRIGGER IF EXISTS update_users_updated_at ON users;
  CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
    
  DROP TRIGGER IF EXISTS update_personal_notes_updated_at ON personal_notes;
  CREATE TRIGGER update_personal_notes_updated_at 
    BEFORE UPDATE ON personal_notes 
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
`
```

}
];

export async function runMigrations() {
const client = await pool.connect();

try {
// Create migrations table
await client.query(`CREATE TABLE IF NOT EXISTS migrations ( id SERIAL PRIMARY KEY, name VARCHAR(255) UNIQUE NOT NULL, executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP )`);

```
for (const migration of migrations) {
  // Check if migration already ran
  const result = await client.query(
    'SELECT 1 FROM migrations WHERE name = $1',
    [migration.name]
  );
  
  if (result.rows.length === 0) {
    logger.info(`Running migration: ${migration.name}`);
    await client.query(migration.sql);
    await client.query(
      'INSERT INTO migrations (name) VALUES ($1)',
      [migration.name]
    );
    logger.info(`✅ Migration completed: ${migration.name}`);
  }
}
```

} catch (error) {
logger.error(‘Migration failed:’, error);
throw error;
} finally {
client.release();
}
}

// Run migrations if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
import(’./connection.js’).then(async () => {
await runMigrations();
process.exit(0);
});
}

// ============================================================================
// src/utils/logger.js - Winston logger configuration
// ============================================================================

import winston from ‘winston’;
import { config } from ‘../config/index.js’;

export const logger = winston.createLogger({
level: config.isDevelopment ? ‘debug’ : ‘info’,
format: winston.format.combine(
winston.format.timestamp(),
winston.format.errors({ stack: true }),
winston.format.json()
),
defaultMeta: { service: ‘iot-quantum’ },
transports: [
new winston.transports.File({ filename: ‘logs/error.log’, level: ‘error’ }),
new winston.transports.File({ filename: ‘logs/combined.log’ }),
],
});

if (config.isDevelopment) {
logger.add(new winston.transports.Console({
format: winston.format.combine(
winston.format.colorize(),
winston.format.simple()
)
}));
}

// ============================================================================
// src/middleware/auth.js - Authentication middleware
// ============================================================================

import jwt from ‘jsonwebtoken’;
import { config } from ‘../config/index.js’;
import { redis } from ‘../database/redis.js’;
import { logger } from ‘../utils/logger.js’;

export const authenticateToken = async (req, res, next) => {
try {
const authHeader = req.headers[‘authorization’];
const token = authHeader && authHeader.split(’ ’)[1];

```
if (!token) {
  return res.status(401).json({ error: 'Access token required' });
}

// Check if token is blacklisted
const isBlacklisted = await redis.get(`blacklist:${token}`);
if (isBlacklisted) {
  return res.status(401).json({ error: 'Token is invalid' });
}

jwt.verify(token, config.jwtSecret, (err, user) => {
  if (err) {
    logger.warn('Invalid token attempt:', { error: err.message });
    return res.status(403).json({ error: 'Invalid token' });
  }
  req.user = user;
  next();
});
```

} catch (error) {
logger.error(‘Authentication error:’, error);
res.status(500).json({ error: ‘Authentication error’ });
}
};

// ============================================================================
// src/middleware/validation.js - Input validation
// ============================================================================

import Joi from ‘joi’;

export const validate = (schema) => {
return (req, res, next) => {
const { error } = schema.validate(req.body);
if (error) {
return res.status(400).json({
error: ‘Validation error’,
details: error.details.map(detail => detail.message)
});
}
next();
};
};

export const schemas = {
email: Joi.object({
email: Joi.string().email().required()
}),

note: Joi.object({
content: Joi.string().min(1).max(5000).required()
}),

updateNote: Joi.object({
content: Joi.string().min(1).max(5000).required()
})
};

// ============================================================================
// src/middleware/errorHandler.js - Error handling
// ============================================================================

import { logger } from ‘../utils/logger.js’;

export const notFound = (req, res, next) => {
const error = new Error(`Not Found - ${req.originalUrl}`);
res.status(404);
next(error);
};

export const errorHandler = (err, req, res, next) => {
let statusCode = res.statusCode === 200 ? 500 : res.statusCode;
let message = err.message;

// PostgreSQL errors
if (err.code === ‘23505’) {
statusCode = 400;
message = ‘Duplicate entry’;
}

logger.error(‘Error:’, {
message: err.message,
stack: err.stack,
url: req.originalUrl,
method: req.method
});

res.status(statusCode).json({
error: message,
…(process.env.NODE_ENV === ‘development’ && { stack: err.stack })
});
};

// ============================================================================
// src/services/emailService.js - Email service
// ============================================================================

import { Resend } from ‘resend’;
import { config } from ‘../config/index.js’;
import { logger } from ‘../utils/logger.js’;

const resend = new Resend(config.resendApiKey);

export const sendMagicLinkEmail = async (email, magicLink) => {
try {
logger.info(‘📧 Sending magic link email to:’, email);

```
const data = await resend.emails.send({
  from: config.fromEmail,
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

logger.info('✅ Email sent successfully!', { messageId: data.id });
return { success: true, messageId: data.id };
```

} catch (error) {
logger.error(‘❌ Email error:’, error);
return { success: false, error: error.message };
}
};

// ============================================================================
// src/routes/auth.js - Authentication routes
// ============================================================================

import express from ‘express’;
import crypto from ‘crypto’;
import jwt from ‘jsonwebtoken’;
import rateLimit from ‘express-rate-limit’;
import { pool } from ‘../database/connection.js’;
import { redis } from ‘../database/redis.js’;
import { config } from ‘../config/index.js’;
import { logger } from ‘../utils/logger.js’;
import { sendMagicLinkEmail } from ‘../services/emailService.js’;
import { validate, schemas } from ‘../middleware/validation.js’;
import { authenticateToken } from ‘../middleware/auth.js’;

const router = express.Router();

// Rate limit for magic link requests
const magicLinkLimiter = rateLimit({
windowMs: 15 * 60 * 1000, // 15 minutes
max: 5, // limit each IP to 5 requests per windowMs
message: { error: ‘Too many magic link requests. Please try again later.’ }
});

// Send magic link
router.post(’/send-magic-link’, magicLinkLimiter, validate(schemas.email), async (req, res) => {
const client = await pool.connect();

try {
const { email } = req.body;
const magicToken = crypto.randomBytes(32).toString(‘hex’);
const expiresAt = Date.now() + (15 * 60 * 1000); // 15 minutes
const magicLink = `${req.protocol}://${req.get('host')}/api/auth/verify-magic-link?token=${magicToken}&email=${encodeURIComponent(email)}`;

```
logger.info('🔗 Generated magic link for:', email);

// Store magic link in database
await client.query(
  'INSERT INTO magic_links (email, token, expires_at) VALUES ($1, $2, $3) ON CONFLICT (token) DO UPDATE SET expires_at = $3',
  [email, magicToken, expiresAt]
);

// Cache magic link in Redis for faster lookup
await redis.setEx(`magic:${magicToken}`, 900, JSON.stringify({ email, expiresAt })); // 15 minutes

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
```

} catch (error) {
logger.error(‘Error sending magic link:’, error);
res.status(500).json({ success: false, error: ‘Server error’ });
} finally {
client.release();
}
});

// Verify magic link
router.get(’/verify-magic-link’, async (req, res) => {
const client = await pool.connect();

try {
const { token, email } = req.query;

```
if (!token || !email) {
  return res.status(400).json({ error: 'Invalid magic link parameters' });
}

// Check Redis first for faster lookup
const cachedData = await redis.get(`magic:${token}`);
let magicLinkData;

if (cachedData) {
  magicLinkData = JSON.parse(cachedData);
} else {
  // Fallback to database
  const result = await client.query(
    'SELECT * FROM magic_links WHERE token = $1 AND email = $2 AND used = FALSE',
    [token, email]
  );
  
  if (result.rows.length === 0) {
    return res.status(400).json({ error: 'Invalid or expired magic link' });
  }
  
  magicLinkData = result.rows[0];
  magicLinkData.expiresAt = magicLinkData.expires_at;
}

if (Date.now() > magicLinkData.expiresAt) {
  await redis.del(`magic:${token}`);
  return res.status(400).json({ error: 'Magic link has expired' });
}

// Mark link as used
await client.query('UPDATE magic_links SET used = TRUE WHERE token = $1', [token]);
await redis.del(`magic:${token}`);

// Create or update user
let user;
const existingUser = await client.query('SELECT * FROM users WHERE email = $1', [email]);

if (existingUser.rows.length === 0) {
  // Create new user
  const insertResult = await client.query(
    'INSERT INTO users (email, name, login_count, last_login) VALUES ($1, $2, 1, CURRENT_TIMESTAMP) RETURNING *',
    [email, email.split('@')[0]]
  );
  user = insertResult.rows[0];
  logger.info('✅ New user created:', email);
} else {
  // Update existing user
  await client.query(
    'UPDATE users SET login_count = login_count + 1, last_login = CURRENT_TIMESTAMP WHERE email = $1',
    [email]
  );
  user = existingUser.rows[0];
  logger.info('✅ User login updated:', email);
}

// Generate JWT token
const jwtToken = jwt.sign(
  { 
    id: user.id, 
    email: user.email,
    name: user.name || user.email.split('@')[0]
  },
  config.jwtSecret,
  { expiresIn: config.jwtExpiresIn }
);

// Cache user session
await redis.setEx(`session:${user.id}`, 24 * 60 * 60, jwtToken); // 24 hours

logger.info('✅ Magic link verified for:', email);

// Redirect to frontend with token
const redirectUrl = `${config.frontendUrl}/dashboard?token=${jwtToken}`;

res.send(`
  <!DOCTYPE html>
  <html>
  <head>
    <title>Login Successful - IoT Systems Quantum</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { 
        font-family: system-ui, sans-serif; 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        margin: 0; padding: 50px 20px; text-align: center; 
        min-height: 100vh; display: flex; align-items: center; justify-content: center;
      }
      .container {
        background: white; border-radius: 12px; padding: 40px; 
        box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-width: 400px; width: 100%;
      }
      .checkmark { color: #10b981; font-size: 48px; margin-bottom: 20px; }
      h1 { color: #1f2937; margin: 0 0 10px 0; font-size: 24px; }
      p { color: #6b7280; margin: 0 0 20px 0; line-height: 1.5; }
      .loading { color: #667eea; font-weight: 500; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="checkmark">✅</div>
      <h1>Login Successful!</h1>
      <p>Welcome to IoT Systems Quantum</p>
      <p class="loading">Redirecting to your dashboard...</p>
    </div>
    <script>
      // Store token and redirect
      if (typeof Storage !== "undefined") {
        localStorage.setItem('authToken', '${jwtToken}');
      }
      setTimeout(() => {
        window.location.href = '${config.frontendUrl}/dashboard';
      }, 2000);
    </script>
  </body>
  </html>
`);
```

} catch (error) {
logger.error(‘Error verifying magic link:’, error);
res.status(500).json({ error: ‘Server error during verification’ });
} finally {
client.release();
}
});

// Logout
router.post(’/logout’, authenticateToken, async (req, res) => {
try {
const token = req.headers[‘authorization’].split(’ ’)[1];

```
// Blacklist the token
await redis.setEx(`blacklist:${token}`, 24 * 60 * 60, 'true'); // 24 hours

// Remove user session
await redis.del(`session:${req.user.id}`);

res.json({ success: true, message: 'Logged out successfully' });
```

} catch (error) {
logger.error(‘Logout error:’, error);
res.status(500).json({ error: ‘Error during logout’ });
}
});

export default router;

// ============================================================================
// src/routes/user.js - User profile and notes routes
// ============================================================================

import express from ‘express’;
import { pool } from ‘../database/connection.js’;
import { authenticateToken } from ‘../middleware/auth.js’;
import { validate, schemas } from ‘../middleware/validation.js’;
import { logger } from ‘../utils/logger.js’;

const router = express.Router();

// All user routes require authentication
router.use(authenticateToken);

// Get user profile
router.get(’/profile’, async (req, res) => {
const client = await pool.connect();

try {
const userId = req.user.id;

```
const userResult = await client.query(
  'SELECT id, email, name, login_count, last_login, location, created_at FROM users WHERE id = $1',
  [userId]
);

if (userResult.rows.length === 0) {
  return res.status(404).json({ error: 'User not found' });
}

const user = userResult.rows[0];

// Get total user count
const countResult = await client.query('SELECT COUNT(*) as total FROM users');

res.json({
  user: {
    id: user.id,
    name: user.name || user.email.split('@')[0] || 'User',
    email: user.email,
    loginCount: user.login_count || 0,
    lastLogin: user.last_login,
    location: user.location || 'California',
    memberSince: user.created_at
  },
  stats: {
    totalUsers: parseInt(countResult.rows[0].total)
  }
});
```

} catch (error) {
logger.error(‘Error fetching user profile:’, error);
res.status(500).json({ error: ‘Database error’ });
} finally {
client.release();
}
});

// Update user profile
router.put(’/profile’, async (req, res) => {
const client = await pool.connect();

try {
const userId = req.user.id;
const { name, location } = req.body;

```
await client.query(
  'UPDATE users SET name = $1, location = $2 WHERE id = $3',
  [name, location, userId]
);

res.json({ success: true, message: 'Profile updated successfully' });
```

} catch (error) {
logger.error(‘Error updating user profile:’, error);
res.status(500).json({ error: ‘Database error’ });
} finally {
client.release();
}
});

// Get user notes
router.get(’/notes’, async (req, res) => {
const client = await pool.connect();

try {
const userId = req.user.id;

```
const result = await client.query(
  'SELECT id, content, created_at, updated_at FROM personal_notes WHERE user_id = $1 ORDER BY created_at DESC',
  [userId]
);

res.json({ notes: result.rows });
```

} catch (error) {
logger.error(‘Error fetching notes:’, error);
res.status(500).json({ error: ‘Database error’ });
} finally {
client.release();
}
});

// Create new note
router.post(’/notes’, validate(schemas.note), async (req, res) => {
const client = await pool.connect();

try {
const userId = req.user.id;
const { content } = req.body;

```
const result = await client.query(
  'INSERT INTO personal_notes (user_id, content) VALUES ($1, $2) RETURNING id, content, created_at, updated_at',
  [userId, content.trim()]
);

res.status(201).json({ note: result.rows[0] });
```

} catch (error) {
logger.error(‘Error creating note:’, error);
res.status(500).json({ error: ‘Database error’ });
} finally {
client.release();
}
});

// Update note
router.put(’/notes/:id’, validate(schemas.updateNote), async (req, res) => {
const client = await pool.connect();

try {
const userId = req.user.id;
const noteId = req.params.id;
const { content } = req.body;

```
const result = await client.query(
  'UPDATE personal_notes SET content = $1 WHERE id = $2 AND user_id = $3 RETURNING id, content, created_at, updated_at',
  [content.trim(), noteId, userId]
);

if (result.rows.length === 0) {
  return res.status(404).json({ error: 'Note not found' });
}

res.json({ note: result.rows[0] });
```

} catch (error) {
logger.error(‘Error updating note:’, error);
res.status(500).json({ error: ‘Database error’ });
} finally {
client.release();
}
});

// Delete note
router.delete(’/notes/:id’, async (req, res) => {
const client = await pool.connect();

try {
const userId = req.user.id;
const noteId = req.params.id;

```
const result = await client.query(
  'DELETE FROM personal_notes WHERE id = $1 AND user_id = $2',
  [noteId, userId]
);

if (result.rowCount === 0) {
  return res.status(404).json({ error: 'Note not found' });
}

res.json({ success: true, message: 'Note deleted successfully' });
```

} catch (error) {
logger.error(‘Error deleting note:’, error);
res.status(500).json({ error: ‘Database error’ });
} finally {
client.release();
}
});

export default router;

// ============================================================================
// src/routes/weather.js - Weather API routes
// ============================================================================

import express from ‘express’;
import axios from ‘axios’;
import { pool } from ‘../database/connection.js’;
import { redis } from ‘../database/redis.js’;
import { authenticateToken } from ‘../middleware/auth.js’;
import { config } from ‘../config/index.js’;
import { logger } from ‘../utils/logger.js’;

const router = express.Router();

// All weather routes require authentication
router.use(authenticateToken);

// Get current weather
router.get(’/current’, async (req, res) => {
const client = await pool.connect();

try {
const userId = req.user.id;

```
// Get user location
const userResult = await client.query('SELECT location FROM users WHERE id = $1', [userId]);
const location = userResult.rows[0]?.location || 'California';

// Check cache first
const cacheKey = `weather:${location.toLowerCase()}`;
const cachedWeather = await redis.get(cacheKey);

if (cachedWeather) {
  return res.json(JSON.parse(cachedWeather));
}

// Fetch from weather API
if (config.weatherApiKey) {
  try {
    const weatherResponse = await axios.get(
      `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(location)}&appid=${config.weatherApiKey}&units=imperial`
    );
    
    const weather = weatherResponse.data;
    const weatherData = {
      location: location,
      temperature: Math.round(weather.main.temp) + '°F',
      humidity: weather.main.humidity + '% rH',
      description: weather.weather[0].description,
      icon: weather.weather[0].icon,
      windSpeed: Math.round(weather.wind?.speed || 0) + ' mph',
      feelsLike: Math.round(weather.main.feels_like) + '°F'
    };
    
    // Cache for 10 minutes
    await redis.setEx(cacheKey, 600, JSON.stringify(weatherData));
    
    res.json(weatherData);
    
  } catch (weatherErr) {
    logger.warn('Weather API error, using fallback data:', weatherErr.message);
    // Fallback to mock data
    const fallbackData = {
      location: location,
      temperature: '75°F',
      humidity: '45% rH',
      description: 'Clear sky',
      icon: '01d',
      windSpeed: '8 mph',
      feelsLike: '77°F'
    };
    
    res.json(fallbackData);
  }
} else {
  // Mock data when no API key
  const mockData = {
    location: location,
    temperature: '72°F',
    humidity: '50% rH',
    description: 'Partly cloudy',
    icon: '02d',
    windSpeed: '12 mph',
    feelsLike: '74°F'
  };
  
  res.json(mockData);
}
```

} catch (error) {
logger.error(‘Weather service error:’, error);
res.status(500).json({ error: ‘Weather service error’ });
} finally {
client.release();
}
});

export default router;

// ============================================================================
// .env.example - Environment variables template
// ============================================================================

/*

# Server Configuration

NODE_ENV=development
PORT=3000
FRONTEND_URL=http://localhost:3000

# Database Configuration

DB_HOST=localhost
DB_PORT=5432
DB_NAME=iot_quantum
DB_USER=postgres
DB_PASSWORD=your_password
DB_SSL=false

# Redis Configuration

REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=

# JWT Configuration

JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=24h

# Email Configuration (Resend)

RESEND_API_KEY=re_your_resend_api_key
FROM_EMAIL=noreply@yourdomain.com

# External APIs

WEATHER_API_KEY=your_openweathermap_api_key
*/

// ============================================================================
// Docker Configuration
// ============================================================================

/*

# docker-compose.yml

version: ‘3.8’

services:
app:
build: .
ports:
- “3000:3000”
environment:
- NODE_ENV=development
- DB_HOST=postgres
- REDIS_URL=redis://redis:6379
depends_on:
- postgres
- redis
volumes:
- .:/app
- /app/node_modules

postgres:
image: postgres:15
environment:
POSTGRES_DB: iot_quantum
POSTGRES_USER: postgres
POSTGRES_PASSWORD: password
ports:
- “5432:5432”
volumes:
- postgres_data:/var/lib/postgresql/data

redis:
image: redis:7-alpine
ports:
- “6379:6379”
volumes:
- redis_data:/data

volumes:
postgres_data:
redis_data:

# Dockerfile

FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci –only=production

COPY . .

EXPOSE 3000

CMD [“npm”, “start”]
*/
