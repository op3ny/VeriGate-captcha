const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const zlib = require('zlib');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs'); // Para escrever o arquivo captcha-client.js
const cors = require('cors'); // Para lidar com requisições de origem cruzada
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT) || 5843;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `https://<SEU_SITE_AQUI>`;
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '*').split(',').map((origin) => origin.trim()).filter(Boolean);
const SESSION_SECRET = "<SUA_SENHA_AQUI>"
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const TOKEN_BINDING = process.env.TOKEN_BINDING || 'ip';
const NODE_ENV = process.env.NODE_ENV || 'development';
const CSP_ALLOW_UNSAFE_INLINE = process.env.CSP_ALLOW_UNSAFE_INLINE === 'true' || NODE_ENV !== 'production';
const CAPTCHA_COOKIE_NAME = process.env.CAPTCHA_COOKIE_NAME || 'verigate_captcha_token';

// =============================================================================
// 1. Configuração do Banco de Dados
// =============================================================================
const db = new sqlite3.Database('database.db');

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) return reject(err);
            resolve(this);
        });
    });
}

function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) return reject(err);
            resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) return reject(err);
            resolve(rows);
        });
    });
}

function dbExec(sql) {
    return new Promise((resolve, reject) => {
        db.exec(sql, (err) => {
            if (err) return reject(err);
            resolve();
        });
    });
}

async function setupDatabase() {
    await dbExec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await dbExec(`
        CREATE TABLE IF NOT EXISTS captcha_admin_tokens (
            token TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked BOOLEAN NOT NULL DEFAULT 0
        )
    `);


    await dbExec(`
        CREATE TABLE IF NOT EXISTS captcha_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            user_id INTEGER,
            status TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    await dbExec(`
        CREATE TABLE IF NOT EXISTS ip_activity (
            ip_address TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await dbExec(`
        CREATE TABLE IF NOT EXISTS ip_bans (
            ip_address TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )
    `);

    await dbExec(`
        CREATE TABLE IF NOT EXISTS captcha_tokens (
            token TEXT PRIMARY KEY,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_used BOOLEAN NOT NULL DEFAULT 0
        )
    `);

    await dbExec(`
        CREATE TABLE IF NOT EXISTS captcha_challenges (
            challenge_id TEXT PRIMARY KEY,
            ip_address TEXT NOT NULL,
            piece_id TEXT NOT NULL,
            solution_x INTEGER NOT NULL,
            solution_y INTEGER NOT NULL,
            width INTEGER,
            height INTEGER,
            piece_size INTEGER,
            piece_color TEXT,
            target_shape TEXT,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            start_time TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    `);

    try {
        await dbExec('ALTER TABLE captcha_tokens ADD COLUMN user_agent TEXT');
    } catch (error) {
        // Coluna já existe ou migração não necessária.
    }
    try {
        await dbExec('ALTER TABLE captcha_challenges ADD COLUMN width INTEGER');
    } catch (error) {
        // Coluna já existe ou migração não necessária.
    }
    try {
        await dbExec('ALTER TABLE captcha_challenges ADD COLUMN height INTEGER');
    } catch (error) {
        // Coluna já existe ou migração não necessária.
    }
    try {
        await dbExec('ALTER TABLE captcha_challenges ADD COLUMN piece_size INTEGER');
    } catch (error) {
        // Coluna já existe ou migração não necessária.
    }
    try {
        await dbExec('ALTER TABLE captcha_challenges ADD COLUMN piece_color TEXT');
    } catch (error) {
        // Coluna já existe ou migração não necessária.
    }
    try {
        await dbExec('ALTER TABLE captcha_challenges ADD COLUMN target_shape TEXT');
    } catch (error) {
        // Coluna já existe ou migração não necessária.
    }

    console.log('Banco de dados SQLite inicializado com sucesso.');

    const admin = await dbGet('SELECT * FROM users WHERE username = ?', ['admin']);
    if (!admin) {
        const adminPassword = crypto.randomBytes(8).toString('hex');
        const hashedPassword = bcrypt.hashSync(adminPassword, 10);
        
        await dbRun('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', ['admin', hashedPassword, 1]);
        
        console.log('----------------------------------------------------');
        console.log('USUÁRIO ADMIN CRIADO');
        console.log('Nenhum usuário "admin" encontrado, um novo foi criado.');
        console.log(`Username: admin`);
        console.log(`Password: ${adminPassword}`);
        console.log('Guarde esta senha! Ela só é exibida uma vez.');
        console.log('----------------------------------------------------');
    }
}

async function cleanupOldData() {
    await dbRun("DELETE FROM ip_activity WHERE timestamp < datetime('now', '-1 hour')");
    await dbRun("DELETE FROM captcha_logs WHERE timestamp < datetime('now', '-1 day')");
    await dbRun('DELETE FROM ip_bans WHERE expires_at < CURRENT_TIMESTAMP');
    await dbRun('DELETE FROM captcha_tokens WHERE expires_at < CURRENT_TIMESTAMP');
    await dbRun('DELETE FROM captcha_challenges WHERE expires_at < CURRENT_TIMESTAMP');
    
    console.log('Limpeza de dados antigos executada.');
}

setupDatabase().catch((error) => {
    console.error('Falha ao inicializar o banco de dados:', error);
    process.exit(1);
});
setInterval(() => {
    cleanupOldData().catch((error) => {
        console.error('Falha na limpeza de dados:', error);
    });
}, 3600 * 1000);

// =============================================================================
// 2. Monitoramento de Abuso
// =============================================================================
const SUSPICIOUS_TIME_THRESHOLD_MS = 500;
const HUMAN_TIME_MIN_MS = 800;
const MAX_CHALLENGE_TIME_SECONDS = Number(process.env.MAX_CHALLENGE_TIME_SECONDS) || 30;
const ACTIVITY_TIMEFRAME_MINUTES = Number(process.env.ACTIVITY_TIMEFRAME_MINUTES) || 5;
const FAILED_ATTEMPTS_THRESHOLD = Number(process.env.FAILED_ATTEMPTS_THRESHOLD) || 5;
const LOGIN_FAILED_ATTEMPTS_THRESHOLD = Number(process.env.LOGIN_FAILED_ATTEMPTS_THRESHOLD) || 8;
const SUSPICIOUS_TIME_THRESHOLD_COUNT = Number(process.env.SUSPICIOUS_TIME_THRESHOLD_COUNT) || 3;
const EXCESSIVE_GENERATE_THRESHOLD = Number(process.env.EXCESSIVE_GENERATE_THRESHOLD) || 10;
const EXCESSIVE_REQUESTS_THRESHOLD = Number(process.env.EXCESSIVE_REQUESTS_THRESHOLD) || 3;
const BAN_DURATION_MINUTES = Number(process.env.BAN_DURATION_MINUTES) || 1;
const BAN_DURATION_MS = Number(process.env.BAN_DURATION_MS) || 0;
const CAPTCHA_TOKEN_EXPIRATION_MINUTES = Number(process.env.CAPTCHA_TOKEN_EXPIRATION_MINUTES) || 60; // Tempo de vida do token de captcha

function normalizeIp(ipAddress) {
    if (!ipAddress) return ipAddress;
    if (ipAddress.startsWith('::ffff:')) return ipAddress.replace('::ffff:', '');
    if (ipAddress === '::1') return '127.0.0.1';
    return ipAddress;
}

async function getBanStatus(ipAddress) {
    const normalizedIp = normalizeIp(ipAddress);
    const ban = await dbGet(
        "SELECT *, CAST((julianday(expires_at) - julianday('now')) * 86400 AS INTEGER) AS remaining_seconds " +
        "FROM ip_bans WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
        [normalizedIp]
    );
    return ban || null;
}

async function banIp(ipAddress, reason) {
    const normalizedIp = normalizeIp(ipAddress);
    const durationMs = BAN_DURATION_MS > 0 ? BAN_DURATION_MS : BAN_DURATION_MINUTES * 60 * 1000;
    const durationSeconds = Math.max(1, Math.ceil(durationMs / 1000));
    await dbRun(
        "INSERT OR REPLACE INTO ip_bans (ip_address, reason, banned_at, expires_at) " +
        "VALUES (?, ?, CURRENT_TIMESTAMP, datetime('now', ?))",
        [normalizedIp, reason, `+${durationSeconds} seconds`]
    );
}

function getCookie(req, name) {
    const raw = req.headers && req.headers.cookie ? req.headers.cookie : '';
    if (!raw) return null;
    const cookies = raw.split(';');
    for (const pair of cookies) {
        const index = pair.indexOf('=');
        if (index === -1) continue;
        const key = pair.slice(0, index).trim();
        if (key === name) {
            return decodeURIComponent(pair.slice(index + 1).trim());
        }
    }
    return null;
}

async function recordSuspiciousActivity(ipAddress, activityType, details = '') {
    const normalizedIp = normalizeIp(ipAddress) || '0.0.0.0';
    await dbRun('INSERT INTO ip_activity (ip_address, activity_type, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP)', [normalizedIp, activityType]);
    
    await dbRun('INSERT INTO captcha_logs (ip_address, status, details, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', [normalizedIp, activityType, details]);

    const timeframe = `-${ACTIVITY_TIMEFRAME_MINUTES} minutes`;

    const suspiciousTimeRow = await dbGet(
        "SELECT COUNT(*) as count FROM ip_activity WHERE ip_address = ? AND activity_type = ? AND timestamp > datetime('now', ?)"
        , [normalizedIp, 'fail_time', timeframe]
    );

    const failedAttemptsRow = await dbGet(
        "SELECT COUNT(*) as count FROM ip_activity WHERE ip_address = ? AND activity_type = ? AND timestamp > datetime('now', ?)"
        , [normalizedIp, 'fail_wrong', timeframe]
    );

    const excessiveGenerateRow = await dbGet(
        "SELECT COUNT(*) as count FROM ip_activity WHERE ip_address = ? AND activity_type = ? AND timestamp > datetime('now', ?)"
        , [normalizedIp, 'excessive_generate', timeframe]
    );

    const loginFailedRow = await dbGet(
        "SELECT COUNT(*) as count FROM ip_activity WHERE ip_address = ? AND activity_type = ? AND timestamp > datetime('now', ?)"
        , [normalizedIp, 'login_fail', timeframe]
    );

    const excessiveRequestsRow = await dbGet(
        "SELECT COUNT(*) as count FROM ip_activity WHERE ip_address = ? AND activity_type = ? AND timestamp > datetime('now', ?)"
        , [normalizedIp, 'excessive_requests', timeframe]
    );

    const suspiciousTimeCount = suspiciousTimeRow ? suspiciousTimeRow.count : 0;
    const failedAttemptsCount = failedAttemptsRow ? failedAttemptsRow.count : 0;
    const excessiveGenerateCount = excessiveGenerateRow ? excessiveGenerateRow.count : 0;
    const loginFailedCount = loginFailedRow ? loginFailedRow.count : 0;
    const excessiveRequestsCount = excessiveRequestsRow ? excessiveRequestsRow.count : 0;

    let banReason = null;
    if (suspiciousTimeCount >= SUSPICIOUS_TIME_THRESHOLD_COUNT) {
        banReason = `Banido por resolver CAPTCHA rápido demais ${suspiciousTimeCount} vezes em ${ACTIVITY_TIMEFRAME_MINUTES} minutos.`;
    } else if (failedAttemptsCount >= FAILED_ATTEMPTS_THRESHOLD) {
        banReason = `Banido por ${failedAttemptsCount} tentativas incorretas de CAPTCHA em ${ACTIVITY_TIMEFRAME_MINUTES} minutos.`;
    } else if (excessiveGenerateCount >= EXCESSIVE_GENERATE_THRESHOLD) {
        banReason = `Banido por ${excessiveGenerateCount} gerações excessivas de CAPTCHA em ${ACTIVITY_TIMEFRAME_MINUTES} minutos.`;
    } else if (loginFailedCount >= LOGIN_FAILED_ATTEMPTS_THRESHOLD) {
        banReason = `Banido por ${loginFailedCount} tentativas de login inválidas em ${ACTIVITY_TIMEFRAME_MINUTES} minutos.`;
    } else if (excessiveRequestsCount >= EXCESSIVE_REQUESTS_THRESHOLD) {
        banReason = `Banido por excesso de requisições em ${ACTIVITY_TIMEFRAME_MINUTES} minutos.`;
    }

    if (banReason) {
        await banIp(normalizedIp, banReason);
    }
}

// =============================================================================
// 3. Middlewares de Autenticação/Autorização
// =============================================================================
async function blockBanned(req, res, next) {
    try {
        const banStatus = await getBanStatus(req.ipAddress);
        if (banStatus) {
            if (req.path.startsWith('/captcha')) {
                return res.status(403).json({ error: 'Seu IP está temporariamente bloqueado.', reason: banStatus.reason });
            }
            const remainingMs = typeof banStatus.remaining_seconds === 'number'
                ? Math.max(0, banStatus.remaining_seconds * 1000)
                : null;
            return res.status(403).render('banned', {
                title: 'Acesso Bloqueado',
                error: banStatus.reason,
                banned: [],
                currentBan: {
                    ip_address: banStatus.ip_address,
                    reason: banStatus.reason,
                    banned_at: banStatus.banned_at,
                    expires_at: banStatus.expires_at,
                    remaining_ms: remainingMs
                }
            });
        }
        return next();
    } catch (error) {
        return next(error);
    }
}

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login?error=' + encodeURIComponent('Você precisa fazer login para acessar esta página.'));
}

function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.isAdmin) {
        return next();
    }
    res.redirect('/profile?error=' + encodeURIComponent('Acesso negado. Você não tem permissão de administrador.'));
}

// =============================================================================
// 4. Configuração do Express e Middlewares Gerais
// =============================================================================
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

if (!process.env.SESSION_SECRET) {
    console.warn('[VeriGate] SESSION_SECRET não definido. Um segredo temporário foi gerado (não recomendado para produção).');
}

app.set('trust proxy', TRUST_PROXY ? 1 : 0);

app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
});

const buildScriptSrc = () => {
    const base = ["'self'", 'https://cdn.jsdelivr.net'];
    if (CSP_ALLOW_UNSAFE_INLINE) {
        return [...base, "'unsafe-inline'"];
    }
    return [...base, (req, res) => `'nonce-${res.locals.cspNonce}'`];
};

app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            baseUri: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'self'"],
            scriptSrc: buildScriptSrc(),
            scriptSrcElem: buildScriptSrc(),
            styleSrc: ["'self'", 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"]
        }
    }
}));

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: false,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use('/captcha', cors(corsOptions));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const globalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path.startsWith('/captcha'),
    handler: async (req, res) => {
        await recordSuspiciousActivity(req.ipAddress, 'excessive_requests', 'Rate limit excedido.');
        return res.status(429).send('Muitas requisições. Tente novamente em alguns minutos.');
    }
});
app.use(globalLimiter);

app.use((req, res, next) => {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor && typeof forwardedFor === 'string') {
        req.ipAddress = normalizeIp(forwardedFor.split(',')[0].trim());
    } else if (req.ip) {
        req.ipAddress = normalizeIp(req.ip);
    } else if (req.socket && req.socket.remoteAddress) {
        req.ipAddress = normalizeIp(req.socket.remoteAddress);
    } else {
        req.ipAddress = '0.0.0.0';
    }
    next();
});

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.SESSION_SECURE === 'true'
    }
}));

app.use((req, res, next) => {
    res.locals.user = req.session.user;
    res.locals.ipAddress = req.ipAddress;
    res.locals.error = req.query.error;
    res.locals.success = req.query.success;
    next();
});

// =============================================================================
// 5. Rotas do CAPTCHA
// =============================================================================
const captchaGenerateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false
});
const captchaActionLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.path === '/captcha/move'
});
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false
});

const CAPTCHA_MIN_WIDTH = 280;
const CAPTCHA_MAX_WIDTH = 420;
const CAPTCHA_MIN_HEIGHT = 120;
const CAPTCHA_MAX_HEIGHT = 200;
const CAPTCHA_MIN_PIECE_SIZE = 40;
const CAPTCHA_MAX_PIECE_SIZE = 60;
const CAPTCHA_TOLERANCE = 15;
const CAPTCHA_PIECE_COLOR = '#0d6efd';
const CAPTCHA_TARGET_SHAPES = ['rect', 'circle', 'rounded'];
const CAPTCHA_OVERLAY_MIN_SCALE = 0.85;
const CAPTCHA_OVERLAY_MAX_SCALE = 1.15;
const STREAM_ANALYSIS_MIN_POINTS = 14;
const STREAM_ANALYSIS_MIN_DISTANCE = 35;
const STREAM_ANALYSIS_MIN_TIME_MS = 450;
const MOVEMENT_MAX_POINTS = 3000;

const movementQueues = new Map();

const getRandomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const generateId = () => crypto.randomBytes(6).toString('hex');

function appendMovement(challengeId, points) {
    if (!Array.isArray(points) || points.length === 0) return;
    const queue = movementQueues.get(challengeId) || [];
    for (const point of points) {
        if (point && typeof point.x === 'number' && typeof point.y === 'number') {
            queue.push({
                x: point.x,
                y: point.y,
                timestamp: typeof point.timestamp === 'number' ? point.timestamp : Date.now()
            });
        }
    }
    if (queue.length > MOVEMENT_MAX_POINTS) {
        queue.splice(0, queue.length - MOVEMENT_MAX_POINTS);
    }
    movementQueues.set(challengeId, queue);
}

const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c >>> 0;
    }
    return table;
})();

function crc32(buf) {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
        c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
    const typeBuf = Buffer.from(type);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(data.length, 0);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function parseHexColor(hex) {
    const normalized = hex.replace('#', '');
    const r = parseInt(normalized.slice(0, 2), 16);
    const g = parseInt(normalized.slice(2, 4), 16);
    const b = parseInt(normalized.slice(4, 6), 16);
    return { r, g, b };
}

function encodePng(width, height, rgbaBuffer) {
    const stride = width * 4;
    const raw = Buffer.alloc((stride + 1) * height);
    for (let y = 0; y < height; y++) {
        const rowStart = y * (stride + 1);
        raw[rowStart] = 0;
        rgbaBuffer.copy(raw, rowStart + 1, y * stride, (y + 1) * stride);
    }
    const compressed = zlib.deflateSync(raw);
    const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = 8;
    ihdr[9] = 6;
    ihdr[10] = 0;
    ihdr[11] = 0;
    ihdr[12] = 0;
    return Buffer.concat([signature, pngChunk('IHDR', ihdr), pngChunk('IDAT', compressed), pngChunk('IEND', Buffer.alloc(0))]);
}

function setPixel(rgbaBuffer, width, x, y, r, g, b, a = 255) {
    const idx = (width * y + x) * 4;
    rgbaBuffer[idx] = r;
    rgbaBuffer[idx + 1] = g;
    rgbaBuffer[idx + 2] = b;
    rgbaBuffer[idx + 3] = a;
}

function fillRect(rgbaBuffer, width, height, x, y, rectWidth, rectHeight, r, g, b, a = 255) {
    const startX = Math.max(0, x);
    const startY = Math.max(0, y);
    const endX = Math.min(width, x + rectWidth);
    const endY = Math.min(height, y + rectHeight);
    for (let yy = startY; yy < endY; yy++) {
        for (let xx = startX; xx < endX; xx++) {
            setPixel(rgbaBuffer, width, xx, yy, r, g, b, a);
        }
    }
}

function drawRectOutline(rgbaBuffer, width, height, x, y, rectWidth, rectHeight, r, g, b, a = 255) {
    for (let xx = x; xx < x + rectWidth; xx++) {
        if (xx >= 0 && xx < width) {
            if (y >= 0 && y < height) setPixel(rgbaBuffer, width, xx, y, r, g, b, a);
            const bottom = y + rectHeight - 1;
            if (bottom >= 0 && bottom < height) setPixel(rgbaBuffer, width, xx, bottom, r, g, b, a);
        }
    }
    for (let yy = y; yy < y + rectHeight; yy++) {
        if (yy >= 0 && yy < height) {
            if (x >= 0 && x < width) setPixel(rgbaBuffer, width, x, yy, r, g, b, a);
            const right = x + rectWidth - 1;
            if (right >= 0 && right < width) setPixel(rgbaBuffer, width, right, yy, r, g, b, a);
        }
    }
}

function fillCircle(rgbaBuffer, width, height, cx, cy, radius, r, g, b, a = 255) {
    const r2 = radius * radius;
    const startX = Math.max(0, Math.floor(cx - radius));
    const endX = Math.min(width, Math.ceil(cx + radius));
    const startY = Math.max(0, Math.floor(cy - radius));
    const endY = Math.min(height, Math.ceil(cy + radius));
    for (let y = startY; y < endY; y++) {
        for (let x = startX; x < endX; x++) {
            const dx = x - cx;
            const dy = y - cy;
            if ((dx * dx + dy * dy) <= r2) {
                setPixel(rgbaBuffer, width, x, y, r, g, b, a);
            }
        }
    }
}

function drawCircleOutline(rgbaBuffer, width, height, cx, cy, radius, r, g, b, a = 255) {
    const r2 = radius * radius;
    const inner = (radius - 1) * (radius - 1);
    const startX = Math.max(0, Math.floor(cx - radius));
    const endX = Math.min(width, Math.ceil(cx + radius));
    const startY = Math.max(0, Math.floor(cy - radius));
    const endY = Math.min(height, Math.ceil(cy + radius));
    for (let y = startY; y < endY; y++) {
        for (let x = startX; x < endX; x++) {
            const dx = x - cx;
            const dy = y - cy;
            const d2 = dx * dx + dy * dy;
            if (d2 <= r2 && d2 >= inner) {
                setPixel(rgbaBuffer, width, x, y, r, g, b, a);
            }
        }
    }
}

function fillRoundedRect(rgbaBuffer, width, height, x, y, rectWidth, rectHeight, radius, r, g, b, a = 255) {
    const r2 = radius * radius;
    for (let yy = y; yy < y + rectHeight; yy++) {
        for (let xx = x; xx < x + rectWidth; xx++) {
            if (xx < 0 || yy < 0 || xx >= width || yy >= height) continue;
            const dx = xx < x + radius ? x + radius - xx : xx >= x + rectWidth - radius ? xx - (x + rectWidth - radius - 1) : 0;
            const dy = yy < y + radius ? y + radius - yy : yy >= y + rectHeight - radius ? yy - (y + rectHeight - radius - 1) : 0;
            if (dx === 0 || dy === 0 || (dx * dx + dy * dy) <= r2) {
                setPixel(rgbaBuffer, width, xx, yy, r, g, b, a);
            }
        }
    }
}

function drawRoundedRectOutline(rgbaBuffer, width, height, x, y, rectWidth, rectHeight, radius, r, g, b, a = 255) {
    fillRoundedRect(rgbaBuffer, width, height, x, y, rectWidth, rectHeight, radius, r, g, b, a);
    fillRoundedRect(rgbaBuffer, width, height, x + 1, y + 1, rectWidth - 2, rectHeight - 2, Math.max(0, radius - 1), 0, 0, 0, 0);
}

function createCaptchaPng(width, height, targetX, targetY, pieceSize, targetShape) {
    const rgbaBuffer = Buffer.alloc(width * height * 4);
    for (let i = 0; i < rgbaBuffer.length; i += 4) {
        rgbaBuffer[i] = 240;
        rgbaBuffer[i + 1] = 240;
        rgbaBuffer[i + 2] = 240;
        rgbaBuffer[i + 3] = 255;
    }
    drawRectOutline(rgbaBuffer, width, height, 0, 0, width, height, 204, 204, 204, 255);
    if (targetShape === 'circle') {
        const radius = Math.floor(pieceSize / 2);
        const cx = targetX + radius;
        const cy = targetY + radius;
        fillCircle(rgbaBuffer, width, height, cx, cy, radius, 224, 224, 224, 255);
        drawCircleOutline(rgbaBuffer, width, height, cx, cy, radius, 153, 153, 153, 255);
    } else if (targetShape === 'rounded') {
        const radius = Math.max(6, Math.floor(pieceSize / 5));
        fillRoundedRect(rgbaBuffer, width, height, targetX, targetY, pieceSize, pieceSize, radius, 153, 153, 153, 255);
        fillRoundedRect(rgbaBuffer, width, height, targetX + 1, targetY + 1, pieceSize - 2, pieceSize - 2, Math.max(0, radius - 1), 224, 224, 224, 255);
    } else {
        fillRect(rgbaBuffer, width, height, targetX, targetY, pieceSize, pieceSize, 224, 224, 224, 255);
        drawRectOutline(rgbaBuffer, width, height, targetX, targetY, pieceSize, pieceSize, 153, 153, 153, 255);
    }
    return encodePng(width, height, rgbaBuffer);
}

function decodePng(buffer) {
    const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    if (!buffer.slice(0, 8).equals(signature)) {
        throw new Error('PNG inválido.');
    }
    let offset = 8;
    let width = 0;
    let height = 0;
    let bitDepth = 0;
    let colorType = 0;
    const idatChunks = [];
    while (offset < buffer.length) {
        const length = buffer.readUInt32BE(offset);
        const type = buffer.slice(offset + 4, offset + 8).toString('ascii');
        const data = buffer.slice(offset + 8, offset + 8 + length);
        offset += 12 + length;
        if (type === 'IHDR') {
            width = data.readUInt32BE(0);
            height = data.readUInt32BE(4);
            bitDepth = data[8];
            colorType = data[9];
        } else if (type === 'IDAT') {
            idatChunks.push(data);
        } else if (type === 'IEND') {
            break;
        }
    }
    if (bitDepth !== 8 || colorType !== 6) {
        throw new Error('PNG com formato não suportado.');
    }
    const compressed = Buffer.concat(idatChunks);
    const raw = zlib.inflateSync(compressed);
    const stride = width * 4;
    const rgba = Buffer.alloc(width * height * 4);
    let rawOffset = 0;
    let outOffset = 0;
    const paeth = (a, b, c) => {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        if (pa <= pb && pa <= pc) return a;
        if (pb <= pc) return b;
        return c;
    };
    for (let y = 0; y < height; y++) {
        const filter = raw[rawOffset++];
        for (let x = 0; x < stride; x++) {
            const rawByte = raw[rawOffset++];
            const left = x >= 4 ? rgba[outOffset + x - 4] : 0;
            const up = y > 0 ? rgba[outOffset + x - stride] : 0;
            const upLeft = (y > 0 && x >= 4) ? rgba[outOffset + x - stride - 4] : 0;
            let value;
            if (filter === 0) value = rawByte;
            else if (filter === 1) value = (rawByte + left) & 0xff;
            else if (filter === 2) value = (rawByte + up) & 0xff;
            else if (filter === 3) value = (rawByte + Math.floor((left + up) / 2)) & 0xff;
            else if (filter === 4) value = (rawByte + paeth(left, up, upLeft)) & 0xff;
            else throw new Error('Filtro PNG não suportado.');
            rgba[outOffset + x] = value;
        }
        outOffset += stride;
    }
    return { width, height, data: rgba };
}

function extractPieceCenterFromImage(rgba, width, height, color) {
    const colorTolerance = 20;
    let minX = width;
    let minY = height;
    let maxX = -1;
    let maxY = -1;
    for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
            const idx = (width * y + x) * 4;
            const r = rgba[idx];
            const g = rgba[idx + 1];
            const b = rgba[idx + 2];
            if (Math.abs(r - color.r) <= colorTolerance &&
                Math.abs(g - color.g) <= colorTolerance &&
                Math.abs(b - color.b) <= colorTolerance) {
                if (x < minX) minX = x;
                if (y < minY) minY = y;
                if (x > maxX) maxX = x;
                if (y > maxY) maxY = y;
            }
        }
    }
    if (maxX < 0 || maxY < 0) return null;
    return {
        centerX: (minX + maxX) / 2,
        centerY: (minY + maxY) / 2
    };
}

function analyzeMovementData(movementData) {
    if (!Array.isArray(movementData) || movementData.length < 2) {
        return { suspicious: true, reasons: ['poucos_pontos'] };
    }

    const points = movementData
        .filter((p) => p && typeof p.x === 'number' && typeof p.y === 'number' && typeof p.timestamp === 'number')
        .sort((a, b) => a.timestamp - b.timestamp);

    if (points.length < 2) {
        return { suspicious: true, reasons: ['pontos_invalidos'] };
    }

    let totalDistance = 0;
    let totalTime = points[points.length - 1].timestamp - points[0].timestamp;
    let linearDistance = Math.hypot(points[points.length - 1].x - points[0].x, points[points.length - 1].y - points[0].y);
    let directionChanges = 0;
    let speedSamples = [];
    let intervalSamples = [];
    let lastAngle = null;
    let pauses = 0;

    for (let i = 1; i < points.length; i++) {
        const dx = points[i].x - points[i - 1].x;
        const dy = points[i].y - points[i - 1].y;
        const dt = points[i].timestamp - points[i - 1].timestamp;
        const dist = Math.hypot(dx, dy);
        totalDistance += dist;

        if (dt > 0) {
            speedSamples.push(dist / dt);
            intervalSamples.push(dt);
            if (dt > 220) pauses += 1;
        }

        const angle = Math.atan2(dy, dx);
        if (lastAngle !== null) {
            const delta = Math.abs(angle - lastAngle);
            if (delta > 0.35) directionChanges += 1;
        }
        lastAngle = angle;
    }

    const avgSpeed = speedSamples.reduce((a, b) => a + b, 0) / speedSamples.length;
    const speedVar = speedSamples.reduce((a, b) => a + Math.pow(b - avgSpeed, 2), 0) / speedSamples.length;
    const speedStd = Math.sqrt(speedVar);

    const avgInterval = intervalSamples.reduce((a, b) => a + b, 0) / intervalSamples.length;
    const intervalVar = intervalSamples.reduce((a, b) => a + Math.pow(b - avgInterval, 2), 0) / intervalSamples.length;
    const intervalStd = Math.sqrt(intervalVar);

    const straightness = linearDistance > 0 ? totalDistance / linearDistance : 0;

    const reasons = [];
    if (points.length < 6 && totalDistance > 20) reasons.push('poucos_pontos');
    if (straightness < 1.02) reasons.push('muito_reto');
    if (directionChanges < 1 && totalDistance > 55) reasons.push('poucas_mudancas_direcao');
    if (speedStd < 0.0002 && totalDistance > 45) reasons.push('velocidade_constante');
    if (intervalStd < 2 && intervalSamples.length > 7) reasons.push('intervalos_constantes');
    if (pauses === 0 && totalTime > 1300 && totalDistance > 80) reasons.push('sem_pausas');

    return {
        suspicious: reasons.length >= 4 || (reasons.length >= 3 && totalDistance > 140),
        reasons,
        stats: {
            totalDistance,
            totalTime,
            straightness,
            directionChanges,
            avgSpeed,
            speedStd,
            avgInterval,
            intervalStd,
            pauses
        }
    };
}

// Função para gerar um token de CAPTCHA
async function generateCaptchaToken(ipAddress, userAgent) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + CAPTCHA_TOKEN_EXPIRATION_MINUTES * 60 * 1000).toISOString();
    await dbRun('INSERT INTO captcha_tokens (token, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?)', [token, ipAddress, userAgent || null, expiresAt]);
    return token;
}

// Rota para gerar o desafio CAPTCHA (apenas a peça e o buraco, sem iniciar timer)
app.get('/captcha/generate', captchaGenerateLimiter, blockBanned, async (req, res) => {
    const generateRow = await dbGet(
        "SELECT COUNT(*) as count FROM ip_activity WHERE ip_address = ? AND activity_type = ? AND timestamp > datetime('now', ?)",
        [req.ipAddress, 'generate', `-${ACTIVITY_TIMEFRAME_MINUTES} minutes`]
    );
    const generateCount = generateRow ? generateRow.count : 0;

    if (generateCount >= EXCESSIVE_GENERATE_THRESHOLD) {
        await recordSuspiciousActivity(req.ipAddress, 'excessive_generate', 'Geração excessiva de CAPTCHA.');
        return res.status(429).json({ error: 'Muitas tentativas de geração de CAPTCHA. Tente novamente em alguns minutos.' });
    }
    
    await dbRun('INSERT INTO ip_activity (ip_address, activity_type, timestamp) VALUES (?, ?, CURRENT_TIMESTAMP)', [req.ipAddress, 'generate']);

    const pieceId = generateId();
    const challengeId = generateId();

    const width = getRandomInt(CAPTCHA_MIN_WIDTH, CAPTCHA_MAX_WIDTH);
    const height = getRandomInt(CAPTCHA_MIN_HEIGHT, CAPTCHA_MAX_HEIGHT);
    let pieceSize = getRandomInt(CAPTCHA_MIN_PIECE_SIZE, CAPTCHA_MAX_PIECE_SIZE);
    pieceSize = Math.max(30, Math.min(pieceSize, width - 20, height - 20));
    const targetShape = CAPTCHA_TARGET_SHAPES[getRandomInt(0, CAPTCHA_TARGET_SHAPES.length - 1)];
    const overlayScale = Math.round((CAPTCHA_OVERLAY_MIN_SCALE + Math.random() * (CAPTCHA_OVERLAY_MAX_SCALE - CAPTCHA_OVERLAY_MIN_SCALE)) * 100) / 100;

    const targetX = getRandomInt(0, width - pieceSize);
    const targetY = getRandomInt(0, height - pieceSize);

    const imageBuffer = createCaptchaPng(width, height, targetX, targetY, pieceSize, targetShape);
    const image = `data:image/png;base64,${imageBuffer.toString('base64')}`;

    const expiresAt = new Date(Date.now() + (MAX_CHALLENGE_TIME_SECONDS + 60) * 1000).toISOString();
    await dbRun(
        'INSERT INTO captcha_challenges (challenge_id, ip_address, piece_id, solution_x, solution_y, width, height, piece_size, piece_color, target_shape, generated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)',
        [challengeId, req.ipAddress, pieceId, targetX, targetY, width, height, pieceSize, CAPTCHA_PIECE_COLOR, targetShape, expiresAt]
    );
    
    await dbRun('INSERT INTO captcha_logs (ip_address, status, details, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', [req.ipAddress, 'generated', `Challenge ID: ${challengeId}`]);

    res.json({
        image,
        challengeId,
        maxTime: MAX_CHALLENGE_TIME_SECONDS,
        width,
        height,
        pieceSize,
        pieceColor: CAPTCHA_PIECE_COLOR,
        targetShape,
        overlayScale,
        tokenExpirationMinutes: CAPTCHA_TOKEN_EXPIRATION_MINUTES
    });
});

// Configuração pública para integração externa
app.get('/captcha/config', (req, res) => {
    res.json({
        maxChallengeTimeSeconds: MAX_CHALLENGE_TIME_SECONDS,
        pieceSize: CAPTCHA_MAX_PIECE_SIZE,
        width: CAPTCHA_MAX_WIDTH,
        height: CAPTCHA_MAX_HEIGHT,
        pieceColor: CAPTCHA_PIECE_COLOR,
        tolerance: CAPTCHA_TOLERANCE,
        tokenExpirationMinutes: CAPTCHA_TOKEN_EXPIRATION_MINUTES
    });
});

app.post('/captcha/start-challenge', captchaActionLimiter, blockBanned, async (req, res) => {
    const { challengeId } = req.body;
    const challenge = await dbGet('SELECT * FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
    if (!challenge || challenge.ip_address !== req.ipAddress) {
        movementQueues.delete(challengeId);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA inválido ou expirado.' });
    }
    if (new Date(challenge.expires_at) < new Date()) {
        await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
        movementQueues.delete(challengeId);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA expirado. Por favor, gere um novo.' });
    }

    const startTime = Date.now();
    await dbRun('UPDATE captcha_challenges SET start_time = ? WHERE challenge_id = ?', [startTime, challengeId]);
    movementQueues.set(challengeId, []);
    res.json({ success: true, startTime });
});

app.post('/captcha/move', captchaActionLimiter, blockBanned, async (req, res) => {
    const { challengeId, image } = req.body || {};
    if (!challengeId || !image) {
        return res.status(400).json({ success: false, message: 'Parâmetros inválidos.' });
    }

    const challenge = await dbGet('SELECT * FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
    if (!challenge || challenge.ip_address !== req.ipAddress || !challenge.start_time) {
        movementQueues.delete(challengeId);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA inválido.' });
    }
    if (new Date(challenge.expires_at) < new Date()) {
        await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
        movementQueues.delete(challengeId);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA expirado.' });
    }

    try {
        const base64 = image.startsWith('data:image/png;base64,')
            ? image.replace('data:image/png;base64,', '')
            : image;
        const buffer = Buffer.from(base64, 'base64');
        const decoded = decodePng(buffer);
        const pieceColor = parseHexColor(challenge.piece_color || CAPTCHA_PIECE_COLOR);
        const center = extractPieceCenterFromImage(decoded.data, decoded.width, decoded.height, pieceColor);
        if (!center) {
            return res.status(400).json({ success: false, message: 'Imagem inválida.' });
        }
        appendMovement(challengeId, [{ x: center.centerX, y: center.centerY, timestamp: Date.now() }]);
    } catch (error) {
        return res.status(400).json({ success: false, message: 'Erro ao analisar imagem.' });
    }

    const count = (movementQueues.get(challengeId) || []).length;
    return res.json({ success: true, count });
});

app.post('/captcha/verify', captchaActionLimiter, blockBanned, async (req, res) => {
    const { finalX, finalY, challengeId, movementData, image } = req.body;
    const challenge = await dbGet('SELECT * FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
    if (!challenge || challenge.ip_address !== req.ipAddress || !challenge.start_time) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', `Tentativa de verificação sem desafio válido para ID: ${challengeId}`);
        await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
        movementQueues.delete(challengeId);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA inválido ou expirado. Por favor, gere um novo.' });
    }

    if (new Date(challenge.expires_at) < new Date()) {
        await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
        movementQueues.delete(challengeId);
        await recordSuspiciousActivity(req.ipAddress, 'fail_time', `CAPTCHA expirado (challengeId: ${challengeId}).`);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA expirado. Por favor, gere um novo.' });
    }

    const resolutionTime = Date.now() - Number(challenge.start_time);
    const maxTimeMs = MAX_CHALLENGE_TIME_SECONDS * 1000;
    const pieceSize = Number(challenge.piece_size) || CAPTCHA_MAX_PIECE_SIZE;
    const pieceColor = parseHexColor(challenge.piece_color || CAPTCHA_PIECE_COLOR);

    let resolvedX = Number(finalX);
    let resolvedY = Number(finalY);
    if (image && typeof image === 'string') {
        try {
            const base64 = image.startsWith('data:image/png;base64,')
                ? image.replace('data:image/png;base64,', '')
                : image;
            const buffer = Buffer.from(base64, 'base64');
            const decoded = decodePng(buffer);
            const center = extractPieceCenterFromImage(decoded.data, decoded.width, decoded.height, pieceColor);
            if (center) {
                resolvedX = center.centerX;
                resolvedY = center.centerY;
            } else {
                await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', `Imagem sem peça detectável (challengeId: ${challengeId}).`);
                await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
                movementQueues.delete(challengeId);
                return res.status(400).json({ success: false, message: 'Imagem inválida. Por favor, tente novamente.' });
            }
        } catch (error) {
            await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', `Falha ao analisar imagem (challengeId: ${challengeId}).`);
            await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
            movementQueues.delete(challengeId);
            return res.status(400).json({ success: false, message: 'Erro ao analisar imagem.' });
        }
    }

    const expectedX = challenge.solution_x + pieceSize / 2;
    const expectedY = challenge.solution_y + pieceSize / 2;
    const isCorrectPosition = Math.abs(resolvedX - expectedX) < CAPTCHA_TOLERANCE &&
                              Math.abs(resolvedY - expectedY) < CAPTCHA_TOLERANCE;

    await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);

    const storedMovement = movementQueues.get(challengeId) || [];
    const effectiveMovementData = storedMovement.length ? storedMovement : (movementData || []);
    // --- Análise de Movimento ---
    let movementIsSuspicious = false;
    if (effectiveMovementData && effectiveMovementData.length > 0) {
        const analysis = analyzeMovementData(effectiveMovementData);
        if (analysis.suspicious) {
            movementIsSuspicious = true;
            console.warn(`[CAPTCHA Anti-bot] Movimento suspeito (${analysis.reasons.join(', ')}).`);
        }
    } else if (effectiveMovementData && effectiveMovementData.length === 0 && (resolutionTime > HUMAN_TIME_MIN_MS && resolutionTime < maxTimeMs)) {
        movementIsSuspicious = true;
        console.warn(`[CAPTCHA Anti-bot] Movimento suspeito: dados de movimento vazios.`);
    }

    if (movementIsSuspicious) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_time', `Movimento suspeito detectado (challengeId: ${challengeId}).`);
        await banIp(req.ipAddress, 'Atividade de movimento suspeita detectada.');
        movementQueues.delete(challengeId);
        return res.status(403).json({ success: false, message: 'Atividade de movimento suspeita detectada. Banido por 1 minuto.' });
    }
    // --- Fim Análise de Movimento ---

    if (resolutionTime > maxTimeMs) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_time', `CAPTCHA expirou. Resolvido em ${resolutionTime}ms.`);
        await banIp(req.ipAddress, 'Tempo esgotado no CAPTCHA.');
        movementQueues.delete(challengeId);
        return res.status(400).json({ success: false, message: `Tempo esgotado (${resolutionTime / 1000}s). Banido por 1 minuto.` });
    }

    if (isCorrectPosition) {
        if (resolutionTime < HUMAN_TIME_MIN_MS) {
            await recordSuspiciousActivity(req.ipAddress, 'fail_time', `Resolvido em ${resolutionTime}ms (abaixo do mínimo humano).`);
            await banIp(req.ipAddress, 'Resolução rápida demais.');
            movementQueues.delete(challengeId);
            return res.status(403).json({ success: false, message: `Atividade suspeita detectada (muito rápido: ${resolutionTime}ms). Banido por 1 minuto.` });
        }
        
        await dbRun('INSERT INTO captcha_logs (ip_address, status, details, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', [req.ipAddress, 'success', `Resolvido em ${resolutionTime}ms.`]);
        
        const captchaToken = await generateCaptchaToken(req.ipAddress, req.headers['user-agent']);
        movementQueues.delete(challengeId);
        return res.json({ success: true, message: 'CAPTCHA verificado com sucesso!', token: captchaToken });

    } else {
        await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', `Posição final incorreta: ${resolvedX},${resolvedY}.`);
        await banIp(req.ipAddress, 'Posição incorreta no CAPTCHA.');
        movementQueues.delete(challengeId);
        return res.status(400).json({ success: false, message: 'Posição incorreta. Banido por 1 minuto.' });
    }
});

// Novo endpoint para validação externa do token de CAPTCHA
app.post('/captcha/validate-token', captchaActionLimiter, blockBanned, async (req, res) => {
    const token = req.body && req.body.token ? req.body.token : getCookie(req, CAPTCHA_COOKIE_NAME);
    if (!token) {
        return res.status(400).json({ valid: false, message: 'Token não fornecido.' });
    }

    const captchaToken = await dbGet('SELECT * FROM captcha_tokens WHERE token = ?', [token]);

    if (!captchaToken) {
        return res.status(404).json({ valid: false, message: 'Token inválido ou não encontrado.' });
    }
    if (captchaToken.is_used) {
        return res.status(400).json({ valid: false, message: 'Token já utilizado.' });
    }
    if (new Date(captchaToken.expires_at) < new Date()) {
        return res.status(400).json({ valid: false, message: 'Token expirado.' });
    }
    if (TOKEN_BINDING === 'ip' && captchaToken.ip_address !== req.ipAddress) {
        // Pode ser um token roubado ou usado de outro IP.
        return res.status(403).json({ valid: false, message: 'Token não corresponde ao IP de origem.' });
    }

    await dbRun('UPDATE captcha_tokens SET is_used = 1 WHERE token = ?', [token]);
    return res.json({ valid: true, message: 'Token CAPTCHA válido.' });
});

app.get('/captcha/validate-token', captchaActionLimiter, blockBanned, async (req, res) => {
    const token = req.query && req.query.token ? req.query.token : getCookie(req, CAPTCHA_COOKIE_NAME);
    if (!token) {
        return res.status(400).json({ valid: false, message: 'Token não fornecido.' });
    }

    const captchaToken = await dbGet('SELECT * FROM captcha_tokens WHERE token = ?', [token]);
    if (!captchaToken) {
        return res.status(404).json({ valid: false, message: 'Token inválido ou não encontrado.' });
    }
    if (captchaToken.is_used) {
        return res.status(400).json({ valid: false, message: 'Token já utilizado.' });
    }
    if (new Date(captchaToken.expires_at) < new Date()) {
        return res.status(400).json({ valid: false, message: 'Token expirado.' });
    }
    if (TOKEN_BINDING === 'ip' && captchaToken.ip_address !== req.ipAddress) {
        return res.status(403).json({ valid: false, message: 'Token não corresponde ao IP de origem.' });
    }

    return res.json({ valid: true, message: 'Token CAPTCHA válido.' });
});

// =============================================================================
// CAPTCHA ADMIN INVALIDATE ENDPOINT
// =============================================================================
app.get('/captcha/admin/invalidate', async (req, res) => {
    const adminToken = req.query.admin;
    const captchaToken = req.query.token;
    const getToken = req.query['get-token'];

    // --------------------------------------------------
    // 1️⃣ Gerar token administrativo
    // (apenas estar logada e ser admin)
    // --------------------------------------------------
    if (getToken === 'true') {
        // valida autenticação e admin SOMENTE aqui
        if (!req.session.user || !req.session.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Acesso restrito a administradores autenticados.'
            });
        }

        const newAdminToken = crypto.randomBytes(48).toString('hex');

        await dbRun(
            'INSERT INTO captcha_admin_tokens (token) VALUES (?)',
            [newAdminToken]
        );

        return res.json({
            success: true,
            adminToken: newAdminToken,
            message: 'Token administrativo gerado. Guarde com segurança.'
        });
    }

    // --------------------------------------------------
    // 2️⃣ Validação básica para uso do token
    // --------------------------------------------------
    if (!adminToken || !captchaToken) {
        return res.status(400).json({
            success: false,
            message: 'Parâmetros obrigatórios: admin e token.'
        });
    }

    // --------------------------------------------------
    // 3️⃣ Validar token administrativo
    // --------------------------------------------------
    const adminTokenRow = await dbGet(
        'SELECT * FROM captcha_admin_tokens WHERE token = ? AND revoked = 0',
        [adminToken]
    );

    if (!adminTokenRow) {
        return res.status(403).json({
            success: false,
            message: 'Token administrativo inválido ou revogado.'
        });
    }

    // --------------------------------------------------
    // 4️⃣ Invalidar token de CAPTCHA
    // --------------------------------------------------
    const captchaTokenRow = await dbGet(
        'SELECT * FROM captcha_tokens WHERE token = ?',
        [captchaToken]
    );

    if (!captchaTokenRow) {
        return res.status(404).json({
            success: false,
            message: 'Token CAPTCHA não encontrado.'
        });
    }

    await dbRun(
        'UPDATE captcha_tokens SET is_used = 1 WHERE token = ?',
        [captchaToken]
    );

    await dbRun(
        'INSERT INTO captcha_logs (ip_address, status, details, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
        [
            req.ip || req.connection.remoteAddress,
            'admin_invalidate',
            `Token invalidado manualmente: ${captchaToken}`
        ]
    );

    return res.json({
        success: true,
        message: 'Token CAPTCHA invalidado com sucesso.'
    });
});


// =============================================================================
// 9. Geração do Cliente JavaScript Externo (captcha-client.js)
// =============================================================================
function generateExternalClientJS() {
    let clientJSContent = fs.readFileSync(path.join(__dirname, 'public', 'captcha-client.js'), 'utf8');
    clientJSContent = clientJSContent
        .replace(/const DEFAULT_SERVER_URL = ".*?";/, `const DEFAULT_SERVER_URL = "${PUBLIC_BASE_URL}";`)
        .replace(/const CAPTCHA_COOKIE_NAME = ".*?";/, `const CAPTCHA_COOKIE_NAME = "${CAPTCHA_COOKIE_NAME}";`);

    // Garante que o diretório 'public' exista
    if (!fs.existsSync(path.join(__dirname, 'public'))) {
        fs.mkdirSync(path.join(__dirname, 'public'));
    }
    fs.writeFileSync(path.join(__dirname, 'public', 'captcha-client.js'), clientJSContent);
    console.log('Arquivo public/captcha-client.js gerado com sucesso.');
}
// Chamar a função para gerar o JS do cliente ao iniciar o servidor
generateExternalClientJS();

// =============================================================================
// 6. Rotas de Autenticação
// =============================================================================
app.get('/login', blockBanned, (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('login', {
        title: 'Login',
        error: res.locals.error,
        success: res.locals.success
    });
});

app.post('/login', authLimiter, blockBanned, async (req, res) => {
    const { username, password, captchaToken } = req.body;

    const tokenFromCookie = getCookie(req, CAPTCHA_COOKIE_NAME);
    const tokenToValidate = captchaToken || tokenFromCookie;
    if (!tokenToValidate) {
        return res.status(400).render('login', { title: 'Login', error: 'Por favor, complete o CAPTCHA antes de entrar.', success: null });
    }
    const tokenValidationResult = tokenToValidate
        ? await dbGet('SELECT * FROM captcha_tokens WHERE token = ? AND expires_at > CURRENT_TIMESTAMP AND is_used = 0', [tokenToValidate])
        : null;
    if (!tokenValidationResult) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', 'Login attempt: CAPTCHA token inválido.');
        return res.status(400).render('login', { title: 'Login', error: 'Token CAPTCHA inválido, expirado ou já utilizado.', success: null });
    }
    if (TOKEN_BINDING === 'ip' && tokenValidationResult.ip_address !== req.ipAddress) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', 'Login attempt: CAPTCHA token não corresponde ao IP.');
        return res.status(403).render('login', { title: 'Login', error: 'Token CAPTCHA não corresponde ao IP de origem.', success: null });
    }
    await dbRun('UPDATE captcha_tokens SET is_used = 1 WHERE token = ?', [tokenToValidate]);

    const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        await recordSuspiciousActivity(req.ipAddress, 'login_fail', `Login attempt for user '${username}'`);
        return res.status(401).render('login', { title: 'Login', error: 'Usuário ou senha inválidos.', success: null });
    }

    req.session.user = {
        id: user.id,
        username: user.username,
        isAdmin: user.is_admin === 1
    };

    await dbRun('INSERT INTO captcha_logs (ip_address, user_id, status, details, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)', [req.ipAddress, user.id, 'success', 'Login successful.']);

    res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Erro ao destruir sessão:', err);
        }
        res.redirect('/login');
    });
});

// =============================================================================
// 7. Rotas do Dashboard
// =============================================================================
app.get('/dashboard', isAuthenticated, async (req, res) => {
    if (!req.session.user.isAdmin) {
        return res.redirect('/profile');
    }

    const totalUsersRow = await dbGet('SELECT COUNT(*) as count FROM users');
    const totalAdminsRow = await dbGet('SELECT COUNT(*) as count FROM users WHERE is_admin = 1');
    const recentLogs = await dbAll('SELECT * FROM captcha_logs ORDER BY timestamp DESC LIMIT 5');
    const bannedIPs = await dbAll('SELECT * FROM ip_bans ORDER BY banned_at DESC LIMIT 5');
    const stats = {
        totalUsers: totalUsersRow ? totalUsersRow.count : 0,
        totalAdmins: totalAdminsRow ? totalAdminsRow.count : 0,
        recentLogs,
        bannedIPs
    };

    const recentUsers = await dbAll(`
        SELECT u.username, u.is_admin, MAX(l.timestamp) as last_activity
        FROM users u
        LEFT JOIN captcha_logs l ON u.id = l.user_id
        GROUP BY u.id
        ORDER BY last_activity DESC
        LIMIT 5
    `);

    res.render('dashboard', {
        title: 'Dashboard',
        user: req.session.user,
        stats,
        recentUsers,
        error: req.query.error || res.locals.error,
        success: req.query.success || res.locals.success
    });
});

app.get('/integration', isAuthenticated, isAdmin, (req, res) => {
    res.render('integration', {
        title: 'Integração',
        user: req.session.user,
        publicBaseUrl: PUBLIC_BASE_URL
    });
});

app.get('/profile', isAuthenticated, async (req, res) => {
    const userInfo = await dbGet('SELECT id, username, created_at FROM users WHERE id = ?', [req.session.user.id]);
    res.render('profile', {
        title: 'Meu Perfil',
        user: req.session.user,
        userInfo,
        error: req.query.error || res.locals.error,
        success: req.query.success || res.locals.success
    });
});

app.get('/users', isAuthenticated, isAdmin, async (req, res) => {
    const users = await dbAll('SELECT id, username, is_admin, created_at FROM users ORDER BY username');
    res.render('users', {
        title: 'Gerenciar Usuários',
        user: req.session.user,
        users,
        error: req.query.error || res.locals.error,
        success: req.query.success || res.locals.success
    });
});

app.post('/users/create', isAuthenticated, isAdmin, async (req, res) => {
    const { username, password, isAdmin: makeAdmin } = req.body;
    if (!username || !password) {
        return res.redirect('/users?error=' + encodeURIComponent('Nome de usuário e senha são obrigatórios.'));
    }

    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const isAdminFlag = makeAdmin === 'on' ? 1 : 0;
        await dbRun('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', [username, hashedPassword, isAdminFlag]);
        res.redirect('/users?success=' + encodeURIComponent(`Usuário '${username}' criado com sucesso.`));
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE' || (error.message && error.message.includes('UNIQUE'))) {
            return res.redirect('/users?error=' + encodeURIComponent(`Usuário '${username}' já existe.`));
        }
        res.redirect('/users?error=' + encodeURIComponent('Ocorreu um erro ao criar o usuário.'));
    }
});

app.post('/users/delete/:id', isAuthenticated, isAdmin, async (req, res) => {
    const id = req.params.id;
    if (id == req.session.user.id) {
        return res.redirect('/users?error=' + encodeURIComponent('Você não pode deletar a si mesmo.'));
    }
    if (id == 1) {
        return res.redirect('/users?error=' + encodeURIComponent('O administrador principal não pode ser deletado.'));
    }
    await dbRun('DELETE FROM users WHERE id = ?', [id]);
    res.redirect('/users?success=' + encodeURIComponent('Usuário deletado com sucesso.'));
});

app.get('/banned', isAuthenticated, isAdmin, async (req, res) => {
    const banned = await dbAll('SELECT * FROM ip_bans ORDER BY banned_at DESC');
    res.render('banned', {
        title: 'IPs Banidos',
        user: req.session.user,
        banned,
        currentBan: null,
        error: req.query.error || res.locals.error,
        success: req.query.success || res.locals.success
    });
});

app.post('/banned/unban/:ip', isAuthenticated, isAdmin, async (req, res) => {
    const ip = req.params.ip;
    await dbRun('DELETE FROM ip_bans WHERE ip_address = ?', [ip]);
    res.redirect('/banned?success=' + encodeURIComponent(`IP ${ip} desbanido com sucesso.`));
});

// =============================================================================
// 8. Rota Raiz e Inicialização do Servidor
// =============================================================================

app.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

app.listen(PORT, () => {
    console.log(`Servidor VeriGate iniciado na porta ${PORT}`);
});

module.exports = app;
