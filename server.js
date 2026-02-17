const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs'); // Para escrever o arquivo captcha-client.js
const cors = require('cors'); // Para lidar com requisições de origem cruzada
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT) || 5843;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `https://captcha.hsyst.org`;
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '*').split(',').map((origin) => origin.trim()).filter(Boolean);
const SESSION_SECRET = "minhachavemuitoboaviuemuitoboavocenuncavaiadivinhar93489257@(*&#(*$"
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

app.use(express.json({ limit: '100kb' }));
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
    legacyHeaders: false
});
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false
});

const CAPTCHA_SVG_WIDTH = 350;
const CAPTCHA_SVG_HEIGHT = 150;
const CAPTCHA_PIECE_SIZE = 50;
const CAPTCHA_TOLERANCE = 15;

const getRandomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const generateId = () => crypto.randomBytes(6).toString('hex');

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
    const targetId = generateId();
    const challengeId = generateId();

    const initialPieceX = getRandomInt(0, CAPTCHA_SVG_WIDTH - CAPTCHA_PIECE_SIZE);
    const initialPieceY = getRandomInt(0, CAPTCHA_SVG_HEIGHT - CAPTCHA_PIECE_SIZE);

    const targetX = getRandomInt(0, CAPTCHA_SVG_WIDTH - CAPTCHA_PIECE_SIZE);
    const targetY = getRandomInt(0, CAPTCHA_SVG_HEIGHT - CAPTCHA_PIECE_SIZE);

    const svg = `
        <svg width="${CAPTCHA_SVG_WIDTH}" height="${CAPTCHA_SVG_HEIGHT}" viewBox="0 0 ${CAPTCHA_SVG_WIDTH} ${CAPTCHA_SVG_HEIGHT}" style="border: 1px solid #ccc; background-color: #f0f0f0; border-radius: 5px; touch-action: none;">
            <rect x="${targetX}" y="${targetY}" width="${CAPTCHA_PIECE_SIZE}" height="${CAPTCHA_PIECE_SIZE}" fill="#e0e0e0" stroke="#999" stroke-dasharray="3,3"/>
            <text x="10" y="20" font-family="Arial" font-size="14" fill="#333">Arraste a peça para o buraco.</text>
            <rect id="${pieceId}" class="draggable-piece" x="${initialPieceX}" y="${initialPieceY}" width="${CAPTCHA_PIECE_SIZE}" height="${CAPTCHA_PIECE_SIZE}" fill="#0d6efd" style="cursor: grab;"/>
        </svg>
    `;

    const expiresAt = new Date(Date.now() + (MAX_CHALLENGE_TIME_SECONDS + 60) * 1000).toISOString();
    await dbRun(
        'INSERT INTO captcha_challenges (challenge_id, ip_address, piece_id, solution_x, solution_y, generated_at, expires_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)',
        [challengeId, req.ipAddress, pieceId, targetX, targetY, expiresAt]
    );
    
    await dbRun('INSERT INTO captcha_logs (ip_address, status, details, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', [req.ipAddress, 'generated', `Challenge ID: ${challengeId}`]);

    res.json({
        svg,
        pieceId,
        challengeId,
        maxTime: MAX_CHALLENGE_TIME_SECONDS
    });
});

// Configuração pública para integração externa
app.get('/captcha/config', (req, res) => {
    res.json({
        maxChallengeTimeSeconds: MAX_CHALLENGE_TIME_SECONDS,
        pieceSize: CAPTCHA_PIECE_SIZE,
        tolerance: CAPTCHA_TOLERANCE,
        tokenExpirationMinutes: CAPTCHA_TOKEN_EXPIRATION_MINUTES
    });
});

app.post('/captcha/start-challenge', captchaActionLimiter, blockBanned, async (req, res) => {
    const { challengeId } = req.body;
    const challenge = await dbGet('SELECT * FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
    if (!challenge || challenge.ip_address !== req.ipAddress) {
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA inválido ou expirado.' });
    }
    if (new Date(challenge.expires_at) < new Date()) {
        await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA expirado. Por favor, gere um novo.' });
    }

    const startTime = Date.now();
    await dbRun('UPDATE captcha_challenges SET start_time = ? WHERE challenge_id = ?', [startTime, challengeId]);
    res.json({ success: true, startTime });
});

app.post('/captcha/verify', captchaActionLimiter, blockBanned, async (req, res) => {
    const { finalX, finalY, challengeId, movementData } = req.body;
    const challenge = await dbGet('SELECT * FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
    if (!challenge || challenge.ip_address !== req.ipAddress || !challenge.start_time) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', `Tentativa de verificação sem desafio válido para ID: ${challengeId}`);
        await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA inválido ou expirado. Por favor, gere um novo.' });
    }

    if (new Date(challenge.expires_at) < new Date()) {
        await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);
        await recordSuspiciousActivity(req.ipAddress, 'fail_time', `CAPTCHA expirado (challengeId: ${challengeId}).`);
        return res.status(400).json({ success: false, message: 'Desafio CAPTCHA expirado. Por favor, gere um novo.' });
    }

    const resolutionTime = Date.now() - Number(challenge.start_time);
    const maxTimeMs = MAX_CHALLENGE_TIME_SECONDS * 1000;

    const isCorrectPosition = Math.abs(finalX - (challenge.solution_x + CAPTCHA_PIECE_SIZE / 2)) < CAPTCHA_TOLERANCE &&
                              Math.abs(finalY - (challenge.solution_y + CAPTCHA_PIECE_SIZE / 2)) < CAPTCHA_TOLERANCE;

    await dbRun('DELETE FROM captcha_challenges WHERE challenge_id = ?', [challengeId]);

    // --- Análise de Movimento Simples ---
    let movementIsSuspicious = false;
    if (movementData && movementData.length > 0) {
        // Exemplo: Movimento muito direto (poucos pontos ou distância muito próxima da linear)
        const startPoint = movementData[0];
        const endPoint = movementData[movementData.length - 1];
        const linearDistance = Math.sqrt(Math.pow(endPoint.x - startPoint.x, 2) + Math.pow(endPoint.y - startPoint.y, 2));
        let totalDistance = 0;
        for (let i = 1; i < movementData.length; i++) {
            totalDistance += Math.sqrt(Math.pow(movementData[i].x - movementData[i-1].x, 2) + Math.pow(movementData[i].y - movementData[i-1].y, 2));
        }

        if (movementData.length < 5 && totalDistance > 10) { // Poucos pontos para um movimento significativo
            movementIsSuspicious = true;
            console.warn(`[CAPTCHA Anti-bot] Movimento suspeito: poucos pontos (${movementData.length}) para distância.`);
        }
        if (linearDistance > 0 && (totalDistance / linearDistance) < 1.1) { // Trajetória muito "reta"
             movementIsSuspicious = true;
             console.warn(`[CAPTCHA Anti-bot] Movimento suspeito: trajetória muito reta (total/linear = ${totalDistance / linearDistance}).`);
        }
    } else if (movementData && movementData.length === 0 && (resolutionTime > HUMAN_TIME_MIN_MS && resolutionTime < maxTimeMs)) {
        // Se não houve movimento mas o tempo é "humano", pode ser um script injetando a posição final
        movementIsSuspicious = true;
        console.warn(`[CAPTCHA Anti-bot] Movimento suspeito: dados de movimento vazios.`);
    }

    if (movementIsSuspicious) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_time', `Movimento suspeito detectado (challengeId: ${challengeId}).`);
        await banIp(req.ipAddress, 'Atividade de movimento suspeita detectada.');
        return res.status(403).json({ success: false, message: 'Atividade de movimento suspeita detectada. Banido por 1 minuto.' });
    }
    // --- Fim Análise de Movimento Simples ---

    if (resolutionTime > maxTimeMs) {
        await recordSuspiciousActivity(req.ipAddress, 'fail_time', `CAPTCHA expirou. Resolvido em ${resolutionTime}ms.`);
        await banIp(req.ipAddress, 'Tempo esgotado no CAPTCHA.');
        return res.status(400).json({ success: false, message: `Tempo esgotado (${resolutionTime / 1000}s). Banido por 1 minuto.` });
    }

    if (isCorrectPosition) {
        if (resolutionTime < HUMAN_TIME_MIN_MS) {
            await recordSuspiciousActivity(req.ipAddress, 'fail_time', `Resolvido em ${resolutionTime}ms (abaixo do mínimo humano).`);
            await banIp(req.ipAddress, 'Resolução rápida demais.');
            return res.status(403).json({ success: false, message: `Atividade suspeita detectada (muito rápido: ${resolutionTime}ms). Banido por 1 minuto.` });
        }
        
        await dbRun('INSERT INTO captcha_logs (ip_address, status, details, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)', [req.ipAddress, 'success', `Resolvido em ${resolutionTime}ms.`]);
        
        const captchaToken = await generateCaptchaToken(req.ipAddress, req.headers['user-agent']);
        return res.json({ success: true, message: 'CAPTCHA verificado com sucesso!', token: captchaToken });

    } else {
        await recordSuspiciousActivity(req.ipAddress, 'fail_wrong', `Posição final incorreta: ${finalX},${finalY}.`);
        await banIp(req.ipAddress, 'Posição incorreta no CAPTCHA.');
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
        if (!req.user || !req.user.isAdmin) {
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
    const clientJSContent = `
(function() {
    const DEFAULT_SERVER_URL = "${PUBLIC_BASE_URL}";
    const scriptTag = document.currentScript || document.querySelector('script[data-verigate]');
    const CAPTCHA_SERVER_URL = (scriptTag && scriptTag.getAttribute('data-server-url')) || window.VeriGateCaptchaServer || DEFAULT_SERVER_URL;
    const CAPTCHA_COOKIE_NAME = "${CAPTCHA_COOKIE_NAME}";

    window.VeriGateCaptcha = {
        _captchaState: {
            captchaContainer: null,
            captchaLoading: null,
            captchaError: null,
            startCaptchaBtn: null,
            captchaTimerDisplay: null,
            finalXInput: null,
            finalYInput: null,
            challengeIdInput: null,
            formSubmitBtn: null, // Opcional, para desabilitar o submit enquanto CAPTCHA não está pronto

            dragItem: null,
            currentChallengeId: null,
            active: false,
            currentX: 0, currentY: 0, initialX: 0, initialY: 0,
            xOffset: 0, yOffset: 0,
            captchaTimerInterval: null,
            maxChallengeTime: 0,
            movementData: [] // Armazenar dados de movimento
        },

        init: function(containerId, successCallback, errorCallback, formToBind = null, options = {}) {
            const state = this._captchaState;
            state.serverUrl = options.serverUrl || CAPTCHA_SERVER_URL;
            state.captchaContainer = document.getElementById(containerId);
            if (!state.captchaContainer) {
                console.error("VeriGateCaptcha: Container DIV com ID '" + containerId + "' não encontrado.");
                return;
            }

            state.captchaContainer.innerHTML = \`
                <div id="\${containerId}-display" class="border rounded p-2 mb-2" style="min-height: 170px; display: flex; justify-content: center; align-items: center; flex-direction: column;">
                    <div id="\${containerId}-svg-container" class="captcha-container">
                        <!-- CAPTCHA SVG será carregado aqui -->
                    </div>
                    <div id="\${containerId}-loading" class="spinner-border text-primary" role="status" style="display: none;">
                        <span class="visually-hidden">Carregando...</span>
                    </div>
                </div>
                <div id="\${containerId}-info" class="d-flex justify-content-between align-items-center mb-2">
                    <button type="button" id="\${containerId}-start-btn" class="btn btn-sm btn-info" disabled>Iniciar CAPTCHA</button>
                    <span id="\${containerId}-timer" class="badge bg-secondary" style="display: none;"></span>
                </div>
                <div id="\${containerId}-error" class="text-danger mt-1" style="display: none;"></div>
                <input type="hidden" id="\${containerId}-x">
                <input type="hidden" id="\${containerId}-y">
                <input type="hidden" id="\${containerId}-challenge-id">
            \`;


            // Atribuir elementos ao estado
            state.captchaSvgContainer = document.getElementById(containerId + '-svg-container');
            state.captchaLoading = document.getElementById(containerId + '-loading');
            state.captchaError = document.getElementById(containerId + '-error');
            state.startCaptchaBtn = document.getElementById(containerId + '-start-btn');
            state.captchaTimerDisplay = document.getElementById(containerId + '-timer');
            state.finalXInput = document.getElementById(containerId + '-x');
            state.finalYInput = document.getElementById(containerId + '-y');
            state.challengeIdInput = document.getElementById(containerId + '-challenge-id');
            state.successCallback = successCallback;
            state.errorCallback = errorCallback;
            state.formToBind = formToBind; // O formulário a ser "protegido"
            state.formSubmitBtn = state.formToBind ? state.formToBind.querySelector('button[type="submit"], input[type="submit"]') : null;
            if (state.formSubmitBtn) {
                state.formSubmitBtn.disabled = true;
            }

            // Ocultar o container do SVG inicialmente
            state.captchaSvgContainer.style.display = 'none';

            // Evento para o botão Iniciar/Recarregar
            state.startCaptchaBtn.addEventListener('click', () => {
                if (state.startCaptchaBtn.classList.contains('btn-danger') || state.startCaptchaBtn.textContent === 'Recarregar CAPTCHA') {
                    this._loadCaptcha(); // Recarrega se estiver em estado de erro
                } else {
                    this._startChallenge(); // Inicia o desafio
                }
            });

            // Se um formulário foi fornecido, previne o submit antes do CAPTCHA
            if (state.formToBind) {
                state.formToBind.addEventListener('submit', (e) => {
                    if (!state.captchaToken) { // Se o token não estiver presente
                        e.preventDefault();
                        this._showCaptchaError('Por favor, complete o CAPTCHA antes de enviar o formulário.');
                    } else {
                        // Anexa/atualiza o token ao formulário antes de submit
                        let tokenInput = state.formToBind.querySelector('input[name="captchaToken"]');
                        if (!tokenInput) {
                            tokenInput = document.createElement('input');
                            tokenInput.type = 'hidden';
                            tokenInput.name = 'captchaToken';
                            state.formToBind.appendChild(tokenInput);
                        }
                        tokenInput.value = state.captchaToken;
                    }
                });
            }

            this._loadCaptcha(); // Carrega o primeiro CAPTCHA
        },

        _showCaptchaError: function(message) {
            const state = this._captchaState;
            state.captchaError.textContent = message;
            state.captchaError.style.display = 'block';
            state.captchaTimerDisplay.style.display = 'none';
            state.startCaptchaBtn.textContent = 'Recarregar CAPTCHA';
            state.startCaptchaBtn.classList.remove('btn-info');
            state.startCaptchaBtn.classList.add('btn-danger');
            state.startCaptchaBtn.disabled = false;
            state.captchaSvgContainer.style.display = 'none'; // Esconde o SVG em caso de erro
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval);
            if (state.errorCallback) state.errorCallback(message);
            if (state.formSubmitBtn) state.formSubmitBtn.disabled = true;
        },

        _startTimer: function() {
            const state = this._captchaState;
            let timeLeft = state.maxChallengeTime;
            state.captchaTimerDisplay.textContent = 'Tempo restante: ' + timeLeft + 's';
            state.captchaTimerDisplay.style.display = 'inline-block';
            
            state.captchaTimerInterval = setInterval(() => {
                timeLeft--;
                if (timeLeft <= 0) {
                    clearInterval(state.captchaTimerInterval);
                    state.captchaTimerDisplay.textContent = 'Tempo esgotado!';
                    this._showCaptchaError('Tempo esgotado. Por favor, recarregue o CAPTCHA.');
                    if (state.dragItem) state.dragItem.style.pointerEvents = 'none';
                } else {
                    state.captchaTimerDisplay.textContent = 'Tempo restante: ' + timeLeft + 's';
                }
            }, 1000);
        },

        _loadCaptcha: async function() {
            const state = this._captchaState;
            state.captchaSvgContainer.innerHTML = '';
            state.captchaError.style.display = 'none';
            state.startCaptchaBtn.disabled = true;
            state.startCaptchaBtn.textContent = 'Aguarde...';
            state.startCaptchaBtn.classList.remove('btn-danger');
            state.startCaptchaBtn.classList.add('btn-info');
            state.captchaTimerDisplay.style.display = 'none';
            state.captchaSvgContainer.style.display = 'none';
            state.captchaToken = null; // Limpa qualquer token anterior
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval);
            if (state.formSubmitBtn) state.formSubmitBtn.disabled = true;

            state.captchaLoading.style.display = 'block';

            try {
                const response = await fetch(state.serverUrl + '/captcha/generate');
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.reason || 'Falha ao carregar o CAPTCHA.');
                }
                const { svg, pieceId, challengeId, maxTime } = await response.json();
                
                state.captchaLoading.style.display = 'none';
                state.captchaSvgContainer.innerHTML = svg;

                state.dragItem = document.getElementById(pieceId);
                state.currentChallengeId = challengeId;
                state.challengeIdInput.value = challengeId;
                state.maxChallengeTime = maxTime;

                if (!state.dragItem) {
                    throw new Error('Elemento arrastável do CAPTCHA não encontrado.');
                }
                
                state.dragItem.style.pointerEvents = 'none'; // Desabilitar drag inicialmente
                state.startCaptchaBtn.textContent = 'Iniciar CAPTCHA';
                state.startCaptchaBtn.disabled = false;
                state.captchaSvgContainer.style.display = 'block'; // Exibe o SVG
                state.movementData = []; // Zera dados de movimento
                
            } catch (error) {
                state.captchaLoading.style.display = 'none';
                this._showCaptchaError(error.message);
            }
        },

        _startChallenge: async function() {
            const state = this._captchaState;
            state.startCaptchaBtn.disabled = true;
            state.startCaptchaBtn.textContent = 'Iniciando...';
            state.captchaError.style.display = 'none';
            state.captchaToken = null; // Garante que não haja token antigo

            try {
                const response = await fetch(state.serverUrl + '/captcha/start-challenge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ challengeId: state.currentChallengeId })
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.message || 'Falha ao iniciar o desafio.');
                }

                state.dragItem.style.pointerEvents = 'auto';
                state.dragItem.style.cursor = 'grab';
                state.startCaptchaBtn.style.display = 'none'; // Esconder o botão iniciar
                this._startTimer();

                // Adicionar listeners para drag-and-drop
                state.captchaSvgContainer.addEventListener('mousedown', this._dragStart.bind(this), false);
                state.captchaSvgContainer.addEventListener('mouseup', this._dragEnd.bind(this), false);
                state.captchaSvgContainer.addEventListener('mousemove', this._drag.bind(this), false);

                state.captchaSvgContainer.addEventListener('touchstart', this._dragStart.bind(this), { passive: false });
                state.captchaSvgContainer.addEventListener('touchend', this._dragEnd.bind(this), false);
                state.captchaSvgContainer.addEventListener('touchmove', this._drag.bind(this), { passive: false });

            } catch (error) {
                this._showCaptchaError(error.message);
                state.startCaptchaBtn.textContent = 'Tentar Novamente';
                state.startCaptchaBtn.disabled = false;
                state.startCaptchaBtn.style.display = 'inline-block';
            }
        },

        _dragStart: function(e) {
            const state = this._captchaState;
            if (e.target === state.dragItem) {
                if (e.type === 'touchstart') {
                    state.initialX = e.touches[0].clientX - state.xOffset;
                    state.initialY = e.touches[0].clientY - state.yOffset;
                } else {
                    state.initialX = e.clientX - state.xOffset;
                    state.initialY = e.clientY - state.yOffset;
                }
                state.active = true;
                state.dragItem.style.cursor = 'grabbing';
                state.movementData = [{x: e.clientX, y: e.clientY, timestamp: Date.now()}]; // Inicia coleta
            }
        },

        _dragEnd: async function(e) {
            const state = this._captchaState;
            if (!state.active) return;
            state.initialX = state.currentX;
            state.initialY = state.currentY;
            state.active = false;
            state.dragItem.style.cursor = 'grab';
            state.dragItem.style.pointerEvents = 'none'; // Desabilita interação após soltar
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval); // Para o timer

            state.movementData.push({x: e.clientX, y: e.clientY, timestamp: Date.now()}); // Finaliza coleta

            const svgElement = state.captchaSvgContainer.querySelector('svg');
            if (!svgElement) return;

            const svgRect = svgElement.getBoundingClientRect();
            const dragRect = state.dragItem.getBoundingClientRect();

            const finalX = dragRect.left - svgRect.left + (dragRect.width / 2);
            const finalY = dragRect.top - svgRect.top + (dragRect.height / 2);

            state.finalXInput.value = finalX;
            state.finalYInput.value = finalY;

            // Enviar para verificação
            try {
                const response = await fetch(state.serverUrl + '/captcha/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        finalX: finalX,
                        finalY: finalY,
                        challengeId: state.currentChallengeId,
                        movementData: state.movementData // Envia os dados de movimento
                    })
                });

                const result = await response.json();

                if (result.success) {
                    state.captchaToken = result.token;
                    const maxAge = ${CAPTCHA_TOKEN_EXPIRATION_MINUTES} * 60;
                    const secure = window.location && window.location.protocol === 'https:' ? '; Secure' : '';
                    document.cookie = CAPTCHA_COOKIE_NAME + '=' + encodeURIComponent(result.token) + '; Max-Age=' + maxAge + '; Path=/; SameSite=Lax' + secure;
                    state.captchaTimerDisplay.textContent = 'CAPTCHA Válido!';
                    state.captchaTimerDisplay.classList.remove('bg-secondary');
                    state.captchaTimerDisplay.classList.add('bg-success');
                    if (state.successCallback) state.successCallback(result.token);
                    if (state.formSubmitBtn) state.formSubmitBtn.disabled = false;
                } else {
                    this._showCaptchaError(result.message);
                }
            } catch (error) {
                this._showCaptchaError('Erro de comunicação com o servidor CAPTCHA.');
            }
        },

        _drag: function(e) {
            const state = this._captchaState;
            if (state.active) {
                e.preventDefault();
                if (e.type === 'touchmove') {
                    state.currentX = e.touches[0].clientX - state.initialX;
                    state.currentY = e.touches[0].clientY - state.initialY;
                } else {
                    state.currentX = e.clientX - state.initialX;
                    state.currentY = e.clientY - state.initialY;
                }
                state.xOffset = state.currentX;
                state.yOffset = state.currentY;
                this._setTranslate(state.currentX, state.currentY, state.dragItem);
                state.movementData.push({x: e.clientX, y: e.clientY, timestamp: Date.now()}); // Coleta movimento
            }
        },

        _setTranslate: function(xPos, yPos, el) {
            el.style.transform = 'translate3d(' + xPos + 'px, ' + yPos + 'px, 0)';
        }
    };
})();
    `;

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
