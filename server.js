// ================= ROYAL CASINO - BACKEND FIXED - PUBLIC LAUNCH SECURE =================
// FIXED: 1. /fix-db Admin Lock  2. Aviator clear() Fix  3. Withdraw Approve/Reject + Refund  4. CORS Vercel + Tiiny  5. OTP Attempt Limit
const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const crypto = require('crypto');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

// ===== FIX 4: CORS - Tiiny + Vercel dono allow =====[span_0](start_span)[span_0](end_span)
const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || 'https://royalcasino.tiiny.site,https://royal-casino-club.vercel.app').split(',').map(s => s.trim());
console.log('Allowed Origins:', ALLOWED_ORIGINS);

function isOriginAllowed(origin){
  if(!origin) return true;
  if(ALLOWED_ORIGINS.includes(origin)) return true;
  if(origin.endsWith('.tiiny.site')) return true;
  if(origin.endsWith('.vercel.app')) return true;
  if(origin.includes('localhost')) return true;
  return false;
}
app.use(cors({ origin: function(origin, cb){ if(isOriginAllowed(origin)) return cb(null, true); return cb(new Error('CORS Blocked')); }, credentials: true }));
app.options('*', cors({ origin: function(origin, cb){ if(isOriginAllowed(origin)) return cb(null, true); return cb(new Error('CORS Blocked')); }, credentials: true }));
app.use(express.json({ limit: '10kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: 'Bahut zyada try kiya, 15 min baad try karo' } });[span_1](start_span)[span_1](end_span)
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { success: false, message: 'Bahut zyada login try, 15 min ruk' } });[span_2](start_span)[span_2](end_span)
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.use('/api/', apiLimiter);

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: function(origin, cb){ if(isOriginAllowed(origin)) return cb(null, true); return cb(new Error('Socket CORS Blocked')); }, methods: ["GET","POST"], credentials: true } });

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS lvl INTEGER DEFAULT 0;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS sig_level INTEGER DEFAULT 0;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS vip_level INTEGER DEFAULT 0;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS balance NUMERIC(12,2) DEFAULT 0;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS dob DATE;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT false;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS self_excluded_until TIMESTAMP;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit NUMERIC(12,2) DEFAULT 0;`).catch(()=>{});
pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit_date DATE DEFAULT CURRENT_DATE;`).catch(()=>{});

// ===== FIX 1: /fix-db AB ADMIN LOCK HAI =====[span_3](start_span)[span_3](end_span)
app.get('/fix-db', checkAdmin, async (req, res) => {
  try {
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS lvl INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS sig_level INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS vip_level INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS balance NUMERIC(12,2) DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS dob DATE;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT false;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS self_excluded_until TIMESTAMP;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit NUMERIC(12,2) DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit_date DATE DEFAULT CURRENT_DATE;`);
    res.send('HO GAYA! Public Launch wale sab column ban gaye!');
  } catch(e){ res.send('ERROR: ' + e.message); }
});

const MY_UPI_ID = "ombk.aahi70694v2ydnslbfb@mbk";
const MY_UPI_NAME = "Aahi";
const MY_MIN_DEPOSIT = 150;
const MY_MIN_WITHDRAW = 300;
const DAILY_DEPOSIT_LIMIT = 10000;
const DAILY_BET_LIMIT = 20000;

app.get('/api/payment-info', (req, res) => {
  res.json({ success: true, upi_id: MY_UPI_ID, upi_name: MY_UPI_NAME, min_deposit: MY_MIN_DEPOSIT, min_withdraw: MY_MIN_WITHDRAW, daily_deposit_limit: DAILY_DEPOSIT_LIMIT, message: `Min Deposit ₹${MY_MIN_DEPOSIT} | Min Withdraw ₹${MY_MIN_WITHDRAW} | Daily Deposit Limit ₹${DAILY_DEPOSIT_LIMIT}` });
});
app.get('/api/health', (req, res) => { res.json({ success: true, msg: 'Backend ON hai - Public Secure FIXED', time: new Date().toISOString() }); });[span_4](start_span)[span_4](end_span)

app.post('/api/deposit/create-qr', checkAuth, async (req, res) => {
  const depositAmount = parseFloat(req.body.amount);
  if (!depositAmount || depositAmount < MY_MIN_DEPOSIT) return res.status(400).json({ success: false, message: `Min Deposit ₹${MY_MIN_DEPOSIT} hai bhai!` });
  if (depositAmount > 50000) return res.status(400).json({ success: false, message: 'Max ₹50000 ek baar me!' });
  let w = await pool.query('SELECT daily_deposit, daily_deposit_date FROM wallets WHERE user_id=$1', [req.user.mobile]);
  if (w.rows.length) {
    let row = w.rows[0];
    let today = new Date().toISOString().slice(0, 10);
    let depToday = (row.daily_deposit_date && row.daily_deposit_date.toISOString().slice(0, 10) === today) ? parseFloat(row.daily_deposit) : 0;
    if (depToday + depositAmount > DAILY_DEPOSIT_LIMIT) return res.status(400).json({ success: false, message: `Aaj ka Deposit Limit ₹${DAILY_DEPOSIT_LIMIT} khatam ho gaya! Kal try karo.` });
  }
  const upiLink = `upi://pay?pa=${MY_UPI_ID}&pn=${encodeURIComponent(MY_UPI_NAME)}&am=${depositAmount}&cu=INR&tn=${encodeURIComponent('Deposit ' + depositAmount + ' - ' + req.user.mobile)}`;
  const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(upiLink)}`;
  res.json({ success: true, amount: depositAmount, upi_id: MY_UPI_ID, upi_name: MY_UPI_NAME, upiLink, qrImage: qrImageUrl, message: `₹${depositAmount} ka QR ban gaya!` });
});

function safeHttpsGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e){ reject(e); } });
    });
    req.setTimeout(8000, ()=>{ req.destroy(new Error('OTP Timeout')); });
    req.on('error', reject);
  });
}
function makeToken(mobile) { return jwt.sign({ mobile }, process.env.JWT_SECRET, { expiresIn: '1d' }); } // FIX: 7d से 1d kiya - phone chori pe safe[span_5](start_span)[span_5](end_span)
function checkAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Login karo pehle' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); } catch(e){ return res.status(401).json({ success: false, message: 'Token galat / expire ho gaya' }); }
}
function checkAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Admin login chahiye' });
  try {
    const d = jwt.verify(token, process.env.JWT_SECRET);
    if (d.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin nahi ho' });
    req.admin = d; next();
  } catch(e){ return res.status(401).json({ success: false, message: 'Admin token galat hai' }); }
}
async function audit(actor, action, details, ip) {
  try { await pool.query('INSERT INTO audit_logs (actor_id, action_type, details, ip_address) VALUES ($1,$2,$3,$4)', [actor, action, details, ip]); } catch(e){}
}
async function initDatabase() {
  await pool.query(`CREATE TABLE IF NOT EXISTS wallets (id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE NOT NULL, balance NUMERIC(12,2) DEFAULT 0 CHECK(balance>=0), vip_level INT DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW(), dob DATE, is_blocked BOOLEAN DEFAULT false, self_excluded_until TIMESTAMP, daily_deposit NUMERIC(12,2) DEFAULT 0, daily_deposit_date DATE DEFAULT CURRENT_DATE)`);
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS lvl INTEGER DEFAULT 0;`).catch(()=>{});
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS sig_level INTEGER DEFAULT 0;`).catch(()=>{});
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS vip_level INTEGER DEFAULT 0;`).catch(()=>{});
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS dob DATE;`).catch(()=>{});
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT false;`).catch(()=>{});
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS self_excluded_until TIMESTAMP;`).catch(()=>{});
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit NUMERIC(12,2) DEFAULT 0;`).catch(()=>{});
  await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit_date DATE DEFAULT CURRENT_DATE;`).catch(()=>{});
  await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, type VARCHAR(50) NOT NULL, status VARCHAR(50) NOT NULL, utr VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS deposits (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, utr VARCHAR(100) UNIQUE NOT NULL, status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS withdraws (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, method VARCHAR(20) DEFAULT 'UPI', upi_id VARCHAR(255), account_no VARCHAR(50), ifsc VARCHAR(20), status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS admin_users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT 'admin')`);
  await pool.query(`CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, actor_id VARCHAR(255) NOT NULL, action_type VARCHAR(100) NOT NULL, details TEXT, ip_address VARCHAR(50), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL)`);
  await pool.query(`INSERT INTO settings (key, value) VALUES ('global_rtp','96'), ('min_bet','10'), ('max_bet','5000'), ('teenpatti_rake','5'), ('teenpatti_boot','5'), ('aviator_house_edge','4'), ('aviator_min_crash','1.10'), ('aviator_max_crash','100'), ('spin_rtp','96'), ('dragontiger_rtp','96'), ('roulette_rtp','96'), ('mines_rtp','96'), ('andarbahar_rtp','96'), ('plinko_rtp','96'), ('baccarat_rtp','96'), ('poker_rtp','96'), ('slots_rtp','96'), ('colour_rtp','96'), ('chicken_rtp','96'), ('fortunegems_rtp','96'), ('gemstemple_rtp','96') ON CONFLICT (key) DO NOTHING`);
  try {
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD;
    if (adminPass) {
      const ex = await pool.query('SELECT * FROM admin_users WHERE username=$1', [adminUser]);
      if (!ex.rows.length) {
        const hash = await bcrypt.hash(adminPass, 12);
        await pool.query('INSERT INTO admin_users (username, password_hash, role) VALUES ($1,$2,\'admin\')', [adminUser, hash]);
        console.log('✅ Admin bana diya:', adminUser);
      }
    } else { console.log('⚠️ ADMIN_PASSWORD env nahi dala - Admin login nahi hoga'); }
  } catch(e){ console.log('Admin create error', e.message); }
  console.log('DB Ready - PUBLIC SECURE FIXED - 15 GAMES!');
}
async function getSetting(key, def) {
  const r = await pool.query('SELECT value FROM settings WHERE key=$1', [key]);
  return r.rows.length ? parseFloat(r.rows[0].value) : def;
}
function is18Plus(dobStr) {
  if (!dobStr) return false;
  let dob = new Date(dobStr);
  let today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  let m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
  return age >= 18;
}
async function checkBlocked(userId) {
  const r = await pool.query('SELECT is_blocked, self_excluded_until FROM wallets WHERE user_id=$1', [userId]);
  if (!r.rows.length) return { blocked: false };
  if (r.rows[0].is_blocked) return { blocked: true, reason: 'Admin ne block kiya hai' };
  if (r.rows[0].self_excluded_until && new Date(r.rows[0].self_excluded_until) > new Date()) return { blocked: true, reason: 'Tune khud ko Self-Exclusion me dala hai till ' + r.rows[0].self_excluded_until };
  return { blocked: false };
}
async function placeBet(userId, betAmount) {
  const blocked = await checkBlocked(userId);
  if (blocked.blocked) return { success: false, error: blocked.reason };
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT balance FROM wallets WHERE user_id=$1 FOR UPDATE', [userId]);
    if (!w.rows.length) throw new Error('Wallet not found');
    if (parseFloat(w.rows[0].balance) < betAmount) throw new Error('Insufficient balance');
    const todayBet = await c.query(`SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE user_id=$1 AND type='BET' AND DATE(created_at)=CURRENT_DATE`, [userId]);
    if (parseFloat(todayBet.rows[0].total) + betAmount > DAILY_BET_LIMIT) throw new Error(`Aaj ka Bet Limit ₹${DAILY_BET_LIMIT} khatam! Kal khelo.`);
    await c.query('UPDATE wallets SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2', [betAmount, userId]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'BET\',\'SUCCESS\')', [userId, betAmount]);
    await c.query('COMMIT');
    return { success: true, newBalance: parseFloat(w.rows[0].balance) - betAmount };
  } catch(e){ await c.query('ROLLBACK'); return { success: false, error: e.message }; } finally { c.release(); }
}
async function creditWin(userId, winnings) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query('UPDATE wallets SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 RETURNING balance', [winnings, userId]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'WIN\',\'SUCCESS\')', [userId, winnings]);
    await c.query('COMMIT');
    return parseFloat(r.rows[0].balance);
  } catch(e){ await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}
function generateServerSeed() { return crypto.randomBytes(32).toString('hex'); }
function hashSeed(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function fairOutcome(serverSeed, clientSeed, nonce) {
  const msg = `${serverSeed}:${clientSeed}:${nonce}`;
  const h = crypto.createHmac('sha256', serverSeed).update(msg).digest('hex');
  const val = parseInt(h.slice(0, 8), 16) % 10000;
  return { val, hash: h };
}
function fairRandom(max) { return crypto.randomInt(0, max); }
function shuffleDeck() {
  let deck = [];
  const suits = ['♠', '♥', '♦', '♣'];
  const ranks = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];
  for (let s of suits) { for (let r of ranks) { deck.push(s + '-' + r); } }
  for (let i = deck.length - 1; i > 0; i--) { const j = crypto.randomInt(0, i + 1); [deck[i], deck[j]] = [deck[j], deck[i]]; }
  return deck;
}
function getRankValue(card) {
  const r = card.split('-')[1] || card.replace(/[♠♥♦♣]/g,'');
  const map = { '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, '10': 10, 'J': 11, 'Q': 12, 'K': 13, 'A': 14 };
  return map[r];
}
function evaluateHand(cards) {
  const ranks = cards.map(getRankValue).sort((a, b) => a - b);
  const suits = cards.map(c => c.split('-')[0] || c.slice(-1));
  const isFlush = suits[0] === suits[1] && suits[1] === suits[2];
  const isSeq = (ranks[2] - ranks[1] === 1 && ranks[1] - ranks[0] === 1) || (ranks[0] === 2 && ranks[1] === 3 && ranks[2] === 14);
  const isTrail = ranks[0] === ranks[1] && ranks[1] === ranks[2];
  const isPair = ranks[0] === ranks[1] || ranks[1] === ranks[2] || ranks[0] === ranks[2];
  if (isTrail) return { score: 600 + ranks[0], name: 'Trail' };
  if (isFlush && isSeq) return { score: 500 + ranks[2], name: 'Pure Sequence' };
  if (isSeq) return { score: 400 + ranks[2], name: 'Sequence' };
  if (isFlush) return { score: 300 + ranks[2], name: 'Colour' };
  if (isPair) { let pairVal = ranks[0] === ranks[1] ? ranks[0] : ranks[2]; return { score: 200 + pairVal, name: 'Pair' }; }
  return { score: 100 + ranks[2], name: 'High Card' };
}

let teenTables = new Map();
let gameState = 'WAITING';
let currentMultiplier = 1.00;
let crashPoint = 1.50;
let roundTimer = 5;
let roundId = 1;
let aviatorBets = new Map();

async function generateFunCrash() {
  const edge = await getSetting('aviator_house_edge', 4) / 100;
  const minC = await getSetting('aviator_min_crash', 1.10);
  const maxC = await getSetting('aviator_max_crash', 100);
  const r = crypto.randomBytes(4).readUInt32BE(0) / 4294967295;
  let crash = (1 - edge) / (1 - r);
  if (crash < minC) crash = minC;
  if (crash > maxC) crash = maxC;
  return parseFloat(crash.toFixed(2));
}

// ===== FIX 2: Aviator clear() ab CRASH pe hai, RUNNING pe nahi =====[span_6](start_span)[span_6](end_span)
function startAviator() {
  setInterval(async () => {
    if (gameState === 'WAITING') {
      roundTimer--;
      io.emit('game:timer', { timer: roundTimer, roundId });
      if (roundTimer <= 0) {
        gameState = 'RUNNING';
        currentMultiplier = 1.00;
        crashPoint = await generateFunCrash();
        // FIXED: Yaha se aviatorBets.clear() HATA DIYA - warna Bet gayab ho jata tha[span_7](start_span)[span_7](end_span)
        io.emit('game:started', { roundId });
        io.emit('game:tick', { multiplier: currentMultiplier, roundId });
      }
    } else if (gameState === 'RUNNING') {
      currentMultiplier = parseFloat((currentMultiplier + currentMultiplier * 0.08 + 0.02).toFixed(2));
      io.emit('game:tick', { multiplier: currentMultiplier, roundId });
      if (currentMultiplier >= crashPoint) {
        gameState = 'CRASHED';
        io.emit('game:crashed', { multiplier: crashPoint, roundId });
        aviatorBets.clear(); // FIXED: Ab yaha clear hoga - Crash ke baad[span_8](start_span)[span_8](end_span)
        roundTimer = 5;
        roundId++;
        setTimeout(() => { gameState = 'WAITING'; }, 3000);
      }
    }
  }, 500);
}

const otpStore = new Map();

app.post('/api/auth/send-otp', otpLimiter, async (req, res) => {
  const { mobile, dob } = req.body;
  if (!mobile || !/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({ success: false, message: 'Sahi 10 digit mobile daalo' });
  let w = await pool.query('SELECT dob FROM wallets WHERE user_id=$1', [mobile]);
  if (!w.rows.length) {
    if (!dob) return res.status(400).json({ success: false, message: '18+ hone ke liye Date of Birth chahiye' });
    if (!is18Plus(dob)) return res.status(403).json({ success: false, message: '18 saal se kam wale nahi khel sakte.' });
  } else if (w.rows[0].dob && !is18Plus(w.rows[0].dob)) return res.status(403).json({ success: false, message: '18 saal se kam wale nahi khel sakte' });
  const apiKey = process.env.TWO_FACTOR_API_KEY;
  if (!apiKey) return res.status(500).json({ success: false, message: 'OTP service band hai - TWO_FACTOR_API_KEY Render me nahi dala' });
  try {
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/${mobile}/AUTOGEN/OTP1`);
    if (data.Status === 'Success') {
      otpStore.set(mobile, { sessionId: data.Details, expiresAt: Date.now() + 5 * 60 * 1000, dob: dob || w.rows[0]?.dob, attempts: 0 });
      res.json({ success: true, message: 'OTP bhej diya' });
    } else res.status(400).json({ success: false, message: 'OTP nahi bheja gaya - ' + (data.Details || '2Factor error') });
  } catch(e){ console.error(e); res.status(500).json({ success: false, message: 'OTP fail - ' + e.message }); }
});

// ===== FIX 5: OTP 3 baar galat pe block =====[span_9](start_span)[span_9](end_span)
app.post('/api/auth/verify-otp', loginLimiter, async (req, res) => {
  const { mobile, otp } = req.body;
  const rec = otpStore.get(mobile);
  if (!rec || Date.now() > rec.expiresAt) return res.status(400).json({ success: false, message: 'OTP expire ho gaya, dobara bhejo' });
  if ((rec.attempts || 0) >= 3) { otpStore.delete(mobile); return res.status(400).json({ success: false, message: '3 baar galat OTP - Naya OTP bhejo' }); }
  const apiKey = process.env.TWO_FACTOR_API_KEY;
  try {
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/VERIFY/${rec.sessionId}/${otp}`);
    if (data.Status !== 'Success') { rec.attempts = (rec.attempts || 0) + 1; otpStore.set(mobile, rec); return res.status(400).json({ success: false, message: `Galat OTP - ${3 - rec.attempts} try bacha hai` }); }
    otpStore.delete(mobile);
    let w = await pool.query('SELECT * FROM wallets WHERE user_id=$1', [mobile]);
    if (!w.rows.length) {
      if (!is18Plus(rec.dob)) return res.status(403).json({ success: false, message: '18+ hi khel sakta hai' });
      w = await pool.query('INSERT INTO wallets (user_id,balance,vip_level,dob) VALUES ($1,0,0,$2) RETURNING *', [mobile, rec.dob]);
    }
    const blocked = await checkBlocked(mobile);
    if (blocked.blocked) return res.status(403).json({ success: false, message: blocked.reason });
    const token = makeToken(mobile);
    res.json({ success: true, token, user: { mobile, balance: w.rows[0].balance, vip_level: w.rows[0].vip_level } });
  } catch(e){ console.error(e); res.status(500).json({ success: false, message: 'Login fail' }); }
});

app.post('/api/user/self-exclude', checkAuth, async (req, res) => {
  const { hours } = req.body;
  const h = [24, 168, 720].includes(parseInt(hours)) ? parseInt(hours) : 24;
  await pool.query('UPDATE wallets SET self_excluded_until = NOW() + ($1 || \' hours\')::interval WHERE user_id=$2', [h, req.user.mobile]);
  await audit(req.user.mobile, 'SELF_EXCLUDE', `Self excluded for ${h}h`, req.ip);
  res.json({ success: true, message: `Tune khud ko ${h} ghante ke liye band kar diya.` });
});
app.get('/api/wallet/balance', checkAuth, async (req, res) => {
  const r = await pool.query('SELECT balance, vip_level, is_blocked, self_excluded_until FROM wallets WHERE user_id=$1', [req.user.mobile]);
  if (!r.rows.length) return res.status(404).json({ success: false, message: 'Wallet nahi mila' });
  res.json({ success: true, balance: r.rows[0].balance, vip_level: r.rows[0].vip_level });
});
app.get('/api/wallet/history', checkAuth, async (req, res) => {
  const r = await pool.query('SELECT amount,type,status,created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [req.user.mobile]);
  res.json({ success: true, history: r.rows });
});
app.post('/api/wallet/deposit-request', checkAuth, async (req, res) => {
  const { amount, utr } = req.body;
  if (!amount || amount < 150) return res.status(400).json({ success: false, message: 'Min ₹150 Deposit hai bhai!' });
  if (amount > 50000) return res.status(400).json({ success: false, message: 'Max ₹50000 ek baar me!' });
  if (!utr || String(utr).length < 6) return res.status(400).json({ success: false, message: 'Sahi UTR daalo' });
  const blocked = await checkBlocked(req.user.mobile);
  if (blocked.blocked) return res.status(403).json({ success: false, message: blocked.reason });
  try {
    await pool.query('INSERT INTO deposits (user_id, amount, utr) VALUES ($1,$2,$3)', [req.user.mobile, amount, String(utr)]);
    await audit(req.user.mobile, 'DEPOSIT_REQUEST', `Amt ${amount} UTR ${utr}`, req.ip);
    res.json({ success: true, message: 'Deposit request bhej diya, Admin approve karega' });
  } catch(e){
    if (e.code === '23505') return res.status(400).json({ success: false, message: 'Ye UTR pehle use ho chuka hai' });
    res.status(500).json({ success: false, message: 'Deposit fail' });
  }
});

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const r = await pool.query('SELECT * FROM admin_users WHERE username=$1', [username]);
  if (!r.rows.length) return res.status(401).json({ success: false, message: 'Galat login' });
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!ok) { await audit(username, 'ADMIN_LOGIN_FAIL', 'Wrong password', req.ip); return res.status(401).json({ success: false, message: 'Galat login' }); }
  const token = jwt.sign({ username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '12h' });
  await audit(username, 'ADMIN_LOGIN', 'Login success', req.ip);
  res.json({ success: true, token });
});
app.post('/api/admin/approve-deposit', checkAdmin, async (req, res) => {
  const { depositId, approve } = req.body;
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const d = await c.query('SELECT * FROM deposits WHERE id=$1 FOR UPDATE', [depositId]);
    if (!d.rows.length) throw new Error('Deposit nahi mila');
    if (d.rows[0].status !== 'PENDING') throw new Error('Pehle se handle ho chuka hai');
    if (approve) {
      await c.query('UPDATE deposits SET status=\'APPROVED\' WHERE id=$1', [depositId]);
      await c.query(`UPDATE wallets SET balance=balance+$1, vip_level=GREATEST(vip_level,1), updated_at=NOW(), daily_deposit = CASE WHEN daily_deposit_date=CURRENT_DATE THEN daily_deposit+$1 ELSE $1 END, daily_deposit_date=CURRENT_DATE WHERE user_id=$2 RETURNING balance`, [d.rows[0].amount, d.rows[0].user_id]);
      const up = await c.query('SELECT balance FROM wallets WHERE user_id=$1', [d.rows[0].user_id]);
      await c.query('INSERT INTO transactions (user_id, amount, type, status, utr) VALUES ($1,$2,\'DEPOSIT\',\'SUCCESS\',$3)', [d.rows[0].user_id, d.rows[0].amount, d.rows[0].utr]);
      await c.query('COMMIT');
      await audit(req.admin.username, 'APPROVE_DEPOSIT', `Deposit ${depositId} Amt ${d.rows[0].amount} User ${d.rows[0].user_id}`, req.ip);
      res.json({ success: true, message: 'Deposit approve ho gaya, VIP1 unlock!', balance: up.rows[0].balance });
    } else {
      await c.query('UPDATE deposits SET status=\'REJECTED\' WHERE id=$1', [depositId]);
      await c.query('COMMIT');
      res.json({ success: true, message: 'Deposit reject kar diya' });
    }
  } catch(e){ await c.query('ROLLBACK'); res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});
app.get('/api/admin/pending-deposits', checkAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM deposits WHERE status=\'PENDING\' ORDER BY created_at ASC');
  res.json({ success: true, deposits: r.rows });
});
app.get('/api/admin/pending-withdraws', checkAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM withdraws WHERE status=\'PENDING\' ORDER BY created_at ASC');
  res.json({ success: true, withdraws: r.rows });
});

// ===== FIX 3: Withdraw Approve / Reject + Refund =====[span_10](start_span)[span_10](end_span)
app.post('/api/admin/handle-withdraw', checkAdmin, async (req, res) => {
  const { withdrawId, approve } = req.body;
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT * FROM withdraws WHERE id=$1 FOR UPDATE', [withdrawId]);
    if (!w.rows.length) throw new Error('Withdraw nahi mila');
    if (w.rows[0].status !== 'PENDING') throw new Error('Pehle se handle ho chuka hai');
    if (approve) {
      await c.query(`UPDATE withdraws SET status='APPROVED' WHERE id=$1`, [withdrawId]);
      await c.query('COMMIT');
      await audit(req.admin.username, 'APPROVE_WITHDRAW', `Withdraw ${withdrawId} Amt ${w.rows[0].amount} User ${w.rows[0].user_id}`, req.ip);
      res.json({ success: true, message: 'Withdraw approve ho gaya - Paisa bhej do' });
    } else {
      await c.query(`UPDATE withdraws SET status='REJECTED' WHERE id=$1`, [withdrawId]);
      await c.query(`UPDATE wallets SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2`, [w.rows[0].amount, w.rows[0].user_id]);
      await c.query(`INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,'WITHDRAW_REFUND','SUCCESS')`, [w.rows[0].user_id, w.rows[0].amount]);
      await c.query('COMMIT');
      await audit(req.admin.username, 'REJECT_WITHDRAW', `Withdraw ${withdrawId} Reject + Refund ${w.rows[0].amount}`, req.ip);
      res.json({ success: true, message: 'Withdraw reject + Paisa wapas kar diya' });
    }
  } catch(e){ await c.query('ROLLBACK'); res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});

app.get('/api/admin/settings', checkAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM settings');
  res.json({ success: true, settings: Object.fromEntries(r.rows.map(x => [x.key, x.value])) });
});
app.post('/api/admin/teenpatti-settings', checkAdmin, async (req, res) => {
  const { teenpatti_rake, teenpatti_boot } = req.body;
  if (teenpatti_rake !== undefined) {
    const v = parseFloat(teenpatti_rake);
    if (v < 3 || v > 8) return res.status(400).json({ success: false, message: 'Rake 3% se 8% ke beech rakho' });
    await pool.query(`INSERT INTO settings (key,value) VALUES ('teenpatti_rake',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(v)]);
  }
  if (teenpatti_boot !== undefined) {
    const b = parseFloat(teenpatti_boot);
    if (b < 5 || b > 500) return res.status(400).json({ success: false, message: 'Boot 5 se 500 ke beech' });
    await pool.query(`INSERT INTO settings (key,value) VALUES ('teenpatti_boot',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(b)]);
  }
  res.json({ success: true, message: 'Teen Patti Settings Save!' });
});
app.post('/api/admin/aviator-settings', checkAdmin, async (req, res) => {
  const { aviator_house_edge, aviator_min_crash, aviator_max_crash } = req.body;
  if (aviator_house_edge !== undefined) {
    const v = parseFloat(aviator_house_edge);
    if (v < 2 || v > 10) return res.status(400).json({ success: false, message: 'House Edge 2% se 10% ke beech' });
    await pool.query(`INSERT INTO settings (key,value) VALUES ('aviator_house_edge',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(v)]);
  }
  if (aviator_min_crash !== undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('aviator_min_crash',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(aviator_min_crash)]);
  if (aviator_max_crash !== undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('aviator_max_crash',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(aviator_max_crash)]);
  res.json({ success: true, message: 'Aviator Settings Save!' });
});
app.post('/api/admin/spin-settings', checkAdmin, async (req, res) => {
  const { spin_rtp, min_bet, max_bet } = req.body;
  if (spin_rtp !== undefined) {
    const v = parseFloat(spin_rtp);
    if (v < 80 || v > 98) return res.status(400).json({ success: false, message: 'Spin RTP 80 se 98 ke beech' });
    await pool.query(`INSERT INTO settings (key,value) VALUES ('spin_rtp',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(v)]);
  }
  if (min_bet !== undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('min_bet',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(min_bet)]);
  if (max_bet !== undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('max_bet',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [String(max_bet)]);
  res.json({ success: true, message: 'Spin Settings Save!' });
});
app.post('/api/admin/casino-settings', checkAdmin, async (req, res) => {
  const { dragontiger_rtp, roulette_rtp, mines_rtp, andarbahar_rtp, plinko_rtp, baccarat_rtp, poker_rtp, slots_rtp, colour_rtp, chicken_rtp, fortunegems_rtp, gemstemple_rtp } = req.body;
  const map = { dragontiger_rtp, roulette_rtp, mines_rtp, andarbahar_rtp, plinko_rtp, baccarat_rtp, poker_rtp, slots_rtp, colour_rtp, chicken_rtp, fortunegems_rtp, gemstemple_rtp };
  for (let k in map) { if (map[k] !== undefined) { const v = parseFloat(map[k]); if (v < 80 || v > 98) continue; await pool.query(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2`, [k, String(v)]); } }
  res.json({ success: true, message: 'Casino Games Save!' });
});
app.post('/api/admin/block-user', checkAdmin, async (req, res) => {
  const { mobile, block } = req.body;
  await pool.query('UPDATE wallets SET is_blocked=$1 WHERE user_id=$2', [!!block, mobile]);
  await audit(req.admin.username, block ? 'BLOCK_USER' : 'UNBLOCK_USER', `User ${mobile}`, req.ip);
  res.json({ success: true, message: block ? 'User block kar diya' : 'User unblock kar diya' });
});

app.post('/api/wallet/withdraw', checkAuth, async (req, res) => {
  const { amount, upi_id, account_no, ifsc } = req.body;
  const userId = req.user.mobile;
  if (!amount || amount < 300) return res.status(400).json({ success: false, message: 'Min ₹300 Withdraw hai bhai!' });
  if (amount > 50000) return res.status(400).json({ success: false, message: 'Max ₹50000 ek baar me!' });
  if (upi_id && !String(upi_id).includes('@')) return res.status(400).json({ success: false, message: 'Sahi UPI ID daalo - jaise 98765@paytm' });[span_11](start_span)[span_11](end_span)
  if (!upi_id && !account_no) return res.status(400).json({ success: false, message: 'UPI ya Account daalo' });
  const blocked = await checkBlocked(userId);
  if (blocked.blocked) return res.status(403).json({ success: false, message: blocked.reason });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT balance, vip_level FROM wallets WHERE user_id=$1 FOR UPDATE', [userId]);
    if (!w.rows.length) throw new Error('Wallet nahi mila');
    if ((w.rows[0].vip_level || 0) < 1) throw new Error('Pehle VIP1 Deposit karo fir Withdraw hoga!');
    if (parseFloat(w.rows[0].balance) < parseFloat(amount)) throw new Error('Balance kam hai');
    await c.query('UPDATE wallets SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2', [amount, userId]);
    await c.query('INSERT INTO withdraws (user_id, amount, upi_id, account_no, ifsc) VALUES ($1,$2,$3,$4,$5)', [userId, amount, upi_id || null, account_no || null, ifsc || null]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'WITHDRAW\',\'PENDING\')', [userId, amount]);
    await c.query('COMMIT');
    await audit(userId, 'WITHDRAW_REQUEST', `Amt ${amount} IP ${req.ip}`, req.ip);
    res.json({ success: true, message: 'Withdraw request bhej diya' });
  } catch(e){ await c.query('ROLLBACK'); res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});

// ================= SOCKET + 15 GAMES =================
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Token chahiye'));
  try { socket.user = jwt.verify(token, process.env.JWT_SECRET); next(); } catch(e){ next(new Error('Token galat hai')); }
});

io.on('connection', (socket) => {
  const userId = socket.user.mobile;
  let serverSeed = generateServerSeed();
  let seedHash = hashSeed(serverSeed);
  let nonce = 1;
  socket.emit('provably-fair:init', { serverSeedHash: seedHash });
  socket.emit('game:state', { gameState, currentMultiplier, roundTimer, roundId });

  socket.on('game:spin', async (data) => {
    const betAmount = parseFloat(data.betAmount);
    const clientSeed = String(data.clientSeed || 'default');
    const minBet = await getSetting('min_bet', 10);
    const maxBet = await getSetting('max_bet', 5000);
    const rtp = await getSetting('spin_rtp', 96);
    if (!betAmount || betAmount < minBet || betAmount > maxBet) return socket.emit('game:error', { message: `Bet ${minBet} se ${maxBet} ke beech rakho` });
    const tx = await placeBet(userId, betAmount);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const { val } = fairOutcome(serverSeed, clientSeed, nonce);
    const winChance = Math.floor((rtp / 2) * 100);
    const isWin = val < winChance;
    const winnings = isWin ? betAmount * 2 : 0;
    let finalBalance = tx.newBalance;
    if (isWin) finalBalance = await creditWin(userId, winnings);
    socket.emit('game:result', { outcome: val, isWin, winnings, newBalance: finalBalance, nonce, serverSeedHash: seedHash, revealedServerSeed: serverSeed });
    nonce++;
    if (nonce % 100 === 0) { serverSeed = generateServerSeed(); seedHash = hashSeed(serverSeed); nonce = 1; socket.emit('provably-fair:init', { serverSeedHash: seedHash }); }
  });

  socket.on('aviator:bet', async (data) => {
    if (gameState !== 'WAITING') return socket.emit('game:error', { message: 'Betting band ho gayi, agle round me try karo' });
    if (aviatorBets.has(socket.id)) return socket.emit('game:error', { message: 'Ek round me 1 hi Bet lag sakti hai' });
    const bet = parseFloat(data.betAmount);
    if (!bet || bet < 10 || bet > 50000) return socket.emit('game:error', { message: 'Min Bet ₹10 - Max ₹50000' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    aviatorBets.set(socket.id, { userId, bet, cashedOut: false, roundId });
    socket.emit('aviator:bet-placed', { bet, newBalance: tx.newBalance });
  });
  
  socket.on('aviator:cashout', async () => {
    const b = aviatorBets.get(socket.id);
    if (!b || b.cashedOut) return socket.emit('game:error', { message: 'Bet nahi hai' });
    if (b.cashoutLock) return socket.emit('game:error', { message: 'Cashout already ho raha hai' }); // Race condition fix[span_12](start_span)[span_12](end_span)
    b.cashoutLock = true;
    if (gameState !== 'RUNNING') return socket.emit('game:error', { message: 'Game abhi chal nahi rahi' });
    if (b.roundId !== roundId) return socket.emit('game:error', { message: 'Ye Bet purane round ki hai' });
    b.cashedOut = true;
    const win = parseFloat((b.bet * currentMultiplier).toFixed(2));
    const bal = await creditWin(userId, win);
    socket.emit('aviator:cashed', { win, multiplier: currentMultiplier, newBalance: bal });
  });

  // TEEN PATTI MULTIPLAYER ENGINE
  function tpCardFormat(card){ if(!card) return card; if(card.includes('-')){ let p = card.split('-'); return p[1] + p[0]; } return card; }
  function tpEvaluate(cards){
    if(!cards || !cards.length) return { score:0, name:'NO CARD' };
    let vals = cards.map(c=>{ let r = c.replace(/[♠♥♦♣]/g,''); return r==='A'?14 : r==='K'?13 : r==='Q'?12 : r==='J'?11 : parseInt(r); }).sort((a,b)=>a-b);
    let suits = cards.map(c=>c.slice(-1));
    let isFlush = suits[0]===suits[1] && suits[1]===suits[2];
    let isSeq = (vals[2]-vals[1]===1 && vals[1]-vals[0]===1) || (vals[0]===2 && vals[1]===3 && vals[2]===14);
    let isTrail = vals[0]===vals[1] && vals[1]===vals[2];
    let isPair = vals[0]===vals[1] || vals[1]===vals[2];
    if(isTrail) return { score: 600+vals[0], name:'TRAIL' };
    if(isFlush && isSeq) return { score: 500+vals[2], name:'PURE SEQUENCE' };
    if(isSeq) return { score: 400+vals[2], name:'SEQUENCE' };
    if(isFlush) return { score: 300+vals[2], name:'COLOR' };
    if(isPair){ let pv = vals[0]===vals[1]?vals[0]:vals[2]; return { score: 200+pv, name:'PAIR' }; }
    return { score: 100+vals[2], name:'HIGH CARD' };
  }
  function getOrCreateTeenTable(tableId, boot){
    if(!teenTables.has(tableId)){
      teenTables.set(tableId, { pot: 0, blind: boot, currentChaal: boot, turnIdx: 0, order: [], active: {}, seenMap: {}, cardsMap: {}, puts: {}, players: [], watchers: [], started: false, timer: null, lastAction: null, startTimeout: null });
    }
    return teenTables.get(tableId);
  }
  function clearTeenTimer(table){ if(table.timer){ clearTimeout(table.timer); table.timer=null; } }
  function teenRecalcPot(table){ table.pot = Object.values(table.puts||{}).reduce((a,b)=>a+(parseFloat(b)||0),0); return table.pot; }
  function teenCost(table, seat){ return table.seenMap[seat] ? table.currentChaal*2 : table.currentChaal; }
  
  function teenBotAction(tableId){
    let table = teenTables.get(tableId); if(!table || !table.started) return;
    let who = table.order[table.turnIdx];
    if(!who || !table.active[who]) return;
    let isBot = table.players.find(p=>p.seat===who)?.isBot;
    if(!isBot) return;
    clearTeenTimer(table);
    table.timer = setTimeout(()=>{
      let t = teenTables.get(tableId); if(!t || !t.started) return;
      if(t.order[t.turnIdx]!==who) return;
      let ev = tpEvaluate(t.cardsMap[who]);
      let dec = 'PACK';
      // Secure random check via crypto
      if(ev.score >= 500) dec = crypto.randomInt(0,100)<85?'CHAAL':'PACK';
      else if(ev.score >= 400) dec = crypto.randomInt(0,100)<60?'CHAAL':'PACK';
      else if(ev.score >= 200) dec = crypto.randomInt(0,100)<50?'CHAAL':'PACK';
      else dec = crypto.randomInt(0,100)<15?'CHAAL':'PACK';
      
      if(dec==='PACK'){
        t.active[who]=false;
        io.to(tableId).emit('teenpatti:bot-action', { bot: who, action:'PACK', amount:0, totalPut: t.puts[who]||0, puts: t.puts });
        io.to(tableId).emit('teenpatti:player-packed', { userId: who, reason:'PACK', name: who });
      } else {
        if(crypto.randomInt(0,100)<30) t.seenMap[who]=true;
        if(ev.score>=400 && crypto.randomInt(0,100)<25) t.currentChaal = t.currentChaal*2;
        let botCost = teenCost(t, who);
        t.puts[who] = (t.puts[who]||0) + botCost;
        teenRecalcPot(t);
        io.to(tableId).emit('teenpatti:bot-action', { bot: who, action: t.seenMap[who]?'CHAAL':'BLIND', amount: botCost, totalPut: t.puts[who], puts: t.puts, currentChaal: t.currentChaal });
        io.to(tableId).emit('teenpatti:pot-update', { pot: t.pot, blind: t.currentChaal, seen: t.currentChaal*2, currentChaal: t.currentChaal, puts: t.puts, lastAction:{ userId: who, action: t.seenMap[who]?'CHAAL':'BLIND', amount: botCost, totalPut: t.puts[who] } });
      }
      clearTeenTimer(t);
      teenNextTurn(tableId);
    }, 2000 + crypto.randomInt(0, 2000));
  }
  
  function startTeenTurnTimer(tableId){
    let table = teenTables.get(tableId); if(!table) return;
    clearTeenTimer(table);
    let who = table.order[table.turnIdx];
    io.to(tableId).emit('teenpatti:turn', { turn: who, blind: table.currentChaal, seen: table.currentChaal*2, currentChaal: table.currentChaal, pot: table.pot, puts: table.puts, time: 10, yourCost: teenCost(table, who) });
    let isBot = table.players.find(p=>p.seat===who)?.isBot;
    if(isBot) return teenBotAction(tableId);
    table.timer = setTimeout(()=>{
      let t = teenTables.get(tableId); if(!t) return;
      let timedOut = t.order[t.turnIdx];
      t.active[timedOut] = false;
      io.to(tableId).emit('teenpatti:player-packed', { userId: timedOut, reason:'TIMEOUT', name: timedOut });
      let alive = Object.values(t.active).filter(Boolean).length;
      if(alive <= 1) return teenFinishGame(tableId);
      for(let i=0;i<5;i++){ t.turnIdx = (t.turnIdx+1)%5; if(t.active[t.order[t.turnIdx]]) break; }
      startTeenTurnTimer(tableId);
    }, 10000);
  }
  
  function teenNextTurn(tableId){
    let table = teenTables.get(tableId); if(!table) return;
    let alive = Object.values(table.active).filter(Boolean).length;
    if(alive <= 1) return teenFinishGame(tableId);
    for(let i=0;i<10;i++){ table.turnIdx = (table.turnIdx+1)%table.order.length; if(table.active[table.order[table.turnIdx]]) break; }
    startTeenTurnTimer(tableId);
  }
  
  async function teenFinishGame(tableId){
    let table = teenTables.get(tableId); if(!table) return;
    clearTeenTimer(table);
    if(table.startTimeout) clearTimeout(table.startTimeout);
    let best=null, bestScore=-1;
    for(let name of table.order){
      if(!table.active[name]) continue;
      let s = tpEvaluate(table.cardsMap[name]).score;
      if(s > bestScore){ bestScore=s; best=name; }
    }
    if(!best){ teenTables.delete(tableId); return; }
    const rakePercent = await getSetting('teenpatti_rake', 5);
    const totalPot = table.pot;
    const rake = Math.floor(totalPot * rakePercent / 100);
    const winnerAmount = totalPot - rake;
    let winnerPlayer = table.players.find(p=>p.seat===best);
    if(winnerPlayer && !winnerPlayer.isBot) await creditWin(winnerPlayer.userId, winnerAmount);
    await pool.query(`INSERT INTO wallets (user_id, balance) VALUES ('HOUSE_ACCOUNT', $1) ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + $1`, [rake]);
    io.to(tableId).emit('teenpatti:winner', { winner: best, winnerId: best, totalPot, rake, rakePercent, winnerGot: winnerAmount, puts: table.puts, allCards: table.order.map(n=>({ name:n, cards: table.cardsMap[n], hand: tpEvaluate(table.cardsMap[n]).name })) });
    io.to(tableId).emit('teenpatti:showdown', { winner: best, hands: Object.fromEntries(table.order.map(n=>[n, table.cardsMap[n]])) });
    teenTables.delete(tableId);
  }

  socket.on('teenpatti:join', async (data) => {
    const tableId = data.tableId || 'table1';
    const isWatch = !!data.watch;
    const boot = await getSetting('teenpatti_boot', 5);
    let table = getOrCreateTeenTable(tableId, boot);
    if(isWatch){
      socket.join(tableId);
      table.watchers.push({ socketId: socket.id, userId });
      socket.emit('teenpatti:waiting', { message: 'Watch Mode - Real Game dekh rahe ho', pot: table.pot, boot, puts: table.puts });
      if(table.started){
        socket.emit('teenpatti:game-started', { pot: table.pot, blind: table.blind, seen: table.blind*2, turn: table.order[table.turnIdx], puts: table.puts });
        socket.emit('teenpatti:turn', { turn: table.order[table.turnIdx], blind: table.blind, seen: table.blind*2, pot: table.pot, puts: table.puts, time: 10 });
      }
      return;
    }
    if(table.started) return socket.emit('game:error', { message: 'Game chal rahi hai, agle game me aao - 5 sec wait' });
    if(table.players.find(p=>p.userId===userId)) return socket.emit('game:error', { message: 'Pehle se table me ho' });
    if(table.players.length >= 5) return socket.emit('game:error', { message: 'Table full hai, agle game me aao' });
    const tx = await placeBet(userId, boot);
    if(!tx.success) return socket.emit('game:error', { message: tx.error });
    let seatName = 'P' + (table.players.length+1);
    table.players.push({ socketId: socket.id, userId, seat: seatName, isBot:false, status:'ACTIVE' });
    table.puts[seatName] = boot;
    table.currentChaal = boot;
    teenRecalcPot(table);
    socket.join(tableId);
    socket.data.teenSeat = seatName;
    socket.data.teenTable = tableId;
    socket.emit('teenpatti:waiting', { message: 'New Game 5 sec me start hoga...', pot: table.pot, boot, puts: table.puts, seat: seatName });
    socket.emit('teenpatti:joined', { pot: table.pot, seat: seatName, message: 'Table Join ho gaya' });
    if(table.players.length===1 && !table.startTimeout){
      table.startTimeout = setTimeout(()=>{
        let t = teenTables.get(tableId); if(!t || t.started) return;
        t.started = true;
        const botNames = ['Vikram','Rahul','Apurbo','Bapan'];
        let botIdx = 0;
        while(t.players.length < 5){
          let bSeat = 'BOT_' + botNames[botIdx];
          t.players.push({ socketId:'BOT_'+bSeat, userId:'BOT_'+bSeat, seat: bSeat, isBot:true, status:'ACTIVE' });
          t.puts[bSeat] = boot;
          teenRecalcPot(t);
          botIdx++;
        }
        t.order = t.players.map(p=>p.seat);
        t.order.forEach(name=>{ t.active[name]=true; t.seenMap[name]=false; });
        let deck = shuffleDeck().map(tpCardFormat);
        let idx=0;
        t.order.forEach(name=>{ t.cardsMap[name] = [deck[idx++], deck[idx++], deck[idx++]]; });
        t.players.forEach(p=>{
          if(!p.isBot){
            io.to(p.socketId).emit('teenpatti:cards', { myCards: t.cardsMap[p.seat], cards: t.cardsMap[p.seat], pot: t.pot, boot: t.blind, puts: t.puts, seat: p.seat, players: t.order });
          }
        });
        io.to(tableId).emit('teenpatti:game-started', { pot: t.pot, blind: t.currentChaal, seen: t.currentChaal*2, currentChaal: t.currentChaal, turn: t.order[0], puts: t.puts, order: t.order });
        t.turnIdx = 0;
        startTeenTurnTimer(tableId);
      }, 5000);
    } else {
      io.to(tableId).emit('teenpatti:pot-update', { pot: table.pot, blind: table.blind, seen: table.blind*2, puts: table.puts });
    }
  });

  function getMySeat(socket, tableId){
    if(socket.data.teenSeat) return socket.data.teenSeat;
    let table = teenTables.get(tableId); if(!table) return null;
    let p = table.players.find(x=>x.socketId===socket.id);
    return p ? p.seat : null;
  }
  
  socket.on('teenpatti:seen', async (data)=>{
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId); if(!table) return;
    let seat = getMySeat(socket, tableId); if(!seat) return;
    table.seenMap[seat] = true;
    socket.emit('teenpatti:seen-ok', { seenAmount: table.currentChaal*2, blind: table.currentChaal, currentChaal: table.currentChaal, seat });
    socket.emit('teenpatti:seen', { cards: table.cardsMap[seat], myCards: table.cardsMap[seat] });
  });
  
  socket.on('teenpatti:chaal', async (data) => {
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId); if(!table) return;
    let seat = getMySeat(socket, tableId); if(!seat) return socket.emit('game:error', { message: 'Table me nahi ho' });
    if(table.order[table.turnIdx] !== seat) return socket.emit('game:error', { message: 'Abhi teri baari nahi hai' });
    let expected = teenCost(table, seat);
    let chaalAmt = parseFloat(data.amount);
    if(chaalAmt !== expected) return socket.emit('game:error', { message: `Galat amount! Abhi chaal ₹${table.currentChaal} hai, tujhe ₹${expected} dena hai` });
    const tx = await placeBet(userId, chaalAmt);
    if(!tx.success) return socket.emit('game:error', { message: tx.error });
    table.puts[seat] = (table.puts[seat]||0) + chaalAmt;
    teenRecalcPot(table);
    table.lastAction = { userId: seat, action: table.seenMap[seat]?'CHAAL':'BLIND', amount: chaalAmt, totalPut: table.puts[seat] };
    io.to(tableId).emit('teenpatti:pot-update', { pot: table.pot, blind: table.currentChaal, seen: table.currentChaal*2, currentChaal: table.currentChaal, puts: table.puts, lastAction: table.lastAction });
    clearTeenTimer(table);
    teenNextTurn(tableId);
  });
  
  async function handleBlind2(socket, data){
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId); if(!table) return;
    let seat = getMySeat(socket, tableId); if(!seat) return;
    if(table.order[table.turnIdx] !== seat) return socket.emit('game:error', { message: 'Teri baari nahi hai' });
    table.currentChaal = table.currentChaal * 2;
    let cost = teenCost(table, seat);
    const tx = await placeBet(userId, cost);
    if(!tx.success) return socket.emit('game:error', { message: tx.error });
    table.puts[seat] = (table.puts[seat]||0) + cost;
    teenRecalcPot(table);
    io.to(tableId).emit('teenpatti:pot-update', { pot: table.pot, blind: table.currentChaal, seen: table.currentChaal*2, currentChaal: table.currentChaal, puts: table.puts, lastAction:{ userId: seat, action:'BLIND x2', amount:cost, totalPut: table.puts[seat] } });
    clearTeenTimer(table);
    teenNextTurn(tableId);
  }
  socket.on('teenpatti:blind2', async (data)=>{ await handleBlind2(socket, data); });
  socket.on('teenpatti:blind', async (data)=>{ await handleBlind2(socket, data); });

  socket.on('teenpatti:pack', async (data) => {
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId); if(!table) return;
    let seat = getMySeat(socket, tableId); if(!seat) return;
    if(table.order[table.turnIdx] !== seat) return socket.emit('game:error', { message: 'Teri baari nahi hai, Pack nahi kar sakta' });
    if(!table.active[seat]) return;
    table.active[seat] = false;
    io.to(tableId).emit('teenpatti:player-packed', { userId: seat, name: seat });
    clearTeenTimer(table);
    teenNextTurn(tableId);
  });
  
  socket.on('teenpatti:sideshow', async (data)=>{
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId); if(!table) return;
    let seat = getMySeat(socket, tableId); if(!seat) return;
    if(table.order[table.turnIdx] !== seat) return socket.emit('game:error', { message: 'Side Show apni baari me hi hoga' });
    let opp = data.opp;
    if(opp && !table.order.includes(opp)){
      let found = table.players.find(p=>p.seat.includes(opp) || opp.includes(p.seat));
      if(found) opp = found.seat;
    }
    if(!opp) {
      let idx = table.order.indexOf(seat);
      for(let k=1;k<5;k++){ let n = table.order[(idx - k + table.order.length)%table.order.length]; if(table.active[n]){ opp=n; break; } }
    }
    if(!opp || !table.active[opp]) return socket.emit('game:error', { message: 'Wo player Pack ho chuka hai' });
    if(!table.seenMap[seat]) return socket.emit('game:error', { message: 'Side Show ke liye pehle SEE dabao' });
    let cost = table.currentChaal*2;
    const tx = await placeBet(userId, cost);
    if(!tx.success) return socket.emit('game:error', { message: tx.error });
    table.puts[seat] = (table.puts[seat]||0) + cost;
    teenRecalcPot(table);
    let myRank = tpEvaluate(table.cardsMap[seat]);
    let oppRank = tpEvaluate(table.cardsMap[opp]);
    let meWin = myRank.score > oppRank.score;
    if(myRank.score===oppRank.score){
      let myMax = Math.max(...table.cardsMap[seat].map(c=>{ let r=c.replace(/[♠♥♦♣]/g,''); return r==='A'?14:r==='K'?13:r==='Q'?12:r==='J'?11:parseInt(r); }));
      let oppMax = Math.max(...table.cardsMap[opp].map(c=>{ let r=c.replace(/[♠♥♦♣]/g,''); return r==='A'?14:r==='K'?13:r==='Q'?12:r==='J'?11:parseInt(r); }));
      meWin = myMax > oppMax;
    }
    let loser = meWin ? opp : seat;
    table.active[loser] = false;
    socket.emit('teenpatti:sideshow-private', { you: table.cardsMap[seat], youRank: myRank.name, youScore: myRank.score, opp: table.cardsMap[opp], oppName: opp, oppRank: oppRank.name, oppScore: oppRank.score, winner: meWin?seat:opp, loser });
    socket.to(tableId).emit('teenpatti:sideshow-done', { winner: meWin?seat:opp, loser, pot: table.pot, puts: table.puts });
    io.to(tableId).emit('teenpatti:pot-update', { pot: table.pot, blind: table.blind, seen: table.blind*2, puts: table.puts });
    clearTeenTimer(table);
    setTimeout(()=> teenNextTurn(tableId), 1000);
  });
  
  socket.on('teenpatti:show', async (data) => {
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId); if(!table) return;
    let alive = Object.values(table.active).filter(Boolean).length;
    if(alive > 2) return socket.emit('game:error', { message: 'Show ke liye 2 player hone chahiye, abhi Side Show lo' });
    await teenFinishGame(tableId);
  });

  // OTHER CASINO GAMES
  socket.on('dragontiger:bet', async (data) => {
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    if (!['DRAGON', 'TIGER', 'TIE'].includes(choice)) return socket.emit('game:error', { message: 'Dragon / Tiger / Tie chuno' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const deck = shuffleDeck();
    const dCard = deck[0];
    const tCard = deck[1];
    const dVal = getRankValue(dCard);
    const tVal = getRankValue(tCard);
    let winner = dVal > tVal ? 'DRAGON' : tVal > dVal ? 'TIGER' : 'TIE';
    let isWin = (choice === winner);
    let multiplier = 1;
    if (winner === 'TIE') multiplier = 8; else if (isWin) multiplier = 2;
    let winnings = isWin ? bet * multiplier : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('dragontiger:result', { dragonCard: dCard, tigerCard: tCard, winner, choice, isWin, winnings, newBalance: bal });
  });

  socket.on('roulette:bet', async (data) => {
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const num = fairRandom(37);
    let color = num === 0 ? 'GREEN' : [1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36].includes(num) ? 'RED' : 'BLACK';
    let isWin = false; let multiplier = 0;
    if (choice === 'RED' && color === 'RED') { isWin = true; multiplier = 2; }
    if (choice === 'BLACK' && color === 'BLACK') { isWin = true; multiplier = 2; }
    if (choice === 'GREEN' && color === 'GREEN') { isWin = true; multiplier = 14; }
    if (!isNaN(parseInt(choice)) && parseInt(choice) === num) { isWin = true; multiplier = 36; }
    let winnings = isWin ? bet * multiplier : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('roulette:result', { number: num, color, choice, isWin, winnings, newBalance: bal });
  });

  socket.on('mines:play', async (data) => {
    const bet = parseFloat(data.betAmount);
    const minesCount = parseInt(data.mines) || 3;
    const picked = data.picked || [];
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    if (picked.length === 0) return socket.emit('game:error', { message: 'Ek box chuno' });
    if (minesCount < 1 || minesCount > 10) return socket.emit('game:error', { message: 'Mines 1-10 ke beech' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    let minePositions = new Set();
    while (minePositions.size < minesCount) minePositions.add(fairRandom(25));
    let hitMine = picked.some(p => minePositions.has(p));
    let multiplier = 1 + (picked.length * 0.4) + (minesCount * 0.2);
    let winnings = hitMine ? 0 : parseFloat((bet * multiplier).toFixed(2));
    let bal = tx.newBalance;
    if (!hitMine) bal = await creditWin(userId, winnings);
    socket.emit('mines:result', { picked, hitMine, isWin: !hitMine, winnings, multiplier: parseFloat(multiplier.toFixed(2)), newBalance: bal });
  });

  socket.on('andarbahar:bet', async (data) => {
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    if (!['ANDAR', 'BAHAR'].includes(choice)) return socket.emit('game:error', { message: 'Andar / Bahar chuno' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const deck = shuffleDeck();
    const joker = deck[0];
    const jokerVal = getRankValue(joker);
    let winner = null;
    let cards = { andar: [], bahar: [] };
    for (let i = 1; i < deck.length; i++) {
      if (i % 2 === 1) { cards.andar.push(deck[i]); if (getRankValue(deck[i]) === jokerVal) { winner = 'ANDAR'; break; } }
      else { cards.bahar.push(deck[i]); if (getRankValue(deck[i]) === jokerVal) { winner = 'BAHAR'; break; } }
      if (i > 20) break;
    }
    let isWin = (choice === winner);
    let winnings = isWin ? bet * 2 : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('andarbahar:result', { joker, winner, choice, isWin, winnings, cards, newBalance: bal });
  });

  socket.on('plinko:play', async (data) => {
    const bet = parseFloat(data.betAmount);
    const risk = data.risk || 'MEDIUM';
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    let pos = 0; let path = [];
    for (let i = 0; i < 8; i++) { let dir = fairRandom(2) === 0 ? -1 : 1; path.push(dir === -1 ? 'L' : 'R'); pos += dir; }
    const multipliers = [10, 3, 1.5, 0.8, 0.5, 0.8, 1.5, 3, 10];
    let slot = pos + 4; if (slot < 0) slot = 0; if (slot > 8) slot = 8;
    let mult = multipliers[slot];
    if (risk === 'HIGH') mult = mult * 1.5;
    if (risk === 'LOW') mult = mult * 0.7;
    mult = parseFloat(mult.toFixed(2));
    let winnings = parseFloat((bet * mult).toFixed(2));
    let bal = await creditWin(userId, winnings);
    socket.emit('plinko:result', { path, slot, multiplier: mult, winnings, newBalance: bal, risk });
  });

  socket.on('baccarat:bet', async (data) => {
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    if (!['PLAYER', 'BANKER', 'TIE'].includes(choice)) return socket.emit('game:error', { message: 'Player / Banker / Tie chuno' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const deck = shuffleDeck();
    const bVal = (c) => { let v = getRankValue(c); if (v >= 10) return 0; if (v === 14) return 1; return v; };
    let pCards = [deck[0], deck[2]];
    let bCards = [deck[1], deck[3]];
    let pTotal = (bVal(pCards[0]) + bVal(pCards[1])) % 10;
    let bTotal = (bVal(bCards[0]) + bVal(bCards[1])) % 10;
    let winner = pTotal > bTotal ? 'PLAYER' : bTotal > pTotal ? 'BANKER' : 'TIE';
    let isWin = (choice === winner);
    let mult = 0;
    if (isWin) { if (winner === 'TIE') mult = 8; else if (winner === 'PLAYER') mult = 2; else mult = 1.95; }
    let winnings = isWin ? parseFloat((bet * mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('baccarat:result', { playerCards: pCards, bankerCards: bCards, playerTotal: pTotal, bankerTotal: bTotal, winner, choice, isWin, winnings, newBalance: bal });
  });

  socket.on('poker:play', async (data) => {
    const bet = parseFloat(data.betAmount);
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const deck = shuffleDeck();
    const myCards = deck.slice(0, 5);
    const botCards = deck.slice(5, 10);
    function pokerScore(cards) {
      const vals = cards.map(getRankValue).sort((a, b) => a - b);
      const counts = {};
      vals.forEach(v => counts[v] = (counts[v] || 0) + 1);
      const pairs = Object.values(counts).sort((a, b) => b - a);
      const isFlush = cards.map(c => c.split('-')[0]).every(s => s === cards[0].split('-')[0]);
      const isStraight = vals[4] - vals[0] === 4 && new Set(vals).size === 5;
      if (isFlush && isStraight) return { score: 800 + vals[4], name: 'Straight Flush' };
      if (pairs[0] === 4) return { score: 700, name: 'Four of a Kind' };
      if (pairs[0] === 3 && pairs[1] === 2) return { score: 600, name: 'Full House' };
      if (isFlush) return { score: 500 + vals[4], name: 'Flush' };
      if (isStraight) return { score: 400 + vals[4], name: 'Straight' };
      if (pairs[0] === 3) return { score: 300, name: 'Three of a Kind' };
      if (pairs[0] === 2 && pairs[1] === 2) return { score: 200, name: 'Two Pair' };
      if (pairs[0] === 2) return { score: 100, name: 'Pair' };
      return { score: vals[4], name: 'High Card' };
    }
    const myScore = pokerScore(myCards);
    const botScore = pokerScore(botCards);
    let isWin = myScore.score > botScore.score;
    let isTie = myScore.score === botScore.score;
    let winnings = 0;
    if (isTie) winnings = bet;
    if (isWin) winnings = bet * 2;
    let bal = tx.newBalance;
    if (winnings > 0) bal = await creditWin(userId, winnings);
    socket.emit('poker:result', { myCards, botCards, myHand: myScore.name, botHand: botScore.name, isWin, isTie, winnings, newBalance: bal });
  });

  socket.on('slots:spin', async (data) => {
    const bet = parseFloat(data.betAmount);
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const symbols = ['🍒', '🍋', '🔔', '⭐', '💎', '7️⃣'];
    const r1 = symbols[fairRandom(symbols.length)];
    const r2 = symbols[fairRandom(symbols.length)];
    const r3 = symbols[fairRandom(symbols.length)];
    let mult = 0; let isWin = false; let winName = '';
    if (r1 === '7️⃣' && r2 === '7️⃣' && r3 === '7️⃣') { mult = 50; winName = 'JACKPOT 777!'; isWin = true; }
    else if (r1 === r2 && r2 === r3) { mult = 10; winName = 'Triple Match!'; isWin = true; }
    else if (r1 === r2 || r2 === r3 || r1 === r3) { mult = 2; winName = 'Double Match!'; isWin = true; }
    else if (r1 === '💎' || r2 === '💎' || r3 === '💎') { mult = 1.5; winName = 'Diamond!'; isWin = true; }
    let winnings = isWin ? parseFloat((bet * mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('slots:result', { reels: [r1, r2, r3], isWin, winName, multiplier: mult, winnings, newBalance: bal });
  });

  socket.on('colour:bet', async (data) => {
    const bet = parseFloat(data.betAmount);
    const target = data.target;
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const num = fairRandom(10);
    let color = '';
    if (num === 0) color = 'RED-VIOLET'; else if (num === 5) color = 'GREEN-VIOLET'; else if ([1, 3, 7, 9].includes(num)) color = 'GREEN'; else if ([2, 4, 6, 8].includes(num)) color = 'RED';
    let size = num >= 5 ? 'BIG' : 'SMALL';
    let isWin = false; let mult = 0;
    if (String(target) === String(num)) { isWin = true; mult = 9; }
    else if (target === 'RED' && (color === 'RED' || color === 'RED-VIOLET')) { isWin = true; mult = 2; }
    else if (target === 'GREEN' && (color === 'GREEN' || color === 'GREEN-VIOLET')) { isWin = true; mult = 2; }
    else if (target === 'VIOLET' && (color.includes('VIOLET'))) { isWin = true; mult = 4.5; }
    else if (target === 'BIG' && size === 'BIG') { isWin = true; mult = 2; }
    else if (target === 'SMALL' && size === 'SMALL') { isWin = true; mult = 2; }
    let winnings = isWin ? parseFloat((bet * mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('colour:result', { number: num, color, size, target, isWin, winnings, multiplier: mult, newBalance: bal });
  });

  socket.on('chicken:play', async (data) => {
    const bet = parseFloat(data.betAmount);
    const stepsWant = parseInt(data.steps) || 1;
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    if (stepsWant < 1 || stepsWant > 5) return socket.emit('game:error', { message: '1 se 5 step chuno' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const MULTS = [1.20, 1.50, 2.00, 3.50, 5.00];
    const crashAt = fairRandom(6);
    let isWin = crashAt >= stepsWant;
    if (stepsWant === 5) isWin = fairRandom(100) > 35;
    let mult = MULTS[stepsWant - 1];
    let winnings = isWin ? parseFloat((bet * mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('chicken:result', { steps: stepsWant, reached: isWin ? stepsWant : crashAt, isWin, multiplier: isWin ? mult : 0, winnings, newBalance: bal });
  });

  socket.on('fortunegems:spin', async (data) => {
    const bet = parseFloat(data.betAmount);
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const gems = ['💎','💚','💙','❤️','💜'];
    const reels = [gems[fairRandom(gems.length)], gems[fairRandom(gems.length)], gems[fairRandom(gems.length)], gems[fairRandom(gems.length)], gems[fairRandom(gems.length)]];
    const counts = {};
    reels.forEach(g=> counts[g]=(counts[g]||0)+1);
    const maxCount = Math.max(...Object.values(counts));
    let mult = 0, isWin = false, winName = '';
    if (maxCount >= 5) { mult = 15; winName = '5 Gems!'; isWin = true; }
    else if (maxCount === 4) { mult = 5; winName = '4 Gems!'; isWin = true; }
    else if (maxCount === 3) { mult = 2; winName = '3 Gems!'; isWin = true; }
    let winnings = isWin ? parseFloat((bet*mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('fortunegems:result', { reels, isWin, winName, multiplier: mult, winnings, newBalance: bal });
  });

  socket.on('gemstemple:spin', async (data) => {
    const bet = parseFloat(data.betAmount);
    if (!bet || bet < 10) return socket.emit('game:error', { message: 'Min Bet ₹10' });
    const tx = await placeBet(userId, bet);
    if (!tx.success) return socket.emit('game:error', { message: tx.error });
    const syms = ['⛩️','💎','🏯','🗿','🔮'];
    const reels = Array.from({length: 9}, ()=> syms[fairRandom(syms.length)]);
    const counts = {};
    reels.forEach(s=> counts[s]=(counts[s]||0)+1);
    const maxCount = Math.max(...Object.values(counts));
    let mult = 0, isWin = false;
    if (maxCount >= 7) { mult = 15; isWin = true; }
    else if (maxCount >= 5) { mult = 5; isWin = true; }
    else if (maxCount >= 4) { mult = 2; isWin = true; }
    else if (maxCount >= 3) { mult = 1.5; isWin = true; }
    let winnings = isWin ? parseFloat((bet*mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if (isWin) bal = await creditWin(userId, winnings);
    socket.emit('gemstemple:result', { reels, isWin, multiplier: mult, winnings, newBalance: bal });
  });

  socket.on('disconnect', () => {
    aviatorBets.delete(socket.id);
    if (socket.data.teenSeat && socket.data.teenTable) {
      let tableId = socket.data.teenTable;
      let table = teenTables.get(tableId);
      let seat = socket.data.teenSeat;
      if (table && !table.started) {
        delete table.puts[seat];
        table.players = table.players.filter(p=>p.seat!==seat);
        teenRecalcPot(table);
        if(table.players.length === 0){
          if(table.startTimeout) clearTimeout(table.startTimeout);
          teenTables.delete(tableId);
        }
      } else if(table && table.started && table.active[seat]){
        table.active[seat] = false;
        io.to(tableId).emit('teenpatti:player-packed', { userId: seat, name: seat, reason:'DISCONNECT' });
        clearTeenTimer(table);
        teenNextTurn(tableId);
      }
    }
  });
});

// BONUS & REFERRAL ENDPOINTS
app.post('/api/bonus/welcome', checkAuth, async (req, res) => {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT balance, welcome_claimed FROM wallets WHERE user_id=$1 FOR UPDATE', [req.user.mobile]);
    if (!w.rows.length) throw new Error('Wallet nahi mila');
    if (w.rows[0].welcome_claimed) { await c.query('ROLLBACK'); return res.json({ success: false, message: 'Welcome Bonus already mil gaya hai' }); }
    await c.query('UPDATE wallets SET balance=balance+50, bonus_total=bonus_total+50, welcome_claimed=true, updated_at=NOW() WHERE user_id=$1', [req.user.mobile]);
    await c.query(`INSERT INTO transactions (user_id, amount, type, status) VALUES ($1, 50, 'BONUS', 'SUCCESS')`, [req.user.mobile]);
    await c.query('COMMIT');
    const b = await pool.query('SELECT balance, bonus_total FROM wallets WHERE user_id=$1', [req.user.mobile]);
    res.json({ success: true, message: 'Welcome Bonus ₹50 mil gaya!', newBalance: b.rows[0].balance, bonus: b.rows[0].bonus_total });
  } catch(e){ await c.query('ROLLBACK'); res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});

app.post('/api/referral/share', checkAuth, async (req, res) => {
  const code = String(req.body.code || '').slice(0, 50);
  if (!code) return res.status(400).json({ success: false, message: 'Code chahiye' });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT balance FROM wallets WHERE user_id=$1 FOR UPDATE', [req.user.mobile]);
    if (!w.rows.length) throw new Error('Wallet nahi mila');
    await c.query('INSERT INTO referral_claims (user_id, code, amount) VALUES ($1,$2,20)', [req.user.mobile, code]);
    await c.query('UPDATE wallets SET balance=balance+20, bonus_total=bonus_total+20, last_share_date=CURRENT_DATE, updated_at=NOW() WHERE user_id=$1', [req.user.mobile]);
    await c.query(`INSERT INTO transactions (user_id, amount, type, status) VALUES ($1, 20, 'BONUS', 'SUCCESS')`, [req.user.mobile]);
    await c.query('COMMIT');
    const b = await pool.query('SELECT balance FROM wallets WHERE user_id=$1', [req.user.mobile]);
    res.json({ success: true, message: 'Share Bonus ₹20 mil gaya!', newBalance: b.rows[0].balance });
  } catch(e){
    await c.query('ROLLBACK');
    if (e.code === '23505') return res.json({ success: false, message: 'Aaj ka Share Bonus already mil gaya hai' });
    res.status(400).json({ success: false, message: e.message });
  } finally { c.release(); }
});

app.post('/api/teenpatti/settle', checkAuth, async (req, res) => {
  const { pot, isHumanWin } = req.body;
  if (!isHumanWin) return res.json({ success: true, newBalance: 0 });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT balance FROM wallets WHERE user_id=$1 FOR UPDATE', [req.user.mobile]);
    if (!w.rows.length) throw new Error('Wallet nahi mila');
    const safePot = Math.min(parseFloat(pot) || 0, 51200);
    await c.query('UPDATE wallets SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2', [safePot, req.user.mobile]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'TEEN_WIN\',\'SUCCESS\')', [req.user.mobile, safePot]);
    await c.query('COMMIT');
    const up = await c.query('SELECT balance FROM wallets WHERE user_id=$1', [req.user.mobile]);
    res.json({ success: true, newBalance: parseFloat(up.rows[0].balance) });
  } catch(e){ await c.query('ROLLBACK'); res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});

app.get('/', (req, res) => { res.send('FULL CASINO 15 GAMES Running! - PUBLIC SECURE FIXED'); });

const PORT = process.env.PORT || 4000;
initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`Server on ${PORT} - PUBLIC SECURE FIXED`);
    startAviator();
  });
});
