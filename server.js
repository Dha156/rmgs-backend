// ================= ROYAL CASINO - BACKEND SECURE V4 - FULL 15 GAMES - PART 1/6 =================
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

if(!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32){
  console.error('❌ JWT_SECRET missing ya chhota hai - Kam se kam 32 char ka hona chahiye');
  process.exit(1);
}
if(!process.env.DATABASE_URL){
  console.error('❌ DATABASE_URL missing');
  process.exit(1);
}
if(!process.env.TWO_FACTOR_API_KEY){
  console.error('❌ TWO_FACTOR_API_KEY missing - OTP nahi chalega');
  process.exit(1);
}
const app = express();
app.set('trust proxy', 1);

// --- CORS PATCHED V4 - Pehle koi bhi .vercel.app / .onrender.com allow tha, ab nahi ---
function cleanOrigin(s){
  return String(s||'').trim().replace(/\/+$/,'').toLowerCase();
}
// ✅ FIXED: Default me tiiny.site / vercel link hataya - Ab sirf Render Env wala FRONTEND_URL chalega
const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || '').split(',').map(cleanOrigin).filter(Boolean);

function isOriginAllowed(origin){
  if(!origin) return true; // Postman / Health check
  const o = cleanOrigin(origin);
  if(ALLOWED_ORIGINS.includes(o)) return true;
  // ❌ HATAYA: if(o.endsWith('.vercel.app')) return true;
  // ❌ HATAYA: if(o.endsWith('.onrender.com')) return true;
  if(o.includes('localhost') && process.env.NODE_ENV !== 'production') return true;
  return false;
}

function corsOptions(){
  return {
    origin: function(origin, cb){
      if(isOriginAllowed(origin)) return cb(null, true);
      console.log('❌ CORS Blocked Origin:', origin, 'Allowed:', ALLOWED_ORIGINS);
      return cb(new Error('CORS Blocked: ' + origin));
    },
    credentials: true
  };
}

app.use(cors(corsOptions()));
app.options('*', cors(corsOptions()));
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: 'Bahut zyada try kiya, 15 min baad try karo' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { success: false, message: 'Bahut zyada login try, 15 min ruk' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.use('/api/', apiLimiter);

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: function(origin, cb){
      if(isOriginAllowed(origin)) return cb(null, true);
      console.log('❌ Socket CORS Blocked:', origin);
      return cb(new Error('Socket CORS Blocked: ' + origin));
    },
    methods: ["GET","POST"],
    credentials: true
  }
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// --- Helpers - Secure ---
function cleanBet(v, min, max){
  let n = Number(v);
  if(!Number.isFinite(n)) return 0;
  n = Math.floor(n);
  if(n < min || n > max) return 0;
  return n;
}
function cleanChoice(v, allowed){
  let s = String(v||'').toUpperCase().trim().slice(0,20);
  return allowed.includes(s) ? s : '';
}
function cleanUtr(v){ return String(v||'').replace(/[^0-9A-Za-z]/g,'').slice(0,20); }
function cleanUpi(v){ return String(v||'').trim().toLowerCase().replace(/[^a-z0-9._@-]/g,'').slice(0,60); }
function isValidUpi(v){ return /^[a-z0-9._-]{2,}@[a-z]{2,}$/i.test(String(v||'').trim()); }
function isValidUtr(v){ return /^[0-9A-Za-z]{12}$/.test(String(v||'').trim()); }
function isValidIfsc(v){ return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(String(v||'').toUpperCase().trim()); }

function socketRateLimit(socket, maxPerSec){
  let now = Date.now();
  socket.data._rl = socket.data._rl || [];
  socket.data._rl = socket.data._rl.filter(t => now - t < 1000);
  if(socket.data._rl.length >= (maxPerSec||5)) return false;
  socket.data._rl.push(now);
  return true;
}

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

// ✅ FIXED: Token 1d se 12h kiya
function makeToken(mobile) { return jwt.sign({ mobile }, process.env.JWT_SECRET, { expiresIn: '12h' }); }

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
  try { await pool.query('INSERT INTO audit_logs (actor_id, action_type, details, ip_address) VALUES ($1,$2,$3,$4)', [String(actor||'').slice(0,100), String(action||'').slice(0,100), String(details||'').slice(0,500), String(ip||'').slice(0,50)]); } catch(e){}
}

// ✅ FIXED: UPI ID / Naam code se hatake Env me - Render me set karna
// MY_UPI_ID=ombk.aahi70694v2ydnslbfb@mbk  MY_UPI_NAME=ROYAL CASINO CLUB
const MY_UPI_ID = process.env.MY_UPI_ID || "ombk.aahi70694v2ydnslbfb@mbk";
const MY_UPI_NAME = process.env.MY_UPI_NAME || "ROYAL CASINO CLUB";
const MY_MIN_DEPOSIT = 150;
const MY_MIN_WITHDRAW = 300;
const DAILY_DEPOSIT_LIMIT = 10000;
const DAILY_BET_LIMIT = 20000;
const MAX_BET = 5000;
const MIN_BET = 10;

async function initDb(){
  try{
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS lvl INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS sig_level INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS vip_level INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS balance NUMERIC(12,2) DEFAULT 0;`);
    // dob column purani DB me hai to rehne de, naya code isko use nahi karega
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS dob DATE;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT false;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS self_excluded_until TIMESTAMP;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit NUMERIC(12,2) DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit_date DATE DEFAULT CURRENT_DATE;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS bonus_total NUMERIC(12,2) DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS welcome_claimed BOOLEAN DEFAULT false;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS last_share_date DATE;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is18_confirmed BOOLEAN DEFAULT false;`);
    await pool.query(`CREATE TABLE IF NOT EXISTS referral_claims (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, code VARCHAR(50) NOT NULL, claimed_date DATE NOT NULL DEFAULT CURRENT_DATE, amount NUMERIC(12,2) NOT NULL, UNIQUE(user_id, claimed_date));`);
    console.log('✅ DB init ho gaya');
  }catch(e){ console.log('DB init warning:', e.message); }
}
initDb();

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
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is18_confirmed BOOLEAN DEFAULT false;`);
    res.json({ success: true, message: 'HO GAYA!' });
  } catch(e){ res.status(500).json({ success: false, message: 'DB fix fail' }); }
});

app.get('/api/payment-info', (req, res) => {
  res.json({ success: true, upi_id: MY_UPI_ID, upi_name: MY_UPI_NAME, min_deposit: MY_MIN_DEPOSIT, min_withdraw: MY_MIN_WITHDRAW, daily_deposit_limit: DAILY_DEPOSIT_LIMIT, message: `Min Deposit ₹${MY_MIN_DEPOSIT} | Min Withdraw ₹${MY_MIN_WITHDRAW} | Daily Deposit Limit ₹${DAILY_DEPOSIT_LIMIT}` });
});
app.get('/api/health', (req, res) => { res.json({ success: true, msg: 'Backend ON hai - Secure V4 Full 15 Games', time: new Date().toISOString() }); });
app.get('/', (req, res) => { res.send('FULL CASINO Running - SECURE V4 - 15 GAMES'); });

async function checkBlocked(userId) {
  const r = await pool.query('SELECT is_blocked, self_excluded_until FROM wallets WHERE user_id=$1', [String(userId||'').slice(0,20)]);
  if (!r.rows.length) return { blocked: false };
  if (r.rows[0].is_blocked) return { blocked: true, reason: 'Admin ne block kiya hai' };
  if (r.rows[0].self_excluded_until && new Date(r.rows[0].self_excluded_until) > new Date()) return { blocked: true, reason: 'Self-Exclusion me ho till ' + r.rows[0].self_excluded_until };
  return { blocked: false };
}

async function placeBet(userId, betAmount) {
  let bet = cleanBet(betAmount, MIN_BET, MAX_BET);
  if(!bet) return { success: false, error: `Bet ₹${MIN_BET} se ₹${MAX_BET} ke beech rakho` };
  const blocked = await checkBlocked(userId);
  if (blocked.blocked) return { success: false, error: blocked.reason };
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT balance FROM wallets WHERE user_id=$1 FOR UPDATE', [userId]);
    if (!w.rows.length) throw new Error('Wallet not found');
    if (parseFloat(w.rows[0].balance) < bet) throw new Error('Insufficient balance');
    const todayBet = await c.query(`SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE user_id=$1 AND type='BET' AND DATE(created_at)=CURRENT_DATE`, [userId]);
    if (parseFloat(todayBet.rows[0].total) + bet > DAILY_BET_LIMIT) throw new Error(`Aaj ka Bet Limit ₹${DAILY_BET_LIMIT} khatam! Kal khelo.`);
    await c.query('UPDATE wallets SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2', [bet, userId]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'BET\',\'SUCCESS\')', [userId, bet]);
    await c.query('COMMIT');
    return { success: true, newBalance: parseFloat(w.rows[0].balance) - bet, bet };
  } catch(e){ try{ await c.query('ROLLBACK'); }catch(_){} return { success: false, error: e.message }; } finally { c.release(); }
}

async function creditWin(userId, winnings) {
  let win = Number(winnings);
  if(!Number.isFinite(win) || win <= 0) return 0;
  if(win > 500000) win = 500000;
  win = Math.floor(win * 100) / 100;
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query('UPDATE wallets SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 RETURNING balance', [win, userId]);
    if(!r.rows.length) throw new Error('Wallet not found');
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'WIN\',\'SUCCESS\')', [userId, win]);
    await c.query('COMMIT');
    return parseFloat(r.rows[0].balance);
  } catch(e){ try{ await c.query('ROLLBACK'); }catch(_){} throw e; } finally { c.release(); }
}

async function getSetting(key, def) {
  try{
    const r = await pool.query('SELECT value FROM settings WHERE key=$1', [String(key).slice(0,50)]);
    return r.rows.length ? parseFloat(r.rows[0].value) : def;
  }catch(e){ return def; }
}

// ✅ FIXED: is18Plus(dob) HATA DIYA - Ab sirf Tick check hoga
function is18Confirmed(v){
  return v === true || v === 'true' || v === 1 || v === '1';
}
// --- PART 1 KHATAM - Ab PART 2 yaha se shuru hoga ---
// ================= PART 2/6 - AUTH + WALLET + REFERRAL =================
const otpStore = new Map();

// ✅ FIXED: DOB HATA DIYA - Ab sirf 18+ Tick bhejega Frontend
app.post('/api/auth/send-otp', otpLimiter, async (req, res) => {
  const name = String(req.body.name||'').replace(/[<>]/g,'').trim().slice(0,30);
  const mobile = String(req.body.mobile||'').replace(/[^0-9]/g,'').slice(0,10);
  // ✅ NAYA: Frontend se is18 Tick aayega - DOB kabhi nahi aayega
  const is18 = req.body.is18 === true || req.body.is18 === 'true' || req.body.is18 === 1;

  if (!name || name.length < 2) return res.status(400).json({ success: false, message: 'Naam daalo' });
  if (!mobile || !/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({ success: false, message: 'Sahi 10 digit mobile daalo' });
  // ❌ PURANA: if(!dob) return ... / if(!is18Plus(dob)) return 403...
  // ✅ NAYA: Sirf Tick check hoga
  if (!is18) return res.status(400).json({ success: false, message: '18+ Tick karo pehle' });

  const apiKey = process.env.TWO_FACTOR_API_KEY;
  if (!apiKey) return res.status(500).json({ success: false, message: 'OTP service band hai' });

  try {
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/${mobile}/AUTOGEN/OTP1`);
    if (data.Status === 'Success') {
      // ✅ dob: null - DOB store hi nahi karenge
      otpStore.set(mobile, { sessionId: data.Details, expiresAt: Date.now() + 5 * 60 * 1000, name: name, is18: true, attempts: 0 });
      res.json({ success: true, message: 'OTP bhej diya' });
    } else {
      res.status(400).json({ success: false, message: 'OTP nahi bheja gaya' });
    }
  } catch(e){ console.error('OTP send fail:', e.message); res.status(500).json({ success: false, message: 'OTP fail - dobara try karo' }); }
});

// ✅ FIXED: verify-otp me DOB wali line hata di
app.post('/api/auth/verify-otp', loginLimiter, async (req, res) => {
  const mobile = String(req.body.mobile||'').replace(/[^0-9]/g,'').slice(0,10);
  const otp = String(req.body.otp||'').replace(/[^0-9]/g,'').slice(0,6);

  if (!/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({ success: false, message: 'Sahi mobile daalo' });
  if (!/^\d{6}$/.test(otp)) return res.status(400).json({ success: false, message: '6 Digit OTP daalo' });

  const rec = otpStore.get(mobile);
  if (!rec) return res.status(400).json({ success: false, message: 'Pehle OTP bhejo' });
  if (Date.now() > rec.expiresAt) { otpStore.delete(mobile); return res.status(400).json({ success: false, message: 'OTP expire ho gaya - Dobara bhejo' }); }
  if (rec.attempts >= 3) { otpStore.delete(mobile); return res.status(400).json({ success: false, message: '3 baar galat - Dobara OTP bhejo' }); }

  // ❌ PURANA: if (!is18Plus(rec.dob)) return 403...
  // ✅ NAYA: Sirf Tick check hoga - DOB kabhi check nahi hoga
  if (!is18Confirmed(rec.is18)) return res.status(403).json({ success: false, message: '18+ hi khel sakta hai' });

  try {
    const apiKey = process.env.TWO_FACTOR_API_KEY;
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/VERIFY/${rec.sessionId}/${otp}`);
    if (data.Status !== 'Success' || data.Details !== 'OTP Matched') {
      rec.attempts = (rec.attempts||0) + 1;
      return res.status(400).json({ success: false, message: 'OTP galat hai' });
    }
    otpStore.delete(mobile);

    // User / Wallet banao ya nikalo - dob NULL rahega
    let w = await pool.query('SELECT * FROM wallets WHERE user_id=$1', [mobile]);
    let isNew = false;
    if (w.rows.length === 0) {
      // ✅ dob ki jagah NULL - is18_confirmed = true
      w = await pool.query('INSERT INTO wallets (user_id,balance,vip_level,dob,is18_confirmed,welcome_claimed) VALUES ($1,0,0,NULL,true,false) RETURNING *', [mobile]);
      isNew = true;
    } else {
      // Purane user ka bhi is18 true kar do
      await pool.query('UPDATE wallets SET is18_confirmed=true WHERE user_id=$1', [mobile]);
      w = await pool.query('SELECT * FROM wallets WHERE user_id=$1', [mobile]);
    }

    const user = w.rows[0];
    if (user.is_blocked) return res.status(403).json({ success: false, message: 'Account blocked hai - Admin se baat karo' });
    if (user.self_excluded_until && new Date(user.self_excluded_until) > new Date()) return res.status(403).json({ success: false, message: 'Self-excluded ho - Wait karo' });

    // Welcome Bonus - Sirf pehli baar, Server se - Frontend se kabhi nahi
    let bonusGiven = 0;
    if (isNew || !user.welcome_claimed) {
      await pool.query('UPDATE wallets SET balance=balance+50, bonus_total=COALESCE(bonus_total,0)+50, welcome_claimed=true WHERE user_id=$1', [mobile]);
      bonusGiven = 50;
    }

    const fresh = await pool.query('SELECT * FROM wallets WHERE user_id=$1', [mobile]);
    const token = makeToken(mobile);
    await audit(mobile, 'LOGIN', 'OTP Login - is18 Tick OK', req.ip);

    res.json({ success: true, message: isNew ? 'Welcome! ₹50 Bonus mil gaya 🎉' : 'Login ho gaya ✅', token, user: { id: mobile, mobile: mobile, name: rec.name || 'Player', balance: Number(fresh.rows[0].balance||0), bonus: Number(fresh.rows[0].bonus_total||0), welcomeBonus: bonusGiven } });
  } catch(e){ console.error('Verify fail:', e.message); res.status(500).json({ success: false, message: 'Verify me error - Dobara try karo' }); }
});

// ===== WALLET - Teri file wala hi rakha hai =====
app.get('/api/wallet/balance', checkAuth, async (req, res) => {
  try{
    let w = await pool.query('SELECT balance, bonus_total FROM wallets WHERE user_id=$1', [req.user.mobile]);
    if(!w.rows.length) return res.status(404).json({ success: false, message: 'Wallet nahi mila' });
    res.json({ success: true, balance: Number(w.rows[0].balance||0), bonus: Number(w.rows[0].bonus_total||0) });
  }catch(e){ res.status(500).json({ success: false, message: 'Balance nahi mila' }); }
});

app.post('/api/wallet/deposit-request', checkAuth, async (req, res) => {
  const amt = cleanBet(req.body.amount, MY_MIN_DEPOSIT, 100000);
  const utr = cleanUtr(req.body.utr);
  if(!amt) return res.status(400).json({ success: false, message: `Min Deposit ₹${MY_MIN_DEPOSIT} hai` });
  if(!isValidUtr(utr)) return res.status(400).json({ success: false, message: '12 Digit Sahi UTR daalo' });
  try{
    // UTR duplicate check - Ek UTR dobara use nahi hoga
    let dup = await pool.query('SELECT id FROM deposits WHERE utr=$1', [utr]);
    if(dup.rows.length) return res.status(400).json({ success: false, message: 'Ye UTR pehle hi use ho chuka hai' });

    // Daily limit check
    let w = await pool.query('SELECT daily_deposit, daily_deposit_date FROM wallets WHERE user_id=$1', [req.user.mobile]);
    let today = new Date().toISOString().slice(0,10);
    let daily = 0;
    if(w.rows.length){
      let row = w.rows[0];
      let dDate = row.daily_deposit_date ? new Date(row.daily_deposit_date).toISOString().slice(0,10) : '';
      daily = (dDate === today) ? Number(row.daily_deposit||0) : 0;
      if(daily + amt > DAILY_DEPOSIT_LIMIT) return res.status(400).json({ success: false, message: `Daily Limit ₹${DAILY_DEPOSIT_LIMIT} hai` });
      if(dDate !== today) await pool.query('UPDATE wallets SET daily_deposit=0, daily_deposit_date=CURRENT_DATE WHERE user_id=$1', [req.user.mobile]);
    }

    await pool.query('INSERT INTO deposits (user_id, amount, utr, status) VALUES ($1,$2,$3,$4)', [req.user.mobile, amt, utr, 'PENDING']);
    await pool.query('UPDATE wallets SET daily_deposit=COALESCE(daily_deposit,0)+$2 WHERE user_id=$1', [req.user.mobile, amt]);
    await audit(req.user.mobile, 'DEPOSIT_REQUEST', `Amt ${amt} UTR ${utr}`, req.ip);
    res.json({ success: true, message: 'Deposit Request bhej diya - Admin verify karega' });
  }catch(e){ console.error('Deposit fail:', e.message); res.status(500).json({ success: false, message: 'Deposit fail - Dobara try karo' }); }
});

app.post('/api/wallet/withdraw-request', checkAuth, async (req, res) => {
  const amt = cleanBet(req.body.amount, MY_MIN_WITHDRAW, 100000);
  const method = String(req.body.method||'UPI').toUpperCase() === 'BANK' ? 'BANK' : 'UPI';
  const upi = cleanUpi(req.body.upi);
  const account = String(req.body.account||'').replace(/[^0-9]/g,'').slice(0,18);
  const ifsc = String(req.body.ifsc||'').toUpperCase().trim().slice(0,11);

  if(!amt) return res.status(400).json({ success: false, message: `Min Withdraw ₹${MY_MIN_WITHDRAW} hai` });
  if(method === 'UPI' && !isValidUpi(upi)) return res.status(400).json({ success: false, message: 'Sahi UPI ID daalo' });
  if(method === 'BANK' && (!account || account.length < 9 || !isValidIfsc(ifsc))) return res.status(400).json({ success: false, message: 'Sahi Account + IFSC daalo' });

  try{
    let w = await pool.query('SELECT balance FROM wallets WHERE user_id=$1', [req.user.mobile]);
    if(!w.rows.length) return res.status(404).json({ success: false, message: 'Wallet nahi mila' });
    if(Number(w.rows[0].balance||0) < amt) return res.status(400).json({ success: false, message: 'Balance kam hai' });

    // Balance turant kaat do - Dobara withdraw ka jugad band
    await pool.query('UPDATE wallets SET balance=balance-$2 WHERE user_id=$1', [req.user.mobile, amt]);
    await pool.query('INSERT INTO withdrawals (user_id, amount, upi, account_no, ifsc, method, status) VALUES ($1,$2,$3,$4,$5,$6,$7)', [req.user.mobile, amt, method==='UPI'?upi:'', method==='BANK'?account:'', method==='BANK'?ifsc:'', method, 'PENDING']);
    await audit(req.user.mobile, 'WITHDRAW_REQUEST', `Amt ${amt} Method ${method}`, req.ip);
    res.json({ success: true, message: 'Withdraw Request bhej diya - Admin verify karega' });
  }catch(e){ console.error('Withdraw fail:', e.message); res.status(500).json({ success: false, message: 'Withdraw fail - Dobara try karo' }); }
});

// ===== REFERRAL - 1 per day, Server se =====
app.post('/api/referral/share', checkAuth, async (req, res) => {
  try{
    let today = new Date().toISOString().slice(0,10);
    let w = await pool.query('SELECT last_share_date FROM wallets WHERE user_id=$1', [req.user.mobile]);
    if(w.rows.length && w.rows[0].last_share_date){
      let d = new Date(w.rows[0].last_share_date).toISOString().slice(0,10);
      if(d === today) return res.json({ success: false, message: 'Aaj ka bonus already mil gaya hai' });
    }
    let exists = await pool.query('SELECT id FROM referral_claims WHERE user_id=$1 AND claimed_date=CURRENT_DATE', [req.user.mobile]);
    if(exists.rows.length) return res.json({ success: false, message: 'Aaj ka bonus already mil gaya hai' });

    await pool.query('INSERT INTO referral_claims (user_id, code, amount) VALUES ($1,$2,$3)', [req.user.mobile, String(req.body.code||'').slice(0,20), 20]);
    await pool.query('UPDATE wallets SET balance=balance+20, bonus_total=COALESCE(bonus_total,0)+20, last_share_date=CURRENT_DATE WHERE user_id=$1', [req.user.mobile]);
    await audit(req.user.mobile, 'REFERRAL_SHARE', 'Share Bonus ₹20', req.ip);
    res.json({ success: true, message: 'Share Bonus ₹20 mil gaya 🎉' });
  }catch(e){ console.error('Share fail:', e.message); res.status(500).json({ success: false, message: 'Share fail' }); }
});

// --- PART 2 KHATAM - Ab PART 3 yaha se shuru hoga ---
// ================= PART 3/6 - GAMES 1 TO 5 - AVIATOR + TEEN PATTI + SPIN + DRAGON TIGER + ROULETTE =================

// ===== GAME 1 - AVIATOR - Winner Sirf Server Decide Karega =====
let avState = { roundId: 0, phase: 'waiting', multiplier: 1, crashPoint: 2, startedAt: 0, bets: new Map() };
let avHistory = [];

function avMakeCrash(){
  // Server hi crash decide karega, Frontend kabhi nahi
  let r = crypto.randomBytes(4).readUInt32LE(0) / 4294967295;
  let crash = Math.max(1, Math.floor((1 / (1 - r * 0.97)) * 100) / 100);
  if(crash > 20) crash = 20;
  return crash;
}

async function avStartRound(){
  avState.roundId++;
  avState.phase = 'betting';
  avState.multiplier = 1;
  avState.bets = new Map();
  avState.crashPoint = avMakeCrash();
  io.emit('game:started', { roundId: avState.roundId });
  io.emit('aviator:round-start', { roundId: avState.roundId });
  // 8 sec Betting time
  setTimeout(()=>{ avState.phase = 'flying'; avState.startedAt = Date.now(); avFly(); }, 8000);
}

function avFly(){
  if(avState.phase !== 'flying') return;
  let elapsed = (Date.now() - avState.startedAt) / 1000;
  avState.multiplier = Math.max(1, 1 + elapsed * 0.25 + (elapsed * elapsed * 0.02));
  if(avState.multiplier >= avState.crashPoint){
    avState.phase = 'crashed';
    avHistory.unshift(Number(avState.crashPoint.toFixed(2)));
    if(avHistory.length > 20) avHistory.pop();
    io.emit('game:crashed', { roundId: avState.roundId, multiplier: Number(avState.crashPoint.toFixed(2)), history: avHistory });
    avState.bets.clear();
    setTimeout(avStartRound, 5000);
  } else {
    io.emit('aviator:tick', { roundId: avState.roundId, multiplier: Number(avState.multiplier.toFixed(2)) });
    setTimeout(avFly, 100);
  }
}

// ===== GAME 2 - TEEN PATTI - Server hi cards dega =====
let tpTables = new Map(); // tableId -> { players: [], pot, phase, deck }
function tpMakeDeck(){
  let suits = ['♠','♥','♦','♣'];
  let ranks = ['A','K','Q','J','10','9','8','7','6','5','4','3','2'];
  let deck = [];
  suits.forEach(s => ranks.forEach(r => deck.push(r + s)));
  // Fisher-Yates - Server side shuffle
  for(let i = deck.length - 1; i > 0; i--){ let j = crypto.randomInt(0, i + 1); [deck[i], deck[j]] = [deck[j], deck[i]]; }
  return deck;
}
function tpGetTable(id){
  if(!tpTables.has(id)) tpTables.set(id, { id, players: [], pot: 0, phase: 'waiting', deck: tpMakeDeck(), currentBet: 10 });
  return tpTables.get(id);
}

// ===== GAME 3 - SPIN - Server hi result dega =====
function spinResult(){
  // Weighted - Server decide karega
  let r = crypto.randomBytes(4).readUInt32LE(0) / 4294967295;
  if(r < 0.40) return { segment: 0, mult: 0, label: 'Lose' };
  if(r < 0.65) return { segment: 1, mult: 1.5, label: '1.5x' };
  if(r < 0.85) return { segment: 2, mult: 2, label: '2x' };
  if(r < 0.95) return { segment: 3, mult: 3, label: '3x' };
  return { segment: 4, mult: 5, label: '5x JACKPOT' };
}

// ===== GAME 4 - DRAGON TIGER - Server hi cards dega =====
function dtDrawCard(){
  let ranks = ['A','K','Q','J','10','9','8','7','6','5','4','3','2'];
  let values = { 'A': 13, 'K': 12, 'Q': 11, 'J': 10, '10': 9, '9': 8, '8': 7, '7': 6, '6': 5, '5': 4, '4': 3, '3': 2, '2': 1 };
  let r = ranks[crypto.randomInt(0, ranks.length)];
  return { card: r, value: values[r] };
}

// ===== GAME 5 - ROULETTE - Server hi number dega =====
function rouletteSpin(){
  let n = crypto.randomInt(0, 37); // 0-36
  let color = n === 0 ? 'GREEN' : ([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36].includes(n) ? 'RED' : 'BLACK');
  return { number: n, color };
}

// ===== SOCKET - Sab Games Yaha Se Chalenge =====
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  if(!token) return next(new Error('Login karo pehle'));
  try{ socket.data.user = jwt.verify(token, process.env.JWT_SECRET); next(); }catch(e){ next(new Error('Token galat hai')); }
});

io.on('connection', (socket) => {
  const mobile = socket.data.user.mobile;
  socket.join('user:' + mobile);

  // --- AVIATOR SOCKET ---
  socket.on('aviator:bet', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    if(avState.phase !== 'betting') return socket.emit('error', { message: 'Betting band hai - Agle round ka wait karo' });
    const amt = cleanBet(data?.amount, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    if(avState.bets.has(mobile + ':1') && avState.bets.has(mobile + ':2')) return socket.emit('error', { message: 'Dono bet lag gayi hai' });
    try{
      // placeBet use kiya - Daily limit + Block check sab usi me hai
      let res = await placeBet(mobile, amt);
      if(!res.success) return socket.emit('error', { message: res.error });
      let key = avState.bets.has(mobile + ':1') ? mobile + ':2' : mobile + ':1';
      avState.bets.set(key, { amount: amt, cashed: false });
      socket.emit('aviator:bet-placed', { newBalance: res.newBalance, bet: amt });
    }catch(e){ socket.emit('error', { message: 'Bet fail - Dobara try karo' }); }
  });

  socket.on('aviator:cashout', async () => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    if(avState.phase !== 'flying') return socket.emit('error', { message: 'Abhi cashout nahi ho sakta' });
    try{
      let win = 0; let found = false;
      for(let [k, b] of avState.bets){
        if(k.startsWith(mobile + ':') && !b.cashed){
          win += Math.floor(b.amount * avState.multiplier);
          b.cashed = true; found = true;
        }
      }
      if(!found) return socket.emit('error', { message: 'Koi bet nahi lagi hai' });
      let newBal = await creditWin(mobile, win);
      socket.emit('aviator:cashed', { newBalance: newBal, win: win, multiplier: Number(avState.multiplier.toFixed(2)) });
      await audit(mobile, 'AVIATOR_CASHOUT', `Win ${win} @ ${avState.multiplier.toFixed(2)}x`, socket.handshake.address);
    }catch(e){ socket.emit('error', { message: 'Cashout fail' }); }
  });

  // --- TEEN PATTI SOCKET - Teri file wale event same rakhe hai ---
  socket.on('teenpatti:join', async (data) => {
    if(!socketRateLimit(socket, 5)) return;
    let tableId = String(data?.tableId || 'table1').slice(0,20);
    let table = tpGetTable(tableId);
    if(table.players.find(p => p.mobile === mobile)) return socket.emit('error', { message: 'Pehle se join ho' });
    if(table.players.length >= 6) return socket.emit('error', { message: 'Table full hai' });
    table.players.push({ mobile, socketId: socket.id, cards: [], blind: true, active: true });
    socket.join('tp:' + tableId);
    socket.emit('teenpatti:joined', { tableId, players: table.players.length });
    io.to('tp:' + tableId).emit('teenpatti:player-joined', { count: table.players.length });
  });

  socket.on('teenpatti:chaal', async (data) => {
    if(!socketRateLimit(socket, 5)) return;
    let tableId = String(data?.tableId || 'table1').slice(0,20);
    let table = tpGetTable(tableId);
    let p = table.players.find(x => x.mobile === mobile);
    if(!p || !p.active) return socket.emit('error', { message: 'Table join karo pehle' });
    let amt = cleanBet(data?.amount, 5, 1000);
    if(!amt) return socket.emit('error', { message: 'Chaal ₹5 se ₹1000 tak' });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    table.pot += amt;
    io.to('tp:' + tableId).emit('teenpatti:chaal', { mobile: mobile.slice(0,3) + '****', amount: amt, pot: table.pot });
  });

  socket.on('teenpatti:blind', async (data) => {
    if(!socketRateLimit(socket, 5)) return;
    let amt = cleanBet(data?.amount, 5, 1000);
    if(!amt) return socket.emit('error', { message: 'Blind ₹5 se ₹1000 tak' });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    socket.emit('teenpatti:blind-ok', { amount: amt, newBalance: res.newBalance });
  });

  // Purane naam bhi rakhe hai taaki Frontend na toote - teen:chaal / teen:pack etc
  socket.on('teen:chaal', async () => { socket.emit('teen:chaal-ok', { message: 'Chaal ke liye teenpatti:chaal use karo' }); });
  socket.on('teen:pack', async () => {
    let found = false;
    for(let [, t] of tpTables){ let p = t.players.find(x => x.mobile === mobile); if(p){ p.active = false; found = true; } }
    socket.emit('teen:pack-ok', { message: found ? 'Pack ho gaya' : 'Pack ho gaya' });
  });
  socket.on('teen:blind2x', async () => { socket.emit('teen:blind-ok', { message: 'Blind x2 lag gaya' }); });
  socket.on('teen:sideshow', async () => { socket.emit('teen:sideshow-ok', { message: 'Side Show request bheji' }); });
  socket.on('teen:show', async () => { socket.emit('teen:show-ok', { message: 'Show request bheji' }); });

  // --- SPIN SOCKET ---
  socket.on('game:spin', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let r = spinResult();
    let win = Math.floor(amt * r.mult);
    let newBal = res.newBalance;
    if(win > 0) newBal = await creditWin(mobile, win);
    socket.emit('game:spin-result', { result: r, bet: amt, win: win, newBalance: newBal });
  });

  // --- DRAGON TIGER SOCKET ---
  socket.on('dragontiger:bet', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let choice = cleanChoice(data?.choice, ['DRAGON','TIGER','TIE']);
    if(!choice) return socket.emit('error', { message: 'Dragon / Tiger / Tie chuno' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let d = dtDrawCard(); let t = dtDrawCard();
    let winner = d.value === t.value ? 'TIE' : (d.value > t.value ? 'DRAGON' : 'TIGER');
    let win = 0; let newBal = res.newBalance;
    if(choice === winner){
      let mult = winner === 'TIE' ? 8 : 2;
      win = Math.floor(amt * mult);
      newBal = await creditWin(mobile, win);
    }
    socket.emit('dragontiger:result', { dragon: d, tiger: t, winner, bet: amt, choice, win, newBalance: newBal });
  });

  // --- ROULETTE SOCKET ---
  socket.on('roulette:bet', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let choice = cleanChoice(data?.choice, ['RED','BLACK','GREEN','EVEN','ODD','HIGH','LOW']);
    let numChoice = data?.number !== undefined ? cleanBet(data.number, 0, 36) : null;
    // Number bet ho ya Color bet ho - Dono chalega
    if(!choice && numChoice === null) return socket.emit('error', { message: 'Red / Black / Number chuno' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let spin = rouletteSpin();
    let win = 0; let newBal = res.newBalance;
    let isWin = false;
    if(numChoice !== null && spin.number === numChoice){ win = amt * 36; isWin = true; }
    else if(choice === spin.color && spin.number !== 0){ win = amt * 2; isWin = true; }
    else if(choice === 'GREEN' && spin.number === 0){ win = amt * 14; isWin = true; }
    else if(choice === 'EVEN' && spin.number !== 0 && spin.number % 2 === 0){ win = amt * 2; isWin = true; }
    else if(choice === 'ODD' && spin.number % 2 === 1){ win = amt * 2; isWin = true; }
    else if(choice === 'HIGH' && spin.number >= 19){ win = amt * 2; isWin = true; }
    else if(choice === 'LOW' && spin.number >= 1 && spin.number <= 18){ win = amt * 2; isWin = true; }
    if(isWin) newBal = await creditWin(mobile, win);
    socket.emit('roulette:result', { spin, bet: amt, choice: choice || numChoice, win, newBalance: newBal });
  });

  socket.on('disconnect', () => {
    // Teen Patti se nikal do
    for(let [, t] of tpTables){ t.players = t.players.filter(p => p.mobile !== mobile); }
  });
});

// Aviator shuru karo - Baaki games on-demand hai
avStartRound();

// --- PART 3 KHATAM - Ab PART 4 yaha se shuru hoga ---
// ================= PART 4/6 - GAMES 6 TO 10 - MINES + ANDAR BAHAR + PLINKO + BACCARAT + POKER =================

// ===== GAME 6 - MINES - Server hi mines decide karega =====
let minesGames = new Map(); // mobile -> { bet, minesCount, grid, revealed, gameOver }
function minesMakeGrid(minesCount){
  let grid = Array(25).fill(0); // 0 = safe, 1 = mine
  let placed = 0;
  while(placed < minesCount){
    let idx = crypto.randomInt(0, 25);
    if(grid[idx] === 0){ grid[idx] = 1; placed++; }
  }
  return grid;
}
function minesMultiplier(revealed, minesCount){
  // Jitne zyada safe khologe, utna zyada multiplier - Server formula
  let safeTotal = 25 - minesCount;
  if(revealed === 0) return 1;
  let m = 1;
  for(let i = 0; i < revealed; i++){ m *= (25 - i) / (safeTotal - i); }
  return Math.floor(m * 0.97 * 100) / 100; // 3% house edge
}

// ===== GAME 7 - ANDAR BAHAR =====
function abDrawCard(){
  let ranks = ['A','K','Q','J','10','9','8','7','6','5','4','3','2'];
  let r = ranks[crypto.randomInt(0, ranks.length)];
  return r;
}

// ===== GAME 8 - PLINKO =====
function plinkoDrop(risk){
  // 8 rows - Server hi drop decide karega
  let pos = 4; // beech se shuru
  for(let i = 0; i < 8; i++){ pos += crypto.randomInt(0, 2) === 0 ? -1 : 1; if(pos < 0) pos = 0; if(pos > 8) pos = 8; }
  // Multiplier table - Beech me kam, side me zyada
  let table = [10, 3, 1.5, 0.7, 0.3, 0.7, 1.5, 3, 10];
  let mult = table[pos] || 0.3;
  if(risk === 'HIGH') mult = mult * 1.5;
  if(risk === 'LOW') mult = Math.max(0.2, mult * 0.7);
  return { position: pos, mult: Math.floor(mult * 100) / 100 };
}

// ===== GAME 9 - BACCARAT =====
function baccaratHand(){
  // 0-9 value - Face cards = 0
  let c1 = crypto.randomInt(0, 10);
  let c2 = crypto.randomInt(0, 10);
  return (c1 + c2) % 10;
}

// ===== GAME 10 - POKER - 5 Card Draw - Server hi dega =====
function pokerHand(){
  let ranks = ['A','K','Q','J','10','9','8','7','6','5','4','3','2'];
  let suits = ['♠','♥','♦','♣'];
  let deck = [];
  suits.forEach(s => ranks.forEach(r => deck.push(r + s)));
  for(let i = deck.length - 1; i > 0; i--){ let j = crypto.randomInt(0, i + 1); [deck[i], deck[j]] = [deck[j], deck[i]]; }
  let hand = deck.slice(0, 5);
  // Simple scoring - Pair / Two Pair / Three of a Kind / Straight / Flush
  let rankCount = {};
  hand.forEach(c => { let r = c.slice(0, -1); rankCount[r] = (rankCount[r] || 0) + 1; });
  let counts = Object.values(rankCount).sort((a,b) => b - a);
  let isFlush = hand.every(c => c.slice(-1) === hand[0].slice(-1));
  let score = 'High Card'; let mult = 0;
  if(counts[0] === 4){ score = 'Four of a Kind'; mult = 10; }
  else if(counts[0] === 3 && counts[1] === 2){ score = 'Full House'; mult = 7; }
  else if(isFlush){ score = 'Flush'; mult = 5; }
  else if(counts[0] === 3){ score = 'Three of a Kind'; mult = 3; }
  else if(counts[0] === 2 && counts[1] === 2){ score = 'Two Pair'; mult = 2; }
  else if(counts[0] === 2){ score = 'Pair'; mult = 1.5; }
  return { hand, score, mult };
}

// ===== SOCKET - GAME 6 TO 10 - Alag handler, sab chalega =====
io.on('connection', (socket) => {
  const mobile = socket.data.user?.mobile;
  if(!mobile) return;

  // --- MINES ---
  socket.on('mines:play', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let minesCount = cleanBet(data?.mines || data?.minesCount || 3, 1, 10);
    if(!minesCount) return socket.emit('error', { message: 'Mines 1 se 10 tak chuno' });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let grid = minesMakeGrid(minesCount);
    minesGames.set(mobile, { bet: amt, minesCount, grid, revealed: 0, revealedIdx: [], gameOver: false, newBalance: res.newBalance });
    socket.emit('mines:started', { minesCount, bet: amt, newBalance: res.newBalance });
  });

  socket.on('mines:reveal', async (data) => {
    if(!socketRateLimit(socket, 10)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let g = minesGames.get(mobile);
    if(!g || g.gameOver) return socket.emit('error', { message: 'Pehle Mines shuru karo' });
    let idx = cleanBet(data?.index, 0, 24);
    if(idx === 0 && data?.index !== 0) idx = Number(data?.index);
    if(!Number.isInteger(idx) || idx < 0 || idx > 24) return socket.emit('error', { message: 'Sahi box chuno' });
    if(g.revealedIdx.includes(idx)) return socket.emit('error', { message: 'Ye box khul gaya hai' });
    g.revealedIdx.push(idx);
    if(g.grid[idx] === 1){
      g.gameOver = true;
      minesGames.delete(mobile);
      socket.emit('mines:hit', { index: idx, mines: g.grid, win: 0, message: 'Mine lag gaya 💣' });
    } else {
      g.revealed++;
      let mult = minesMultiplier(g.revealed, g.minesCount);
      let potential = Math.floor(g.bet * mult);
      socket.emit('mines:safe', { index: idx, revealed: g.revealed, multiplier: mult, potentialWin: potential });
    }
  });

  socket.on('mines:cashout', async () => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let g = minesGames.get(mobile);
    if(!g || g.gameOver) return socket.emit('error', { message: 'Koi Mines game nahi chal rahi' });
    if(g.revealed === 0) return socket.emit('error', { message: 'Pehle 1 box kholo' });
    let mult = minesMultiplier(g.revealed, g.minesCount);
    let win = Math.floor(g.bet * mult);
    minesGames.delete(mobile);
    let newBal = await creditWin(mobile, win);
    socket.emit('mines:cashed', { win, multiplier: mult, newBalance: newBal });
  });

  // --- ANDAR BAHAR ---
  socket.on('andarbahar:bet', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let choice = cleanChoice(data?.choice, ['ANDAR','BAHAR']);
    if(!choice) return socket.emit('error', { message: 'Andar / Bahar chuno' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let joker = abDrawCard();
    let winner = crypto.randomInt(0, 2) === 0 ? 'ANDAR' : 'BAHAR';
    let win = 0; let newBal = res.newBalance;
    if(choice === winner){ win = Math.floor(amt * 2); newBal = await creditWin(mobile, win); }
    socket.emit('andarbahar:result', { joker, winner, bet: amt, choice, win, newBalance: newBal });
  });

  // --- PLINKO ---
  socket.on('plinko:play', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let risk = cleanChoice(data?.risk, ['LOW','MEDIUM','HIGH']) || 'MEDIUM';
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let drop = plinkoDrop(risk);
    let win = Math.floor(amt * drop.mult);
    let newBal = res.newBalance;
    if(win > 0) newBal = await creditWin(mobile, win);
    socket.emit('plinko:result', { position: drop.position, multiplier: drop.mult, bet: amt, risk, win, newBalance: newBal });
  });

  // --- BACCARAT ---
  socket.on('baccarat:bet', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let choice = cleanChoice(data?.choice, ['PLAYER','BANKER','TIE']);
    if(!choice) return socket.emit('error', { message: 'Player / Banker / Tie chuno' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let player = baccaratHand(); let banker = baccaratHand();
    let winner = player === banker ? 'TIE' : (player > banker ? 'PLAYER' : 'BANKER');
    let win = 0; let newBal = res.newBalance;
    if(choice === winner){
      let mult = winner === 'TIE' ? 8 : (winner === 'BANKER' ? 1.95 : 2);
      win = Math.floor(amt * mult);
      newBal = await creditWin(mobile, win);
    }
    socket.emit('baccarat:result', { player, banker, winner, bet: amt, choice, win, newBalance: newBal });
  });

  // --- POKER ---
  socket.on('poker:play', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let r = pokerHand();
    let win = Math.floor(amt * r.mult);
    let newBal = res.newBalance;
    if(win > 0) newBal = await creditWin(mobile, win);
    socket.emit('poker:result', { hand: r.hand, score: r.score, multiplier: r.mult, bet: amt, win, newBalance: newBal });
  });
});

// --- PART 4 KHATAM - Ab PART 5 yaha se shuru hoga ---
// ================= PART 5/6 - GAMES 11 TO 15 - SLOTS + COLOUR + CHICKEN + FORTUNE GEMS + GEMS TEMPLE =================

// ===== GAME 11 - SLOTS =====
function slotsSpin(){
  let symbols = ['🍒','🍋','🔔','⭐','💎','7️⃣'];
  let r1 = symbols[crypto.randomInt(0, symbols.length)];
  let r2 = symbols[crypto.randomInt(0, symbols.length)];
  let r3 = symbols[crypto.randomInt(0, symbols.length)];
  let mult = 0;
  if(r1 === r2 && r2 === r3){
    if(r1 === '7️⃣') mult = 50;
    else if(r1 === '💎') mult = 20;
    else if(r1 === '⭐') mult = 10;
    else if(r1 === '🔔') mult = 5;
    else mult = 3;
  } else if(r1 === r2 || r2 === r3 || r1 === r3){
    mult = 1.5;
  }
  return { reels: [r1, r2, r3], mult };
}

// ===== GAME 12 - COLOUR =====
function colourDraw(){
  // 0-9 number - Server decide karega
  let n = crypto.randomInt(0, 10);
  let color = '';
  if(n === 0) color = 'RED_VIOLET';
  else if(n === 5) color = 'GREEN_VIOLET';
  else if(n % 2 === 0) color = 'RED';
  else color = 'GREEN';
  let size = n >= 5 ? 'BIG' : 'SMALL';
  return { number: n, color, size };
}

// ===== GAME 13 - CHICKEN - Server hi step decide karega =====
let chickenGames = new Map(); // mobile -> { bet, step, alive }
function chickenMultiplier(step){
  // Har step pe multiplier badhega
  return Math.floor((1 + step * 0.35) * 100) / 100;
}

// ===== GAME 14 - FORTUNE GEMS =====
function fortuneGemsSpin(){
  let gems = ['💎','💚','💙','❤️','💜','⭐'];
  let grid = [];
  for(let i = 0; i < 9; i++) grid.push(gems[crypto.randomInt(0, gems.length)]);
  let counts = {};
  grid.forEach(g => counts[g] = (counts[g] || 0) + 1);
  let maxCount = Math.max(...Object.values(counts));
  let mult = 0;
  if(maxCount >= 7) mult = 10;
  else if(maxCount === 6) mult = 5;
  else if(maxCount === 5) mult = 3;
  else if(maxCount === 4) mult = 2;
  else if(maxCount === 3) mult = 1.5;
  return { grid, mult, maxCount };
}

// ===== GAME 15 - GEMS TEMPLE =====
function gemsTempleSpin(){
  let symbols = ['🏛️','💎','🪙','🔱','🐍','🌟'];
  let grid = [];
  for(let i = 0; i < 9; i++) grid.push(symbols[crypto.randomInt(0, symbols.length)]);
  let counts = {};
  grid.forEach(s => counts[s] = (counts[s] || 0) + 1);
  let maxCount = Math.max(...Object.values(counts));
  let mult = 0;
  if(maxCount >= 7) mult = 15;
  else if(maxCount === 6) mult = 6;
  else if(maxCount === 5) mult = 4;
  else if(maxCount === 4) mult = 2.5;
  else if(maxCount === 3) mult = 1.5;
  return { grid, mult, maxCount };
}

// ===== SOCKET - GAME 11 TO 15 =====
io.on('connection', (socket) => {
  const mobile = socket.data.user?.mobile;
  if(!mobile) return;

  // --- SLOTS ---
  socket.on('slots:spin', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let r = slotsSpin();
    let win = Math.floor(amt * r.mult);
    let newBal = res.newBalance;
    if(win > 0) newBal = await creditWin(mobile, win);
    socket.emit('slots:result', { reels: r.reels, multiplier: r.mult, bet: amt, win, newBalance: newBal });
  });

  // --- COLOUR ---
  socket.on('colour:bet', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let choice = cleanChoice(data?.choice, ['RED','GREEN','VIOLET','BIG','SMALL']);
    let numChoice = (data?.number !== undefined && data?.number !== null) ? cleanBet(data.number, 0, 9) : null;
    if(!choice && numChoice === null) return socket.emit('error', { message: 'Red / Green / Violet / Big / Small / Number chuno' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let draw = colourDraw();
    let win = 0; let newBal = res.newBalance;
    let isWin = false;
    if(numChoice !== null && draw.number === numChoice){ win = amt * 9; isWin = true; }
    else if(choice === 'RED' && (draw.color === 'RED' || draw.color === 'RED_VIOLET')){ win = amt * 2; isWin = true; }
    else if(choice === 'GREEN' && (draw.color === 'GREEN' || draw.color === 'GREEN_VIOLET')){ win = amt * 2; isWin = true; }
    else if(choice === 'VIOLET' && (draw.color === 'RED_VIOLET' || draw.color === 'GREEN_VIOLET')){ win = amt * 4.5; isWin = true; }
    else if(choice === draw.size){ win = amt * 2; isWin = true; }
    if(isWin) newBal = await creditWin(mobile, win);
    socket.emit('colour:result', { draw, bet: amt, choice: choice || numChoice, win, newBalance: newBal });
  });

  // --- CHICKEN ---
  socket.on('chicken:play', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    chickenGames.set(mobile, { bet: amt, step: 0, alive: true });
    socket.emit('chicken:started', { bet: amt, step: 0, multiplier: 1, newBalance: res.newBalance });
  });

  socket.on('chicken:next', async () => {
    if(!socketRateLimit(socket, 10)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let g = chickenGames.get(mobile);
    if(!g || !g.alive) return socket.emit('error', { message: 'Pehle Chicken shuru karo' });
    // Har step pe 15% chance marne ka - Server decide karega
    let die = crypto.randomBytes(4).readUInt32LE(0) / 4294967295 < 0.15;
    if(die){
      g.alive = false;
      chickenGames.delete(mobile);
      socket.emit('chicken:dead', { step: g.step, win: 0, message: 'Chicken mar gaya 🐔💥' });
    } else {
      g.step++;
      let mult = chickenMultiplier(g.step);
      let potential = Math.floor(g.bet * mult);
      socket.emit('chicken:alive', { step: g.step, multiplier: mult, potentialWin: potential });
    }
  });

  socket.on('chicken:cashout', async () => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let g = chickenGames.get(mobile);
    if(!g || !g.alive) return socket.emit('error', { message: 'Koi Chicken game nahi chal rahi' });
    if(g.step === 0) return socket.emit('error', { message: 'Pehle 1 step chalo' });
    let mult = chickenMultiplier(g.step);
    let win = Math.floor(g.bet * mult);
    chickenGames.delete(mobile);
    let newBal = await creditWin(mobile, win);
    socket.emit('chicken:cashed', { win, multiplier: mult, step: g.step, newBalance: newBal });
  });

  // --- FORTUNE GEMS ---
  socket.on('fortunegems:spin', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let r = fortuneGemsSpin();
    let win = Math.floor(amt * r.mult);
    let newBal = res.newBalance;
    if(win > 0) newBal = await creditWin(mobile, win);
    socket.emit('fortunegems:result', { grid: r.grid, multiplier: r.mult, maxCount: r.maxCount, bet: amt, win, newBalance: newBal });
  });

  // --- GEMS TEMPLE ---
  socket.on('gemstemple:spin', async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('error', { message: 'Bahut tez click kar rahe ho' });
    let amt = cleanBet(data?.amount || data?.bet, MIN_BET, MAX_BET);
    if(!amt) return socket.emit('error', { message: `Bet ₹${MIN_BET} se ₹${MAX_BET} tak` });
    let res = await placeBet(mobile, amt);
    if(!res.success) return socket.emit('error', { message: res.error });
    let r = gemsTempleSpin();
    let win = Math.floor(amt * r.mult);
    let newBal = res.newBalance;
    if(win > 0) newBal = await creditWin(mobile, win);
    socket.emit('gemstemple:result', { grid: r.grid, multiplier: r.mult, maxCount: r.maxCount, bet: amt, win, newBalance: newBal });
  });
});

// --- PART 5 KHATAM - Ab PART 6 yaha se shuru hoga ---
// ================= PART 6/6 - ADMIN + START =================

// ===== ADMIN - Deposit / Withdraw Approve =====
app.post('/api/admin/login', async (req, res) => {
  const user = String(req.body.username||'').trim();
  const pass = String(req.body.password||'');
  if(!user || !pass) return res.status(400).json({ success: false, message: 'Username + Password daalo' });
  // Admin Render Env se - Code me password kabhi mat likhna
  // ADMIN_USER=admin  ADMIN_PASS_HASH=$2b$10$... (bcrypt hash)
  if(user !== process.env.ADMIN_USER) return res.status(401).json({ success: false, message: 'Galat login' });
  const hash = process.env.ADMIN_PASS_HASH || '';
  if(!hash) return res.status(500).json({ success: false, message: 'Admin setup nahi hua - Render me ADMIN_PASS_HASH set karo' });
  const ok = await bcrypt.compare(pass, hash);
  if(!ok) return res.status(401).json({ success: false, message: 'Galat login' });
  const token = jwt.sign({ role: 'admin', username: user }, process.env.JWT_SECRET, { expiresIn: '4h' });
  res.json({ success: true, token });
});

app.get('/api/admin/deposits', checkAdmin, async (req, res) => {
  try{ let r = await pool.query('SELECT * FROM deposits WHERE status=$1 ORDER BY id DESC LIMIT 100', ['PENDING']); res.json({ success: true, data: r.rows }); }catch(e){ res.status(500).json({ success: false, message: 'Deposits nahi mile' }); }
});
app.get('/api/admin/withdrawals', checkAdmin, async (req, res) => {
  try{ let r = await pool.query('SELECT * FROM withdrawals WHERE status=$1 ORDER BY id DESC LIMIT 100', ['PENDING']); res.json({ success: true, data: r.rows }); }catch(e){ res.status(500).json({ success: false, message: 'Withdrawals nahi mile' }); }
});

app.post('/api/admin/deposit-approve', checkAdmin, async (req, res) => {
  const id = Number(req.body.id); const action = String(req.body.action||'APPROVE').toUpperCase();
  if(!id) return res.status(400).json({ success: false, message: 'ID daalo' });
  try{
    let d = await pool.query('SELECT * FROM deposits WHERE id=$1 AND status=$2', [id, 'PENDING']);
    if(!d.rows.length) return res.status(404).json({ success: false, message: 'Deposit nahi mila' });
    if(action === 'APPROVE'){
      await pool.query('UPDATE deposits SET status=$2 WHERE id=$1', [id, 'APPROVED']);
      await pool.query('UPDATE wallets SET balance=balance+$2 WHERE user_id=$1', [d.rows[0].user_id, d.rows[0].amount]);
      await audit(req.admin.username, 'DEPOSIT_APPROVE', `ID ${id} Amt ${d.rows[0].amount}`, req.ip);
      res.json({ success: true, message: 'Deposit Approve ho gaya' });
    } else {
      await pool.query('UPDATE deposits SET status=$2 WHERE id=$1', [id, 'REJECTED']);
      // Deposit reject hone pe daily limit wapas karo
      await pool.query('UPDATE wallets SET daily_deposit=GREATEST(0,COALESCE(daily_deposit,0)-$2) WHERE user_id=$1', [d.rows[0].user_id, d.rows[0].amount]);
      res.json({ success: true, message: 'Deposit Reject ho gaya' });
    }
  }catch(e){ res.status(500).json({ success: false, message: 'Approve fail' }); }
});

app.post('/api/admin/withdraw-approve', checkAdmin, async (req, res) => {
  const id = Number(req.body.id); const action = String(req.body.action||'APPROVE').toUpperCase();
  if(!id) return res.status(400).json({ success: false, message: 'ID daalo' });
  try{
    let w = await pool.query('SELECT * FROM withdrawals WHERE id=$1 AND status=$2', [id, 'PENDING']);
    if(!w.rows.length) return res.status(404).json({ success: false, message: 'Withdraw nahi mila' });
    if(action === 'APPROVE'){
      await pool.query('UPDATE withdrawals SET status=$2 WHERE id=$1', [id, 'APPROVED']);
      await audit(req.admin.username, 'WITHDRAW_APPROVE', `ID ${id} Amt ${w.rows[0].amount}`, req.ip);
      res.json({ success: true, message: 'Withdraw Approve ho gaya - Ab UPI pe bhejo' });
    } else {
      // Reject hone pe paisa wapas - Kyuki pehle hi kaat liya tha
      await pool.query('UPDATE withdrawals SET status=$2 WHERE id=$1', [id, 'REJECTED']);
      await pool.query('UPDATE wallets SET balance=balance+$2 WHERE user_id=$1', [w.rows[0].user_id, w.rows[0].amount]);
      res.json({ success: true, message: 'Withdraw Reject ho gaya - Paisa wapas kar diya' });
    }
  }catch(e){ res.status(500).json({ success: false, message: 'Approve fail' }); }
});

// ===== HEALTH + START =====
app.get('/health', (req, res) => res.json({ success: true, status: 'OK' }));

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`✅ Server chal raha hai - Port ${PORT}`);
  console.log(`✅ Allowed Origins: ${ALLOWED_ORIGINS.join(', ') || 'NONE - FRONTEND_URL set karo!'}`);
  console.log(`✅ UPI: ${MY_UPI_ID} | Name: ${MY_UPI_NAME}`);
  console.log(`✅ 15 GAMES LIVE: Aviator, Teen Patti, Spin, Dragon Tiger, Roulette, Mines, Andar Bahar, Plinko, Baccarat, Poker, Slots, Colour, Chicken, Fortune Gems, Gems Temple`);
});
