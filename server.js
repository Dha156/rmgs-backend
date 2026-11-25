// ================= ROYAL CASINO - BACKEND SECURE V5 - PURA ILAAJ =================
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
  console.error('❌ JWT_SECRET missing ya chhota hai');
  process.exit(1);
}
if(!process.env.DATABASE_URL){
  console.error('❌ DATABASE_URL missing');
  process.exit(1);
}
const app = express();
app.set('trust proxy', 1);

function cleanOrigin(s){ return String(s||'').trim().replace(/\/+$/,'').toLowerCase(); }
const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || 'https://royal-casino-club.vercel.app,https://royalcasino.tiiny.site').split(',').map(cleanOrigin).filter(Boolean);
function isOriginAllowed(origin){
  if(!origin) return true;
  const o = cleanOrigin(origin);
  if(ALLOWED_ORIGINS.includes(o)) return true;
  if(o.endsWith('.vercel.app')) return true;
  if(o.endsWith('.tiiny.site')) return true;
  if(o.endsWith('.onrender.com')) return true;
  if(o.includes('localhost') && process.env.NODE_ENV !== 'production') return true;
  return false;
}
function corsOptions(){
  return {
    origin: function(origin, cb){
      if(isOriginAllowed(origin)) return cb(null, true);
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
      return cb(new Error('Socket CORS Blocked: ' + origin));
    },
    methods: ["GET","POST"],
    credentials: true
  }
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

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
// ===== PURA ILAAJ - TOKEN 30 DIN + REFRESH 90 DIN =====
function makeToken(mobile) { return jwt.sign({ mobile }, process.env.JWT_SECRET, { expiresIn: '30d' }); }
function makeRefreshToken(mobile) { return jwt.sign({ mobile, type: 'refresh' }, process.env.JWT_SECRET, { expiresIn: '90d' }); }
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

const MY_UPI_ID = process.env.MY_UPI_ID || "";
const MY_UPI_NAME = process.env.MY_UPI_NAME || "Royal Casino";
const MY_MIN_DEPOSIT = 150;
const MY_MIN_WITHDRAW = 300;
const DAILY_DEPOSIT_LIMIT = 10000;
const DAILY_BET_LIMIT = 20000;
const MAX_BET = 5000;
const MIN_BET = 10;

async function getUpiInfo(){
  try{
    let r1 = await pool.query("SELECT value FROM settings WHERE key='my_upi_id'");
    let r2 = await pool.query("SELECT value FROM settings WHERE key='my_upi_name'");
    let upi = (r1.rows[0]?.value || "").trim();
    let name = (r2.rows[0]?.value || "").trim();
    if(!upi) upi = MY_UPI_ID;
    if(!name) name = MY_UPI_NAME;
    return { upi_id: upi, upi_name: name };
  }catch(e){ return { upi_id: MY_UPI_ID, upi_name: MY_UPI_NAME }; }
}

async function initDb(){
  try{
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS lvl INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS sig_level INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS vip_level INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS balance NUMERIC(12,2) DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS dob DATE;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT false;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS self_excluded_until TIMESTAMP;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit NUMERIC(12,2) DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS daily_deposit_date DATE DEFAULT CURRENT_DATE;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS bonus_total NUMERIC(12,2) DEFAULT 0;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS welcome_claimed BOOLEAN DEFAULT false;`);
    await pool.query(`ALTER TABLE wallets ADD COLUMN IF NOT EXISTS last_share_date DATE;`);
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
    res.json({ success: true, message: 'HO GAYA!' });
  } catch(e){ res.status(500).json({ success: false, message: 'DB fix fail' }); }
});

app.get('/api/payment-info', async (req, res) => {
  let upi = await getUpiInfo();
  res.json({ success: true, upi_id: upi.upi_id, upi_name: upi.upi_name, min_deposit: MY_MIN_DEPOSIT, min_withdraw: MY_MIN_WITHDRAW, daily_deposit_limit: DAILY_DEPOSIT_LIMIT, message: `Min Deposit ₹${MY_MIN_DEPOSIT} | Min Withdraw ₹${MY_MIN_WITHDRAW} | Daily Deposit Limit ₹${DAILY_DEPOSIT_LIMIT}` });
});
app.get('/api/health', (req, res) => { res.json({ success: true, msg: 'Backend ON hai - Secure V5', time: new Date().toISOString() }); });
app.get('/', (req, res) => { res.send('FULL CASINO Running - SECURE V5 - 15 GAMES'); });

async function checkBlocked(userId) {
  const r = await pool.query('SELECT is_blocked, self_excluded_until FROM wallets WHERE user_id=$1', [String(userId||'').slice(0,20)]);
  if (!r.rows.length) return { blocked: false };
  if (r.rows[0].is_blocked) return { blocked: true, reason: 'Admin ne block kiya hai' };
  if (r.rows[0].self_excluded_until && new Date(r.rows[0].self_excluded_until) > new Date()) return { blocked: true, reason: 'Self-Exclusion me ho till ' + r.rows[0].self_excluded_until };
  return { blocked: false };
}

async function placeBet(userId, betAmount, minBet) {
  let bet = cleanBet(betAmount, minBet || MIN_BET, MAX_BET);
  if(!bet) return { success: false, error: `Bet ₹${minBet||MIN_BET} se ₹${MAX_BET} ke beech rakho` };
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

async function refundBet(userId, amount) {
  let amt = Math.floor(Number(amount||0)*100)/100;
  if(!amt || amt <= 0) return 0;
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query('UPDATE wallets SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 RETURNING balance', [amt, userId]);
    if(!r.rows.length) throw new Error('Wallet not found');
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'REFUND\',\'SUCCESS\')', [userId, amt]);
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
function is18Plus(dobStr) {
  if (!dobStr) return false;
  let dob = new Date(dobStr);
  if(isNaN(dob.getTime())) return false;
  if(dob > new Date()) return false;
  let today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  let m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
  return age >= 18;
}
// ================= PART 2 / 4 =================
async function handleDepositCreateQR(req, res){
  const depositAmount = cleanBet(req.body.amount, MY_MIN_DEPOSIT, 50000);
  if(!depositAmount) return res.status(400).json({ success: false, message: `Min Deposit ₹${MY_MIN_DEPOSIT} - Max ₹50000` });
  let w = await pool.query('SELECT daily_deposit, daily_deposit_date FROM wallets WHERE user_id=$1', [req.user.mobile]);
  if (w.rows.length) {
    let row = w.rows[0];
    let today = new Date().toISOString().slice(0, 10);
    let depToday = (row.daily_deposit_date && row.daily_deposit_date.toISOString().slice(0, 10) === today) ? parseFloat(row.daily_deposit) : 0;
    if (depToday + depositAmount > DAILY_DEPOSIT_LIMIT) return res.status(400).json({ success: false, message: `Aaj ka Deposit Limit ₹${DAILY_DEPOSIT_LIMIT} khatam ho gaya!` });
  }
  let upiInfo = await getUpiInfo();
  if(!upiInfo.upi_id) return res.status(500).json({ success: false, message: 'UPI set nahi hai, Admin se baat karo' });
  const upiLink = `upi://pay?pa=${upiInfo.upi_id}&pn=${encodeURIComponent(upiInfo.upi_name)}&am=${depositAmount}&cu=INR&tn=${encodeURIComponent('Deposit ' + depositAmount + ' - ' + req.user.mobile)}`;
  const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(upiLink)}`;
  res.json({ success: true, amount: depositAmount, upi_id: upiInfo.upi_id, upi_name: upiInfo.upi_name, upiLink, qrImage: qrImageUrl, message: `₹${depositAmount} ka QR ban gaya!` });
}
app.post('/api/deposit/create-qr', checkAuth, handleDepositCreateQR);
app.post('/api/wallet/deposit-create-qr', checkAuth, handleDepositCreateQR);

async function handleDepositRequest(req, res){
  const amount = cleanBet(req.body.amount, MY_MIN_DEPOSIT, 50000);
  if(!amount) return res.status(400).json({ success: false, message: `Min ₹${MY_MIN_DEPOSIT} - Max ₹50000` });
  const utr = cleanUtr(req.body.utr);
  if(!isValidUtr(utr)) return res.status(400).json({ success: false, message: 'Sahi 12 digit UTR daalo' });
  const w2 = await pool.query('SELECT daily_deposit, daily_deposit_date FROM wallets WHERE user_id=$1', [req.user.mobile]);
  if (w2.rows.length) { const today2 = new Date().toISOString().slice(0,10); const depToday2 = (w2.rows[0].daily_deposit_date && w2.rows[0].daily_deposit_date.toISOString().slice(0,10)===today2) ? parseFloat(w2.rows[0].daily_deposit||0) : 0; if (depToday2 + amount > DAILY_DEPOSIT_LIMIT) return res.status(400).json({ success: false, message: 'Aaj ka Deposit Limit khatam!' }); }
  const blocked = await checkBlocked(req.user.mobile);
  if (blocked.blocked) return res.status(403).json({ success: false, message: blocked.reason });
  try {
    await pool.query('INSERT INTO deposits (user_id, amount, utr) VALUES ($1,$2,$3)', [req.user.mobile, amount, utr]);
    await audit(req.user.mobile, 'DEPOSIT_REQUEST', `Amt ${amount} UTR ${utr}`, req.ip);
    res.json({ success: true, message: 'Deposit request bhej diya, Admin approve karega' });
  } catch(e){
    if (e.code === '23505') return res.status(400).json({ success: false, message: 'Ye UTR pehle use ho chuka hai' });
    res.status(500).json({ success: false, message: 'Deposit fail' });
  }
}
app.post('/api/wallet/deposit-request', checkAuth, handleDepositRequest);
app.post('/api/deposit/request', checkAuth, handleDepositRequest);
app.post('/api/deposit-request', checkAuth, handleDepositRequest);

async function handleWithdraw(req, res){
  const amount = cleanBet(req.body.amount, MY_MIN_WITHDRAW, 50000);
  if(!amount) return res.status(400).json({ success: false, message: `Min ₹${MY_MIN_WITHDRAW} - Max ₹50000` });
  let upi_id = cleanUpi(req.body.upi_id || req.body.upiId || '');
  let account_no = String(req.body.account_no || req.body.accountNo || '').replace(/[^0-9]/g,'').slice(0,18);
  let ifsc = String(req.body.ifsc || '').toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,11);
  if(upi_id){
    if(!isValidUpi(upi_id)) return res.status(400).json({ success: false, message: 'Sahi UPI ID daalo' });
  } else {
    if(!account_no || account_no.length < 9) return res.status(400).json({ success: false, message: 'Sahi Account No daalo' });
    if(!isValidIfsc(ifsc)) return res.status(400).json({ success: false, message: 'Sahi IFSC daalo' });
  }
  const userId = req.user.mobile;
  const blocked = await checkBlocked(userId);
  if (blocked.blocked) return res.status(403).json({ success: false, message: blocked.reason });
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const pend = await c.query(`SELECT COUNT(*) as cnt FROM withdraws WHERE user_id=$1 AND status='PENDING' FOR UPDATE`, [userId]);
    if(parseInt(pend.rows[0].cnt) >= 1) throw new Error('Ek Withdraw pehle se Pending hai');
    const w = await c.query('SELECT balance, vip_level FROM wallets WHERE user_id=$1 FOR UPDATE', [userId]);
    if (!w.rows.length) throw new Error('Wallet nahi mila');
    if ((w.rows[0].vip_level || 0) < 1) throw new Error('Pehle VIP1 Deposit karo fir Withdraw hoga!');
    if (parseFloat(w.rows[0].balance) < amount) throw new Error('Balance kam hai');
    await c.query('UPDATE wallets SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2', [amount, userId]);
    await c.query('INSERT INTO withdraws (user_id, amount, upi_id, account_no, ifsc) VALUES ($1,$2,$3,$4,$5)', [userId, amount, upi_id || null, account_no || null, ifsc || null]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'WITHDRAW\',\'PENDING\')', [userId, amount]);
    await c.query('COMMIT');
    await audit(userId, 'WITHDRAW_REQUEST', `Amt ${amount} IP ${req.ip}`, req.ip);
    res.json({ success: true, message: 'Withdraw request bhej diya' });
  } catch(e){ try{ await c.query('ROLLBACK'); }catch(_){} res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
}
app.post('/api/wallet/withdraw', checkAuth, handleWithdraw);
app.post('/api/withdraw/request', checkAuth, handleWithdraw);
app.post('/api/withdraw-request', checkAuth, handleWithdraw);

async function initDatabase() {
  await pool.query(`CREATE TABLE IF NOT EXISTS wallets (id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE NOT NULL, balance NUMERIC(12,2) DEFAULT 0 CHECK(balance>=0), vip_level INT DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW(), dob DATE, is_blocked BOOLEAN DEFAULT false, self_excluded_until TIMESTAMP, daily_deposit NUMERIC(12,2) DEFAULT 0, daily_deposit_date DATE DEFAULT CURRENT_DATE, bonus_total NUMERIC(12,2) DEFAULT 0, welcome_claimed BOOLEAN DEFAULT false, last_share_date DATE)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, type VARCHAR(50) NOT NULL, status VARCHAR(50) NOT NULL, utr VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS deposits (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, utr VARCHAR(100) UNIQUE NOT NULL, status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS withdraws (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, method VARCHAR(20) DEFAULT 'UPI', upi_id VARCHAR(255), account_no VARCHAR(50), ifsc VARCHAR(20), status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS admin_users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT 'admin')`);
  await pool.query(`CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, actor_id VARCHAR(255) NOT NULL, action_type VARCHAR(100) NOT NULL, details TEXT, ip_address VARCHAR(50), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL)`);
  await pool.query(`INSERT INTO settings (key, value) VALUES ('global_rtp','96'), ('min_bet','10'), ('max_bet','5000'), ('teenpatti_rake','5'), ('teenpatti_boot','5'), ('aviator_house_edge','4'), ('aviator_min_crash','1.10'), ('aviator_max_crash','100'), ('spin_rtp','96'), ('dragontiger_rtp','96'), ('roulette_rtp','96'), ('mines_rtp','96'), ('andarbahar_rtp','96'), ('plinko_rtp','96'), ('baccarat_rtp','96'), ('poker_rtp','96'), ('slots_rtp','96'), ('colour_rtp','96'), ('chicken_rtp','96'), ('fortune_rtp','96'), ('gems_rtp','96') ON CONFLICT (key) DO NOTHING`);
  try {
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD;
    if (adminPass && adminPass.length >= 10) {
      const ex = await pool.query('SELECT * FROM admin_users WHERE username=$1', [adminUser]);
      if (!ex.rows.length) {
        const hash = await bcrypt.hash(adminPass, 12);
        await pool.query('INSERT INTO admin_users (username, password_hash, role) VALUES ($1,$2,\'admin\')', [adminUser, hash]);
        console.log('✅ Admin bana diya:', adminUser);
      }
    } else { console.log('⚠️ ADMIN_PASSWORD 10+ char ka nahi dala'); }
  } catch(e){ console.log('Admin create error'); }
  console.log('DB Ready - SECURE V5');
}
initDatabase();

const otpStore = new Map();
app.post('/api/auth/send-otp', otpLimiter, async (req, res) => {
  const mobile = String(req.body.mobile||'').replace(/[^0-9]/g,'').slice(0,10);
  const dob = String(req.body.dob||'').slice(0,10);
  const reqName = String(req.body.name||'').slice(0,30);
  if (!mobile || !/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({ success: false, message: 'Sahi 10 digit mobile daalo' });
  let w;
  try{ w = await pool.query('SELECT dob FROM wallets WHERE user_id=$1', [mobile]); }
  catch(e){ return res.status(500).json({ success: false, message: 'Database down hai' }); }
  if (!w.rows.length) {
    if (!dob) return res.status(400).json({ success: false, message: '18+ ke liye DOB chahiye' });
    if (!is18Plus(dob)) return res.status(403).json({ success: false, message: '18 saal se kam wale nahi khel sakte.' });
  } else if (w.rows[0].dob && !is18Plus(w.rows[0].dob)) return res.status(403).json({ success: false, message: '18 saal se kam wale nahi khel sakte' });
  const apiKey = process.env.TWO_FACTOR_API_KEY;
  if (!apiKey) return res.status(500).json({ success: false, message: 'OTP service band hai' });
  try {
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/${mobile}/AUTOGEN/OTP1`);
    if (data.Status === 'Success') {
      otpStore.set(mobile, { sessionId: data.Details, expiresAt: Date.now() + 5 * 60 * 1000, dob: dob || w.rows[0]?.dob || null, attempts: 0, name: reqName });
      res.json({ success: true, message: 'OTP bhej diya' });
    } else { res.status(400).json({ success: false, message: 'OTP nahi bheja gaya' }); }
  } catch(e){ res.status(500).json({ success: false, message: 'OTP fail' }); }
});

app.post('/api/auth/verify-otp', loginLimiter, async (req, res) => {
  const mobile = String(req.body.mobile||'').replace(/[^0-9]/g,'').slice(0,10);
  const otp = String(req.body.otp||'').replace(/[^0-9]/g,'').slice(0,6);
  if(!/^[6-9]\d{9}$/.test(mobile) || otp.length !== 6) return res.status(400).json({ success: false, message: 'Sahi mobile / 6 digit OTP daalo' });
  const rec = otpStore.get(mobile);
  if (!rec || Date.now() > rec.expiresAt) return res.status(400).json({ success: false, message: 'OTP expire ho gaya, dobara bhejo' });
  if ((rec.attempts || 0) >= 3) { otpStore.delete(mobile); return res.status(400).json({ success: false, message: '3 baar galat OTP' }); }
  const apiKey = process.env.TWO_FACTOR_API_KEY;
  try {
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/VERIFY/${rec.sessionId}/${otp}`);
    if (data.Status !== 'Success') { rec.attempts = (rec.attempts || 0) + 1; otpStore.set(mobile, rec); return res.status(400).json({ success: false, message: `Galat OTP - ${3 - rec.attempts} try bacha hai` }); }
    otpStore.delete(mobile);
    let w = await pool.query('SELECT * FROM wallets WHERE user_id=$1', [mobile]);
    if (!w.rows.length) {
      if (rec.dob && !is18Plus(rec.dob)) return res.status(403).json({ success: false, message: '18+ hi khel sakta hai' });
      w = await pool.query('INSERT INTO wallets (user_id,balance,vip_level,dob) VALUES ($1,0,0,$2) RETURNING *', [mobile, rec.dob || null]);
    }
    const blocked = await checkBlocked(mobile);
    if (blocked.blocked) return res.status(403).json({ success: false, message: blocked.reason });
    const token = makeToken(mobile);
    const refreshToken = makeRefreshToken(mobile);
    res.json({ success: true, token, refreshToken, user: { id: mobile, mobile, name: rec.name || 'Player', balance: w.rows[0].balance, bonus: Number(w.rows[0].bonus_total||0), vip_level: w.rows[0].vip_level } });
  } catch(e){ res.status(500).json({ success: false, message: 'Login fail' }); }
});

// ===== TOKEN REFRESH - Bina OTP ke naya Token =====
app.post('/api/auth/refresh', async (req, res) => {
  const rt = String(req.body.refreshToken || req.body.refresh_token || '');
  if(!rt) return res.status(401).json({ success: false, message: 'Refresh nahi hai, dobara Login karo' });
  try {
    const d = jwt.verify(rt, process.env.JWT_SECRET);
    if(d.type !== 'refresh') throw new Error('Galat refresh');
    const w = await pool.query('SELECT is_blocked FROM wallets WHERE user_id=$1', [d.mobile]);
    if(w.rows[0]?.is_blocked) return res.status(403).json({ success: false, message: 'Blocked ho' });
    const newToken = makeToken(d.mobile);
    return res.json({ success: true, token: newToken, refreshToken: rt });
  } catch(e){ return res.status(401).json({ success: false, message: 'Dobara Login karo' }); }
});

app.post('/api/user/self-exclude', checkAuth, async (req, res) => {
  const h = [24, 168, 720].includes(parseInt(req.body.hours)) ? parseInt(req.body.hours) : 24;
  await pool.query('UPDATE wallets SET self_excluded_until = NOW() + ($1 || \' hours\')::interval WHERE user_id=$2', [h, req.user.mobile]);
  await audit(req.user.mobile, 'SELF_EXCLUDE', `Self excluded for ${h}h`, req.ip);
  res.json({ success: true, message: `Tune khud ko ${h} ghante ke liye band kar diya.` });
});
app.get('/api/wallet/balance', checkAuth, async (req, res) => {
  const r = await pool.query('SELECT balance, vip_level, bonus_total, is_blocked, self_excluded_until FROM wallets WHERE user_id=$1', [req.user.mobile]);
  if (!r.rows.length) return res.status(404).json({ success: false, message: 'Wallet nahi mila' });
  res.json({ success: true, balance: r.rows[0].balance, bonus: Number(r.rows[0].bonus_total||0), vip_level: r.rows[0].vip_level });
});
app.get('/api/wallet/history', checkAuth, async (req, res) => {
  const r = await pool.query('SELECT amount,type,status,created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [req.user.mobile]);
  res.json({ success: true, history: r.rows });
});

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const username = String(req.body.username||'').slice(0,100);
  const password = String(req.body.password||'').slice(0,200);
  if(!username || !password) return res.status(401).json({ success: false, message: 'Username / Password daalo' });
  const r = await pool.query('SELECT * FROM admin_users WHERE username=$1', [username]);
  if (!r.rows.length) return res.status(401).json({ success: false, message: 'Galat login' });
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if(!ok) return res.status(401).json({ success: false, message: 'Galat login' });
  const token = jwt.sign({ username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '12h' });
  res.json({ success: true, token });
});
app.post('/api/admin/approve-deposit', checkAdmin, async (req, res) => {
  const id = parseInt(req.body.id);
  const action = String(req.body.action||'APPROVE').toUpperCase();
  const c = await pool.connect();
  try{
    await c.query('BEGIN');
    const d = await c.query('SELECT * FROM deposits WHERE id=$1 FOR UPDATE', [id]);
    if(!d.rows.length) throw new Error('Deposit nahi mila');
    if(d.rows[0].status !== 'PENDING') throw new Error('Already handled');
    if(action === 'APPROVE'){
      await c.query('UPDATE deposits SET status=\'APPROVED\' WHERE id=$1', [id]);
      await c.query('UPDATE wallets SET balance=balance+$1, daily_deposit=COALESCE(daily_deposit,0)+$1, daily_deposit_date=CURRENT_DATE, vip_level=GREATEST(vip_level,1), updated_at=NOW() WHERE user_id=$2', [d.rows[0].amount, d.rows[0].user_id]);
      await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'DEPOSIT\',\'SUCCESS\')', [d.rows[0].user_id, d.rows[0].amount]);
    } else {
      await c.query('UPDATE deposits SET status=\'REJECTED\' WHERE id=$1', [id]);
    }
    await c.query('COMMIT');
    res.json({ success: true, message: action === 'APPROVE' ? 'Deposit approve ho gaya' : 'Deposit reject ho gaya' });
  }catch(e){ try{ await c.query('ROLLBACK'); }catch(_){} res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});
app.post('/api/admin/handle-withdraw', checkAdmin, async (req, res) => {
  const id = parseInt(req.body.id);
  const action = String(req.body.action||'APPROVE').toUpperCase();
  const c = await pool.connect();
  try{
    await c.query('BEGIN');
    const w = await c.query('SELECT * FROM withdraws WHERE id=$1 FOR UPDATE', [id]);
    if(!w.rows.length) throw new Error('Withdraw nahi mila');
    if(w.rows[0].status !== 'PENDING') throw new Error('Already handled');
    if(action === 'APPROVE'){
      await c.query('UPDATE withdraws SET status=\'APPROVED\' WHERE id=$1', [id]);
      await c.query('UPDATE transactions SET status=\'SUCCESS\' WHERE user_id=$1 AND type=\'WITHDRAW\' AND status=\'PENDING\'', [w.rows[0].user_id]);
    } else {
      await c.query('UPDATE withdraws SET status=\'REJECTED\' WHERE id=$1', [id]);
      await c.query('UPDATE wallets SET balance=balance+$1 WHERE user_id=$2', [w.rows[0].amount, w.rows[0].user_id]);
      await c.query('UPDATE transactions SET status=\'REJECTED\' WHERE user_id=$1 AND type=\'WITHDRAW\' AND status=\'PENDING\'', [w.rows[0].user_id]);
    }
    await c.query('COMMIT');
    res.json({ success: true, message: 'Withdraw ' + action });
  }catch(e){ try{ await c.query('ROLLBACK'); }catch(_){} res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});
app.get('/api/admin/pending-deposits', checkAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM deposits WHERE status=\'PENDING\' ORDER BY created_at ASC LIMIT 100');
  res.json({ success: true, deposits: r.rows });
});
app.get('/api/admin/pending-withdraws', checkAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM withdraws WHERE status=\'PENDING\' ORDER BY created_at ASC LIMIT 100');
  res.json({ success: true, withdraws: r.rows });
});
app.get('/api/admin/settings', checkAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM settings');
  res.json({ success: true, settings: r.rows });
});
app.post('/api/admin/teenpatti-settings', checkAdmin, async (req, res) => {
  await pool.query(`INSERT INTO settings (key,value) VALUES ('teenpatti_rake',$1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, [String(req.body.rake ?? 5)]);
  res.json({ success: true, message: 'TeenPatti settings save' });
});
app.post('/api/admin/aviator-settings', checkAdmin, async (req, res) => {
  if(req.body.house_edge !== undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('aviator_house_edge',$1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, [String(req.body.house_edge)]);
  res.json({ success: true, message: 'Aviator settings save' });
});
app.post('/api/admin/spin-settings', checkAdmin, async (req, res) => {
  if(req.body.rtp !== undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('spin_rtp',$1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, [String(req.body.rtp)]);
  res.json({ success: true, message: 'Spin settings save' });
});
app.post('/api/admin/casino-settings', checkAdmin, async (req, res) => {
  if(req.body.key && req.body.value !== undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, [String(req.body.key).slice(0,50), String(req.body.value).slice(0,50)]);
  res.json({ success: true, message: 'Settings save' });
});
app.post('/api/admin/block-user', checkAdmin, async (req, res) => {
  const userId = String(req.body.user_id || req.body.mobile || '').slice(0,20);
  const block = req.body.block !== false;
  await pool.query('UPDATE wallets SET is_blocked=$1 WHERE user_id=$2', [block, userId]);
  res.json({ success: true, message: block ? 'User block ho gaya' : 'User unblock ho gaya' });
});
app.post('/api/bonus/welcome', checkAuth, async (req, res) => {
  const c = await pool.connect();
  try{
    await c.query('BEGIN');
    const w = await c.query('SELECT welcome_claimed, balance FROM wallets WHERE user_id=$1 FOR UPDATE', [req.user.mobile]);
    if(!w.rows.length) throw new Error('Wallet nahi mila');
    if(w.rows[0].welcome_claimed) throw new Error('Welcome bonus already liya hai');
    await c.query('UPDATE wallets SET balance=balance+50, bonus_total=COALESCE(bonus_total,0)+50, welcome_claimed=true WHERE user_id=$1', [req.user.mobile]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,50,\'BONUS\',\'SUCCESS\')', [req.user.mobile]);
    await c.query('COMMIT');
    res.json({ success: true, message: '₹50 Welcome Bonus mil gaya!' });
  }catch(e){ try{ await c.query('ROLLBACK'); }catch(_){} res.status(400).json({ success: false, message: e.message }); } finally { c.release(); }
});
app.post('/api/referral/share', checkAuth, async (req, res) => {
  const code = String(req.body.code||'').slice(0,50);
  if(!code) return res.status(400).json({ success: false, message: 'Code chahiye' });
  try{
    await pool.query('INSERT INTO referral_claims (user_id, code, amount) VALUES ($1,$2,20) RETURNING *', [req.user.mobile, code]);
    await pool.query('UPDATE wallets SET balance=balance+20, bonus_total=COALESCE(bonus_total,0)+20 WHERE user_id=$1', [req.user.mobile]);
    await pool.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,20,\'BONUS\',\'SUCCESS\')', [req.user.mobile]);
    res.json({ success: true, message: '₹20 Share Bonus mil gaya!' });
  }catch(e){
    if(e.code === '23505') return res.status(400).json({ success: false, message: 'Aaj ka bonus already mil gaya hai' });
    res.status(500).json({ success: false, message: 'Bonus fail' });
  }
});
app.post('/api/teenpatti/settle', checkAuth, async (req, res) => {
  const r = await pool.query('SELECT balance FROM wallets WHERE user_id=$1', [req.user.mobile]);
  return res.json({ success: true, win: 0, newBalance: Number(r.rows[0]?.balance || 0), balance: Number(r.rows[0]?.balance || 0), message: 'TeenPatti Free Play' });
});
// ================= PART 3 / 4 =================
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.split(' ')[1];
    if(!token) return next(new Error('Token chahiye'));
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch(e){ next(new Error('Token galat hai')); }
});

let aviatorState = { roundId: 0, multiplier: 1, status: 'WAITING', startedAt: 0, crashAt: 2, timer: null };
let aviatorBets = new Map();

function randomCrash(){
  const r = Math.random();
  let crash = Math.max(1.10, 0.96 / Math.max(0.01, 1 - r));
  if(crash > 100) crash = 100;
  return Math.floor(crash * 100) / 100;
}
function startAviator(){
  if(aviatorState.timer) return;
  const loop = async () => {
    aviatorState.roundId++;
    aviatorState.status = 'WAITING';
    aviatorState.multiplier = 1;
    for(let [k,b] of aviatorBets){ if(b.state==='next') b.state='waiting'; }
    io.emit('game:started', { game: 'aviator', roundId: aviatorState.roundId });
    io.emit('aviator:waiting', { game: 'aviator', roundId: aviatorState.roundId, status: 'WAITING' });
    await new Promise(r => setTimeout(r, 5000));
    aviatorState.crashAt = randomCrash();
    aviatorState.status = 'RUNNING';
    aviatorState.startedAt = Date.now();
    for(let [k,b] of aviatorBets){ if(b.state==='waiting') b.state='flying'; }
    io.emit('aviator:flying', { game: 'aviator', roundId: aviatorState.roundId, status: 'RUNNING' });
    const tick = setInterval(() => {
      const elapsed = (Date.now() - aviatorState.startedAt) / 1000;
      aviatorState.multiplier = Math.floor((1 + elapsed * 0.35 + elapsed * elapsed * 0.02) * 100) / 100;
      if(aviatorState.multiplier >= aviatorState.crashAt){
        clearInterval(tick);
        aviatorState.status = 'CRASHED';
        io.emit('game:crashed', { game: 'aviator', roundId: aviatorState.roundId, multiplier: aviatorState.crashAt });
        for(let [k,b] of aviatorBets){ if(b.state==='flying'){ aviatorBets.delete(k); } }
        setTimeout(loop, 4000);
      }
    }, 100);
  };
  loop();
}

async function playGenericGame(socket, gameName, betAmount, winChance, maxMult){
  if(!socketRateLimit(socket, 5)) return { success: false, message: 'Bahut tez khel rahe ho' };
  const betRes = await placeBet(socket.user.mobile, betAmount);
  if(!betRes.success) return { success: false, message: betRes.error };
  const rtp = await getSetting(gameName + '_rtp', 96);
  const winRoll = Math.random() * 100;
  const isWin = winRoll < (rtp / 2);
  let winnings = 0;
  if(isWin){
    const mult = 1 + Math.random() * (maxMult - 1);
    winnings = Math.floor(betAmount * mult * 100) / 100;
    const bal = await creditWin(socket.user.mobile, winnings);
    return { success: true, isWin: true, winnings, newBalance: bal };
  }
  const balRow = await pool.query('SELECT balance FROM wallets WHERE user_id=$1', [socket.user.mobile]);
  return { success: true, isWin: false, winnings: 0, newBalance: parseFloat(balRow.rows[0]?.balance || 0) };
}

const TEEN_BOOTS = [5, 10, 15, 20, 25, 50, 100];
const teenTables = new Map();
function teenDeck(){
  const suits = ['♠','♥','♦','♣'];
  const ranks = ['2','3','4','5','6','7','8','9','10','J','Q','K','A'];
  let d = [];
  for(let s of suits) for(let r of ranks) d.push({rank:r, suit:s, val: r==='A'?14 : r==='K'?13 : r==='Q'?12 : r==='J'?11 : parseInt(r)});
  for(let i=d.length-1;i>0;i--){ const j=Math.floor(Math.random()*(i+1)); [d[i],d[j]]=[d[j],d[i]]; }
  return d;
}
function teenRankHand(cards){
  const vals = cards.map(c=>c.val).sort((a,b)=>b-a);
  const isFlush = cards[0].suit===cards[1].suit && cards[1].suit===cards[2].suit;
  const isSeq = (vals[0]-vals[1]===1 && vals[1]-vals[2]===1) || (vals[0]===14 && vals[1]===3 && vals[2]===2);
  const isTrail = vals[0]===vals[1] && vals[1]===vals[2];
  const isPair = vals[0]===vals[1] || vals[1]===vals[2];
  let score=0, name='High Card';
  if(isTrail){ score=600+vals[0]; name='Trail'; }
  else if(isFlush && isSeq){ score=500+vals[0]; name='Pure Sequence'; }
  else if(isSeq){ score=400+vals[0]; name='Sequence'; }
  else if(isFlush){ score=300+vals[0]; name='Flush'; }
  else if(isPair){ const p=vals[0]===vals[1]?vals[0]:vals[1]; score=200+p; name='Pair'; }
  else { score=100+vals[0]; name='High Card'; }
  return { score, name };
}
function teenGetBet(boot, type){
  if(type==='BLIND') return boot;
  if(type==='CHAAL') return boot*2;
  return boot;
}
function teenPublicTable(table, mobile){
  return {
    boot: table.boot, pot: table.pot, round: table.round, turn: table.turn,
    players: table.players.map(p=>({
      name: p.name, isBot: p.isBot, isYou: p.mobile===mobile,
      packed: p.packed, seen: p.seen, betTotal: p.betTotal,
      cards: (p.mobile===mobile || table.showdown) ? p.cards : null,
      handName: (p.mobile===mobile || table.showdown) ? p.handName : null
    })),
    showdown: table.showdown, winner: table.winner
  };
}

io.on('connection', (socket) => {
  const mobile = socket.user.mobile;
  console.log('Socket connected:', mobile);
  socket.join('game-room');

  socket.on('aviator:join', () => {
    socket.emit('game:started', { game: 'aviator', roundId: aviatorState.roundId, status: aviatorState.status });
  });

  const handleAviatorBet = async (data) => {
    if(!socketRateLimit(socket, 5)) return socket.emit('aviator:error', { message: 'Bahut tez dabaa rahe ho' });
    if(aviatorState.status === 'CRASHED') return socket.emit('aviator:error', { message: 'FLEW AWAY ho gaya - Next Round ka wait karo' });
    if(aviatorState.status !== 'WAITING' && aviatorState.status !== 'RUNNING') return socket.emit('aviator:error', { message: 'Bet window band hai' });
    let panel = Number(data?.panel || 1);
    if(![1,2].includes(panel)) panel = 1;
    let key = mobile + ':' + panel;
    if(aviatorBets.has(key)) return socket.emit('aviator:error', { message: 'Is panel me Bet pehle se lagi hai' });
    const bet = cleanBet(data?.betAmount || data?.bet, 1, MAX_BET);
    if(!bet) return socket.emit('aviator:error', { message: `Bet ₹1 se ₹${MAX_BET} ke beech` });
    const betRes = await placeBet(mobile, bet, 1);
    if(!betRes.success) return socket.emit('aviator:error', { message: betRes.error });
    let state = aviatorState.status === 'WAITING' ? 'waiting' : 'next';
    aviatorBets.set(key, { bet, cashed: false, state, panel, mobile });
    socket.emit('aviator:bet-placed', { bet, panel, phase: aviatorState.status, state, newBalance: betRes.newBalance });
    socket.emit('wallet:update', { balance: betRes.newBalance });
  };
  socket.on('aviator:bet', handleAviatorBet);
  socket.on('aviator:place-bet', handleAviatorBet);
  socket.on('aviator:placeBet', handleAviatorBet);

  const handleAviatorCancel = async (data) => {
    let panel = Number(data?.panel || 1);
    if(![1,2].includes(panel)) panel = 1;
    let key = mobile + ':' + panel;
    let b = aviatorBets.get(key);
    if(!b) return socket.emit('aviator:error', { message: 'Cancel karne ke liye koi Bet nahi hai' });
    if(b.state === 'flying') return socket.emit('aviator:error', { message: 'Flying me Cancel nahi hoga, Cash Out karo' });
    if(b.cashed) return socket.emit('aviator:error', { message: 'Cash Out ho chuka hai' });
    aviatorBets.delete(key);
    try{
      let newBal = await refundBet(mobile, b.bet);
      socket.emit('aviator:cancelled', { panel, refund: b.bet, newBalance: newBal });
      socket.emit('wallet:update', { balance: newBal });
    }catch(e){ socket.emit('aviator:error', { message: 'Cancel me error' }); }
  };
  socket.on('aviator:cancel', handleAviatorCancel);
  socket.on('aviator:cancel-bet', handleAviatorCancel);

  socket.on('aviator:cashout', async (data) => {
    if(aviatorState.status !== 'RUNNING') return socket.emit('aviator:error', { message: 'Plane uda nahi / crash ho gaya' });
    let panel = Number(data?.panel || 1);
    if(![1,2].includes(panel)) panel = 1;
    let key = mobile + ':' + panel;
    const myBet = aviatorBets.get(key);
    if(!myBet || myBet.cashed) return socket.emit('aviator:error', { message: 'Bet nahi lagi ya cashout ho gaya' });
    if(myBet.state !== 'flying') return socket.emit('aviator:error', { message: 'Ye Bet is round ka nahi hai, Next Round ka hai' });
    const mult = Math.min(Number(data?.multiplier || aviatorState.multiplier || 1), aviatorState.multiplier);
    if(!Number.isFinite(mult) || mult < 1) return;
    myBet.cashed = true;
    aviatorBets.delete(key);
    const win = Math.floor(myBet.bet * mult * 100) / 100;
    try{
      const bal = await creditWin(mobile, win);
      socket.emit('aviator:cashed', { win, multiplier: mult, panel, newBalance: bal });
      socket.emit('wallet:update', { balance: bal });
    }catch(e){ socket.emit('aviator:error', { message: 'Cash Out me error' }); }
  });

  const genericHandler = (gameKey, maxMult) => async (data) => {
    const bet = cleanBet(data?.betAmount || data?.bet, MIN_BET, MAX_BET);
    if(!bet) return socket.emit('game:result', { isWin: false, message: `Bet ₹${MIN_BET} se ₹${MAX_BET}` });
    const res = await playGenericGame(socket, gameKey, bet, 48, maxMult);
    if(!res.success) return socket.emit('game:result', { isWin: false, message: res.message });
    socket.emit('game:result', { isWin: res.isWin, winnings: res.winnings, newBalance: res.newBalance });
    socket.emit('wallet:update', { balance: res.newBalance });
  };
  socket.on('dragontiger:bet', async (data) => {
    const choice = cleanChoice(data?.choice, ['DRAGON','TIGER','TIE']);
    if(!choice) return socket.emit('game:result', { isWin: false, message: 'Dragon / Tiger chuno' });
    const bet = cleanBet(data?.betAmount, MIN_BET, MAX_BET);
    const res = await playGenericGame(socket, 'dragontiger', bet, 48, 2);
    if(!res.success) return socket.emit('game:result', { isWin: false, message: res.message });
    socket.emit('game:result', { isWin: res.isWin, winnings: res.winnings, newBalance: res.newBalance, choice });
  });
  socket.on('slots:spin', genericHandler('slots', 10));
  socket.on('gemstemple:spin', genericHandler('gems', 8));
  socket.on('gems:spin', genericHandler('gems', 8));
  socket.on('roulette:bet', genericHandler('roulette', 5));
  socket.on('andarbahar:bet', genericHandler('andarbahar', 2));
  socket.on('baccarat:bet', genericHandler('baccarat', 2));
  socket.on('poker:bet', genericHandler('poker', 5));
  socket.on('colour:bet', genericHandler('colour', 2));
  socket.on('colour:play', genericHandler('colour', 2));
  socket.on('chicken:play', genericHandler('chicken', 3));
  socket.on('fortune:spin', genericHandler('fortune', 5));
  socket.on('plinko:drop', genericHandler('plinko', 10));
  socket.on('spin:spin', genericHandler('spin', 10));

  socket.on('mines:play', async (data) => {
    const bet = cleanBet(data?.betAmount, MIN_BET, MAX_BET);
    const minesCount = Math.min(8, Math.max(1, parseInt(data?.mines || 3)));
    if(!bet) return socket.emit('game:result', { isWin: false, message: 'Bet sahi daalo' });
    const res = await playGenericGame(socket, 'mines', bet, 48, 3);
    if(!res.success) return socket.emit('game:result', { isWin: false, message: res.message });
    socket.emit('game:result', { isWin: res.isWin, winnings: res.winnings, newBalance: res.newBalance, mines: minesCount });
  });

  socket.on('teenpatti:join', async (data) => {
    try{
      const boot = parseInt(data?.boot);
      if(!TEEN_BOOTS.includes(boot)) return socket.emit('teenpatti:error', { message: 'Galat Boot!' });
      if(teenTables.has(mobile)) return socket.emit('teenpatti:error', { message: 'Pehle wala game khatam karo' });
      const betRes = await placeBet(mobile, boot);
      if(!betRes.success) return socket.emit('teenpatti:error', { message: betRes.message || 'Balance kam hai' });
      const deck = teenDeck();
      const botNames = ['Raju','Vikram'];
      const players = [];
      const myCards = deck.splice(0,3);
      const myRank = teenRankHand(myCards);
      players.push({ name:'You', mobile: mobile, isBot:false, cards: myCards, handScore: myRank.score, handName: myRank.name, packed:false, seen:false, betTotal: boot });
      for(let i=0;i<2;i++){
        const c = deck.splice(0,3);
        const r = teenRankHand(c);
        players.push({ name: botNames[i], mobile:'bot_'+i+'_'+mobile, isBot:true, cards:c, handScore:r.score, handName:r.name, packed:false, seen:false, betTotal: boot });
      }
      const table = { boot, pot: boot*3, round:1, turn:0, players, showdown:false, winner:null };
      teenTables.set(mobile, table);
      socket.emit('teenpatti:state', teenPublicTable(table, mobile));
    }catch(e){ socket.emit('teenpatti:error',{message:'Join fail ho gaya'}); }
  });
  socket.on('teenpatti:bet', async (data) => {
    try{
      const table = teenTables.get(mobile);
      if(!table || table.showdown) return;
      if(table.turn!==0) return socket.emit('teenpatti:error',{message:'Teri baari nahi hai'});
      const me = table.players[0];
      if(me.packed) return;
      const type = data?.type;
      if(type==='PACK'){ me.packed = true; }
      else if(type==='SEEN'){ me.seen = true; }
      else if(type==='BLIND' || type==='CHAAL'){
        const amt = teenGetBet(table.boot, type);
        const betRes = await placeBet(mobile, amt);
        if(!betRes.success) return socket.emit('teenpatti:error',{message:'Balance kam hai'});
        me.betTotal += amt; table.pot += amt;
      } else return;
      await teenRunBots(mobile, table);
      await teenCheckEnd(mobile, table);
      socket.emit('teenpatti:state', teenPublicTable(table, mobile));
    }catch(e){ console.log('teen bet err', e); }
  });
  socket.on('teenpatti:show', async () => {
    try{
      const table = teenTables.get(mobile);
      if(!table || table.showdown) return;
      const me = table.players[0];
      if(me.packed) return socket.emit('teenpatti:error',{message:'Tu Pack ho chuka hai'});
      const amt = teenGetBet(table.boot, 'CHAAL');
      const betRes = await placeBet(mobile, amt);
      if(!betRes.success) return socket.emit('teenpatti:error',{message:'Balance kam hai'});
      me.betTotal += amt; table.pot += amt;
      table.showdown = true;
      await teenFinish(mobile, table);
      socket.emit('teenpatti:state', teenPublicTable(table, mobile));
    }catch(e){ console.log('teen show err', e); }
  });
  socket.on('teenpatti:leave', () => { teenTables.delete(mobile); });
  async function teenRunBots(mobile, table){
    for(let idx=1; idx<=2; idx++){
      const bot = table.players[idx];
      if(bot.packed || table.showdown) continue;
      const r = Math.random();
      if(bot.handScore < 210 && r < 0.4){ bot.packed = true; }
      else { const amt = teenGetBet(table.boot, 'CHAAL'); bot.betTotal += amt; table.pot += amt; }
    }
    table.round++;
    table.turn = 0;
    if(table.round >= 4){ table.showdown = true; await teenFinish(mobile, table); }
  }
  async function teenCheckEnd(mobile, table){
    const alive = table.players.filter(p=>!p.packed);
    if(alive.length===1){ table.showdown = true; await teenFinish(mobile, table); }
  }
  async function teenFinish(mobile, table){
    const alive = table.players.filter(p=>!p.packed);
    alive.sort((a,b)=>b.handScore - a.handScore);
    const win = alive[0];
    table.winner = { name: win.name, handName: win.handName, isYou: win.mobile===mobile, pot: table.pot };
    if(win.mobile===mobile){ await creditWin(mobile, table.pot); }
    setTimeout(()=>{ teenTables.delete(mobile); }, 3000);
  }
  socket.on('teenpatti:get-state', () => {
    const table = teenTables.get(mobile);
    if(table) socket.emit('teenpatti:state', teenPublicTable(table, mobile));
  });
  socket.on('disconnect', () => {
    teenTables.delete(mobile);
    console.log('Socket disconnected:', mobile);
  });
});
// ================= PART 4 / 4 =================
app.use((req, res) => {
  res.status(404).json({ success:false, message:'Route nahi mila: ' + req.path });
});
app.use((err, req, res, next) => {
  if(err && err.message && err.message.includes('CORS')){
    console.log('CORS Error:', err.message, 'Origin:', req.headers.origin);
    return res.status(403).json({ success:false, message:'CORS Blocked - FRONTEND_URL check karo', origin: req.headers.origin });
  }
  console.log('Server Error:', err.message);
  return res.status(500).json({ success:false, message:'Server error' });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`🚀 Server on ${PORT} - SECURE V5 - All 15 Games Locked`);
  startAviator();
});
// ================= SERVER.JS KHATAM - V5 =================
