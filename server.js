// ================= ROYAL CASINO - BACKEND SECURE V4 - FULL 15 GAMES - PART 1/6 =================
// Games: TeenPatti, Aviator, DragonTiger, Slots, Gems, Roulette, AndarBahar, Baccarat, Poker, Colour, Chicken, Fortune, Plinko, Spin, Mines
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

const allowedOrigins = (process.env.FRONTEND_URL || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function(origin, cb){
    if(!origin) return cb(null, true);
    if(allowedOrigins.length === 0) return cb(null, true);
    if(allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('CORS Blocked - FRONTEND_URL check karo'));
  },
  credentials: true
}));
app.use(express.json({ limit: '100kb' }));

const io = new Server(server, {
  cors: {
    origin: function(origin, cb){
      if(!origin) return cb(null, true);
      if(allowedOrigins.length === 0) return cb(null, true);
      if(allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error('CORS Blocked'));
    },
    methods: ['GET','POST'],
    credentials: true
  }
});

// ===== DB - FIXED: Render self-signed SSL =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 10
});

// ===== SECURE RANDOM - FIXED: Math.random() kahin nahi =====
function secureRandom(){ return crypto.randomInt(0, 1000000) / 1000000; }
function secureRandomInt(min, max){ return crypto.randomInt(min, max + 1); }

const MY_UPI_ID = process.env.MY_UPI_ID || 'royalcasino@okhdfc';
const MY_UPI_NAME = process.env.MY_UPI_NAME || 'Royal Casino';
const MIN_BET = 10, MAX_BET = 5000;
const MY_MIN_DEPOSIT = 100, MY_MIN_WITHDRAW = 200;
const DAILY_DEPOSIT_LIMIT = 50000, DAILY_BET_LIMIT = 50000;
const revokedTokens = new Set();

// ===== RATE LIMITERS =====
const otpLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { success:false, message:'Bahut zyada OTP try - 15 min baad try karo' } });
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { success:false, message:'Bahut zyada try - thodi der baad try karo' } });
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 100, message: { success:false, message:'Bahut tez request bhej rahe ho' } });
app.use('/api/', apiLimiter);

// ===== HELPERS =====
function cleanBet(v, min, max){
  let n = Number(v);
  if(!Number.isFinite(n)) return null;
  n = Math.floor(n * 100) / 100;
  if(n < min || n > max) return null;
  return n;
}
function cleanUtr(v){ return String(v || '').replace(/[^0-9]/g, '').slice(0, 12); }
function isValidUtr(u){ return /^[0-9]{12}$/.test(u); }
function cleanUpi(v){ return String(v || '').toLowerCase().replace(/[^a-z0-9._@-]/g, '').slice(0, 50); }
function isValidUpi(u){ return /^[a-z0-9._-]{2,}@[a-z0-9]{2,}$/.test(u); }
function cleanChoice(v, allowed){ let s = String(v || '').toUpperCase().trim(); return allowed.includes(s) ? s : null; }

const socketHits = new Map();
function socketRateLimit(socket, maxPerSec){
  const now = Date.now();
  const key = socket.user?.mobile || socket.id;
  let arr = (socketHits.get(key) || []).filter(t => now - t < 1000);
  arr.push(now); socketHits.set(key, arr);
  return arr.length <= maxPerSec;
}

function makeToken(mobile){ return jwt.sign({ mobile }, process.env.JWT_SECRET, { expiresIn: '12h' }); }
function checkAuth(req, res, next){
  try{
    const token = req.headers.authorization?.split(' ')[1];
    if(!token) return res.status(401).json({ success:false, message:'Login karo pehle' });
    if(revokedTokens.has(token)) return res.status(401).json({ success:false, message:'Logout ho chuka hai' });
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  }catch(e){ return res.status(401).json({ success:false, message:'Token galat / expire hai' }); }
}
function checkAdmin(req, res, next){
  try{
    const token = req.headers.authorization?.split(' ')[1];
    if(!token) return res.status(401).json({ success:false, message:'Admin login karo' });
    if(revokedTokens.has(token)) return res.status(401).json({ success:false, message:'Logout ho chuka hai' });
    const d = jwt.verify(token, process.env.JWT_SECRET);
    if(d.role !== 'admin') return res.status(403).json({ success:false, message:'Admin hi allowed hai' });
    req.admin = d; next();
  }catch(e){ return res.status(401).json({ success:false, message:'Admin token galat hai' }); }
}
async function audit(actor, action, details, ip){
  try{ await pool.query('INSERT INTO audit_logs (actor_id, action_type, details, ip_address) VALUES ($1,$2,$3,$4)', [String(actor).slice(0,50), String(action).slice(0,50), String(details).slice(0,500), String(ip || '').slice(0,50)]); }catch(e){}
}
async function checkBlocked(mobile){
  const r = await pool.query('SELECT is_blocked, blocked_reason FROM users WHERE mobile=$1', [mobile]);
  if(!r.rows[0]) return { blocked:true, reason:'User nahi mila' };
  return { blocked: !!r.rows[0].is_blocked, reason: r.rows[0].blocked_reason || '' };
}
async function getSetting(game, key, def){
  try{
    const r = await pool.query('SELECT setting FROM game_settings WHERE game=$1', [game]);
    if(!r.rows[0]) return def;
    const s = typeof r.rows[0].setting === 'string' ? JSON.parse(r.rows[0].setting) : r.rows[0].setting;
    return s[key] ?? def;
  }catch(e){ return def; }
}
async function placeBet(mobile, game, amount, client){
  if(amount < MIN_BET || amount > MAX_BET) return { success:false, message:`Bet ${MIN_BET} - ${MAX_BET} ke beech honi chahiye` };
  const chk = await checkBlocked(mobile);
  if(chk.blocked) return { success:false, message:'Account blocked hai: ' + chk.reason };
  const today = await pool.query(`SELECT COALESCE(SUM(bet_amount),0) as total FROM bets WHERE user_mobile=$1 AND created_at >= CURRENT_DATE`, [mobile]);
  if(Number(today.rows[0].total) + amount > DAILY_BET_LIMIT) return { success:false, message:'Aaj ka bet limit khatam (50000)' };
  const cl = await client.query('SELECT wallet FROM users WHERE mobile=$1 FOR UPDATE', [mobile]);
  if(!cl.rows[0] || Number(cl.rows[0].wallet) < amount) return { success:false, message:'Wallet me paisa kam hai' };
  await client.query('UPDATE users SET wallet = wallet - $1 WHERE mobile=$2', [amount, mobile]);
  await client.query('INSERT INTO bets (user_mobile, game, bet_amount, result) VALUES ($1,$2,$3,$4)', [mobile, game, amount, 'pending']);
  return { success:true };
}
async function creditWin(mobile, game, amount, client){
  if(amount <= 0) return;
  await client.query('UPDATE users SET wallet = wallet + $1 WHERE mobile=$2', [amount, mobile]);
  await client.query('UPDATE bets SET win_amount = $1, result = $2 WHERE user_mobile=$3 AND game=$4 AND result=$5 ORDER BY id DESC LIMIT 1', [amount, 'win', mobile, game, 'pending']);
}
// ================= SECURE V4 - 15 GAMES - PART 2 / 6 - DB + AUTH + WALLET =================

// ===== DB INIT =====
async function initDatabase(){
  try{
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      mobile TEXT PRIMARY KEY, name TEXT, password_hash TEXT, upi TEXT, ifsc TEXT, bank_account TEXT,
      wallet NUMERIC DEFAULT 0, bonus NUMERIC DEFAULT 0,
      kyc_status TEXT DEFAULT 'pending', kyc_submitted_at TIMESTAMPTZ,
      is_blocked BOOLEAN DEFAULT false, blocked_reason TEXT, self_excluded_until TIMESTAMPTZ,
      total_deposited NUMERIC DEFAULT 0, total_withdrawn NUMERIC DEFAULT 0,
      referral_code TEXT UNIQUE, referred_by TEXT, referral_claimed BOOLEAN DEFAULT false,
      is_new_user BOOLEAN DEFAULT true, welcome_claimed BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS deposits (
      id SERIAL PRIMARY KEY, user_mobile TEXT, amount NUMERIC, utr TEXT UNIQUE,
      status TEXT DEFAULT 'pending', deposit_code TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY, user_mobile TEXT, amount NUMERIC, upi TEXT,
      status TEXT DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS bets (
      id SERIAL PRIMARY KEY, user_mobile TEXT, game TEXT, bet_amount NUMERIC,
      win_amount NUMERIC DEFAULT 0, result TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS audit_logs (
      id SERIAL PRIMARY KEY, actor_id TEXT, action_type TEXT, details TEXT,
      ip_address TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS otps (
      mobile TEXT PRIMARY KEY, otp TEXT, expires_at TIMESTAMPTZ, attempts INT DEFAULT 0
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS referral_claims (
      id SERIAL PRIMARY KEY, user_mobile TEXT UNIQUE, referral_code TEXT,
      reward_amount NUMERIC DEFAULT 0, claimed_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS game_settings (
      game TEXT PRIMARY KEY, setting TEXT DEFAULT '{}', updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    console.log('DB Ready - SECURE V4 - 15 GAMES');
  }catch(e){ console.error('DB Init Error:', e.message); }
}
initDatabase();
app.get('/fix-db', checkAdmin, async (req, res) => { await initDatabase(); res.json({ success:true, message:'DB fixed - saari tables ban gayi' }); });

// ===== AUTH =====
app.post('/api/auth/send-otp', otpLimiter, async (req, res) => {
  const mobile = String(req.body.mobile || '').replace(/[^0-9]/g, '').slice(0, 10);
  if(!/^[6-9][0-9]{9}$/.test(mobile)) return res.json({ success:false, message:'Sahi 10 digit mobile daalo' });
  const otp = String(secureRandomInt(100000, 999999));
  await pool.query(`INSERT INTO otps (mobile, otp, expires_at, attempts) VALUES ($1,$2,NOW() + INTERVAL '5 minutes', 0) ON CONFLICT (mobile) DO UPDATE SET otp=$2, expires_at=NOW() + INTERVAL '5 minutes', attempts=0`, [mobile, otp]);
  console.log('OTP for', mobile, otp);
  res.json({ success:true, message:'OTP bhej diya' });
});
// Purane naam bhi chalenge
app.post('/api/send-otp', otpLimiter, (req, res) => { req.url = '/api/auth/send-otp'; app.handle(req, res); });

app.post('/api/auth/verify-otp', loginLimiter, async (req, res) => {
  const mobile = String(req.body.mobile || '').replace(/[^0-9]/g, '').slice(0, 10);
  const name = String(req.body.name || '').slice(0, 30);
  const password = String(req.body.password || '');
  const otp = String(req.body.otp || '').slice(0, 6);
  const referral = String(req.body.referralCode || req.body.referral_code || '').toUpperCase().slice(0, 10);
  if(!/^[6-9][0-9]{9}$/.test(mobile) || password.length < 6) return res.json({ success:false, message:'Saari details sahi se bharo' });
  const o = await pool.query('SELECT * FROM otps WHERE mobile=$1', [mobile]);
  if(!o.rows[0] || o.rows[0].otp !== otp || new Date(o.rows[0].expires_at) < new Date()) return res.json({ success:false, message:'OTP galat / expire hai' });
  const ex = await pool.query('SELECT * FROM users WHERE mobile=$1', [mobile]);
  if(ex.rows[0]){
    if(ex.rows[0].is_blocked) return res.json({ success:false, message:'Account blocked hai' });
    const ok = await bcrypt.compare(password, ex.rows[0].password_hash || '');
    if(!ok) return res.json({ success:false, message:'Password galat hai' });
    await pool.query('DELETE FROM otps WHERE mobile=$1', [mobile]);
    return res.json({ success:true, token: makeToken(mobile), user: { mobile, name: ex.rows[0].name, wallet: Number(ex.rows[0].wallet), bonus: Number(ex.rows[0].bonus) } });
  }
  if(!name) return res.json({ success:false, message:'Naam bharo - pehli baar register ho raha hai' });
  const hash = await bcrypt.hash(password, 10);
  const myCode = 'RC' + mobile.slice(6) + String(secureRandomInt(10, 99));
  let referredBy = null;
  if(referral){
    const ref = await pool.query('SELECT mobile FROM users WHERE referral_code=$1', [referral]);
    if(ref.rows[0] && ref.rows[0].mobile !== mobile) referredBy = ref.rows[0].mobile;
  }
  await pool.query('INSERT INTO users (mobile, name, password_hash, referral_code, referred_by) VALUES ($1,$2,$3,$4,$5)', [mobile, name, hash, myCode, referredBy]);
  await pool.query('DELETE FROM otps WHERE mobile=$1', [mobile]);
  res.json({ success:true, token: makeToken(mobile), message:'Register ho gaya!' });
});
app.post('/api/register', loginLimiter, (req, res) => { req.url = '/api/auth/verify-otp'; app.handle(req, res); });
app.post('/api/login', loginLimiter, (req, res) => { req.url = '/api/auth/verify-otp'; app.handle(req, res); });

app.post('/api/logout', checkAuth, async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if(token) revokedTokens.add(token);
  res.json({ success:true, message:'Logout ho gaya' });
});

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const password = String(req.body.password || '');
  const code2fa = String(req.body.code2fa || req.body.totp || '');
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
  const admin2fa = process.env.ADMIN_2FA_CODE || '';
  if(password !== adminPass) return res.json({ success:false, message:'Admin password galat hai' });
  if(admin2fa && code2fa !== admin2fa) return res.json({ success:false, message:'2FA code galat hai' });
  const token = jwt.sign({ role:'admin', mobile:'admin' }, process.env.JWT_SECRET, { expiresIn:'2h' });
  await audit('admin', 'ADMIN_LOGIN', 'Admin login success', req.ip);
  res.json({ success:true, token });
});

// ===== WALLET =====
app.get('/api/wallet/balance', checkAuth, async (req, res) => {
  const r = await pool.query('SELECT mobile, name, wallet, bonus, referral_code, kyc_status, is_blocked FROM users WHERE mobile=$1', [req.user.mobile]);
  if(!r.rows[0]) return res.json({ success:false, message:'User nahi mila' });
  res.json({ success:true, user:{ ...r.rows[0], wallet:Number(r.rows[0].wallet), bonus:Number(r.rows[0].bonus) } });
});
app.get('/api/me', checkAuth, async (req, res) => {
  const r = await pool.query('SELECT mobile, name, wallet, bonus, referral_code, kyc_status, is_blocked FROM users WHERE mobile=$1', [req.user.mobile]);
  if(!r.rows[0]) return res.json({ success:false, message:'User nahi mila' });
  res.json({ success:true, user:{ ...r.rows[0], wallet:Number(r.rows[0].wallet), bonus:Number(r.rows[0].bonus) } });
});
app.get('/api/wallet/history', checkAuth, async (req, res) => {
  const d = await pool.query('SELECT * FROM deposits WHERE user_mobile=$1 ORDER BY id DESC LIMIT 30', [req.user.mobile]);
  const w = await pool.query('SELECT * FROM withdrawals WHERE user_mobile=$1 ORDER BY id DESC LIMIT 30', [req.user.mobile]);
  const b = await pool.query('SELECT * FROM bets WHERE user_mobile=$1 ORDER BY id DESC LIMIT 30', [req.user.mobile]);
  res.json({ success:true, deposits:d.rows, withdrawals:w.rows, bets:b.rows });
});
app.post('/api/user/self-exclude', checkAuth, async (req, res) => {
  const days = Math.min(30, Math.max(1, Number(req.body.days) || 1));
  await pool.query('UPDATE users SET self_excluded_until = NOW() + INTERVAL \'1 day\' * $1 WHERE mobile=$2', [days, req.user.mobile]);
  res.json({ success:true, message:`${days} din ke liye self-exclude ho gaya` });
});
app.get('/api/payment-info', checkAuth, async (req, res) => {
  res.json({ success:true, upiId: MY_UPI_ID, upiName: MY_UPI_NAME, minDeposit: MY_MIN_DEPOSIT, minWithdraw: MY_MIN_WITHDRAW });
});

// ===== DEPOSIT / WITHDRAW HANDLERS =====
async function handleDepositCreateQR(req, res){
  const amount = cleanBet(req.body.amount, MY_MIN_DEPOSIT, 100000);
  if(!amount) return res.json({ success:false, message:`Deposit kam se kam ${MY_MIN_DEPOSIT} ka hona chahiye` });
  const code = 'DEP' + String(secureRandomInt(100000, 999999));
  res.json({ success:true, upiId: MY_UPI_ID, upiName: MY_UPI_NAME, amount, depositCode: code, message:'Is UPI pe payment karo, phir UTR daal ke confirm karo' });
}
async function handleDepositRequest(req, res){
  const amount = cleanBet(req.body.amount, MY_MIN_DEPOSIT, 100000);
  const utr = cleanUtr(req.body.utr);
  if(!amount) return res.json({ success:false, message:`Deposit kam se kam ${MY_MIN_DEPOSIT} ka hona chahiye` });
  if(!isValidUtr(utr)) return res.json({ success:false, message:'Sahi 12 digit UTR daalo' });
  const ex = await pool.query('SELECT id FROM deposits WHERE utr=$1', [utr]);
  if(ex.rows[0]) return res.json({ success:false, message:'Ye UTR pehle use ho chuka hai' });
  const today = await pool.query(`SELECT COALESCE(SUM(amount),0) as total FROM deposits WHERE user_mobile=$1 AND status != 'rejected' AND created_at >= CURRENT_DATE`, [req.user.mobile]);
  if(Number(today.rows[0].total) + amount > DAILY_DEPOSIT_LIMIT) return res.json({ success:false, message:'Aaj ka deposit limit khatam (50000)' });
  await pool.query('INSERT INTO deposits (user_mobile, amount, utr, status, deposit_code) VALUES ($1,$2,$3,$4,$5)', [req.user.mobile, amount, utr, 'pending', String(req.body.depositCode || '').slice(0, 20)]);
  await audit(req.user.mobile, 'DEPOSIT_REQUEST', `Deposit ${amount} UTR ${utr}`, req.ip);
  res.json({ success:true, message:'Deposit request bhej di - admin approve karega' });
}
async function handleWithdraw(req, res){
  const amount = cleanBet(req.body.amount, MY_MIN_WITHDRAW, 100000);
  const upi = cleanUpi(req.body.upi);
  if(!amount) return res.json({ success:false, message:`Withdraw kam se kam ${MY_MIN_WITHDRAW} ka hona chahiye` });
  if(!isValidUpi(upi)) return res.json({ success:false, message:'Sahi UPI ID daalo' });
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const u = await client.query('SELECT wallet FROM users WHERE mobile=$1 FOR UPDATE', [req.user.mobile]);
    if(!u.rows[0] || Number(u.rows[0].wallet) < amount){ await client.query('ROLLBACK'); return res.json({ success:false, message:'Wallet me paisa kam hai' }); }
    await client.query('UPDATE users SET wallet = wallet - $1 WHERE mobile=$2', [amount, req.user.mobile]);
    await client.query('INSERT INTO withdrawals (user_mobile, amount, upi, status) VALUES ($1,$2,$3,$4)', [req.user.mobile, amount, upi, 'pending']);
    await client.query('COMMIT');
    await audit(req.user.mobile, 'WITHDRAW_REQUEST', `Withdraw ${amount} to ${upi}`, req.ip);
    res.json({ success:true, message:'Withdraw request bhej di' });
  }catch(e){ await client.query('ROLLBACK'); res.json({ success:false, message:'Withdraw fail - dobara try karo' }); }
  finally{ client.release(); }
}
app.post('/api/deposit/create-qr', checkAuth, handleDepositCreateQR);
app.post('/api/wallet/deposit-create-qr', checkAuth, handleDepositCreateQR);
app.post('/api/wallet/deposit-request', checkAuth, handleDepositRequest);
app.post('/api/deposit/request', checkAuth, handleDepositRequest);
app.post('/api/deposit-request', checkAuth, handleDepositRequest);
app.post('/api/deposit', checkAuth, handleDepositRequest);
app.post('/api/wallet/withdraw', checkAuth, handleWithdraw);
app.post('/api/withdraw/request', checkAuth, handleWithdraw);
app.post('/api/withdraw-request', checkAuth, handleWithdraw);
app.post('/api/withdraw', checkAuth, handleWithdraw);
// ================= SECURE V4 - 15 GAMES - PART 3 / 6 - ADMIN + BONUS + REFERRAL =================

// ===== ADMIN =====
app.get('/api/admin/pending-deposits', checkAdmin, async (req, res) => {
  const r = await pool.query(`SELECT * FROM deposits WHERE status='pending' ORDER BY id DESC LIMIT 50`);
  res.json({ success:true, deposits: r.rows });
});
app.get('/api/admin/pending-withdraws', checkAdmin, async (req, res) => {
  const r = await pool.query(`SELECT * FROM withdrawals WHERE status='pending' ORDER BY id DESC LIMIT 50`);
  res.json({ success:true, withdrawals: r.rows });
});
app.get('/api/admin/stats', checkAdmin, async (req, res) => {
  const u = await pool.query('SELECT COUNT(*) as total FROM users');
  const d = await pool.query(`SELECT COALESCE(SUM(amount),0) as total FROM deposits WHERE status='approved'`);
  const w = await pool.query(`SELECT COALESCE(SUM(amount),0) as total FROM withdrawals WHERE status='approved'`);
  res.json({ success:true, stats: { users: Number(u.rows[0].total), deposits: Number(d.rows[0].total), withdrawals: Number(w.rows[0].total) } });
});
app.get('/api/admin/settings', checkAdmin, async (req, res) => {
  const r = await pool.query('SELECT * FROM game_settings ORDER BY game');
  res.json({ success:true, settings: r.rows });
});

app.post('/api/admin/approve-deposit', checkAdmin, async (req, res) => {
  const id = Number(req.body.id); const action = req.body.action === 'approve' ? 'approved' : 'rejected';
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const d = await client.query('SELECT * FROM deposits WHERE id=$1 AND status=$2 FOR UPDATE', [id, 'pending']);
    if(!d.rows[0]){ await client.query('ROLLBACK'); return res.json({ success:false, message:'Deposit nahi mili / pehle action ho chuka' }); }
    await client.query('UPDATE deposits SET status=$1 WHERE id=$2', [action, id]);
    if(action === 'approved') await client.query('UPDATE users SET wallet = wallet + $1, total_deposited = total_deposited + $1 WHERE mobile=$2', [Number(d.rows[0].amount), d.rows[0].user_mobile]);
    await client.query('COMMIT');
    await audit('admin', 'DEPOSIT_' + action.toUpperCase(), `Deposit ${id} ${action}`, req.ip);
    res.json({ success:true, message:'Deposit ' + action });
  }catch(e){ await client.query('ROLLBACK'); res.json({ success:false, message:'Fail ho gaya' }); }
  finally{ client.release(); }
});
app.post('/api/admin/deposit-action', checkAdmin, (req, res) => { req.url = '/api/admin/approve-deposit'; app.handle(req, res); });

app.post('/api/admin/handle-withdraw', checkAdmin, async (req, res) => {
  const id = Number(req.body.id); const action = req.body.action === 'approve' ? 'approved' : 'rejected';
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const w = await client.query('SELECT * FROM withdrawals WHERE id=$1 AND status=$2 FOR UPDATE', [id, 'pending']);
    if(!w.rows[0]){ await client.query('ROLLBACK'); return res.json({ success:false, message:'Withdraw nahi mili' }); }
    await client.query('UPDATE withdrawals SET status=$1 WHERE id=$2', [action, id]);
    if(action === 'rejected') await client.query('UPDATE users SET wallet = wallet + $1 WHERE mobile=$2', [Number(w.rows[0].amount), w.rows[0].user_mobile]);
    await client.query('COMMIT');
    await audit('admin', 'WITHDRAW_' + action.toUpperCase(), `Withdraw ${id} ${action}`, req.ip);
    res.json({ success:true, message:'Withdraw ' + action });
  }catch(e){ await client.query('ROLLBACK'); res.json({ success:false, message:'Fail ho gaya' }); }
  finally{ client.release(); }
});
app.post('/api/admin/withdraw-action', checkAdmin, (req, res) => { req.url = '/api/admin/handle-withdraw'; app.handle(req, res); });

async function saveGameSetting(req, res, game){
  let setting = req.body.setting || req.body || {};
  if(typeof setting !== 'object') setting = {};
  // Sirf number / string / boolean allow - injection nahi
  const clean = {};
  for(const k of Object.keys(setting).slice(0, 20)){
    const v = setting[k];
    if(typeof v === 'number' && Number.isFinite(v)) clean[String(k).slice(0, 30)] = Math.max(-1000000, Math.min(1000000, v));
    if(typeof v === 'string') clean[String(k).slice(0, 30)] = String(v).slice(0, 50);
    if(typeof v === 'boolean') clean[String(k).slice(0, 30)] = v;
  }
  await pool.query(`INSERT INTO game_settings (game, setting, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (game) DO UPDATE SET setting=$2, updated_at=NOW()`, [game, JSON.stringify(clean)]);
  await audit('admin', 'SETTING_' + game.toUpperCase(), `Setting update ${game}`, req.ip);
  res.json({ success:true, message: game + ' setting save ho gayi' });
}
app.post('/api/admin/teenpatti-settings', checkAdmin, (req, res) => saveGameSetting(req, res, 'teenpatti'));
app.post('/api/admin/aviator-settings', checkAdmin, (req, res) => saveGameSetting(req, res, 'aviator'));
app.post('/api/admin/spin-settings', checkAdmin, (req, res) => saveGameSetting(req, res, 'spin'));
app.post('/api/admin/casino-settings', checkAdmin, (req, res) => saveGameSetting(req, res, 'casino'));

app.post('/api/admin/block-user', checkAdmin, async (req, res) => {
  const mobile = String(req.body.mobile || '').replace(/[^0-9]/g, '').slice(0, 10);
  const reason = String(req.body.reason || 'Admin ne block kiya').slice(0, 100);
  await pool.query('UPDATE users SET is_blocked=true, blocked_reason=$1 WHERE mobile=$2', [reason, mobile]);
  await audit('admin', 'BLOCK_USER', `Blocked ${mobile} - ${reason}`, req.ip);
  res.json({ success:true, message:'User block ho gaya' });
});
app.post('/api/admin/unblock-user', checkAdmin, async (req, res) => {
  const mobile = String(req.body.mobile || '').replace(/[^0-9]/g, '').slice(0, 10);
  await pool.query('UPDATE users SET is_blocked=false, blocked_reason=NULL WHERE mobile=$1', [mobile]);
  await audit('admin', 'UNBLOCK_USER', `Unblocked ${mobile}`, req.ip);
  res.json({ success:true, message:'User unblock ho gaya' });
});

// ===== BONUS + REFERRAL - FIXED =====
app.post('/api/bonus/welcome', checkAuth, async (req, res) => {
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const u = await client.query('SELECT welcome_claimed FROM users WHERE mobile=$1 FOR UPDATE', [req.user.mobile]);
    if(!u.rows[0]){ await client.query('ROLLBACK'); return res.json({ success:false, message:'User nahi mila' }); }
    if(u.rows[0].welcome_claimed){ await client.query('ROLLBACK'); return res.json({ success:false, message:'Welcome bonus pehle hi mil chuka hai' }); }
    await client.query('UPDATE users SET bonus = bonus + 20, welcome_claimed=true WHERE mobile=$1', [req.user.mobile]);
    await client.query('COMMIT');
    res.json({ success:true, message:'20 Welcome Bonus mil gaya!' });
  }catch(e){ await client.query('ROLLBACK'); res.json({ success:false, message:'Claim fail - dobara try karo' }); }
  finally{ client.release(); }
});

app.post('/api/referral/share', checkAuth, async (req, res) => {
  const code = String(req.body.code || req.body.referralCode || '').toUpperCase().trim().slice(0, 10);
  if(!code) return res.json({ success:false, message:'Referral code daalo' });
  const me = await pool.query('SELECT mobile, referral_code FROM users WHERE mobile=$1', [req.user.mobile]);
  if(!me.rows[0]) return res.json({ success:false, message:'User nahi mila' });
  if(me.rows[0].referral_code === code) return res.json({ success:false, message:'Apna khud ka code nahi chalega' });
  const already = await pool.query('SELECT id FROM referral_claims WHERE user_mobile=$1', [req.user.mobile]);
  if(already.rows[0]) return res.json({ success:false, message:'Bonus pehle hi claim kar chuke ho' });
  const owner = await pool.query('SELECT mobile FROM users WHERE referral_code=$1', [code]);
  if(!owner.rows[0]) return res.json({ success:false, message:'Galat referral code hai' });
  if(owner.rows[0].mobile === req.user.mobile) return res.json({ success:false, message:'Apna khud ka code nahi chalega' });
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    await client.query('INSERT INTO referral_claims (user_mobile, referral_code, reward_amount) VALUES ($1,$2,$3)', [req.user.mobile, code, 50]);
    await client.query('UPDATE users SET bonus = bonus + 50, referred_by = $1 WHERE mobile=$2', [owner.rows[0].mobile, req.user.mobile]);
    await client.query('UPDATE users SET bonus = bonus + 50 WHERE mobile=$1', [owner.rows[0].mobile]);
    await client.query('COMMIT');
    res.json({ success:true, message:'50 Bonus mil gaya! Dono ko 50-50 mila' });
  }catch(e){ await client.query('ROLLBACK'); res.json({ success:false, message:'Claim fail - dobara try karo' }); }
  finally{ client.release(); }
});
app.post('/api/claim-referral', checkAuth, (req, res) => { req.url = '/api/referral/share'; app.handle(req, res); });

// TeenPatti settle - purana frontend isko call karta hai, isliye rakha hai
// Asli settle socket wale TeenPatti round me hota hai, ye sirf safety ke liye hai
app.post('/api/teenpatti/settle', checkAuth, async (req, res) => {
  res.json({ success:true, message:'TeenPatti settle socket se hota hai - live table me khelo' });
});
// ================= SECURE V4 - 15 GAMES - PART 4 / 6 - TEENPATTI + AVIATOR =================

// ===== TEENPATTI HELPERS - FIXED =====
function makeTeenDeck(){
  const suits = ['♠','♥','♦','♣'];
  const ranks = ['2','3','4','5','6','7','8','9','10','J','Q','K','A'];
  const deck = [];
  for(const s of suits) for(const r of ranks) deck.push({ rank: r, suit: s });
  for(let i = deck.length - 1; i > 0; i--){
    const j = secureRandomInt(0, i);
    const t = deck[i]; deck[i] = deck[j]; deck[j] = t;
  }
  return deck;
}
function cardVal(r){
  if(r === 'A') return 14;
  if(r === 'K') return 13;
  if(r === 'Q') return 12;
  if(r === 'J') return 11;
  return Number(r);
}
function evaluateTeenHand(cards){
  const vals = cards.map(c => cardVal(c.rank)).sort((a, b) => a - b);
  const isFlush = cards[0].suit === cards[1].suit && cards[1].suit === cards[2].suit;
  const isSeq = (vals[2] - vals[1] === 1 && vals[1] - vals[0] === 1) || (vals[0] === 2 && vals[1] === 3 && vals[2] === 14);
  const isTrail = vals[0] === vals[1] && vals[1] === vals[2];
  const isPair = vals[0] === vals[1] || vals[1] === vals[2];
  let score = 0; let name = 'High Card';
  if(isTrail){ score = 600 + vals[0]; name = 'Trail'; }
  else if(isSeq && isFlush){ score = 500 + vals[2]; name = 'Pure Sequence'; }
  else if(isSeq){ score = 400 + vals[2]; name = 'Sequence'; }
  else if(isFlush){ score = 300 + vals[2]; name = 'Color'; }
  else if(isPair){ const p = vals[0] === vals[1] ? vals[0] : vals[2]; score = 200 + p; name = 'Pair'; }
  else { score = 100 + vals[2]; name = 'High Card'; }
  return { score, name };
}

// ===== TEENPATTI LIVE TABLE =====
// 1 table per user - simple + safe. Round 30 sec betting -> result -> payout
const teenTables = new Map(); // mobile -> { roundId, cards, bet, choice, seen }
let teenRound = { roundId: 1, phase: 'betting', endsAt: Date.now() + 30000, cards: null, result: null };
function startTeenRound(){
  teenRound.roundId++;
  teenRound.phase = 'betting';
  teenRound.cards = null;
  teenRound.result = null;
  teenRound.endsAt = Date.now() + 30000;
  io.emit('teenpatti:state', { roundId: teenRound.roundId, phase: 'betting', endsAt: teenRound.endsAt });
  setTimeout(async () => {
    const deck = makeTeenDeck();
    const player = [deck.pop(), deck.pop(), deck.pop()];
    const dealer = [deck.pop(), deck.pop(), deck.pop()];
    const p = evaluateTeenHand(player);
    const d = evaluateTeenHand(dealer);
    const winner = p.score > d.score ? 'PLAYER' : (d.score > p.score ? 'DEALER' : 'TIE');
    teenRound.phase = 'result';
    teenRound.cards = { player, dealer };
    teenRound.result = { winner, playerHand: p.name, dealerHand: d.name };
    io.emit('teenpatti:result', { roundId: teenRound.roundId, player, dealer, winner, playerHand: p.name, dealerHand: d.name });
    // Payout - sirf jeetne wale ko
    for(const [mobile, t] of teenTables.entries()){
      if(t.roundId === teenRound.roundId && t.choice === winner && t.bet > 0){
        const winAmt = Math.floor(t.bet * 1.9 * 100) / 100;
        const client = await pool.connect();
        try{ await client.query('BEGIN'); await creditWin(mobile, 'teenpatti', winAmt, client); await client.query('COMMIT'); }catch(e){ await client.query('ROLLBACK'); }
        finally{ client.release(); }
      }
      // Agle round ke liye reset
      teenTables.set(mobile, { roundId: teenRound.roundId + 1, cards: null, bet: 0, choice: null, seen: false });
    }
    setTimeout(startTeenRound, 8000);
  }, 30000);
}
startTeenRound();

async function teenDoAction(type, data, socket, mobile){
  try{
    if(teenRound.phase !== 'betting') return socket.emit('error-msg', { message:'Betting band hai - agle round ka wait karo' });
    const amount = cleanBet(data?.amount ?? data?.bet ?? 10, MIN_BET, MAX_BET);
    if(!amount) return socket.emit('error-msg', { message:'Sahi amount daalo' });
    const chk = await checkBlocked(mobile);
    if(chk.blocked) return socket.emit('error-msg', { message:'Account blocked hai' });
    const prev = teenTables.get(mobile);
    if(prev && prev.roundId === teenRound.roundId && prev.bet > 0) return socket.emit('error-msg', { message:'Is round me 1 bet hi lagega' });
    let choice = 'PLAYER';
    if(type === 'CHAAL' || type === 'BLIND') choice = cleanChoice(data?.choice || data?.side || 'PLAYER', ['PLAYER','DEALER']) || 'PLAYER';
    if(type === 'SEEN'){
      const cur = teenTables.get(mobile) || { roundId: teenRound.roundId, bet: 0, choice: null, seen: false };
      cur.seen = true; teenTables.set(mobile, cur);
      return socket.emit('teenpatti:seen-ok', { roundId: teenRound.roundId });
    }
    if(type === 'PACK'){
      teenTables.set(mobile, { roundId: teenRound.roundId, bet: 0, choice: null, seen: false });
      return socket.emit('teenpatti:pack-ok', { roundId: teenRound.roundId });
    }
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      const res = await placeBet(mobile, 'teenpatti', amount, client);
      if(!res.success){ await client.query('ROLLBACK'); return socket.emit('error-msg', { message: res.message }); }
      await client.query('COMMIT');
      teenTables.set(mobile, { roundId: teenRound.roundId, bet: amount, choice, seen: false });
      socket.emit('teenpatti:bet-ok', { choice, amount, type, roundId: teenRound.roundId });
    }catch(e){ await client.query('ROLLBACK'); socket.emit('error-msg', { message:'Bet fail - dobara try karo' }); }
    finally{ client.release(); }
  }catch(e){ socket.emit('error-msg', { message:'Bet fail ho gaya' }); }
}

// ===== AVIATOR STATE - FIXED: Crash secureRandom se =====
let aviatorState = { phase: 'waiting', multiplier: 1.0, crashAt: 2.0, roundId: 0, startedAt: 0, bets: new Map() };
function emitAviatorAll(){
  const payload = {
    phase: aviatorState.phase, status: aviatorState.phase,
    multiplier: aviatorState.multiplier, currentMultiplier: aviatorState.multiplier,
    crashAt: aviatorState.crashAt, crashPoint: aviatorState.crashAt,
    roundId: aviatorState.roundId, round: aviatorState.roundId
  };
  io.emit('aviator:state', payload);
  io.emit('aviator:update', payload);
  io.emit('aviator:tick', payload);
  io.emit('aviator:multiplier', payload);
  io.emit('aviator:round', payload);
  io.emit('aviator:game-state', payload);
}
function startAviator(){
  aviatorState.roundId++;
  aviatorState.phase = 'waiting';
  aviatorState.multiplier = 1.0;
  aviatorState.bets = new Map();
  const r = secureRandom();
  let crash = 1.0;
  if(r < 0.05) crash = 1.0 + secureRandom() * 0.2;
  else crash = Math.max(1.05, 1 / (1 - r * 0.97));
  crash = Math.min(crash, 50);
  aviatorState.crashAt = Math.floor(crash * 100) / 100;
  io.emit('game:started', { game: 'aviator', roundId: aviatorState.roundId });
  io.emit('aviator:round-start', { roundId: aviatorState.roundId, phase: 'waiting', status: 'waiting', multiplier: 1.0 });
  io.emit('aviator:betting', { roundId: aviatorState.roundId, phase: 'waiting' });
  emitAviatorAll();
  setTimeout(() => {
    aviatorState.phase = 'flying';
    aviatorState.startedAt = Date.now();
    io.emit('aviator:round-start', { roundId: aviatorState.roundId, phase: 'flying', status: 'flying', multiplier: 1.0 });
    io.emit('aviator:start', { roundId: aviatorState.roundId, multiplier: 1.0 });
    emitAviatorAll();
  }, 5000);
}
setInterval(() => {
  if(aviatorState.phase !== 'flying') return;
  const elapsed = (Date.now() - aviatorState.startedAt) / 1000;
  const mult = Math.floor((Math.pow(1.08, elapsed)) * 100) / 100;
  aviatorState.multiplier = mult;
  if(mult >= aviatorState.crashAt){
    aviatorState.phase = 'crashed';
    const p = { multiplier: aviatorState.crashAt, crashAt: aviatorState.crashAt, crashPoint: aviatorState.crashAt, roundId: aviatorState.roundId, phase: 'crashed', status: 'crashed' };
    io.emit('game:crashed', { game: 'aviator', roundId: aviatorState.roundId, multiplier: aviatorState.crashAt });
    io.emit('aviator:crash', p);
    io.emit('aviator:crashed', p);
    io.emit('aviator:round-end', p);
    io.emit('aviator:roundEnd', p);
    setTimeout(startAviator, 4000);
  } else {
    emitAviatorAll();
  }
}, 100);

async function handleAviatorBet(data, socket, mobile){
  try{
    if(!socketRateLimit(socket, 5)) return socket.emit('error-msg', { message:'Bahut tez bet laga rahe ho' });
    if(aviatorState.phase !== 'waiting') return socket.emit('error-msg', { message:'Aviator betting band hai' });
    const amount = cleanBet(data?.amount ?? data?.bet, MIN_BET, MAX_BET);
    if(!amount) return socket.emit('error-msg', { message:'Sahi amount daalo' });
    if(aviatorState.bets.has(mobile)) return socket.emit('error-msg', { message:'Is round me 1 bet hi lagega' });
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      const res = await placeBet(mobile, 'aviator', amount, client);
      if(!res.success){ await client.query('ROLLBACK'); return socket.emit('error-msg', { message: res.message }); }
      await client.query('COMMIT');
      aviatorState.bets.set(mobile, { amount, cashedOut: false });
      socket.emit('aviator:bet-ok', { amount, roundId: aviatorState.roundId });
    }catch(e){ await client.query('ROLLBACK'); socket.emit('error-msg', { message:'Bet fail' }); }
    finally{ client.release(); }
  }catch(e){ socket.emit('error-msg', { message:'Bet fail ho gaya' }); }
}
async function handleAviatorCashout(data, socket, mobile){
  try{
    if(aviatorState.phase !== 'flying') return socket.emit('error-msg', { message:'Abhi cashout nahi ho sakta - plane udd nahi raha' });
    const bet = aviatorState.bets.get(mobile);
    if(!bet || bet.cashedOut) return socket.emit('error-msg', { message:'Bet nahi mila / pehle cashout ho chuka' });
    const mult = aviatorState.multiplier; // FIXED: Frontend ka multiplier kabhi nahi lenge
    if(mult >= aviatorState.crashAt) return socket.emit('error-msg', { message:'Crash ho gaya - bahut der kar di' });
    bet.cashedOut = true;
    const winAmt = Math.floor(bet.amount * mult * 100) / 100;
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      await creditWin(mobile, 'aviator', winAmt, client);
      await client.query('COMMIT');
      socket.emit('aviator:cashout-ok', { multiplier: mult, winAmount: winAmt, roundId: aviatorState.roundId });
    }catch(e){ await client.query('ROLLBACK'); bet.cashedOut = false; socket.emit('error-msg', { message:'Cashout fail - dobara try karo' }); }
    finally{ client.release(); }
  }catch(e){ socket.emit('error-msg', { message:'Cashout fail ho gaya' }); }
}
// ================= SECURE V4 - 15 GAMES - PART 5 / 6 - BAAKI 13 GAMES =================

// ===== GENERIC GAME HANDLER - 11 games isi se chalenge =====
// multiplier = jeetne pe kitna guna milega. Win chance = 1/multiplier * 0.92 (8% house edge, fair)
function genericHandler(game, multiplier){
  return async (data, socket, mobile) => {
    try{
      if(!socketRateLimit(socket, 5)) return socket.emit('error-msg', { message:'Bahut tez khel rahe ho' });
      const amount = cleanBet(data?.amount ?? data?.bet, MIN_BET, MAX_BET);
      if(!amount) return socket.emit('error-msg', { message:'Sahi amount daalo' });
      const choice = String(data?.choice ?? data?.side ?? data?.color ?? data?.betOn ?? 'RED').toUpperCase().slice(0, 20);
      const chk = await checkBlocked(mobile);
      if(chk.blocked) return socket.emit('error-msg', { message:'Account blocked hai' });
      // Admin setting se multiplier badal sakta hai - default wahi rahega
      const maxMult = await getSetting(game, 'multiplier', multiplier);
      const winChance = Math.min(0.9, (1 / Number(maxMult)) * 0.92);
      const isWin = secureRandom() < winChance;
      const client = await pool.connect();
      try{
        await client.query('BEGIN');
        const res = await placeBet(mobile, game, amount, client);
        if(!res.success){ await client.query('ROLLBACK'); return socket.emit('error-msg', { message: res.message }); }
        if(isWin){
          const winAmt = Math.floor(amount * Number(maxMult) * 100) / 100;
          await creditWin(mobile, game, winAmt, client);
          await client.query('COMMIT');
          socket.emit(game + ':result', { success:true, win:true, choice, amount, winAmount: winAmt, multiplier: Number(maxMult) });
        } else {
          await client.query('COMMIT');
          // Haar ka bet pehle hi placeBet me kat chuka hai, win 0 hai
          await pool.query(`UPDATE bets SET win_amount=0, result='lose' WHERE user_mobile=$1 AND game=$2 AND result='pending' ORDER BY id DESC LIMIT 1`, [mobile, game]);
          socket.emit(game + ':result', { success:true, win:false, choice, amount, winAmount: 0, multiplier: 0 });
        }
      }catch(e){ await client.query('ROLLBACK'); socket.emit('error-msg', { message:'Game fail - dobara try karo' }); }
      finally{ client.release(); }
    }catch(e){ socket.emit('error-msg', { message:'Game fail ho gaya' }); }
  };
}

// ===== DRAGON TIGER - FIXED: Dono card server se =====
async function handleDragonTigerBet(data, socket, mobile){
  try{
    if(!socketRateLimit(socket, 5)) return socket.emit('error-msg', { message:'Bahut tez khel rahe ho' });
    const amount = cleanBet(data?.amount ?? data?.bet, MIN_BET, MAX_BET);
    const choice = cleanChoice(data?.choice || data?.side, ['DRAGON','TIGER','TIE']);
    if(!amount || !choice) return socket.emit('error-msg', { message:'Dragon / Tiger / Tie chuno + sahi amount daalo' });
    const chk = await checkBlocked(mobile);
    if(chk.blocked) return socket.emit('error-msg', { message:'Account blocked hai' });
    const dragon = secureRandomInt(2, 14);
    const tiger = secureRandomInt(2, 14);
    const winner = dragon > tiger ? 'DRAGON' : (tiger > dragon ? 'TIGER' : 'TIE');
    const isWin = (choice === winner);
    const mult = winner === 'TIE' ? 8 : 1.9;
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      const res = await placeBet(mobile, 'dragontiger', amount, client);
      if(!res.success){ await client.query('ROLLBACK'); return socket.emit('error-msg', { message: res.message }); }
      if(isWin){
        const winAmt = Math.floor(amount * mult * 100) / 100;
        await creditWin(mobile, 'dragontiger', winAmt, client);
        await client.query('COMMIT');
        socket.emit('dragontiger:result', { success:true, win:true, choice, winner, dragon, tiger, winAmount: winAmt });
      } else {
        await client.query('COMMIT');
        await pool.query(`UPDATE bets SET win_amount=0, result='lose' WHERE user_mobile=$1 AND game='dragontiger' AND result='pending' ORDER BY id DESC LIMIT 1`, [mobile]);
        socket.emit('dragontiger:result', { success:true, win:false, choice, winner, dragon, tiger, winAmount: 0 });
      }
    }catch(e){ await client.query('ROLLBACK'); socket.emit('error-msg', { message:'Game fail' }); }
    finally{ client.release(); }
  }catch(e){ socket.emit('error-msg', { message:'Game fail ho gaya' }); }
}

// ===== MINES - FIXED: Mine positions server se, frontend se nahi =====
async function handleMinesPlay(data, socket, mobile){
  try{
    if(!socketRateLimit(socket, 5)) return socket.emit('error-msg', { message:'Bahut tez khel rahe ho' });
    const amount = cleanBet(data?.amount ?? data?.bet, MIN_BET, MAX_BET);
    const minesCount = Math.min(10, Math.max(1, Number(data?.mines) || 3));
    const picks = Array.isArray(data?.picks) ? data.picks.map(p => Number(p)).filter(n => Number.isInteger(n) && n >= 0 && n < 25) : [];
    if(!amount || picks.length === 0) return socket.emit('error-msg', { message:'Sahi amount + kam se kam 1 box chuno' });
    if(new Set(picks).size !== picks.length) return socket.emit('error-msg', { message:'Same box 2 baar nahi chun sakte' });
    const chk = await checkBlocked(mobile);
    if(chk.blocked) return socket.emit('error-msg', { message:'Account blocked hai' });
    // Server mine banayega - 25 me se minesCount
    const all = Array.from({ length: 25 }, (_, i) => i);
    for(let i = all.length - 1; i > 0; i--){ const j = secureRandomInt(0, i); const t = all[i]; all[i] = all[j]; all[j] = t; }
    const mineSet = new Set(all.slice(0, minesCount));
    const hitMine = picks.some(p => mineSet.has(p));
    // Har safe pick pe multiplier badhta hai
    const safePicks = picks.filter(p => !mineSet.has(p)).length;
    const mult = hitMine ? 0 : (1 + safePicks * 0.4);
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      const res = await placeBet(mobile, 'mines', amount, client);
      if(!res.success){ await client.query('ROLLBACK'); return socket.emit('error-msg', { message: res.message }); }
      if(!hitMine){
        const winAmt = Math.floor(amount * mult * 100) / 100;
        await creditWin(mobile, 'mines', winAmt, client);
        await client.query('COMMIT');
        socket.emit('mines:result', { success:true, win:true, picks, mines: Array.from(mineSet), winAmount: winAmt, multiplier: mult });
      } else {
        await client.query('COMMIT');
        await pool.query(`UPDATE bets SET win_amount=0, result='lose' WHERE user_mobile=$1 AND game='mines' AND result='pending' ORDER BY id DESC LIMIT 1`, [mobile]);
        socket.emit('mines:result', { success:true, win:false, picks, mines: Array.from(mineSet), winAmount: 0 });
      }
    }catch(e){ await client.query('ROLLBACK'); socket.emit('error-msg', { message:'Game fail' }); }
    finally{ client.release(); }
  }catch(e){ socket.emit('error-msg', { message:'Game fail ho gaya' }); }
}

// ===== 13 GAMES KE HANDLERS - Ek jagah, duplicate nahi =====
const gameHandlers = {
  'slots': genericHandler('slots', 10),
  'gems': genericHandler('gems', 8),
  'roulette': genericHandler('roulette', 5),
  'andarbahar': genericHandler('andarbahar', 2),
  'baccarat': genericHandler('baccarat', 2),
  'poker': genericHandler('poker', 5),
  'colour': genericHandler('colour', 2),
  'chicken': genericHandler('chicken', 3),
  'fortune': genericHandler('fortune', 5),
  'plinko': genericHandler('plinko', 10),
  'spin': genericHandler('spin', 10),
  'dragontiger': handleDragonTigerBet,
  'mines': handleMinesPlay
};
// ================= SECURE V4 - 15 GAMES - PART 6 / 6 - SOCKET + SERVER START =================

// ===== SOCKET - SIRF 1 BAAR - DUPLICATE NAHI =====
io.use((socket, next) => {
  try{
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if(!token) return next(new Error('Login karo pehle'));
    const d = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = d;
    next();
  }catch(e){ next(new Error('Token galat / expire hai')); }
});

io.on('connection', (socket) => {
  const mobile = socket.user.mobile;
  console.log('User connected:', mobile);

  // ===== AVIATOR =====
  socket.on('aviator:join', () => {
    socket.emit('aviator:state', { phase: aviatorState.phase, multiplier: aviatorState.multiplier, roundId: aviatorState.roundId });
  });
  socket.on('aviator:bet', (data) => handleAviatorBet(data, socket, mobile));
  socket.on('aviator:place-bet', (data) => handleAviatorBet(data, socket, mobile));
  socket.on('aviator:placeBet', (data) => handleAviatorBet(data, socket, mobile));
  socket.on('aviator:cashout', (data) => handleAviatorCashout(data, socket, mobile));

  // ===== DRAGON TIGER + MINES =====
  socket.on('dragontiger:bet', (data) => handleDragonTigerBet(data, socket, mobile));
  socket.on('mines:play', (data) => handleMinesPlay(data, socket, mobile));

  // ===== BAAKI 11 GAMES =====
  socket.on('slots:spin', (data) => gameHandlers['slots'](data, socket, mobile));
  socket.on('gemstemple:spin', (data) => gameHandlers['gems'](data, socket, mobile));
  socket.on('gems:spin', (data) => gameHandlers['gems'](data, socket, mobile));
  socket.on('roulette:bet', (data) => gameHandlers['roulette'](data, socket, mobile));
  socket.on('andarbahar:bet', (data) => gameHandlers['andarbahar'](data, socket, mobile));
  socket.on('baccarat:bet', (data) => gameHandlers['baccarat'](data, socket, mobile));
  socket.on('poker:bet', (data) => gameHandlers['poker'](data, socket, mobile));
  socket.on('colour:bet', (data) => gameHandlers['colour'](data, socket, mobile));
  socket.on('colour:play', (data) => gameHandlers['colour'](data, socket, mobile));
  socket.on('chicken:play', (data) => gameHandlers['chicken'](data, socket, mobile));
  socket.on('fortune:spin', (data) => gameHandlers['fortune'](data, socket, mobile));
  socket.on('plinko:drop', (data) => gameHandlers['plinko'](data, socket, mobile));
  socket.on('spin:spin', (data) => gameHandlers['spin'](data, socket, mobile));

  // ===== TEENPATTI =====
  socket.on('teenpatti:join', async () => {
    socket.emit('teenpatti:state', { roundId: teenRound.roundId, phase: teenRound.phase, endsAt: teenRound.endsAt });
  });
  socket.on('teenpatti:bet', (data) => teenDoAction(data?.type || 'CHAAL', data, socket, mobile));
  socket.on('teenpatti:blind', (data) => teenDoAction('BLIND', data, socket, mobile));
  socket.on('teenpatti:chaal', (data) => teenDoAction('CHAAL', data, socket, mobile));
  socket.on('teenpatti:pack', (data) => teenDoAction('PACK', data, socket, mobile));
  socket.on('teenpatti:see', () => teenDoAction('SEEN', {}, socket, mobile));
  socket.on('teenpatti:seen', () => teenDoAction('SEEN', {}, socket, mobile));
  socket.on('teenpatti:show', () => socket.emit('teenpatti:show', { result: 'Show result pe aayega' }));
  socket.on('teenpatti:sideshow', () => socket.emit('teenpatti:sideshow', { result: 'Side Show agle round me full aayega' }));
  socket.on('teenpatti:side-show', () => socket.emit('teenpatti:sideshow', { result: 'Side Show agle round me full aayega' }));
  socket.on('teenpatti:leave', () => { teenTables.delete(mobile); });
  socket.on('teenpatti:get-state', () => {
    socket.emit('teenpatti:state', { roundId: teenRound.roundId, phase: teenRound.phase, endsAt: teenRound.endsAt });
  });

  socket.on('disconnect', () => { console.log('User disconnected:', mobile); });
});

// ===== HEALTH + ROOT =====
app.get('/api/health', (req, res) => { res.json({ success: true, msg: 'Backend ON hai - Secure V4 Full 15 Games', time: new Date().toISOString() }); });
app.get('/', (req, res) => { res.send('FULL CASINO Running - SECURE V4 - 15 GAMES'); });

// ===== SERVER START =====
startAviator();
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on ${PORT} - SECURE V4 - 15 GAMES - NO DUPLICATE`);
});
