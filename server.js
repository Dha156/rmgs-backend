// ================= FULL CASINO - 11 GAMES - PART 1 - UPDATED =================
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
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());

const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: 'Bahut zyada try kiya, 15 min baad try karo' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.use('/api/', apiLimiter);

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.FRONTEND_URL || 'http://localhost:3000' } });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ===== TERA UPI + QR SETTING - NEW ADDED =====
const MY_UPI_ID = "ombk.aahi70694v2ydnslbfb@mbk";
const MY_UPI_NAME = "Aahi";
const MY_MIN_DEPOSIT = 150;
const MY_MIN_WITHDRAW = 300;

// Frontend ko UPI batane ke liye
app.get('/api/payment-info', (req, res) => {
  res.json({
    success: true,
    upi_id: MY_UPI_ID,
    upi_name: MY_UPI_NAME,
    min_deposit: MY_MIN_DEPOSIT,
    min_withdraw: MY_MIN_WITHDRAW,
    message: `Min Deposit ₹${MY_MIN_DEPOSIT} | Min Withdraw ₹${MY_MIN_WITHDRAW}`
  });
});

// ===== DYNAMIC QR - HAR PAYMENT PAR ALAG QR - NEW ADDED =====
app.post('/api/deposit/create-qr', checkAuth, async (req, res) => {
  const depositAmount = parseFloat(req.body.amount);
  if(!depositAmount || depositAmount < MY_MIN_DEPOSIT){
    return res.status(400).json({ success: false, message: `Min Deposit ₹${MY_MIN_DEPOSIT} hai bhai!` });
  }
  if(depositAmount > 50000){
    return res.status(400).json({ success: false, message: 'Max ₹50000 ek baar me!' });
  }
  const upiLink = `upi://pay?pa=${MY_UPI_ID}&pn=${encodeURIComponent(MY_UPI_NAME)}&am=${depositAmount}&cu=INR&tn=${encodeURIComponent('Deposit ' + depositAmount + ' - ' + req.user.mobile)}`;
  const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(upiLink)}`;
  res.json({
    success: true,
    amount: depositAmount,
    upi_id: MY_UPI_ID,
    upi_name: MY_UPI_NAME,
    upiLink: upiLink,
    qrImage: qrImageUrl,
    message: `₹${depositAmount} ka QR ban gaya! Scan karke pay karo!`
  });
});

function safeHttpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e){ reject(e); } });
    }).on('error', reject);
  });
}

function makeToken(mobile) {
  return jwt.sign({ mobile }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function checkAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Login karo pehle' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch(e){
    return res.status(401).json({ success: false, message: 'Token galat / expire ho gaya' });
  }
}

function checkAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Admin login chahiye' });
  try {
    const d = jwt.verify(token, process.env.JWT_SECRET);
    if (d.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin nahi ho' });
    req.admin = d;
    next();
  } catch(e){
    return res.status(401).json({ success: false, message: 'Admin token galat hai' });
  }
}

async function audit(actor, action, details, ip) {
  try {
    await pool.query('INSERT INTO audit_logs (actor_id, action_type, details, ip_address) VALUES ($1,$2,$3,$4)', [actor, action, details, ip]);
  } catch(e){}
}

async function initDatabase() {
  await pool.query(`CREATE TABLE IF NOT EXISTS wallets (id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE NOT NULL, balance NUMERIC(12,2) DEFAULT 0 CHECK(balance>=0), vip_level INT DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, type VARCHAR(50) NOT NULL, status VARCHAR(50) NOT NULL, utr VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS deposits (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, utr VARCHAR(100) UNIQUE NOT NULL, status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS withdraws (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, method VARCHAR(20) DEFAULT 'UPI', upi_id VARCHAR(255), account_no VARCHAR(50), ifsc VARCHAR(20), status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS admin_users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT 'admin')`);
  await pool.query(`CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, actor_id VARCHAR(255) NOT NULL, action_type VARCHAR(100) NOT NULL, details TEXT, ip_address VARCHAR(50), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL)`);
  await pool.query(`INSERT INTO settings (key, value) VALUES ('global_rtp','96'), ('min_bet','10'), ('max_bet','5000'), ('teenpatti_rake','5'), ('teenpatti_boot','5'), ('aviator_house_edge','4'), ('aviator_min_crash','1.10'), ('aviator_max_crash','100'), ('spin_rtp','96'), ('dragontiger_rtp','96'), ('roulette_rtp','96'), ('mines_rtp','96'), ('andarbahar_rtp','96'), ('plinko_rtp','96'), ('baccarat_rtp','96'), ('poker_rtp','96'), ('slots_rtp','96') ON CONFLICT (key) DO NOTHING`);
  console.log('DB Ready - FULL CASINO 11 GAMES!');
}

async function getSetting(key, def) {
  const r = await pool.query('SELECT value FROM settings WHERE key=$1', [key]);
  return r.rows.length ? parseFloat(r.rows[0].value) : def;
}

async function placeBet(userId, betAmount) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const w = await c.query('SELECT balance FROM wallets WHERE user_id=$1 FOR UPDATE', [userId]);
    if (!w.rows.length) throw new Error('Wallet not found');
    if (parseFloat(w.rows[0].balance) < betAmount) throw new Error('Insufficient balance');
    await c.query('UPDATE wallets SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2', [betAmount, userId]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'BET\',\'SUCCESS\')', [userId, betAmount]);
    await c.query('COMMIT');
    return { success: true, newBalance: parseFloat(w.rows[0].balance) - betAmount };
  } catch(e){
    await c.query('ROLLBACK');
    return { success: false, error: e.message };
  } finally {
    c.release();
  }
}

async function creditWin(userId, winnings) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query('UPDATE wallets SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 RETURNING balance', [winnings, userId]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'WIN\',\'SUCCESS\')', [userId, winnings]);
    await c.query('COMMIT');
    return parseFloat(r.rows[0].balance);
  } catch(e){
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }
}

function generateServerSeed(){ return crypto.randomBytes(32).toString('hex'); }
function hashSeed(s){ return crypto.createHash('sha256').update(s).digest('hex'); }

function fairOutcome(serverSeed, clientSeed, nonce){
  const msg = `${serverSeed}:${clientSeed}:${nonce}`;
  const h = crypto.createHmac('sha256', serverSeed).update(msg).digest('hex');
  const val = parseInt(h.slice(0,8), 16) % 10000;
  return { val, hash: h };
}

function fairRandom(max){ return crypto.randomInt(0, max); }

function shuffleDeck(){
  let deck=[];
  const suits=['♠','♥','♦','♣'];
  const ranks=['2','3','4','5','6','7','8','9','10','J','Q','K','A'];
  for(let s of suits) for(let r of ranks) deck.push(s+'-'+r);
  for(let i=deck.length-1;i>0;i--){
    const j=crypto.randomInt(0,i+1);
    [deck[i],deck[j]]=[deck[j],deck[i]];
  }
  return deck;
}

function getRankValue(card){
  const r=card.split('-')[1];
  const map={'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8,'9':9,'10':10,'J':11,'Q':12,'K':13,'A':14};
  return map[r];
}

function evaluateHand(cards){
  const ranks = cards.map(getRankValue).sort((a,b)=>a-b);
  const suits = cards.map(c=>c.split('-')[0]);
  const isFlush = suits[0]===suits[1] && suits[1]===suits[2];
  const isSeq = (ranks[2]-ranks[1]===1 && ranks[1]-ranks[0]===1) || (ranks[0]===2 && ranks[1]===3 && ranks[2]===14);
  const isTrail = ranks[0]===ranks[1] && ranks[1]===ranks[2];
  const isPair = ranks[0]===ranks[1] || ranks[1]===ranks[2] || ranks[0]===ranks[2];
  if(isTrail) return { score: 600 + ranks[0], name: 'Trail' };
  if(isFlush && isSeq) return { score: 500 + ranks[2], name: 'Pure Sequence' };
  if(isSeq) return { score: 400 + ranks[2], name: 'Sequence' };
  if(isFlush) return { score: 300 + ranks[2], name: 'Colour' };
  if(isPair){
    let pairVal = ranks[0]===ranks[1]?ranks[0]:ranks[2];
    return { score: 200 + pairVal, name: 'Pair' };
  }
  return { score: 100 + ranks[2], name: 'High Card' };
}

function botDecision(cards){
  const ev = evaluateHand(cards);
  if(ev.score >= 500) return Math.random() < 0.85 ? 'CHAAL' : 'PACK';
  if(ev.score >= 400) return Math.random() < 0.60 ? 'CHAAL' : 'PACK';
  if(ev.score >= 200) return Math.random() < 0.50 ? 'CHAAL' : 'PACK';
  return Math.random() < 0.15 ? 'CHAAL' : 'PACK';
}

let teenTables = new Map();
let gameState='WAITING', currentMultiplier=1.00, crashPoint=1.50, roundTimer=5, roundId=1;
let aviatorBets = new Map();

async function generateFunCrash(){
  const edge = await getSetting('aviator_house_edge', 4) / 100;
  const minC = await getSetting('aviator_min_crash', 1.10);
  const maxC = await getSetting('aviator_max_crash', 100);
  const r = crypto.randomBytes(4).readUInt32BE(0) / 4294967295;
  let crash = (1 - edge) / (1 - r);
  if(crash < minC) crash = minC;
  if(crash > maxC) crash = maxC;
  return parseFloat(crash.toFixed(2));
}

function startAviator(){
  setInterval(async ()=>{
    if(gameState==='WAITING'){
      roundTimer--;
      io.emit('game:timer',{timer:roundTimer, roundId});
      if(roundTimer<=0){
        gameState='RUNNING';
        currentMultiplier=1.00;
        crashPoint = await generateFunCrash();
        aviatorBets.clear();
        io.emit('game:started',{ roundId });
      }
    } else if(gameState==='RUNNING'){
      currentMultiplier = parseFloat((currentMultiplier + currentMultiplier*0.08 + 0.02).toFixed(2));
      io.emit('game:tick',{ multiplier: currentMultiplier, roundId });
      if(currentMultiplier>=crashPoint){
        gameState='CRASHED';
        io.emit('game:crashed',{ multiplier: crashPoint, roundId });
        roundTimer=5;
        roundId++;
        setTimeout(()=>{ gameState='WAITING'; },3000);
      }
    }
  },500);
}

const otpStore = new Map();

app.post('/api/auth/send-otp', otpLimiter, async (req,res)=>{
  const { mobile } = req.body;
  if(!mobile || !/^[6-9]\d{9}$/.test(mobile)) return res.status(400).json({success:false,message:'Sahi 10 digit mobile daalo'});
  const apiKey = process.env.TWO_FACTOR_API_KEY;
  if(!apiKey) return res.status(500).json({success:false,message:'OTP service band hai'});
  try{
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/${mobile}/AUTOGEN/OTP1`);
    if(data.Status==='Success'){
      otpStore.set(mobile,{ sessionId:data.Details, expiresAt: Date.now()+5*60*1000 });
      res.json({success:true,message:'OTP bhej diya'});
    } else {
      res.status(400).json({success:false,message:'OTP nahi bheja gaya'});
    }
  }catch(e){
    console.error(e);
    res.status(500).json({success:false,message:'OTP fail'});
  }
});

app.post('/api/auth/verify-otp', async (req,res)=>{
  const { mobile, otp } = req.body;
  const rec = otpStore.get(mobile);
  if(!rec || Date.now()>rec.expiresAt) return res.status(400).json({success:false,message:'OTP expire ho gaya, dobara bhejo'});
  const apiKey = process.env.TWO_FACTOR_API_KEY;
  try{
    const data = await safeHttpsGet(`https://2factor.in/API/V1/${apiKey}/SMS/VERIFY/${rec.sessionId}/${otp}`);
    if(data.Status!=='Success') return res.status(400).json({success:false,message:'Galat OTP'});
    otpStore.delete(mobile);
    let w = await pool.query('SELECT * FROM wallets WHERE user_id=$1',[mobile]);
    if(!w.rows.length) w = await pool.query('INSERT INTO wallets (user_id,balance,vip_level) VALUES ($1,0,0) RETURNING *',[mobile]);
    const token = makeToken(mobile);
    res.json({success:true, token, user:{ mobile, balance: w.rows[0].balance, vip_level: w.rows[0].vip_level }});
  }catch(e){
    console.error(e);
    res.status(500).json({success:false,message:'Login fail'});
  }
});

app.get('/api/wallet/balance', checkAuth, async (req,res)=>{
  const r = await pool.query('SELECT balance, vip_level FROM wallets WHERE user_id=$1',[req.user.mobile]);
  if(!r.rows.length) return res.status(404).json({success:false,message:'Wallet nahi mila'});
  res.json({success:true, balance: r.rows[0].balance, vip_level: r.rows[0].vip_level});
});

app.get('/api/wallet/history', checkAuth, async (req,res)=>{
  const r = await pool.query('SELECT amount,type,status,created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.user.mobile]);
  res.json({success:true, history: r.rows});
});

// ===== DEPOSIT - MIN 150 UPDATED =====
app.post('/api/wallet/deposit-request', checkAuth, async (req,res)=>{
  const { amount, utr } = req.body;
  if(!amount || amount < 150) return res.status(400).json({success:false,message:'Min ₹150 Deposit hai bhai!'});
  if(!utr || utr.length<6) return res.status(400).json({success:false,message:'Sahi UTR daalo'});
  try{
    await pool.query('INSERT INTO deposits (user_id, amount, utr) VALUES ($1,$2,$3)',[req.user.mobile, amount, utr]);
    await audit(req.user.mobile,'DEPOSIT_REQUEST',`Amt ${amount} UTR ${utr}`, req.ip);
    res.json({success:true,message:'Deposit request bhej diya, Admin approve karega'});
  }catch(e){
    if(e.code==='23505') return res.status(400).json({success:false,message:'Ye UTR pehle use ho chuka hai'});
    res.status(500).json({success:false,message:'Deposit fail'});
  }
});

app.post('/api/admin/login', async (req,res)=>{
  const { username, password } = req.body;
  const r = await pool.query('SELECT * FROM admin_users WHERE username=$1',[username]);
  if(!r.rows.length) return res.status(401).json({success:false,message:'Galat login'});
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if(!ok) return res.status(401).json({success:false,message:'Galat login'});
  const token = jwt.sign({ username, role:'admin' }, process.env.JWT_SECRET, { expiresIn:'12h' });
  res.json({success:true, token});
});

app.post('/api/admin/approve-deposit', checkAdmin, async (req,res)=>{
  const { depositId, approve } = req.body;
  const c = await pool.connect();
  try{
    await c.query('BEGIN');
    const d = await c.query('SELECT * FROM deposits WHERE id=$1 FOR UPDATE',[depositId]);
    if(!d.rows.length) throw new Error('Deposit nahi mila');
    if(d.rows[0].status!=='PENDING') throw new Error('Pehle se handle ho chuka hai');
    if(approve){
      await c.query('UPDATE deposits SET status=\'APPROVED\' WHERE id=$1',[depositId]);
      const up = await c.query('UPDATE wallets SET balance=balance+$1, vip_level=GREATEST(vip_level,1), updated_at=NOW() WHERE user_id=$2 RETURNING balance',[d.rows[0].amount, d.rows[0].user_id]);
      await c.query('INSERT INTO transactions (user_id, amount, type, status, utr) VALUES ($1,$2,\'DEPOSIT\',\'SUCCESS\',$3)',[d.rows[0].user_id, d.rows[0].amount, d.rows[0].utr]);
      await c.query('COMMIT');
      await audit(req.admin.username,'APPROVE_DEPOSIT',`Deposit ${depositId} Amt ${d.rows[0].amount} User ${d.rows[0].user_id}`, req.ip);
      res.json({success:true,message:'Deposit approve ho gaya, VIP1 unlock!', balance: up.rows[0].balance});
    } else {
      await c.query('UPDATE deposits SET status=\'REJECTED\' WHERE id=$1',[depositId]);
      await c.query('COMMIT');
      res.json({success:true,message:'Deposit reject kar diya'});
    }
  }catch(e){
    await c.query('ROLLBACK');
    res.status(400).json({success:false,message:e.message});
  } finally {
    c.release();
  }
});

app.get('/api/admin/pending-deposits', checkAdmin, async (req,res)=>{
  const r = await pool.query('SELECT * FROM deposits WHERE status=\'PENDING\' ORDER BY created_at ASC');
  res.json({success:true, deposits: r.rows});
});

app.get('/api/admin/pending-withdraws', checkAdmin, async (req,res)=>{
  const r = await pool.query('SELECT * FROM withdraws WHERE status=\'PENDING\' ORDER BY created_at ASC');
  res.json({success:true, withdraws: r.rows});
});

app.get('/api/admin/settings', checkAdmin, async (req,res)=>{
  const r = await pool.query('SELECT * FROM settings');
  res.json({success:true, settings: Object.fromEntries(r.rows.map(x=>[x.key,x.value]))});
});

app.post('/api/admin/teenpatti-settings', checkAdmin, async (req,res)=>{
  const { teenpatti_rake, teenpatti_boot } = req.body;
  if(teenpatti_rake!==undefined){
    const v = parseFloat(teenpatti_rake);
    if(v<3 || v>8) return res.status(400).json({success:false,message:'Rake 3% se 8% ke beech rakho'});
    await pool.query(`INSERT INTO settings (key,value) VALUES ('teenpatti_rake',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(v)]);
  }
  if(teenpatti_boot!==undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('teenpatti_boot',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(teenpatti_boot)]);
  res.json({success:true,message:'Teen Patti Settings Save Ho Gayi!'});
});

app.post('/api/admin/aviator-settings', checkAdmin, async (req,res)=>{
  const { aviator_house_edge, aviator_min_crash, aviator_max_crash } = req.body;
  if(aviator_house_edge!==undefined){
    const v = parseFloat(aviator_house_edge);
    if(v<2 || v>10) return res.status(400).json({success:false,message:'Aviator House Edge 2% se 10% ke beech rakho'});
    await pool.query(`INSERT INTO settings (key,value) VALUES ('aviator_house_edge',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(v)]);
  }
  if(aviator_min_crash!==undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('aviator_min_crash',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(aviator_min_crash)]);
  if(aviator_max_crash!==undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('aviator_max_crash',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(aviator_max_crash)]);
  res.json({success:true,message:'Aviator Settings Save Ho Gayi!'});
});

app.post('/api/admin/spin-settings', checkAdmin, async (req,res)=>{
  const { spin_rtp, min_bet, max_bet } = req.body;
  if(spin_rtp!==undefined){
    const v = parseFloat(spin_rtp);
    if(v<80 || v>98) return res.status(400).json({success:false,message:'Spin RTP 80 se 98 ke beech rakho'});
    await pool.query(`INSERT INTO settings (key,value) VALUES ('spin_rtp',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(v)]);
  }
  if(min_bet!==undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('min_bet',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(min_bet)]);
  if(max_bet!==undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ('max_bet',$1) ON CONFLICT (key) DO UPDATE SET value=$1`,[String(max_bet)]);
  res.json({success:true,message:'Spin Settings Save Ho Gayi!'});
});

app.post('/api/admin/casino-settings', checkAdmin, async (req,res)=>{
  const { dragontiger_rtp, roulette_rtp, mines_rtp, andarbahar_rtp, plinko_rtp, baccarat_rtp, poker_rtp, slots_rtp } = req.body;
  const map = { dragontiger_rtp, roulette_rtp, mines_rtp, andarbahar_rtp, plinko_rtp, baccarat_rtp, poker_rtp, slots_rtp };
  for(let k in map){
    if(map[k]!==undefined) await pool.query(`INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2`,[k, String(map[k])]);
  }
  res.json({success:true,message:'Casino Games Save Ho Gaye!'});
});

// ===== WITHDRAW - MIN 300 UPDATED =====
app.post('/api/wallet/withdraw', checkAuth, async (req,res)=>{
  const { amount, upi_id, account_no, ifsc } = req.body;
  const userId = req.user.mobile;
  if(!amount || amount < 300) return res.status(400).json({success:false,message:'Min ₹300 Withdraw hai bhai!'});
  const c = await pool.connect();
  try{
    await c.query('BEGIN');
    const w = await c.query('SELECT balance, vip_level FROM wallets WHERE user_id=$1 FOR UPDATE',[userId]);
    if(!w.rows.length) throw new Error('Wallet nahi mila');
    if((w.rows[0].vip_level||0)<1) throw new Error('Pehle VIP1 Deposit karo fir Withdraw hoga!');
    if(parseFloat(w.rows[0].balance)<parseFloat(amount)) throw new Error('Balance kam hai');
    await c.query('UPDATE wallets SET balance=balance-$1, updated_at=NOW() WHERE user_id=$2',[amount,userId]);
    await c.query('INSERT INTO withdraws (user_id, amount, upi_id, account_no, ifsc) VALUES ($1,$2,$3,$4,$5)',[userId,amount,upi_id||null,account_no||null,ifsc||null]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'WITHDRAW\',\'PENDING\')',[userId,amount]);
    await c.query('COMMIT');
    await audit(userId,'WITHDRAW_REQUEST',`Amt ${amount}`, req.ip);
    res.json({success:true,message:'Withdraw request bhej diya'});
  }catch(e){
    await c.query('ROLLBACK');
    res.status(400).json({success:false,message:e.message});
  } finally {
    c.release();
  }
});
// ================= PART 2 - SOCKET + 11 GAMES =================

io.use((socket, next)=>{
  const token = socket.handshake.auth?.token;
  if(!token) return next(new Error('Token chahiye'));
  try{
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch(e){
    next(new Error('Token galat hai'));
  }
});

io.on('connection',(socket)=>{
  const userId = socket.user.mobile;
  let serverSeed = generateServerSeed();
  let seedHash = hashSeed(serverSeed);
  let nonce = 1;

  socket.emit('provably-fair:init',{ serverSeedHash: seedHash });
  socket.emit('game:state',{ gameState, currentMultiplier, roundTimer, roundId });

  // ===== 1. SPIN =====
  socket.on('game:spin', async (data)=>{
    const betAmount = parseFloat(data.betAmount);
    const clientSeed = String(data.clientSeed || 'default');
    const minBet = await getSetting('min_bet', 10);
    const maxBet = await getSetting('max_bet', 5000);
    const rtp = await getSetting('spin_rtp', 96);
    if(!betAmount || betAmount<minBet || betAmount>maxBet) return socket.emit('game:error',{message:`Bet ${minBet} se ${maxBet} ke beech rakho`});
    const tx = await placeBet(userId, betAmount);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    const { val } = fairOutcome(serverSeed, clientSeed, nonce);
    const winChance = Math.floor((rtp / 2) * 100);
    const isWin = val < winChance;
    const winnings = isWin ? betAmount * 2 : 0;
    let finalBalance = tx.newBalance;
    if(isWin) finalBalance = await creditWin(userId, winnings);
    socket.emit('game:result',{ outcome: val, isWin, winnings, newBalance: finalBalance, nonce, serverSeedHash: seedHash, revealedServerSeed: serverSeed });
    nonce++;
    if(nonce % 100 === 0){
      serverSeed = generateServerSeed();
      seedHash = hashSeed(serverSeed);
      nonce = 1;
      socket.emit('provably-fair:init',{ serverSeedHash: seedHash });
    }
  });

  // ===== 2. AVIATOR =====
  socket.on('aviator:bet', async (data)=>{
    if(gameState!=='WAITING') return socket.emit('game:error',{message:'Betting band ho gayi, agle round me try karo'});
    const bet = parseFloat(data.betAmount);
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    aviatorBets.set(socket.id,{ userId, bet, cashedOut:false });
    socket.emit('aviator:bet-placed',{ bet, newBalance: tx.newBalance });
  });

  socket.on('aviator:cashout', async ()=>{
    const b = aviatorBets.get(socket.id);
    if(!b || b.cashedOut) return socket.emit('game:error',{message:'Bet nahi hai'});
    if(gameState!=='RUNNING') return socket.emit('game:error',{message:'Game abhi chal nahi rahi'});
    b.cashedOut = true;
    const win = parseFloat((b.bet * currentMultiplier).toFixed(2));
    const bal = await creditWin(userId, win);
    socket.emit('aviator:cashed',{ win, multiplier: currentMultiplier, newBalance: bal });
  });

  // ===== 3. TEEN PATTI =====
  socket.on('teenpatti:join', async (data)=>{
    const tableId = data.tableId || 'table1';
    const boot = await getSetting('teenpatti_boot', 5);
    const tx = await placeBet(userId, boot);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    if(!teenTables.has(tableId)) teenTables.set(tableId, { pot: 0, players: [], deck: [] });
    let table = teenTables.get(tableId);
    if(table.players.find(p=>p.userId===userId)) return socket.emit('game:error',{message:'Pehle se table me ho'});
    table.pot += boot;
    let deck = table.deck.length ? table.deck : shuffleDeck();
    let myCards = deck.splice(0,3);
    table.deck = deck;
    table.players.push({ socketId: socket.id, userId, name: 'You', cards: myCards, isBot: false, status: 'ACTIVE' });
    if(table.players.filter(p=>!p.isBot).length === 1){
      for(let botName of ['Vikram','Rahul']){
        let botCards = deck.splice(0,3);
        table.players.push({ socketId: 'BOT_'+botName, userId: 'BOT_'+botName, name: botName, cards: botCards, isBot: true, status: 'ACTIVE' });
        table.pot += boot;
      }
      table.deck = deck;
    }
    socket.join(tableId);
    socket.emit('teenpatti:cards', { myCards, pot: table.pot, boot, players: table.players.map(p=>({ name: p.name, userId: p.userId, isBot: p.isBot, status: p.status })) });
    io.to(tableId).emit('teenpatti:pot-update', { pot: table.pot });
  });

  socket.on('teenpatti:chaal', async (data)=>{
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId);
    if(!table) return;
    const boot = await getSetting('teenpatti_boot', 5);
    const chaalAmt = parseFloat(data.amount) || boot * 2;
    const tx = await placeBet(userId, chaalAmt);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    table.pot += chaalAmt;
    io.to(tableId).emit('teenpatti:pot-update', { pot: table.pot, lastAction: { userId, action: 'CHAAL', amount: chaalAmt } });
    for(let p of table.players.filter(x=>x.isBot && x.status==='ACTIVE')){
      const dec = botDecision(p.cards);
      if(dec === 'PACK'){
        p.status = 'PACKED';
        io.to(tableId).emit('teenpatti:bot-action', { bot: p.name, action: 'PACK' });
      } else {
        table.pot += chaalAmt;
        io.to(tableId).emit('teenpatti:bot-action', { bot: p.name, action: 'CHAAL', amount: chaalAmt });
      }
    }
    io.to(tableId).emit('teenpatti:pot-update', { pot: table.pot });
  });

  socket.on('teenpatti:pack', async (data)=>{
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId);
    if(!table) return;
    let me = table.players.find(p=>p.userId===userId);
    if(me) me.status='PACKED';
    io.to(tableId).emit('teenpatti:player-packed', { userId });
  });

  socket.on('teenpatti:show', async (data)=>{
    const tableId = data.tableId || 'table1';
    let table = teenTables.get(tableId);
    if(!table) return;
    const active = table.players.filter(p=>p.status==='ACTIVE');
    let best = null, bestScore = -1;
    for(let p of active){
      const ev = evaluateHand(p.cards);
      if(ev.score > bestScore){ bestScore = ev.score; best = p; }
    }
    if(!best) return;
    const rakePercent = await getSetting('teenpatti_rake', 5);
    const totalPot = table.pot;
    const rake = Math.floor(totalPot * rakePercent / 100);
    const winnerAmount = totalPot - rake;
    if(!best.isBot){ await creditWin(best.userId, winnerAmount); }
    await pool.query(`INSERT INTO wallets (user_id, balance) VALUES ('HOUSE_ACCOUNT', $1) ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + $1`, [rake]);
    await audit(best.userId, 'TEENPATTI_WIN', `Pot ${totalPot} Rake ${rake} Won ${winnerAmount}`, socket.handshake.address);
    io.to(tableId).emit('teenpatti:winner', { winner: best.name, winnerId: best.userId, totalPot, rake, rakePercent, winnerGot: winnerAmount, allCards: active.map(p=>({ name: p.name, cards: p.cards, hand: evaluateHand(p.cards).name })) });
    teenTables.delete(tableId);
  });

  // ===== 4. DRAGON VS TIGER =====
  socket.on('dragontiger:bet', async (data)=>{
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    if(!['DRAGON','TIGER','TIE'].includes(choice)) return socket.emit('game:error',{message:'Dragon / Tiger / Tie chuno'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    const deck = shuffleDeck();
    const dCard = deck[0];
    const tCard = deck[1];
    const dVal = getRankValue(dCard);
    const tVal = getRankValue(tCard);
    let winner = dVal > tVal ? 'DRAGON' : tVal > dVal ? 'TIGER' : 'TIE';
    let isWin = (choice === winner);
    let multiplier = 1;
    if(winner==='TIE') multiplier = 8;
    else if(isWin) multiplier = 2;
    let winnings = isWin ? bet * multiplier : 0;
    let bal = tx.newBalance;
    if(isWin) bal = await creditWin(userId, winnings);
    socket.emit('dragontiger:result',{ dragonCard: dCard, tigerCard: tCard, winner, choice, isWin, winnings, newBalance: bal });
  });

  // ===== 5. ROULETTE =====
  socket.on('roulette:bet', async (data)=>{
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    const num = fairRandom(37);
    let color = num===0 ? 'GREEN' : [1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36].includes(num) ? 'RED' : 'BLACK';
    let isWin = false;
    let multiplier = 0;
    if(choice==='RED' && color==='RED'){ isWin=true; multiplier=2; }
    if(choice==='BLACK' && color==='BLACK'){ isWin=true; multiplier=2; }
    if(choice==='GREEN' && color==='GREEN'){ isWin=true; multiplier=14; }
    if(!isNaN(parseInt(choice)) && parseInt(choice)===num){ isWin=true; multiplier=36; }
    let winnings = isWin ? bet * multiplier : 0;
    let bal = tx.newBalance;
    if(isWin) bal = await creditWin(userId, winnings);
    socket.emit('roulette:result',{ number: num, color, choice, isWin, winnings, newBalance: bal });
  });

  // ===== 6. MINES =====
  socket.on('mines:play', async (data)=>{
    const bet = parseFloat(data.betAmount);
    const minesCount = parseInt(data.mines) || 3;
    const picked = data.picked || [];
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    if(picked.length===0) return socket.emit('game:error',{message:'Ek box chuno'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    let minePositions = new Set();
    while(minePositions.size < minesCount){ minePositions.add(fairRandom(25)); }
    let hitMine = picked.some(p=>minePositions.has(p));
    let multiplier = 1 + (picked.length * 0.4) + (minesCount * 0.2);
    let winnings = hitMine ? 0 : parseFloat((bet * multiplier).toFixed(2));
    let bal = tx.newBalance;
    if(!hitMine) bal = await creditWin(userId, winnings);
    socket.emit('mines:result',{ minePositions: [...minePositions], picked, hitMine, isWin: !hitMine, winnings, multiplier: parseFloat(multiplier.toFixed(2)), newBalance: bal });
  });

  // ===== 7. ANDAR BAHAR =====
  socket.on('andarbahar:bet', async (data)=>{
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    if(!['ANDAR','BAHAR'].includes(choice)) return socket.emit('game:error',{message:'Andar / Bahar chuno'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    const deck = shuffleDeck();
    const joker = deck[0];
    const jokerVal = getRankValue(joker);
    let winner = null;
    let cards = { andar: [], bahar: [] };
    for(let i=1;i<deck.length;i++){
      if(i%2===1){
        cards.andar.push(deck[i]);
        if(getRankValue(deck[i])===jokerVal){ winner='ANDAR'; break; }
      } else {
        cards.bahar.push(deck[i]);
        if(getRankValue(deck[i])===jokerVal){ winner='BAHAR'; break; }
      }
      if(i>20) break;
    }
    let isWin = (choice===winner);
    let winnings = isWin ? bet*2 : 0;
    let bal = tx.newBalance;
    if(isWin) bal = await creditWin(userId, winnings);
    socket.emit('andarbahar:result',{ joker, winner, choice, isWin, winnings, cards, newBalance: bal });
  });

  // ===== 8. PLINKO =====
  socket.on('plinko:play', async (data)=>{
    const bet = parseFloat(data.betAmount);
    const risk = data.risk || 'MEDIUM';
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    let pos = 0;
    let path = [];
    for(let i=0;i<8;i++){
      let dir = fairRandom(2)===0 ? -1 : 1;
      path.push(dir=== -1 ? 'L' : 'R');
      pos += dir;
    }
    const multipliers = [10, 3, 1.5, 0.8, 0.5, 0.8, 1.5, 3, 10];
    let slot = pos + 4;
    if(slot<0) slot=0;
    if(slot>8) slot=8;
    let mult = multipliers[slot];
    if(risk==='HIGH') mult = mult * 1.5;
    if(risk==='LOW') mult = mult * 0.7;
    mult = parseFloat(mult.toFixed(2));
    let winnings = parseFloat((bet * mult).toFixed(2));
    let bal = await creditWin(userId, winnings);
    socket.emit('plinko:result',{ path, slot, multiplier: mult, winnings, newBalance: bal, risk });
  });

  // ===== 9. BACCARAT =====
  socket.on('baccarat:bet', async (data)=>{
    const bet = parseFloat(data.betAmount);
    const choice = data.choice;
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    if(!['PLAYER','BANKER','TIE'].includes(choice)) return socket.emit('game:error',{message:'Player / Banker / Tie chuno'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    const deck = shuffleDeck();
    const bVal = (c)=>{
      let v = getRankValue(c);
      if(v>=10) return 0;
      if(v===14) return 1;
      return v;
    };
    let pCards = [deck[0], deck[2]];
    let bCards = [deck[1], deck[3]];
    let pTotal = (bVal(pCards[0]) + bVal(pCards[1])) % 10;
    let bTotal = (bVal(bCards[0]) + bVal(bCards[1])) % 10;
    let winner = pTotal > bTotal ? 'PLAYER' : bTotal > pTotal ? 'BANKER' : 'TIE';
    let isWin = (choice===winner);
    let mult = 0;
    if(isWin){
      if(winner==='TIE') mult = 8;
      else if(winner==='PLAYER') mult = 2;
      else mult = 1.95;
    }
    let winnings = isWin ? parseFloat((bet * mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if(isWin) bal = await creditWin(userId, winnings);
    socket.emit('baccarat:result',{ playerCards: pCards, bankerCards: bCards, playerTotal: pTotal, bankerTotal: bTotal, winner, choice, isWin, winnings, newBalance: bal });
  });

  // ===== 10. POKER =====
  socket.on('poker:play', async (data)=>{
    const bet = parseFloat(data.betAmount);
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    const deck = shuffleDeck();
    const myCards = deck.slice(0,5);
    const botCards = deck.slice(5,10);

    function pokerScore(cards){
      const vals = cards.map(getRankValue).sort((a,b)=>a-b);
      const counts = {};
      vals.forEach(v=> counts[v] = (counts[v]||0)+1);
      const pairs = Object.values(counts).sort((a,b)=>b-a);
      const isFlush = cards.map(c=>c.split('-')[0]).every(s=>s===cards[0].split('-')[0]);
      const isStraight = vals[4]-vals[0]===4 && new Set(vals).size===5;
      if(isFlush && isStraight) return { score: 800+vals[4], name: 'Straight Flush' };
      if(pairs[0]===4) return { score: 700, name: 'Four of a Kind' };
      if(pairs[0]===3 && pairs[1]===2) return { score: 600, name: 'Full House' };
      if(isFlush) return { score: 500+vals[4], name: 'Flush' };
      if(isStraight) return { score: 400+vals[4], name: 'Straight' };
      if(pairs[0]===3) return { score: 300, name: 'Three of a Kind' };
      if(pairs[0]===2 && pairs[1]===2) return { score: 200, name: 'Two Pair' };
      if(pairs[0]===2) return { score: 100, name: 'Pair' };
      return { score: vals[4], name: 'High Card' };
    }

    const myScore = pokerScore(myCards);
    const botScore = pokerScore(botCards);
    let isWin = myScore.score > botScore.score;
    let isTie = myScore.score === botScore.score;
    let winnings = 0;
    if(isTie) winnings = bet;
    if(isWin) winnings = bet * 2;
    let bal = tx.newBalance;
    if(winnings>0) bal = await creditWin(userId, winnings);
    socket.emit('poker:result',{ myCards, botCards, myHand: myScore.name, botHand: botScore.name, isWin, isTie, winnings, newBalance: bal });
  });

  // ===== 11. SLOTS - 777 =====
  socket.on('slots:spin', async (data)=>{
    const bet = parseFloat(data.betAmount);
    if(!bet || bet<10) return socket.emit('game:error',{message:'Min Bet ₹10'});
    const tx = await placeBet(userId, bet);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});
    const symbols = ['🍒','🍋','🔔','⭐','💎','7️⃣'];
    const r1 = symbols[fairRandom(symbols.length)];
    const r2 = symbols[fairRandom(symbols.length)];
    const r3 = symbols[fairRandom(symbols.length)];
    let mult = 0, isWin = false, winName = '';
    if(r1==='7️⃣' && r2==='7️⃣' && r3==='7️⃣'){ mult=50; winName='JACKPOT 777!'; isWin=true; }
    else if(r1===r2 && r2===r3){ mult=10; winName='Triple Match!'; isWin=true; }
    else if(r1===r2 || r2===r3 || r1===r3){ mult=2; winName='Double Match!'; isWin=true; }
    else if(r1==='💎' || r2==='💎' || r3==='💎'){ mult=1.5; winName='Diamond!'; isWin=true; }
    let winnings = isWin ? parseFloat((bet*mult).toFixed(2)) : 0;
    let bal = tx.newBalance;
    if(isWin) bal = await creditWin(userId, winnings);
    socket.emit('slots:result',{ reels:[r1,r2,r3], isWin, winName, multiplier: mult, winnings, newBalance: bal });
  });

  socket.on('disconnect',()=>{
    aviatorBets.delete(socket.id);
  });
});

app.get('/',(req,res)=>res.send('FULL CASINO 11 GAMES Running!'));

const PORT = process.env.PORT || 4000;
initDatabase().then(()=>{
  server.listen(PORT,()=>{
    console.log(`Server on ${PORT}`);
    startAviator();
  });
});
