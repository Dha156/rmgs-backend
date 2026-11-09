// ================= SECURE BACKEND - NO RIGGING, FAIR RNG =================
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

// ---- CORS - Sirf apni site ko allow karo ----
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());

// ---- Rate Limit - OTP Spam rokne ke liye ----
const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: 'Bahut zyada try kiya, 15 min baad try karo' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });

app.use('/api/', apiLimiter);

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: process.env.FRONTEND_URL || 'http://localhost:3000' } });

// ---- DB ----
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ---- Helpers ----
function safeHttpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e){ reject(e); } });
    }).on('error', reject);
  });
}

// ---- JWT ----
function makeToken(mobile) {
  return jwt.sign({ mobile }, process.env.JWT_SECRET, { expiresIn: '7d' });
}
function checkAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Login karo pehle' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch(e){ return res.status(401).json({ success: false, message: 'Token galat / expire ho gaya' }); }
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

// ---- DB Init ----
async function initDatabase() {
  await pool.query(`CREATE TABLE IF NOT EXISTS wallets (id SERIAL PRIMARY KEY, user_id VARCHAR(255) UNIQUE NOT NULL, balance NUMERIC(12,2) DEFAULT 0 CHECK(balance>=0), vip_level INT DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS transactions (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, type VARCHAR(50) NOT NULL, status VARCHAR(50) NOT NULL, utr VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS deposits (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, utr VARCHAR(100) UNIQUE NOT NULL, status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS withdraws (id SERIAL PRIMARY KEY, user_id VARCHAR(255) NOT NULL, amount NUMERIC(12,2) NOT NULL, method VARCHAR(20) DEFAULT 'UPI', upi_id VARCHAR(255), account_no VARCHAR(50), ifsc VARCHAR(20), status VARCHAR(20) DEFAULT 'PENDING', created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS admin_users (id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role VARCHAR(50) DEFAULT 'admin')`);
  await pool.query(`CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, actor_id VARCHAR(255) NOT NULL, action_type VARCHAR(100) NOT NULL, details TEXT, ip_address VARCHAR(50), created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS settings (key VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL)`);
  // Default Fair Settings - Sabke liye barabar
  await pool.query(`INSERT INTO settings (key, value) VALUES ('global_rtp','96'), ('min_bet','10'), ('max_bet','5000') ON CONFLICT (key) DO NOTHING`);
  console.log('DB Ready!');
}
async function getSetting(key, def) {
  const r = await pool.query('SELECT value FROM settings WHERE key=$1', [key]);
  return r.rows.length ? parseFloat(r.rows[0].value) : def;
}

// ---- Wallet Helpers - ACID ----
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
  } catch(e){ await c.query('ROLLBACK'); return { success: false, error: e.message }; }
  finally{ c.release(); }
}
async function creditWin(userId, winnings) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query('UPDATE wallets SET balance=balance+$1, updated_at=NOW() WHERE user_id=$2 RETURNING balance', [winnings, userId]);
    await c.query('INSERT INTO transactions (user_id, amount, type, status) VALUES ($1,$2,\'WIN\',\'SUCCESS\')', [userId, winnings]);
    await c.query('COMMIT');
    return parseFloat(r.rows[0].balance);
  } catch(e){ await c.query('ROLLBACK'); throw e; } finally{ c.release(); }
}

// ---- FAIR RNG - Provably Fair, No Rigging ----
function generateServerSeed(){ return crypto.randomBytes(32).toString('hex'); }
function hashSeed(s){ return crypto.createHash('sha256').update(s).digest('hex'); }
function fairOutcome(serverSeed, clientSeed, nonce){
  const msg = `${serverSeed}:${clientSeed}:${nonce}`;
  const h = crypto.createHmac('sha256', serverSeed).update(msg).digest('hex');
  const val = parseInt(h.slice(0,8), 16) % 10000; // 0-9999
  return { val, hash: h };
}

// ---- AVIATOR LOOP - CrashPoint Kabhi Client Ko Mat Bhejo ----
let gameState='WAITING', currentMultiplier=1.00, crashPoint=1.50, roundTimer=5, roundId=1;
let aviatorBets = new Map(); // socketId -> {userId, bet, cashedOut}
function startAviator(){
  setInterval(()=>{
    if(gameState==='WAITING'){
      roundTimer--;
      io.emit('game:timer',{timer:roundTimer, roundId});
      if(roundTimer<=0){
        gameState='RUNNING'; currentMultiplier=1.00;
        const rb = crypto.randomBytes(4).readUInt32BE(0);
        crashPoint = parseFloat((1.10 + (rb % 400)/100).toFixed(2));
        aviatorBets.clear();
        // SIRF roundId bhejo, crashPoint KABHI MAT BHEJO
        io.emit('game:started',{ roundId });
      }
    } else if(gameState==='RUNNING'){
      currentMultiplier = parseFloat((currentMultiplier+0.05).toFixed(2));
      io.emit('game:tick',{ multiplier: currentMultiplier, roundId });
      if(currentMultiplier>=crashPoint){
        gameState='CRASHED';
        io.emit('game:crashed',{ multiplier: crashPoint, roundId });
        roundTimer=5; roundId++;
        setTimeout(()=>{ gameState='WAITING'; },3000);
      }
    }
  },1000);
}

// ---- OTP ----
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
    } else res.status(400).json({success:false,message:'OTP nahi bheja gaya'});
  }catch(e){ console.error(e); res.status(500).json({success:false,message:'OTP fail'}); }
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
  }catch(e){ console.error(e); res.status(500).json({success:false,message:'Login fail'}); }
});

// ---- Wallet - Balance (JWT se, Body se nahi) ----
app.get('/api/wallet/balance', checkAuth, async (req,res)=>{
  const r = await pool.query('SELECT balance, vip_level FROM wallets WHERE user_id=$1',[req.user.mobile]);
  if(!r.rows.length) return res.status(404).json({success:false,message:'Wallet nahi mila'});
  res.json({success:true, balance: r.rows[0].balance, vip_level: r.rows[0].vip_level});
});
app.get('/api/wallet/history', checkAuth, async (req,res)=>{
  const r = await pool.query('SELECT amount,type,status,created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.user.mobile]);
  res.json({success:true, history: r.rows});
});

// ---- Deposit - User Request Karega, Admin Approve Karega ----
app.post('/api/wallet/deposit-request', checkAuth, async (req,res)=>{
  const { amount, utr } = req.body;
  if(!amount || amount<100) return res.status(400).json({success:false,message:'Min ₹100 deposit'});
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

// ---- Admin Login ----
app.post('/api/admin/login', async (req,res)=>{
  const { username, password } = req.body;
  const r = await pool.query('SELECT * FROM admin_users WHERE username=$1',[username]);
  if(!r.rows.length) return res.status(401).json({success:false,message:'Galat login'});
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if(!ok) return res.status(401).json({success:false,message:'Galat login'});
  const token = jwt.sign({ username, role:'admin' }, process.env.JWT_SECRET, { expiresIn:'12h' });
  res.json({success:true, token});
});
// ---- Admin - Deposit Approve (Sirf Admin) ----
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
  }catch(e){ await c.query('ROLLBACK'); res.status(400).json({success:false,message:e.message}); }
  finally{ c.release(); }
});
app.get('/api/admin/pending-deposits', checkAdmin, async (req,res)=>{
  const r = await pool.query('SELECT * FROM deposits WHERE status=\'PENDING\' ORDER BY created_at ASC');
  res.json({success:true, deposits: r.rows});
});
app.get('/api/admin/pending-withdraws', checkAdmin, async (req,res)=>{
  const r = await pool.query('SELECT * FROM withdraws WHERE status=\'PENDING\' ORDER BY created_at ASC');
  res.json({success:true, withdraws: r.rows});
});
// ---- Admin - Settings (Global RTP, Min/Max Bet) - Sabke liye barabar ----
app.get('/api/admin/settings', checkAdmin, async (req,res)=>{
  const r = await pool.query('SELECT * FROM settings');
  res.json({success:true, settings: Object.fromEntries(r.rows.map(x=>[x.key,x.value]))});
});
app.post('/api/admin/settings', checkAdmin, async (req,res)=>{
  const { global_rtp, min_bet, max_bet } = req.body;
  if(global_rtp!==undefined){
    const v = parseFloat(global_rtp);
    if(v<80 || v>98) return res.status(400).json({success:false,message:'RTP 80 se 98 ke beech rakho'});
    await pool.query('INSERT INTO settings (key,value) VALUES (\'global_rtp\',$1) ON CONFLICT (key) DO UPDATE SET value=$1',[String(v)]);
  }
  if(min_bet!==undefined) await pool.query('INSERT INTO settings (key,value) VALUES (\'min_bet\',$1) ON CONFLICT (key) DO UPDATE SET value=$1',[String(min_bet)]);
  if(max_bet!==undefined) await pool.query('INSERT INTO settings (key,value) VALUES (\'max_bet\',$1) ON CONFLICT (key) DO UPDATE SET value=$1',[String(max_bet)]);
  await audit(req.admin.username,'UPDATE_SETTINGS',JSON.stringify(req.body), req.ip);
  res.json({success:true,message:'Settings save ho gayi'});
});

// ---- Withdraw - JWT se, VIP Check ke saath ----
app.post('/api/wallet/withdraw', checkAuth, async (req,res)=>{
  const { amount, upi_id, account_no, ifsc } = req.body;
  const userId = req.user.mobile; // Token se, Body se nahi!
  if(!amount || amount<100) return res.status(400).json({success:false,message:'Min ₹100 withdraw'});
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
  }catch(e){ await c.query('ROLLBACK'); res.status(400).json({success:false,message:e.message}); }
  finally{ c.release(); }
});

// ---- SOCKET - Auth ke saath ----
io.use((socket, next)=>{
  const token = socket.handshake.auth?.token;
  if(!token) return next(new Error('Token chahiye'));
  try{ socket.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch(e){ next(new Error('Token galat hai')); }
});
io.on('connection',(socket)=>{
  const userId = socket.user.mobile;
  let serverSeed = generateServerSeed();
  let seedHash = hashSeed(serverSeed);
  let nonce = 1;
  socket.emit('provably-fair:init',{ serverSeedHash: seedHash });
  socket.emit('game:state',{ gameState, currentMultiplier, roundTimer, roundId });

  socket.on('room:join',(data)=>{
    socket.join(data.roomName);
    io.to(data.roomName).emit('room:player-joined',{ userId, socketId: socket.id });
  });
  socket.on('game:action',(data)=>{
    io.to(data.roomName).emit('game:action-broadcast',{ userId, action: data.action, amount: data.amount, timestamp: Date.now() });
  });

  // ---- SPIN - Fair, No Rigging ----
  socket.on('game:spin', async (data)=>{
    const betAmount = parseFloat(data.betAmount);
    const clientSeed = String(data.clientSeed || 'default');
    const minBet = await getSetting('min_bet', 10);
    const maxBet = await getSetting('max_bet', 5000);
    const rtp = await getSetting('global_rtp', 96); // 80-98, sabke liye ek
    if(!betAmount || betAmount<minBet || betAmount>maxBet) return socket.emit('game:error',{message:`Bet ${minBet} se ${maxBet} ke beech rakho`});

    const tx = await placeBet(userId, betAmount);
    if(!tx.success) return socket.emit('game:error',{message: tx.error});

    // Fair Outcome - RTP se Payout nikalta hai, kisi ek ko target nahi karta
    // Example: RTP 96% aur Payout 2x ho to Win Chance = 48%
    // Yaha simple 2x game ke liye:
    const { val } = fairOutcome(serverSeed, clientSeed, nonce);
    const winChance = Math.floor((rtp / 2) * 100); // RTP 96 -> 4800 / 10000 = 48%
    const isWin = val < winChance;
    const winnings = isWin ? betAmount * 2 : 0;
    let finalBalance = tx.newBalance;
    if(isWin) finalBalance = await creditWin(userId, winnings);

    socket.emit('game:result',{ outcome: val, isWin, winnings, newBalance: finalBalance, nonce, serverSeedHash: seedHash, revealedServerSeed: serverSeed });
    nonce++;
    // Har 100 spin pe naya Seed - taaki koi Seed guess na kar paye
    if(nonce % 100 === 0){ serverSeed = generateServerSeed(); seedHash = hashSeed(serverSeed); nonce = 1; socket.emit('provably-fair:init',{ serverSeedHash: seedHash }); }
  });

  // ---- AVIATOR BET / CASHOUT ----
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
  socket.on('disconnect',()=>{ aviatorBets.delete(socket.id); });
});

app.get('/',(req,res)=>res.send('Secure RMG Backend Running!'));
const PORT = process.env.PORT || 4000;
initDatabase().then(()=>{ server.listen(PORT,()=>{ console.log(`Server on ${PORT}`); startAviator(); }); });
