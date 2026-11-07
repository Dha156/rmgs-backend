const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const crypto = require('crypto');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper function for HTTPS GET requests (Safe for all Node.js versions)
function safeHttpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', (err) => {
      reject(err);
    });
  });
}

// Automatic Tables Initialization
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallets (
          id SERIAL PRIMARY KEY,
          user_id VARCHAR(255) UNIQUE NOT NULL,
          balance NUMERIC(12, 2) DEFAULT 0.00 CHECK (balance >= 0),
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
          id SERIAL PRIMARY KEY,
          user_id VARCHAR(255) NOT NULL,
          amount NUMERIC(12, 2) NOT NULL,
          type VARCHAR(50) NOT NULL,
          status VARCHAR(50) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(100) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(50) DEFAULT 'moderator',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS kyc_records (
          id SERIAL PRIMARY KEY,
          user_id VARCHAR(255) UNIQUE NOT NULL,
          pan_number VARCHAR(20),
          document_status VARCHAR(50) DEFAULT 'PENDING',
          verified_at TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
          id SERIAL PRIMARY KEY,
          actor_id VARCHAR(255) NOT NULL,
          action_type VARCHAR(100) NOT NULL,
          details TEXT,
          ip_address VARCHAR(50),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_kyc_user_id ON kyc_records(user_id);`);

    console.log("All Database tables verified/created successfully!");
  } catch (err) {
    console.error("Error creating database tables:", err);
  }
}

// Wallet transaction function with row-level locking (ACID Compliance)
async function placeBet(userId, betAmount) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const walletRes = await client.query(
      'SELECT id, balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [userId]
    );
    if (walletRes.rows.length === 0) throw new Error('Wallet not found');
    const currentBalance = parseFloat(walletRes.rows[0].balance);
    if (currentBalance < betAmount) throw new Error('Insufficient balance');

    await client.query(
      'UPDATE wallets SET balance = balance - $1, updated_at = NOW() WHERE user_id = $2',
      [betAmount, userId]
    );
    await client.query(
      `INSERT INTO transactions (user_id, amount, type, status) VALUES ($1, $2, 'BET', 'SUCCESS')`,
      [userId, betAmount]
    );
    await client.query('COMMIT');
    return { success: true, newBalance: currentBalance - betAmount };
  } catch (error) {
    await client.query('ROLLBACK');
    return { success: false, error: error.message };
  } finally {
    client.release();
  }
}

// --- PROVABLY FAIR RNG ENGINE ---
function generateServerSeed() {
  return crypto.randomBytes(32).toString('hex');
}

function hashServerSeed(serverSeed) {
  return crypto.createHash('sha256').update(serverSeed).digest('hex');
}

function calculateProvablyFairOutcome(serverSeed, clientSeed, nonce) {
  const message = `${serverSeed}:${clientSeed}:${nonce}`;
  const hash = crypto.createHmac('sha256', serverSeed).update(message).digest('hex');
  const intVal = parseInt(hash.slice(0, 8), 16);
  const outcome = (intVal % 100) + 1;
  return { outcome, hash };
}

// --- REAL-TIME GAME LOOP (Aviator / Crash Style) ---
let gameState = 'WAITING'; // WAITING, RUNNING, CRASHED
let currentMultiplier = 1.00;
let crashPoint = 1.50;
let roundTimer = 5; // 5 seconds betting time

function startAviatorGameLoop() {
  setInterval(() => {
    if (gameState === 'WAITING') {
      roundTimer--;
      io.emit('game:timer', { timer: roundTimer });

      if (roundTimer <= 0) {
        gameState = 'RUNNING';
        currentMultiplier = 1.00;
        const randomBytes = crypto.randomBytes(4).readUInt32BE(0);
        crashPoint = parseFloat((1.10 + (randomBytes % 400) / 100).toFixed(2));
        io.emit('game:started', { crashPoint });
      }
    } else if (gameState === 'RUNNING') {
      currentMultiplier = parseFloat((currentMultiplier + 0.05).toFixed(2));
      io.emit('game:tick', { multiplier: currentMultiplier });

      if (currentMultiplier >= crashPoint) {
        gameState = 'CRASHED';
        io.emit('game:crashed', { multiplier: crashPoint });
        roundTimer = 5;
        setTimeout(() => {
          gameState = 'WAITING';
        }, 3000);
      }
    }
  }, 1000);
}

// --- OTP AUTHENTICATION SYSTEM (2Factor API) ---
const otpStore = new Map();

// 1. Send OTP via 2Factor API
app.post('/api/auth/send-otp', async (req, res) => {
  const { mobile } = req.body;
  
  if (!mobile || mobile.length !== 10) {
    return res.status(400).json({ success: false, message: 'Invalid mobile number' });
  }

  try {
    const apiKey = process.env.TWO_FACTOR_API_KEY || '93132bce-d69f-11f1-ac3e-0200cd936042';
    const templateName = 'OTP1';

    const url = `https://2factor.in/API/V1/${apiKey}/SMS/${mobile}/AUTOGEN/${templateName}`;
    const data = await safeHttpsGet(url);

    if (data.Status === 'Success') {
      otpStore.set(mobile, { sessionId: data.Details, expiresAt: Date.now() + 5 * 60 * 1000 });
      res.json({ success: true, message: 'OTP sent successfully via 2Factor' });
    } else {
      res.status(400).json({ success: false, message: data.Details || 'Failed to send OTP' });
    }
  } catch (error) {
    console.error('2Factor API Error:', error);
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// 2. Verify OTP via 2Factor API & Login / Register
app.post('/api/auth/verify-otp', async (req, res) => {
  const { mobile, otp } = req.body;

  const record = otpStore.get(mobile);
  if (!record) {
    return res.status(400).json({ success: false, message: 'OTP session expired or not found' });
  }

  if (Date.now() > record.expiresAt) {
    otpStore.delete(mobile);
    return res.status(400).json({ success: false, message: 'OTP expired' });
  }

  try {
    const apiKey = process.env.TWO_FACTOR_API_KEY || '93132bce-d69f-11f1-ac3e-0200cd936042';
    const verifyUrl = `https://2factor.in/API/V1/${apiKey}/SMS/VERIFY/${record.sessionId}/${otp}`;
    
    const data = await safeHttpsGet(verifyUrl);

    if (data.Status === 'Success') {
      otpStore.delete(mobile);

      let walletRes = await pool.query('SELECT * FROM wallets WHERE user_id = $1', [mobile]);
      
      if (walletRes.rows.length === 0) {
        walletRes = await pool.query(
          'INSERT INTO wallets (user_id, balance) VALUES ($1, $2) RETURNING *',
          [mobile, 0.00]
        );
      }

      res.json({
        success: true,
        message: 'Login successful',
        user: {
          mobile,
          balance: walletRes.rows[0].balance
        }
      });
    } else {
      res.status(400).json({ success: false, message: 'Incorrect OTP' });
    }
  } catch (err) {
    console.error('Database or Verification error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);

  let currentServerSeed = generateServerSeed();
  let serverSeedHash = hashServerSeed(currentServerSeed);
  let nonce = 1;

  socket.emit('provably-fair:init', { serverSeedHash });
  socket.emit('game:state', { gameState, currentMultiplier, roundTimer });

  socket.on('game:spin', async (data) => {
    const { userId, betAmount, clientSeed = 'default_client_seed' } = data;

    // 1. Deduct bet amount securely using ACID transaction
    const txResult = await placeBet(userId, betAmount);
    if (!txResult.success) {
      return socket.emit('game:error', { message: txResult.error });
    }

    // 2. Calculate game result
    const { outcome } = calculateProvablyFairOutcome(currentServerSeed, clientSeed, nonce);
    const isWin = outcome > 50;
    let winnings = isWin ? betAmount * 2 : 0;

    let finalBalance = txResult.newBalance;

    // 3. If user wins, credit winnings back to PostgreSQL database securely
    if (isWin && winnings > 0) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const updateRes = await client.query(
          'UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2 RETURNING balance',
          [winnings, userId]
        );
        await client.query(
          `INSERT INTO transactions (user_id, amount, type, status) VALUES ($1, $2, 'WIN', 'SUCCESS')`,
          [winnings, userId]
        );
        await client.query('COMMIT');
        finalBalance = parseFloat(updateRes.rows[0].balance);
      } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error crediting winnings to DB:', err);
      } finally {
        client.release();
      }
    }

    // 4. Emit the final result to the socket client
    socket.emit('game:result', {
      outcome,
      isWin,
      winnings,
      newBalance: finalBalance,
      nonce,
      serverSeedHash,
      revealedServerSeed: currentServerSeed
    });

    nonce++;
  });

  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
  });
});

app.get('/', (req, res) => {
  res.send('RMG Production Real-Time WebSocket & 2Factor OTP Server is running successfully!');
});

const PORT = process.env.PORT || 4000;

initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    startAviatorGameLoop();
  });
});
