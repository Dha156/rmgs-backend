const express = require('express');
const http = require('http');
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

// PostgreSQL connection (Render ke liye SSL zaroori hai)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Automatic Tables Initialization Function (Wallets, Transactions, Admin, KYC, Audit)
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

io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);

  let currentServerSeed = generateServerSeed();
  let serverSeedHash = hashServerSeed(currentServerSeed);
  let nonce = 1;

  socket.emit('provably-fair:init', { serverSeedHash });

  socket.on('game:spin', async (data) => {
    const { userId, betAmount, clientSeed = 'default_client_seed' } = data;

    const txResult = await placeBet(userId, betAmount);
    if (!txResult.success) {
      return socket.emit('game:error', { message: txResult.error });
    }

    const { outcome } = calculateProvablyFairOutcome(currentServerSeed, clientSeed, nonce);
    const isWin = outcome > 50;
    let winnings = isWin ? betAmount * 2 : 0;

    socket.emit('game:result', {
      outcome,
      isWin,
      winnings,
      newBalance: txResult.newBalance + winnings,
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
  res.send('RMG Backend, Provably Fair & Admin Systems running successfully!');
});

const PORT = process.env.PORT || 4000;

initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
