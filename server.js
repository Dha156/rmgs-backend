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

// Automatic Tables Initialization Function
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

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);`);

    console.log("Database tables (wallets & transactions) verified/created successfully!");
  } catch (err) {
    console.error("Error creating database tables:", err);
  }
}

// Wallet transaction function with row-level locking
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

// Secure Server-side RNG function
function generateSecureRNG(min, max) {
  const range = max - min + 1;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  const maxValidValue = Math.pow(256, bytesNeeded) - Math.floor(Math.pow(256, bytesNeeded) % range);
  let randomValue;
  do {
    const buffer = crypto.randomBytes(bytesNeeded);
    randomValue = buffer.readUIntBE(0, bytesNeeded);
  } while (randomValue >= maxValidValue);
  return min + (randomValue % range);
}

io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);

  socket.on('game:spin', async (data) => {
    const { userId, betAmount } = data;
    const txResult = await placeBet(userId, betAmount);
    if (!txResult.success) {
      return socket.emit('game:error', { message: txResult.error });
    }

    const outcome = generateSecureRNG(1, 100);
    const isWin = outcome > 50;
    let winnings = isWin ? betAmount * 2 : 0;

    socket.emit('game:result', {
      outcome,
      isWin,
      winnings,
      newBalance: txResult.newBalance + winnings
    });
  });

  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
  });
});

app.get('/', (req, res) => {
  res.send('RMG Backend & WebSocket Server is running successfully!');
});

const PORT = process.env.PORT || 4000;

// Initialize Database and Start Server
initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
