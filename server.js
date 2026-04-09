const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Zephyr@2024';
const sessions = new Map(); // token -> expiry timestamp
const BOOKINGS_FILE = path.join(__dirname, 'bookings.json');

// Load persisted bookings
let bookings = [];
try {
  if (fs.existsSync(BOOKINGS_FILE)) {
    bookings = JSON.parse(fs.readFileSync(BOOKINGS_FILE, 'utf8'));
  }
} catch (e) {
  bookings = [];
}

function saveBookings() {
  try { fs.writeFileSync(BOOKINGS_FILE, JSON.stringify(bookings, null, 2)); } catch (e) {}
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function verifyToken(req) {
  const token = req.headers['x-admin-token'];
  if (!token) return false;
  const expiry = sessions.get(token);
  if (!expiry || Date.now() > expiry) { sessions.delete(token); return false; }
  return true;
}

// ── Admin Auth ──────────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = generateToken();
    sessions.set(token, Date.now() + 8 * 60 * 60 * 1000); // 8 hours
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: 'Invalid password' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token) sessions.delete(token);
  res.json({ success: true });
});

app.get('/api/admin/verify', (req, res) => {
  res.json({ valid: verifyToken(req) });
});

// ── Bookings (protected) ────────────────────────────────────
app.get('/api/admin/bookings', (req, res) => {
  if (!verifyToken(req)) return res.status(401).json({ error: 'Unauthorized' });
  res.json(bookings);
});

app.delete('/api/admin/bookings/:id', (req, res) => {
  if (!verifyToken(req)) return res.status(401).json({ error: 'Unauthorized' });
  bookings = bookings.filter(b => b.id !== req.params.id);
  saveBookings();
  res.json({ success: true });
});

app.patch('/api/admin/bookings/:id/status', (req, res) => {
  if (!verifyToken(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { status } = req.body;
  const booking = bookings.find(b => b.id === req.params.id);
  if (!booking) return res.status(404).json({ error: 'Not found' });
  booking.status = status;
  saveBookings();
  res.json({ success: true });
});

// ── Public Booking Submission ───────────────────────────────
app.post('/api/booking', (req, res) => {
  const { name, phone, date, time, guests, note } = req.body;
  if (!name || !phone || !date || !time || !guests) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const booking = {
    id: crypto.randomBytes(8).toString('hex'),
    name: name.trim(),
    phone: phone.trim(),
    date,
    time,
    guests,
    note: (note || '').trim(),
    submittedAt: new Date().toISOString(),
    status: 'pending'
  };
  bookings.unshift(booking);
  saveBookings();
  res.json({ success: true });
});

// ── Catch-all for SPA ───────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Zephyr Bar running on port ${PORT}`));
