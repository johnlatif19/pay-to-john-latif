'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

/* ================================================================
 * Security & parsers
 * ================================================================ */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.CORS_ORIGIN || true,
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(session({
  name: 'mpg.sid',
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 4 // 4h
  }
}));

/* ================================================================
 * Rate limiters
 * ================================================================ */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many login attempts' } }
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: { code: 'RATE_LIMITED', message: 'Too many payment requests' } }
});

/* ================================================================
 * Cloudinary config
 * ================================================================ */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

const CLOUDINARY_FOLDER = process.env.CLOUDINARY_FOLDER || 'mockpay/screenshots';

/* ================================================================
 * In-memory storage  (استبدلها بـ PostgreSQL في الإنتاج)
 * ================================================================ */
const paymentLinks = new Map();
const transactions = new Map();
const transactionsById = new Map();
const idempotencyIndex = new Map();

/* ================================================================
 * Multer — استقبال سكرين التحويل في الذاكرة ثم نرفعه لـ Cloudinary
 * ================================================================ */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024 }, // 4 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('INVALID_FILE_TYPE'));
    }
    cb(null, true);
  }
});

/* ================================================================
 * Helpers
 * ================================================================ */
function secureId(prefix, bytes = 12) {
  return `${prefix}_${crypto.randomBytes(bytes).toString('hex').toUpperCase()}`;
}

function isValidCurrency(c) {
  return ['EGP', 'USD', 'EUR', 'SAR', 'AED'].includes(c);
}

function sanitizeText(str, max = 120) {
  if (typeof str !== 'string') return null;
  const t = str.trim();
  if (!t || t.length > max) return null;
  return t;
}

function publicTx(tx) {
  return {
    transaction_id: tx.transaction_id,
    payment_token: tx.payment_token,
    link_id: tx.link_id || null,
    order_id: tx.order_id,
    amount: tx.amount,
    currency: tx.currency,
    payment_method: tx.payment_method,
    status: tx.status,
    customer: tx.customer || null,
    screenshot_url: tx.screenshot?.url || null,
    created_at: tx.created_at,
    updated_at: tx.updated_at
  };
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.admin) {
    return res.status(401).json({
      success: false,
      error: { code: 'UNAUTHORIZED', message: 'Admin authentication required' }
    });
  }
  next();
}

/* ================================================================
 * Cloudinary upload helper (Promise wrapper)
 * ================================================================ */
function uploadToCloudinary(buffer, publicIdHint) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder: CLOUDINARY_FOLDER,
        resource_type: 'image',
        public_id: publicIdHint,
        overwrite: false,
        transformation: [
          { width: 1400, height: 1400, crop: 'limit' },
          { quality: 'auto:good', fetch_format: 'auto' }
        ]
      },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );
    stream.end(buffer);
  });
}

/* ================================================================
 * 🛡️ Clean URLs + حماية الصفحات
 * ================================================================ */
const CLEAN_ROUTES = {
  '/waiting':   'waiting.html',
  '/success':   'success.html',
  '/failed':    'failed.html'
  // /login و /dashboard بيتعالجوا تحت (بسبب الحماية)
};

app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  if (req.path.startsWith('/api/')) return next();

  /* -------- /pay/:link_id → index.html (عام) -------- */
  if (req.path.startsWith('/pay/')) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }

  /* -------- 🛡️ /dashboard — يتطلب تسجيل دخول -------- */
  if (req.path === '/dashboard' || req.path === '/dashboard.html') {
    if (!req.session || !req.session.admin) {
      return res.redirect(302, '/login');
    }
    return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  }

  /* -------- 🛡️ /login — لو مسجّل، حوّله للداشبورد -------- */
  if (req.path === '/login' || req.path === '/login.html') {
    if (req.session && req.session.admin) {
      return res.redirect(302, '/dashboard');
    }
    return res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }

  /* -------- باقي الصفحات العامة -------- */
  const clean = CLEAN_ROUTES[req.path];
  if (clean) {
    return res.sendFile(path.join(__dirname, 'public', clean));
  }

  next();
});

/* 🛡️ منع الوصول المباشر لـ dashboard.html من أي مسار تاني */
app.use((req, res, next) => {
  if (req.path.endsWith('/dashboard.html') || req.path === 'dashboard.html') {
    return res.redirect(302, '/login');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

/* ================================================================
 * PUBLIC API — Payment Link info
 * ================================================================ */
app.get('/api/payment-link/:linkId', (req, res) => {
  const link = paymentLinks.get(req.params.linkId);
  if (!link || !link.active) {
    return res.status(404).json({
      success: false,
      error: { code: 'LINK_NOT_FOUND', message: 'Payment link not found or inactive' }
    });
  }
  return res.json({
    success: true,
    link: {
      link_id: link.link_id,
      amount: link.amount,
      currency: link.currency,
      description: link.description,
      active: link.active
    }
  });
});

/* ================================================================
 * PUBLIC API — Create Payment
 * multipart/form-data:
 *   link_id, payment_method, customer_name, customer_email, customer_phone,
 *   screenshot (image)
 * ================================================================ */
app.post(
  '/api/payment/create',
  paymentLimiter,
  upload.single('screenshot'),
  async (req, res) => {
    try {
      /* ---------- Idempotency ---------- */
      const idemKey = req.get('Idempotency-Key');
      if (idemKey) {
        const existingId = idempotencyIndex.get(idemKey);
        if (existingId) {
          const tx = transactionsById.get(existingId);
          if (tx) {
            return res.status(200).json({
              success: true,
              idempotent: true,
              transaction_id: tx.transaction_id,
              payment_token: tx.payment_token,
              status: tx.status,
              redirect_url: `/waiting?token=${tx.payment_token}`
            });
          }
        }
      }

      /* ---------- Validate inputs ---------- */
      const { link_id, payment_method, customer_name, customer_email, customer_phone } = req.body || {};

      const link = paymentLinks.get(link_id);
      if (!link || !link.active) {
        return res.status(404).json({
          success: false,
          error: { code: 'LINK_NOT_FOUND', message: 'Payment link not found or inactive' }
        });
      }

      if (!['wallet', 'instapay'].includes(payment_method)) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_METHOD', message: 'payment_method must be wallet or instapay' }
        });
      }

      const name  = sanitizeText(customer_name, 80);
      const email = sanitizeText(customer_email, 120);
      const phone = sanitizeText(customer_phone, 30);

      if (!name) {
        return res.status(400).json({ success: false, error: { code: 'INVALID_NAME', message: 'customer_name is required' } });
      }
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, error: { code: 'INVALID_EMAIL', message: 'customer_email is invalid' } });
      }
      if (!phone || !/^[0-9+\-\s]{6,30}$/.test(phone)) {
        return res.status(400).json({ success: false, error: { code: 'INVALID_PHONE', message: 'customer_phone is invalid' } });
      }

      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: { code: 'MISSING_SCREENSHOT', message: 'screenshot is required' }
        });
      }

      /* ---------- IDs أولاً عشان نستخدمها كـ public_id ---------- */
      const transactionId = secureId('TXN', 8);
      const paymentToken  = secureId('PTK', 16);

      /* ---------- ارفع الصورة على Cloudinary ---------- */
      let uploadResult;
      try {
        uploadResult = await uploadToCloudinary(req.file.buffer, transactionId);
      } catch (err) {
        console.error('cloudinary upload error:', err.message);
        return res.status(502).json({
          success: false,
          error: { code: 'UPLOAD_FAILED', message: 'Failed to upload screenshot. Please try again.' }
        });
      }

      /* ---------- أنشئ الـ transaction ---------- */
      const now = new Date().toISOString();
      const tx = {
        transaction_id: transactionId,
        payment_token:  paymentToken,
        link_id: link.link_id,
        order_id: 'ORDER_' + Date.now().toString().slice(-6),
        amount: link.amount,
        currency: link.currency,
        payment_method,
        status: 'pending',
        customer: { name, email, phone },
        screenshot: {
          url:       uploadResult.secure_url,
          public_id: uploadResult.public_id,
          format:    uploadResult.format,
          bytes:     uploadResult.bytes,
          width:     uploadResult.width,
          height:    uploadResult.height
        },
        created_at: now,
        updated_at: now
      };

      transactions.set(tx.payment_token, tx);
      transactionsById.set(tx.transaction_id, tx);
      if (idemKey) idempotencyIndex.set(idemKey, tx.transaction_id);

      return res.status(201).json({
        success: true,
        transaction_id: tx.transaction_id,
        payment_token: tx.payment_token,
        status: tx.status,
        redirect_url: `/waiting?token=${tx.payment_token}`
      });
    } catch (err) {
      if (err && err.message === 'INVALID_FILE_TYPE') {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_FILE_TYPE', message: 'Only PNG/JPG/WEBP images are allowed' }
        });
      }
      if (err && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          error: { code: 'FILE_TOO_LARGE', message: 'Screenshot must be <= 4MB' }
        });
      }
      console.error('create payment error:', err.message);
      return res.status(500).json({
        success: false,
        error: { code: 'SERVER_ERROR', message: 'Internal server error' }
      });
    }
  }
);

/**
 * GET /api/payment/status?token=...
 */
app.get('/api/payment/status', (req, res) => {
  const token = String(req.query.token || '');
  if (!token) {
    return res.status(400).json({ success: false, error: { code: 'MISSING_TOKEN', message: 'token is required' } });
  }
  const tx = transactions.get(token);
  if (!tx) {
    return res.status(404).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Invalid payment token' } });
  }
  return res.json({ transaction_id: tx.transaction_id, status: tx.status });
});

/**
 * GET /api/payment/details?token=...
 */
app.get('/api/payment/details', (req, res) => {
  const token = String(req.query.token || '');
  const tx = transactions.get(token);
  if (!tx) {
    return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied' } });
  }
  if (tx.status === 'pending') {
    return res.status(409).json({ success: false, error: { code: 'STILL_PENDING', message: 'Payment is still pending' } });
  }
  return res.json({ success: true, transaction: publicTx(tx) });
});

/* ================================================================
 * AUTH
 * ================================================================ */
app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const envUser = process.env.ADMIN_USERNAME || 'admin';
  const envPass = process.env.ADMIN_PASSWORD || 'change_this_password';

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ success: false, error: { code: 'INVALID_INPUT', message: 'username and password are required' } });
  }

  const userOk = username.length === envUser.length &&
    crypto.timingSafeEqual(Buffer.from(username), Buffer.from(envUser));
  const passOk = password === envPass;

  if (!userOk || !passOk) {
    return res.status(401).json({ success: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid username or password' } });
  }

  req.session.admin = { username: envUser, loginAt: Date.now() };
  return res.json({ success: true, user: { username: envUser } });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('mpg.sid');
    res.json({ success: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.admin) {
    return res.json({ success: true, user: { username: req.session.admin.username } });
  }
  return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Not logged in' } });
});

/* ================================================================
 * ADMIN — Payment Links
 * ================================================================ */
app.post('/api/admin/links', requireAdmin, (req, res) => {
  const { amount, currency, description } = req.body || {};

  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0 || numericAmount > 1000000) {
    return res.status(400).json({ success: false, error: { code: 'INVALID_AMOUNT', message: 'amount must be a positive number' } });
  }

  const curr = (currency || 'EGP').toUpperCase();
  if (!isValidCurrency(curr)) {
    return res.status(400).json({ success: false, error: { code: 'INVALID_CURRENCY', message: 'currency is not supported' } });
  }

  const desc = sanitizeText(description || 'Payment request', 140);
  if (!desc) {
    return res.status(400).json({ success: false, error: { code: 'INVALID_DESCRIPTION', message: 'description is invalid' } });
  }

  const link = {
    link_id: secureId('LNK', 8),
    amount: Math.round(numericAmount * 100) / 100,
    currency: curr,
    description: desc,
    created_by: req.session.admin.username,
    created_at: new Date().toISOString(),
    active: true
  };

  paymentLinks.set(link.link_id, link);

  return res.status(201).json({
    success: true,
    link: {
      ...link,
      public_url: `/pay/${link.link_id}`
    }
  });
});

app.get('/api/admin/links', requireAdmin, (req, res) => {
  const list = Array.from(paymentLinks.values())
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return res.json({ success: true, links: list });
});

app.patch('/api/admin/links/:linkId', requireAdmin, (req, res) => {
  const link = paymentLinks.get(req.params.linkId);
  if (!link) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Link not found' } });
  }
  if (typeof req.body.active === 'boolean') {
    link.active = req.body.active;
  }
  return res.json({ success: true, link });
});

/* ================================================================
 * ADMIN — Transactions
 * ================================================================ */
app.get('/api/admin/transactions', requireAdmin, (req, res) => {
  const list = Array.from(transactionsById.values())
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .map(publicTx);
  return res.json({ success: true, transactions: list });
});

app.post('/api/admin/payment/:transactionId/approve', requireAdmin, (req, res) => {
  const tx = transactionsById.get(req.params.transactionId);
  if (!tx) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Transaction not found' } });
  if (tx.status !== 'pending') return res.status(409).json({ success: false, error: { code: 'INVALID_STATE', message: `Cannot approve a ${tx.status} transaction` } });
  tx.status = 'success';
  tx.updated_at = new Date().toISOString();
  return res.json({ success: true, transaction: publicTx(tx) });
});

app.post('/api/admin/payment/:transactionId/reject', requireAdmin, (req, res) => {
  const tx = transactionsById.get(req.params.transactionId);
  if (!tx) return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Transaction not found' } });
  if (tx.status !== 'pending') return res.status(409).json({ success: false, error: { code: 'INVALID_STATE', message: `Cannot reject a ${tx.status} transaction` } });
  tx.status = 'failed';
  tx.updated_at = new Date().toISOString();
  return res.json({ success: true, transaction: publicTx(tx) });
});

/* ================================================================
 * 404
 * ================================================================ */
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Endpoint not found' } });
  }
  res.status(404).sendFile(path.join(__dirname, 'public', 'failed.html'));
});

/* ================================================================
 * Start
 * ================================================================ */
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Mock Payment Gateway running on http://localhost:${PORT}`);
  });
}

module.exports = app;
