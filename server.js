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
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

/* ================================================================
 * Trust proxy — ضروري على Vercel عشان express-rate-limit
 * ================================================================ */
app.set('trust proxy', 1);

/* ================================================================
 * Firebase Admin SDK — الطريقة 1 (JSON كامل)
 * ================================================================ */
function initFirebase() {
  if (admin.apps.length) return admin.app();

  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      return admin.initializeApp({
        credential: admin.credential.cert(sa)
      });
    } catch (e) {
      console.error('❌ Failed to parse FIREBASE_SERVICE_ACCOUNT:', e.message);
      process.exit(1);
    }
  }

  console.error('');
  console.error('❌ FIREBASE_SERVICE_ACCOUNT is not set.');
  console.error('   Set the full JSON on one line in your .env');
  console.error('');
  process.exit(1);
}

initFirebase();

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

/* ================================================================
 * Collections
 * ================================================================ */
const PREFIX = process.env.FIRESTORE_PREFIX || 'mpg_';
const COL = {
  links:        PREFIX + 'payment_links',
  transactions: PREFIX + 'transactions',
  idempotency:  PREFIX + 'idempotency_keys'
};

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
  proxy: true,
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
 * Multer — memory فقط ثم نرفع لـ Cloudinary
 * ================================================================ */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024 },
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
};

app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  if (req.path.startsWith('/api/')) return next();

  if (req.path.startsWith('/pay/')) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }

  if (req.path === '/dashboard' || req.path === '/dashboard.html') {
    if (!req.session || !req.session.admin) {
      return res.redirect(302, '/login');
    }
    return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  }

  if (req.path === '/login' || req.path === '/login.html') {
    if (req.session && req.session.admin) {
      return res.redirect(302, '/dashboard');
    }
    return res.sendFile(path.join(__dirname, 'public', 'login.html'));
  }

  const clean = CLEAN_ROUTES[req.path];
  if (clean) {
    return res.sendFile(path.join(__dirname, 'public', clean));
  }

  next();
});

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
app.get('/api/payment-link/:linkId', async (req, res) => {
  try {
    const snap = await db.collection(COL.links).doc(req.params.linkId).get();
    if (!snap.exists) {
      return res.status(404).json({
        success: false,
        error: { code: 'LINK_NOT_FOUND', message: 'Payment link not found or inactive' }
      });
    }
    const link = snap.data();
    if (!link.active) {
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
  } catch (err) {
    console.error('payment-link error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

/* ================================================================
 * PUBLIC API — Create Payment
 * ================================================================ */
app.post(
  '/api/payment/create',
  paymentLimiter,
  upload.single('screenshot'),
  async (req, res) => {
    try {
      const idemKey = req.get('Idempotency-Key');
      if (idemKey) {
        const idemSnap = await db.collection(COL.idempotency).doc(idemKey).get();
        if (idemSnap.exists) {
          const txId = idemSnap.data().transaction_id;
          const txSnap = await db.collection(COL.transactions).doc(txId).get();
          if (txSnap.exists) {
            const tx = txSnap.data();
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

      const { link_id, payment_method, customer_name, customer_email, customer_phone } = req.body || {};

      const linkSnap = await db.collection(COL.links).doc(link_id).get();
      if (!linkSnap.exists) {
        return res.status(404).json({
          success: false,
          error: { code: 'LINK_NOT_FOUND', message: 'Payment link not found or inactive' }
        });
      }
      const link = linkSnap.data();
      if (!link.active) {
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

      const transactionId = secureId('TXN', 8);
      const paymentToken  = secureId('PTK', 16);

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

      await db.collection(COL.transactions).doc(transactionId).set(tx);

      if (idemKey) {
        await db.collection(COL.idempotency).doc(idemKey).set({
          transaction_id: transactionId,
          created_at: FieldValue.serverTimestamp()
        });
      }

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
app.get('/api/payment/status', async (req, res) => {
  try {
    const token = String(req.query.token || '');
    if (!token) {
      return res.status(400).json({ success: false, error: { code: 'MISSING_TOKEN', message: 'token is required' } });
    }

    const snap = await db.collection(COL.transactions)
      .where('payment_token', '==', token)
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(404).json({ success: false, error: { code: 'INVALID_TOKEN', message: 'Invalid payment token' } });
    }

    const tx = snap.docs[0].data();
    return res.json({ transaction_id: tx.transaction_id, status: tx.status });
  } catch (err) {
    console.error('payment/status error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

/**
 * GET /api/payment/details?token=...
 */
app.get('/api/payment/details', async (req, res) => {
  try {
    const token = String(req.query.token || '');
    if (!token) {
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied' } });
    }

    const snap = await db.collection(COL.transactions)
      .where('payment_token', '==', token)
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Access denied' } });
    }

    const tx = snap.docs[0].data();

    if (tx.status === 'pending') {
      return res.status(409).json({ success: false, error: { code: 'STILL_PENDING', message: 'Payment is still pending' } });
    }

    return res.json({ success: true, transaction: publicTx(tx) });
  } catch (err) {
    console.error('payment/details error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

/* ================================================================
 * AUTH
 * ================================================================ */
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const envUser = process.env.ADMIN_USERNAME || 'admin';
    const envHash = process.env.ADMIN_PASSWORD_HASH;

    // 🔍 Debug logging
    console.log('🔍 LOGIN ATTEMPT:', {
      received_user: username,
      expected_user: envUser,
      hash_exists: !!envHash,
      hash_length: envHash ? envHash.length : 0,
      hash_prefix: envHash ? envHash.substring(0, 15) : 'NONE',
      hash_has_quotes: envHash ? (envHash.startsWith("'") || envHash.startsWith('"')) : false,
      password_length: typeof password === 'string' ? password.length : 0
    });

    if (typeof username !== 'string' || typeof password !== 'string') {
      console.log('❌ INVALID_INPUT');
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_INPUT', message: 'username and password are required' }
      });
    }

    if (!envHash) {
      console.error('❌ ADMIN_PASSWORD_HASH is not set in .env');
      return res.status(500).json({
        success: false,
        error: { code: 'SERVER_MISCONFIGURED', message: 'Server authentication is not configured' }
      });
    }

    // مقارنة اسم المستخدم (timing-safe)
    let userOk = false;
    try {
      userOk = username.length === envUser.length &&
        crypto.timingSafeEqual(Buffer.from(username), Buffer.from(envUser));
    } catch (e) {
      console.log('❌ user compare error:', e.message);
      userOk = false;
    }

    // مقارنة كلمة المرور
    let passOk = false;
    try {
      passOk = await bcrypt.compare(password, envHash);
    } catch (e) {
      console.log('❌ bcrypt error:', e.message);
      passOk = false;
    }

    console.log('🔍 RESULTS:', { userOk, passOk });

    if (!userOk || !passOk) {
      return res.status(401).json({
        success: false,
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid username or password' }
      });
    }

    req.session.admin = { username: envUser, loginAt: Date.now() };
    console.log('✅ LOGIN SUCCESS:', envUser);
    return res.json({ success: true, user: { username: envUser } });
  } catch (err) {
    console.error('❌ login error:', err.message, err.stack);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
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
app.post('/api/admin/links', requireAdmin, async (req, res) => {
  try {
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

    await db.collection(COL.links).doc(link.link_id).set(link);

    return res.status(201).json({
      success: true,
      link: {
        ...link,
        public_url: `/pay/${link.link_id}`
      }
    });
  } catch (err) {
    console.error('create link error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

app.get('/api/admin/links', requireAdmin, async (req, res) => {
  try {
    const snap = await db.collection(COL.links)
      .orderBy('created_at', 'desc')
      .get();

    const links = snap.docs.map(d => d.data());
    return res.json({ success: true, links });
  } catch (err) {
    console.error('list links error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

app.patch('/api/admin/links/:linkId', requireAdmin, async (req, res) => {
  try {
    const ref = db.collection(COL.links).doc(req.params.linkId);
    const snap = await ref.get();
    if (!snap.exists) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Link not found' } });
    }

    const updates = {};
    if (typeof req.body.active === 'boolean') {
      updates.active = req.body.active;
    }

    await ref.update(updates);
    const updated = (await ref.get()).data();

    return res.json({ success: true, link: updated });
  } catch (err) {
    console.error('update link error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

/* ================================================================
 * ADMIN — Transactions
 * ================================================================ */
app.get('/api/admin/transactions', requireAdmin, async (req, res) => {
  try {
    const snap = await db.collection(COL.transactions)
      .orderBy('created_at', 'desc')
      .limit(500)
      .get();

    const transactions = snap.docs.map(d => publicTx(d.data()));
    return res.json({ success: true, transactions });
  } catch (err) {
    console.error('list transactions error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

app.post('/api/admin/payment/:transactionId/approve', requireAdmin, async (req, res) => {
  try {
    const ref = db.collection(COL.transactions).doc(req.params.transactionId);
    const snap = await ref.get();
    if (!snap.exists) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Transaction not found' } });
    }
    const tx = snap.data();
    if (tx.status !== 'pending') {
      return res.status(409).json({ success: false, error: { code: 'INVALID_STATE', message: `Cannot approve a ${tx.status} transaction` } });
    }

    await ref.update({
      status: 'success',
      updated_at: new Date().toISOString()
    });

    const updated = (await ref.get()).data();
    return res.json({ success: true, transaction: publicTx(updated) });
  } catch (err) {
    console.error('approve error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
});

app.post('/api/admin/payment/:transactionId/reject', requireAdmin, async (req, res) => {
  try {
    const ref = db.collection(COL.transactions).doc(req.params.transactionId);
    const snap = await ref.get();
    if (!snap.exists) {
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Transaction not found' } });
    }
    const tx = snap.data();
    if (tx.status !== 'pending') {
      return res.status(409).json({ success: false, error: { code: 'INVALID_STATE', message: `Cannot reject a ${tx.status} transaction` } });
    }

    await ref.update({
      status: 'failed',
      updated_at: new Date().toISOString()
    });

    const updated = (await ref.get()).data();
    return res.json({ success: true, transaction: publicTx(updated) });
  } catch (err) {
    console.error('reject error:', err.message);
    return res.status(500).json({
      success: false,
      error: { code: 'SERVER_ERROR', message: 'Internal server error' }
    });
  }
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
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
    console.log(`   Admin user: ${process.env.ADMIN_USERNAME || 'admin'}`);
    console.log(`   Hash configured: ${!!process.env.ADMIN_PASSWORD_HASH}`);
    console.log(`   Firebase project: ${admin.app().options.projectId || 'unknown'}`);
  });
}

module.exports = app;
