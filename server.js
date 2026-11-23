'use strict';

require('dotenv').config();
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const OWNER_EMAIL = (process.env.OWNER_EMAIL || 'sajjadhossen10100@gmail.com').trim().toLowerCase();
const OWNER_SECRET_CODE = (process.env.OWNER_SECRET_CODE || '').trim();
const KEYAUTH_OWNER_ID = (process.env.KEYAUTH_OWNER_ID || 'F5NFiFQLOs').trim();
const KEYAUTH_APP_NAME = (process.env.KEYAUTH_APP_NAME || 'UX YouTube').trim();
const KEYAUTH_APP_VERSION = (process.env.KEYAUTH_APP_VERSION || '1.0').trim();
const KEYAUTH_APP_SECRET = (process.env.KEYAUTH_APP_SECRET || '').trim();
const FIRESTORE_DATABASE_ID = (process.env.FIRESTORE_DATABASE_ID || '').trim();
const ALLOWED_ORIGIN = (process.env.ALLOWED_ORIGIN || 'http://localhost:8080').trim();

// Initialize Firebase Admin SDK
let db = null;
if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  db = FIRESTORE_DATABASE_ID
    ? admin.firestore().databaseId === FIRESTORE_DATABASE_ID
      ? admin.firestore()
      : require('firebase-admin/firestore').getFirestore(admin.app(), FIRESTORE_DATABASE_ID)
    : admin.firestore();
}

// Security Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '64kb' }));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || origin === ALLOWED_ORIGIN) return cb(null, true);
    return cb(new Error('Origin not permitted by CORS policy'));
  },
  credentials: true
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Try again later.' }
});

const ownerCodeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Owner verification temporarily locked due to repeated attempts.' }
});

// Constant-time secret check using scrypt derivation
const SERVER_SCRYPT_SALT = crypto.randomBytes(16);
const EXPECTED_OWNER_DERIVED = OWNER_SECRET_CODE
  ? crypto.scryptSync(OWNER_SECRET_CODE, SERVER_SCRYPT_SALT, 32)
  : null;

function verifyOwnerSecretConstantTime(candidate) {
  if (!EXPECTED_OWNER_DERIVED || typeof candidate !== 'string' || !candidate.trim()) {
    return false;
  }
  const derived = crypto.scryptSync(candidate.trim(), SERVER_SCRYPT_SALT, 32);
  return crypto.timingSafeEqual(derived, EXPECTED_OWNER_DERIVED);
}

// Ephemeral in-memory Owner Session tokens (2-hour TTL)
const ownerSessions = new Map();
const OWNER_SESSION_TTL_MS = 2 * 60 * 60 * 1000;

async function requireFirebaseAuth(req, res, next) {
  if (!admin.apps.length) {
    return res.status(503).json({ error: 'Firebase Admin SDK is not configured on backend.' });
  }
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing Bearer ID token.' });
  }
  try {
    const decoded = await admin.auth().verifyIdToken(authHeader.slice(7));
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired authentication token.' });
  }
}

function requireVerifiedOwnerSession(req, res, next) {
  const email = (req.user && req.user.email || '').toLowerCase();
  if (email !== OWNER_EMAIL || !req.user.email_verified) {
    return res.status(403).json({ error: 'Restricted to verified Platform Owner.' });
  }
  const sessionToken = req.headers['x-owner-session'] || '';
  const session = ownerSessions.get(sessionToken);
  if (!session || session.uid !== req.user.uid || session.expiresAt < Date.now()) {
    return res.status(403).json({ error: 'Owner secret verification session required or expired.' });
  }
  return next();
}

// Serve Responsive Web Admin Dashboard
app.use(express.static(path.join(__dirname, 'public')));

// 1. Real Backend Health Check
app.get('/api/health', async (_req, res) => {
  const start = Date.now();
  let firestoreConnected = false;
  if (db) {
    try {
      await db.collection('user_profiles').limit(1).get();
      firestoreConnected = true;
    } catch (_) {
      firestoreConnected = false;
    }
  }
  res.json({
    ok: true,
    firestoreConnected,
    keyAuthConfigured: Boolean(KEYAUTH_APP_SECRET),
    ownerCodeConfigured: Boolean(OWNER_SECRET_CODE),
    latencyMs: Date.now() - start,
    timestampMillis: Date.now()
  });
});

// 2. KeyAuth Server-Side Proxy (keeps KEYAUTH_APP_SECRET strictly off client APK)
async function postKeyAuthForm(params) {
  const body = new URLSearchParams(params);
  const resp = await fetch('https://keyauth.win/api/1.2/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  return resp.json();
}

app.post('/api/keyauth/verify', authLimiter, requireFirebaseAuth, async (req, res) => {
  if (!KEYAUTH_APP_SECRET) {
    return res.status(503).json({ error: 'KEYAUTH_APP_SECRET is not configured on backend.' });
  }
  const { licenseKey, hwid } = req.body || {};
  if (typeof licenseKey !== 'string' || licenseKey.trim().length < 4 || typeof hwid !== 'string') {
    return res.status(400).json({ error: 'Valid licenseKey and hwid are required.' });
  }
  try {
    const init = await postKeyAuthForm({
      type: 'init',
      ver: KEYAUTH_APP_VERSION,
      name: KEYAUTH_APP_NAME,
      ownerid: KEYAUTH_OWNER_ID,
      secret: KEYAUTH_APP_SECRET
    });
    if (!init.success || !init.sessionid) {
      return res.status(401).json({ success: false, error: init.message || 'KeyAuth init failed' });
    }
    const lic = await postKeyAuthForm({
      type: 'license',
      key: licenseKey.trim(),
      hwid: hwid.trim(),
      sessionid: init.sessionid,
      name: KEYAUTH_APP_NAME,
      ownerid: KEYAUTH_OWNER_ID
    });
    const sub0 = lic.info && Array.isArray(lic.info.subscriptions) ? lic.info.subscriptions[0] : null;
    return res.json({
      success: Boolean(lic.success),
      message: lic.message || '',
      sessionId: lic.success ? init.sessionid : '',
      expiryEpochSec: sub0 ? Number(sub0.expiry || 0) : 0
    });
  } catch (err) {
    return res.status(502).json({ error: 'Failed to reach KeyAuth API.' });
  }
});

app.post('/api/keyauth/check', authLimiter, requireFirebaseAuth, async (req, res) => {
  const { sessionId } = req.body || {};
  if (!KEYAUTH_APP_SECRET || typeof sessionId !== 'string' || !sessionId) {
    return res.json({ valid: false });
  }
  try {
    const check = await postKeyAuthForm({
      type: 'check',
      sessionid: sessionId,
      name: KEYAUTH_APP_NAME,
      ownerid: KEYAUTH_OWNER_ID
    });
    return res.json({ valid: Boolean(check.success) });
  } catch (_) {
    return res.json({ valid: false });
  }
});

app.post('/api/keyauth/logout', requireFirebaseAuth, async (req, res) => {
  const { sessionId } = req.body || {};
  if (KEYAUTH_APP_SECRET && typeof sessionId === 'string' && sessionId) {
    try {
      await postKeyAuthForm({
        type: 'logout',
        sessionid: sessionId,
        name: KEYAUTH_APP_NAME,
        ownerid: KEYAUTH_OWNER_ID
      });
    } catch (_) { /* ignore */ }
  }
  res.json({ ok: true });
});

// 3. Private Owner Secret Code Verification (Constant-Time + Rate Limited + Audit Logged)
app.post('/api/owner/verify', ownerCodeLimiter, requireFirebaseAuth, async (req, res) => {
  const email = (req.user.email || '').toLowerCase();
  if (email !== OWNER_EMAIL || !req.user.email_verified) {
    return res.status(403).json({ verified: false, error: 'Unauthorized account.' });
  }
  const { ownerCode, deviceId, deviceLabel } = req.body || {};
  const ok = verifyOwnerSecretConstantTime(ownerCode);

  if (db) {
    await db.collection('admin_audit_logs').add({
      actorUid: req.user.uid,
      actorEmail: email,
      action: ok ? 'BACKEND_OWNER_VERIFY_OK' : 'BACKEND_OWNER_VERIFY_FAILED',
      targetUid: req.user.uid,
      deviceId: String(deviceId || 'web').slice(0, 128),
      detail: `Owner verification via backend (${String(deviceLabel || 'Web Dashboard').slice(0, 120)})`,
      timestampMillis: Date.now(),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  }

  if (!ok) {
    return res.status(403).json({ verified: false, error: 'Invalid Personal Owner Secret Code.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  ownerSessions.set(token, { uid: req.user.uid, expiresAt: Date.now() + OWNER_SESSION_TTL_MS });
  return res.json({
    verified: true,
    trustedDevice: true,
    ownerSessionToken: token,
    expiresAtMillis: Date.now() + OWNER_SESSION_TTL_MS
  });
});

// 4. Owner Admin Dashboard Real Data Endpoints
app.get('/api/admin/overview', requireFirebaseAuth, requireVerifiedOwnerSession, async (_req, res) => {
  if (!db) return res.status(503).json({ error: 'Database unavailable.' });
  try {
    const [usersSnap, eventsSnap, errorsSnap, auditSnap] = await Promise.all([
      db.collection('user_profiles').orderBy('lastActiveMillis', 'desc').limit(300).get(),
      db.collection('activity_events').orderBy('timestampMillis', 'desc').limit(250).get(),
      db.collection('api_logs').orderBy('timestampMillis', 'desc').limit(100).get(),
      db.collection('admin_audit_logs').orderBy('timestampMillis', 'desc').limit(100).get()
    ]);

    const users = usersSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
    const events = eventsSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
    const apiLogs = errorsSnap.docs.map((d) => ({ id: d.id, ...d.data() }));
    const auditLogs = auditSnap.docs.map((d) => ({ id: d.id, ...d.data() }));

    const now = Date.now();
    const day = 86400000;
    const summary = {
      totalUsers: users.length,
      activeToday: users.filter((u) => (u.lastActiveMillis || 0) >= now - day).length,
      activeWeek: users.filter((u) => (u.lastActiveMillis || 0) >= now - 7 * day).length,
      activeMonth: users.filter((u) => (u.lastActiveMillis || 0) >= now - 30 * day).length,
      blockedUsers: users.filter((u) => u.accountStatus === 'BLOCKED').length,
      totalAiRequests: users.reduce((acc, u) => acc + Number(u.aiRequestCount || 0), 0),
      totalProjects: users.reduce((acc, u) => acc + Number(u.projectCreateCount || 0), 0),
      totalErrors: users.reduce((acc, u) => acc + Number(u.errorCount || 0), 0)
    };

    return res.json({ summary, users, events, apiLogs, auditLogs });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to load admin overview.' });
  }
});

app.patch('/api/admin/users/:uid/status', requireFirebaseAuth, requireVerifiedOwnerSession, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database unavailable.' });
  const targetUid = String(req.params.uid || '').trim();
  const { accountStatus, role } = req.body || {};
  if (!targetUid || targetUid === req.user.uid) {
    return res.status(400).json({ error: 'Cannot modify own Owner account.' });
  }
  const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
  if (accountStatus === 'ACTIVE' || accountStatus === 'BLOCKED') {
    updates.accountStatus = accountStatus;
  }
  if (role === 'USER' || role === 'MODERATOR') {
    updates.role = role;
  }
  try {
    await db.collection('user_profiles').doc(targetUid).update(updates);
    await db.collection('admin_audit_logs').add({
      actorUid: req.user.uid,
      actorEmail: req.user.email,
      action: 'WEB_ADMIN_USER_UPDATE',
      targetUid,
      deviceId: 'web-dashboard',
      detail: JSON.stringify({ accountStatus, role }),
      timestampMillis: Date.now(),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ ok: true });
  } catch (_) {
    return res.status(500).json({ error: 'Failed to update user.' });
  }
});

app.listen(PORT, () => {
  console.log(`UX YouTube Secure Backend listening on port ${PORT}`);
});
