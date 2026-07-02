/**
 * Deepfook Server API
 * 
 * Environment Variables:
 * - DEBUG: Set to any value to enable debug logging for IP detection, MaxMind geolocation, anonymous candidate city updates, and liveness detection
 * - PORT: Server port (default: 9000)
 * - MAPBOX_ACCESS_TOKEN: Mapbox API token for geocoding
 * - MAXMIND: Path to MaxMind GeoLite2 City database (default: ./maxmind/GeoLite2-City.mmdb)
 * - FIREBASE_*: Firebase configuration variables
 * - S3_ENDPOINT: S3-compatible storage endpoint
 * - BUNNYKEY: Bunny.net API key for file uploads
 * - PUBLIC_APP_ORIGIN: Optional, e.g. https://in.xchk.io — base URL encoded inside /api/qr-* QR images (avoids 127.0.0.1 when the API is called directly)
 */

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const admin = require('./config/firebase');
const { connectDB, DBNAME } = require('./config/database');
const User = require('./models/User');
const Session = require('./models/Session');
const { generateSessionId } = require('./utils/sessionUtils');
const { proofPageUrl, qrConnectBridgeUrl } = require('./utils/proofUrl');
const { generateShortname } = require('./utils/shortnameUtils');
const crypto = require('crypto');
const net = require('net');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');
const https = require('https');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const maxmind = require('maxmind');
const QRCode = require('qrcode');
const mapboxgl = require('@mapbox/mapbox-sdk');
const geocoding = require('@mapbox/mapbox-sdk/services/geocoding');
const { sendPushNotification } = require('./utils/pushNotifications');
const { verifyEmailConfig, sendContactFormNotification, sendContactFormWelcome, sendWaitlistWelcome, sendPreRegistrationInvitation } = require('./utils/emailUtils');
const { getLinkedInProfileData } = require('./utils/linkedinUtils');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const mongoose = require('mongoose');
const Candidate = require('./models/Candidate');
const {
    normalizeSessionSource,
    isHelpdeskSource,
    calculateSessionDurationMinutes,
    recordCandidateSessionStarted,
    recordCandidateInteractionComplete
} = require('./utils/sessionSource');
const {
    findOrCreateHelpdeskCandidate,
    resolveHelpdeskSubject,
    resolveHelpdeskSessionId,
    ensureHelpdeskSubjectUserRecord,
    attachHelpdeskCandidateToSession,
    resolveZendeskTicketContext,
    cleanupAnonUser,
    isPlaceholderTicketEmail,
    findCandidateByMobileForInterviewer,
    helpdeskSubjectDisplayName,
    resolveHelpdeskOperatorLabel,
    resolveHelpdeskOperatorFields,
    isHelpdeskMobileCheckedIn,
    resolveCheckingInUserForVerification,
    recordHelpdeskPhoneEmailLink
} = require('./utils/helpdeskSession');
const { cleanupStaleAnonUsers } = require('./utils/anonUserCleanup');
const { verifyFirebaseIdToken } = require('./utils/verifyFirebaseIdToken');
const Invite = require('./models/Invite');
const PreRegistration = require('./models/Enrollment');
const {
    findActivePreRegistration,
    findCompletedPreRegistrationByCode,
    findRevokedPreRegistrationByCode,
    notRevokedFilter,
    normalizePreregCode,
    preRegistrationClientFlags,
    recordDesktopEnrollmentLinkOpen,
    signBaselinePhotoUploads,
    buildBaselinePhotoKey,
    photoUrlsMatchCode,
    BASELINE_PHOTO_COUNT,
    isValidPin,
    hashPin,
    verifyPin,
    findCompletedPreRegistration,
    usableContactMobile,
    resolveRealMobileForEmail,
    applyMobileSuffixOverride,
    resolvePreRegistrationForSession,
    getSessionPinRequirement,
    buildPinSessionFields,
    buildSessionVerificationFields,
    resolveSessionSubjectEmail,
    sessionUsesPinEntry,
    getSessionLivenessScore,
    syncPreRegistrationToCandidate,
    mergeEmailVerification,
    mergeBaselineVerification,
    resolveExpectedLocation,
    persistBaselineToCandidate,
    isPlaceholderLocation,
    buildSessionVerifiedIdentity,
    sanitizeCandidateVerified
} = require('./utils/enrollmentUtils');
const { computeIdentityRisk, computeConfidenceIndicator, computeConsistency } = require('./utils/identityRiskUtils');
const { attachThreatAssessment } = require('./services/verificationThreatAnalysisService');
const { ensureTurnStatsForSession } = require('./services/coturnLogService');
const { attachVerificationTelemetry } = require('./utils/verificationTelemetryUtils');
const {
    resolveHistoryUser,
    canAccessCandidatePhotoHistory,
    buildCandidatePhotoHistory
} = require('./utils/sessionHistoryPhotos');

// Import routes
const candidateRoutes = require('./routes/candidates');
const authRoutes = require('./routes/auth');
const integratorRoutes = require('./routes/integrator');
const zendeskIntegratorRoutes = require('./routes/zendeskIntegrator');
const ssoIntegratorRoutes = require('./routes/ssoIntegrator');
const zendeskOAuthRoutes = require('./routes/zendeskOAuth');
const webhookRoutes = require('./routes/webhooks');
const whatsappRoutes = require('./routes/whatsapp');
const teamRoutes = require('./routes/team');
const proveitsmeRoutes = require('./routes/proveitsme');
const { acceptTeamInvite, canManageTeam, getTeamForUser, cleanupTeamConnectionsForUser } = require('./services/teamService');
const { requestForgetMe, confirmForgetMe, getForgetMeOptions, previewForgetMe, requestForgetMeByEmail } = require('./services/forgetMeService');
const { sendEnrollmentWelcome, sendSignupWelcome, shouldSendSignupWelcomeOnLogin } = require('./services/welcomeEmailService');
const {
    getUserDeletionScope,
    collectScreenshotKeys,
    deleteUserAndAllData
} = require('./services/userDeletionService');
const { actorFromUser, recordAuditEventAsync, listAuditEvents } = require('./services/auditLogService');
const {
    invitePreRegistrationBatch,
    normalizeEmailList,
    resolveInviterUser,
    ensureSelfEnrollmentInvite
} = require('./services/enrollmentInviteService');
const { dispatchIntegratorWebhook } = require('./utils/webhookUtils');
const {
    authenticateFirebaseOrApiKey
} = require('./middleware/integratorAuth');
const { syncZendeskTicketResult } = require('./utils/zendeskSync');
const { resolveIntegratorUser } = require('./utils/integratorAccount');
const { deriveEntraCompanyName } = require('./utils/entraCompany');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, '../s');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Generate a temporary name that will be renamed later
        const tempName = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, tempName + '.png');
    }
});

const upload = multer({ storage: storage });

const app = express();
app.set('trust proxy', true);
const port = process.env.PORT || 9000;

// Initialize Mapbox client
const mapboxClient = mapboxgl({ accessToken: process.env.MAPBOX_ACCESS_TOKEN });
const geocodingService = geocoding(mapboxClient);

// Connect to MongoDB
connectDB().then(() => {
  // Run session cleanup on startup after DB connects
  const Session = require('./models/Session');
  const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
  const ninetyMinAgo = new Date(Date.now() - 90 * 60 * 1000);
  
  // Close stale non-interview sessions (>5min)
  Session.updateMany(
    { status: { $ne: 'closed' }, source: { $nin: ['interview', 'social', 'lite'] }, createdAt: { $lt: fiveMinAgo } },
    { $set: { status: 'closed', closedAt: new Date() } }
  ).then(r => {
    if (r.modifiedCount > 0) console.log('Startup cleanup: closed ' + r.modifiedCount + ' stale helpdesk/zendesk sessions');
  }).catch(e => console.error('Startup session cleanup error:', e));
  
  // Close stale interview sessions (>90min)
  Session.updateMany(
    { status: { $ne: 'closed' }, source: 'interview', createdAt: { $lt: ninetyMinAgo } },
    { $set: { status: 'closed', closedAt: new Date() } }
  ).then(r => {
    if (r.modifiedCount > 0) console.log('Startup cleanup: closed ' + r.modifiedCount + ' stale interview sessions');
  }  ).catch(e => console.error('Startup interview cleanup error:', e));

  cleanupStaleAnonUsers().catch(e => console.error('Startup anon user cleanup error:', e));
});

// Initialize MaxMind database
initializeMaxMind().catch(error => {
    console.error('Failed to initialize MaxMind database:', error);
});



// Middleware
const corsAllowlist = [
    'https://in.xchk.io',
    'https://xchk.io',
    'http://localhost:3000',
    'http://localhost:9000'
];
app.use(cors({
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }
    if (corsAllowlist.includes(origin)) {
      return callback(null, true);
    }
    if (/^https:\/\/[a-z0-9][a-z0-9-]*\.zendesk\.com$/i.test(origin)) {
      return callback(null, true);
    }
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true
}));

// Security headers via helmet
app.use(helmet({
  contentSecurityPolicy: false, // CSP managed by nginx
  crossOriginEmbedderPolicy: false
}));

// Global rate limiter — generous, for general API protection
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  message: { error: 'Too many requests, please try again later' }
});
app.use('/api', globalLimiter);

// Strict rate limiter for auth-sensitive endpoints (login, PIN, checkin, contact, forget-me)
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  message: { error: 'Too many attempts, please try again later' }
});

app.use('/api/whatsapp', express.json({
  verify(req, res, buf) {
    req.rawBody = buf;
  }
}), whatsappRoutes);
// Stripe webhook: must come BEFORE express.json() — collect raw body from stream
function stripeWebhookRawBody(req, res, next) {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    req.body = Buffer.concat(chunks);
    next();
  });
  req.on('error', (err) => {
    console.error('Stripe webhook body read error:', err.message);
    res.status(400).send('Webhook Error');
  });
}
app.post('/api/payment/webhook', stripeWebhookRawBody, async (req, res) => {
  // Delegate to the handler defined below (will be hoisted)
  if (typeof handleStripeWebhook === 'function') {
    await handleStripeWebhook(req, res);
  } else {
    // Handler not yet registered — route will be re-registered later
    res.status(503).send('Webhook handler not ready');
  }
});
app.use(express.json());

// Session middleware for OAuth
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

function requestPublicOrigin(req) {
    const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https')
        .split(',')[0]
        .trim();
    const host = String(req.headers['x-forwarded-host'] || req.get('host') || '')
        .split(',')[0]
        .trim() || 'xchk.io';
    return `${proto}://${host}`;
}

/** Base URL embedded inside generated QR images (never 127.0.0.1 unless PUBLIC_APP_ORIGIN says so). */
function originForQrEncodedLinks(req) {
    const explicit = process.env.PUBLIC_APP_ORIGIN;
    if (explicit && String(explicit).trim()) {
        try {
            return new URL(String(explicit).trim()).origin;
        } catch (e) {
            return String(explicit).trim().replace(/\/$/, '');
        }
    }
    if (process.env.FRONTEND_URL) {
        try {
            return new URL(process.env.FRONTEND_URL).origin;
        } catch (e) {
            /* ignore */
        }
    }
    const fromRequest = requestPublicOrigin(req);
    try {
        const u = new URL(fromRequest);
        const h = u.hostname;
        if (h === '127.0.0.1' || h === 'localhost' || h === '0.0.0.0') {
            return 'https://in.xchk.io';
        }
    } catch (e) {
        return 'https://in.xchk.io';
    }
    return fromRequest;
}

// First scan opens this URL; response is PNG of a QR that encodes /v?c= (connect URL)
app.get('/api/qr-connect', async (req, res) => {
    try {
        const c = req.query.c;
        if (!c || typeof c !== 'string' || !/^[a-f0-9]{8}$/i.test(c)) {
            return res.status(400).json({ error: 'Invalid or missing code' });
        }
        const origin = originForQrEncodedLinks(req);
        const sessionId = req.query.s || null;
        const innerUrl = proofPageUrl(origin, c, sessionId);
        const png = await QRCode.toBuffer(innerUrl, {
            type: 'png',
            errorCorrectionLevel: 'H',
            margin: 2,
            width: 320
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'no-store');
        return res.send(png);
    } catch (error) {
        console.error('qr-connect error:', error);
        res.status(500).json({ error: 'Failed to generate QR' });
    }
});

function isValidInterviewSessionParam(session) {
    return (
        typeof session === 'string' &&
        session.length >= 4 &&
        session.length <= 512 &&
        /^[\w.-]+$/.test(session)
    );
}

// PNG: QR encodes mobile.html?session= (second scan for interview onboarding)
app.get('/api/qr-mobile-inner', async (req, res) => {
    try {
        const session = req.query.session;
        if (!isValidInterviewSessionParam(session)) {
            return res.status(400).json({ error: 'Invalid or missing session' });
        }
        const origin = originForQrEncodedLinks(req);
        const mobileUrl = `${origin}/mobile.html?session=${encodeURIComponent(session)}`;
        const png = await QRCode.toBuffer(mobileUrl, {
            type: 'png',
            errorCorrectionLevel: 'H',
            margin: 2,
            width: 480
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'no-store');
        return res.send(png);
    } catch (error) {
        console.error('qr-mobile-inner error:', error);
        res.status(500).json({ error: 'Failed to generate QR' });
    }
});

// PNG: QR encodes enroll.html?r= (enrollment baseline)
app.get('/api/qr-preregister', async (req, res) => {
    try {
        const r = req.query.r;
        if (!r || typeof r !== 'string' || !/^\d{6}$/.test(r)) {
            return res.status(400).json({ error: 'Invalid or missing enrollment code' });
        }
        const origin = originForQrEncodedLinks(req);
        const mobileUrl = `${origin}/enroll.html?r=${encodeURIComponent(r)}`;
        const png = await QRCode.toBuffer(mobileUrl, {
            type: 'png',
            errorCorrectionLevel: 'H',
            margin: 2,
            width: 320
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'public, max-age=604800');
        return res.send(png);
    } catch (error) {
        console.error('qr-preregister error:', error);
        res.status(500).json({ error: 'Failed to generate QR' });
    }
});

// PNG: QR encodes forget-me.html?token= (account deletion confirm)
app.get('/api/qr-forget-me', async (req, res) => {
    try {
        const token = req.query.token;
        const { parseForgetMeToken } = require('./utils/forgetMeToken');
        if (!token || typeof token !== 'string' || !parseForgetMeToken(token)) {
            return res.status(400).json({ error: 'Invalid or missing confirmation token' });
        }
        const origin = originForQrEncodedLinks(req);
        const mobileUrl = `${origin}/forget-me.html?token=${encodeURIComponent(token)}`;
        const png = await QRCode.toBuffer(mobileUrl, {
            type: 'png',
            errorCorrectionLevel: 'H',
            margin: 2,
            width: 320
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'no-store');
        return res.send(png);
    } catch (error) {
        console.error('qr-forget-me error:', error);
        res.status(500).json({ error: 'Failed to generate QR' });
    }
});

// PNG: QR encodes index.html?invite= (team invitation — no email in URL)
app.get('/api/qr-team-invite', async (req, res) => {
    try {
        const invite = req.query.invite || req.query.code;
        if (!invite || typeof invite !== 'string' || !/^\d{6}$/.test(invite)) {
            return res.status(400).json({ error: 'Invalid or missing team invitation code' });
        }
        const origin = originForQrEncodedLinks(req);
        const mobileUrl = `${origin}/index.html?invite=${encodeURIComponent(invite)}`;
        const png = await QRCode.toBuffer(mobileUrl, {
            type: 'png',
            errorCorrectionLevel: 'H',
            margin: 2,
            width: 320
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'public, max-age=604800');
        return res.send(png);
    } catch (error) {
        console.error('qr-team-invite error:', error);
        res.status(500).json({ error: 'Failed to generate QR' });
    }
});

// PNG: QR encodes an allowed same-site URL (e.g. full mobile.html link for desktop handoff)
app.get('/api/qr-link', async (req, res) => {
    try {
        const rawUrl = req.query.url;
        if (typeof rawUrl !== 'string' || rawUrl.length < 8 || rawUrl.length > 2048) {
            return res.status(400).json({ error: 'Invalid or missing url' });
        }
        let parsed;
        try {
            parsed = new URL(rawUrl);
        } catch {
            return res.status(400).json({ error: 'Invalid url' });
        }
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return res.status(400).json({ error: 'Invalid url protocol' });
        }
        const allowedHosts = new Set(['in.xchk.io', 'xchk.io', 'localhost', '127.0.0.1']);
        if (!allowedHosts.has(parsed.hostname)) {
            return res.status(400).json({ error: 'Url host not allowed' });
        }
        const png = await QRCode.toBuffer(rawUrl, {
            type: 'png',
            errorCorrectionLevel: 'H',
            margin: 2,
            width: 480
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'no-store');
        return res.send(png);
    } catch (error) {
        console.error('qr-link error:', error);
        res.status(500).json({ error: 'Failed to generate QR' });
    }
});

// PNG: QR encodes URL to /api/qr-mobile-inner (first scan; opens inner QR image)
app.get('/api/qr-mobile-outer', async (req, res) => {
    try {
        const session = req.query.session;
        if (!isValidInterviewSessionParam(session)) {
            return res.status(400).json({ error: 'Invalid or missing session' });
        }
        const origin = originForQrEncodedLinks(req);
        const innerApiUrl = `${origin}/api/qr-mobile-inner?session=${encodeURIComponent(session)}`;
        const png = await QRCode.toBuffer(innerApiUrl, {
            type: 'png',
            errorCorrectionLevel: 'H',
            margin: 2,
            width: 600
        });
        res.set('Content-Type', 'image/png');
        res.set('Cache-Control', 'no-store');
        return res.send(png);
    } catch (error) {
        console.error('qr-mobile-outer error:', error);
        res.status(500).json({ error: 'Failed to generate QR' });
    }
});

// Use routes
app.use('/api/candidates', candidateRoutes);
app.use('/api/integrator', integratorRoutes);
app.use('/api/integrator/zendesk', zendeskIntegratorRoutes);
app.use('/api/integrator/sso', ssoIntegratorRoutes);
app.use('/api/webhooks', webhookRoutes);
app.use('/api/team', teamRoutes);
app.use('/api/proveitsme', proveitsmeRoutes);
app.use('/auth', authRoutes);
app.use('/auth/zendesk', zendeskOAuthRoutes);

// API root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Deepfook Server API',
    version: '1.0.0',
    endpoints: {
      checkin: 'POST /api/checkin',
      login: 'POST /api/login',
      session: 'GET /api/session',
      candidates: '/api/candidates/*',
      contact: {
        submit: 'POST /api/contact',
        list: 'GET /api/contact (authenticated)',
        update: 'PATCH /api/contact/:id (authenticated)'
      }
    }
  });
});

// Authentication middleware
const { resolveToken } = require('./utils/resolveToken');

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  const result = await resolveToken(token);
  if (!result.ok) return res.status(403).json(result);

  // Load MongoDB user for RBAC fields
  const mongoUser = await User.findOne({ firebaseUid: result.user.uid }).lean();
  req.user = {
    uid: result.user.uid,
    email: result.user.email,
    authMethod: result.user._auth || null,
    subjectEmail: result.user.subjectEmail || null,
    operatorEmail: result.user.operatorEmail || null,
    operatorName: result.user.operatorName || null,
    siteAdmin: mongoUser ? mongoUser.siteAdmin : false,
    emailVerified: mongoUser ? !!mongoUser.emailVerified : false,
    welcomeHelpdesk: mongoUser ? !!mongoUser.welcomeHelpdesk : false,
    welcomeAttest: mongoUser ? !!mongoUser.welcomeAttest : false,
    plan: mongoUser ? mongoUser.plan : null,
    addons: mongoUser ? (mongoUser.addons || []) : [],
    tier: mongoUser ? mongoUser.tier : null
  };
  next();
};

// Return current user profile including admin status
app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const mongoUser = await User.findOne({ firebaseUid: req.user.uid });
        let needsBaselineRegistration = false;
        if (mongoUser && !mongoUser.emailVerified && mongoUser.email) {
            const activePreReg = await PreRegistration.findOne({
                email: mongoUser.email.toLowerCase(),
                baselineSubmittedAt: null,
                expirationDate: { $gt: new Date() },
                ...notRevokedFilter()
            }).sort({ dateInvited: -1 });
            needsBaselineRegistration = !!activePreReg;
        }
        const canManage = mongoUser ? await canManageTeam(mongoUser) : false;
        const { team, role } = mongoUser ? await getTeamForUser(mongoUser) : { team: null, role: null };
        const zendeskLaunch = req.user.authMethod === 'zendesk_launch' || req.user.authMethod === 'sso_launch';
        res.json({
            siteAdmin: req.user.siteAdmin,
            email: zendeskLaunch ? (req.user.operatorEmail || req.user.email) : req.user.email,
            operatorEmail: req.user.operatorEmail || null,
            operatorName: req.user.operatorName || null,
            subjectEmail: zendeskLaunch ? (req.user.subjectEmail || req.user.email) : null,
            zendeskLaunch,
            welcomeHelpdesk: mongoUser ? !!mongoUser.welcomeHelpdesk : false,
            welcomeAttest: mongoUser ? !!mongoUser.welcomeAttest : false,
            emailVerified: !!(mongoUser && mongoUser.emailVerified),
            registrationConfirmed: !!(mongoUser && mongoUser.emailVerified),
            needsBaselineRegistration,
            plan: mongoUser ? mongoUser.plan : null,
            tier: mongoUser ? mongoUser.tier : null,
            canManageTeam: canManage,
            teamRole: role,
            teamName: team ? team.name : null,
            entraOid: mongoUser ? mongoUser.entraOid || null : null,
            companyName: mongoUser ? mongoUser.companyName || null : null
        });
    } catch (error) {
        console.error('/api/me error:', error);
        res.status(500).json({ error: 'Failed to load profile' });
    }
});

// Mark welcome seen — frontend calls this on dismiss
app.post("/api/me/welcomeSeen", authenticateToken, async (req, res) => {
  try {
    const field = req.body.field;
    console.log('welcomeSeen called:', { field, uid: req.user.uid, email: req.user.email });
    if (field !== 'welcomeHelpdesk' && field !== 'welcomeAttest') {
      return res.status(400).json({ error: 'Invalid field; use welcomeHelpdesk or welcomeAttest' });
    }
    const updated = await User.findOneAndUpdate(
      { firebaseUid: req.user.uid },
      { $set: { [field]: true } },
      { new: true }
    );
    if (!updated) {
      console.log('welcomeSeen: user not found for uid', req.user.uid);
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('welcomeSeen set', field, 'for', req.user.email, 'result:', updated[field]);
    res.json({ ok: true, [field]: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/forget-me/options', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const options = await getForgetMeOptions(user);
        res.json(options);
    } catch (error) {
        console.error('GET /api/forget-me/options error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Failed to load Forget Me options' });
    }
});

app.post('/api/forget-me/request', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user) {
            // User was already deleted — clean up Firebase auth
            const fbEmail = req.user.email || '';
            console.log('Forget-me: user not found in DB (already deleted), clearing for', fbEmail);
            try { await admin.auth().deleteUser(req.user.uid); } catch (e) {}
            return res.status(410).json({ error: 'Your account has already been removed from xChk. You may need to log out and back in.' });
        }
        const result = await requestForgetMe(user);
        res.json({
            sent: true,
            channel: result.channel,
            contact: result.contact,
            requiresPin: result.requiresPin,
            requiresPassword: result.requiresPassword,
            expiresAt: result.expiresAt
        });
    } catch (error) {
        console.error('POST /api/forget-me/request error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Failed to send confirmation message' });
    }
});

app.post('/api/forget-me/public-request', authLimiter, async (req, res) => {
    try {
        const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
        await requestForgetMeByEmail(email);
        res.json({
            sent: true,
            message: 'If we have your data on file, check your email on your phone. Scan the QR code, enter your PIN, and removal is final.'
        });
    } catch (error) {
        console.error('POST /api/forget-me/public-request error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Failed to process request' });
    }
});

app.get('/api/forget-me/preview', async (req, res) => {
    try {
        const token = req.query?.token;
        if (!token) {
            return res.status(400).json({ error: 'Confirmation token is required' });
        }
        const preview = await previewForgetMe(token);
        res.json(preview);
    } catch (error) {
        console.error('GET /api/forget-me/preview error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Invalid confirmation link' });
    }
});

app.post('/api/forget-me/confirm', async (req, res) => {
    try {
        const token = req.body?.token || req.query?.token;
        if (!token) {
            return res.status(400).json({ error: 'Confirmation token is required' });
        }
        // Capture mobile before deletion for farewell SMS
        let userMobile = null;
        let userEmail = null;
        try {
            const { parseForgetMeToken } = require('./utils/forgetMeToken');
            const parsed = parseForgetMeToken(token); console.log("ForgetMe token parsed:", parsed ? (parsed.subjectType + "/" + parsed.subjectId.substring(0,8)) : "null");
            if (parsed) {
                const User = require('./models/User');
                const Session = require('./models/Session');
                if (parsed.subjectType === 'user') {
                    const u = await User.findById(parsed.subjectId).select('mobile email').lean();
                    if (u) {
                        userEmail = u.email;
                        if (u.mobile) userMobile = u.mobile;
                    }
                } else if (parsed.subjectType === 'enrollment') {
                    // Enrollment tokens have the enrollment ID — look up PreReg for email
                    const PreReg = require('./models/PreReg');
                    const pr = await PreReg.findOne({ code: parsed.subjectId }).select('email').lean();
                    if (pr) userEmail = pr.email;
                }
                // Fallback: check sessions for a mobile number
                if (!userMobile && userEmail) {
                    const s = await Session.findOne({ email: userEmail, mobile: { $exists: true, $ne: null, $ne: '' } })
                        .select('mobile').sort({ createdAt: -1 }).lean();
                    if (s && s.mobile) userMobile = s.mobile;
                }
            }
        } catch (e) { console.error("Forget-me mobile lookup failed:", e.message); }
        const pin = typeof req.body?.pin === 'string' ? req.body.pin.trim() : '';
        const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
        const password = typeof req.body?.password === 'string' ? req.body.password : '';
        const result = await confirmForgetMe(token, {
            pin: pin || undefined,
            email: email || undefined,
            password: password || undefined
        });
        queueAdminScreenshotCleanup(result.b2Keys, result.audit);
        console.log(JSON.stringify(result.audit));
        res.json({
            deleted: true,
            candidates: result.candidates,
            sessions: result.sessions,
            screenshotFilesQueued: result.screenshotCount,
            fileCleanup: 'background',
            teamCleanup: result.teamCleanup
        });
        console.log("ForgetMe mobile=" + (userMobile || "none") + " email=" + (userEmail || "none"));
        // Send farewell SMS
        if (userMobile) {
            try {
                const { sendMessage } = require('./utils/messagingUtils');
                const c = result.candidates || 0;
                const s = result.sessions || 0;
                const sc = result.screenshotCount || 0;
                const total = c + s + sc;
                const msg = '*Poof* you\'re gone from xChk. We removed ' + total + ' ' + (total === 1 ? 'record' : 'records') + ' (' + c + ' ' + (c === 1 ? 'profile' : 'profiles') + ', ' + s + ' ' + (s === 1 ? 'verification' : 'verifications') + ', ' + sc + ' ' + (sc === 1 ? 'photo' : 'photos') + '). You\'re welcome back any time.';
                await sendMessage(userMobile, msg, 'sms');
            } catch (smsErr) { console.error('Forget-me SMS failed:', smsErr.message); }
        }
    } catch (error) {
        console.error('POST /api/forget-me/confirm error:', error);
        res.status(error.status || 500).json({ error: error.message || 'Failed to delete account' });
    }
});

// Return verification history for the current operator
app.get('/api/me/history', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user) return res.json({ sessions: [], count: 0 });
        const Candidate = require('./models/Candidate');
        const candidates = await Candidate.find({ interviewer: user._id }).select('_id email').lean();
        const candidateIds = candidates.map(c => c._id);
        const candidateEmails = candidates.map(c => c.email);
        const Session = require('./models/Session');
        const sessions = await Session.find({
            $or: [
                { candidateId: { $in: candidateIds } },
                { email: { $in: candidateEmails }, source: { $in: ['helpdesk', 'zendesk'] } },
                { email: user.email.toLowerCase(), source: 'attestation' },
                { operatorEmail: user.email.toLowerCase(), source: 'attestation' }
            ]
        })
        .select('sessionId email createdAt expiresAt status helpdeskResult helpdeskResultAt source candidateId screenshots attestationId operatorEmail operatorName deviceFingerprint')
        .sort({ createdAt: -1 })
        .limit(100)
        .lean();
        const list = sessions.map(s => ({
            sessionId: s.sessionId,
            email: s.email,
            createdAt: s.createdAt,
            expiresAt: s.expiresAt || null,
            status: s.status || null,
            result: s.helpdeskResult || null,
            rating: s.rating || null,
            resultAt: s.helpdeskResultAt || null,
            source: s.source,
            attestationId: s.attestationId ? String(s.attestationId) : null,
            shortname: (s.screenshots && s.screenshots.length && s.screenshots[0].shortname) || null,
            operatorEmail: s.operatorEmail || null,
            operatorName: s.operatorName || null,
        }));

        // Enrich with subject identity info (looked up once per unique email)
        const userCache = {};
        for (const entry of list) {
            const email = entry.email && !entry.email.endsWith('@anon') ? entry.email : null;
            if (!email || userCache[email]) continue;
            try {
                const sub = await User.findOne({ email }).select('authLevel diditVerified kycDocLabel verified linkedinId').lean();
                if (sub) userCache[email] = sub;
            } catch(e) {}
        }
        for (const entry of list) {
            const email = entry.email && !entry.email.endsWith('@anon') ? entry.email : null;
            const sub = email ? userCache[email] : null;
            entry.authLevel = sub?.authLevel || null;
            entry.diditVerified = !!sub?.diditVerified;
            entry.kycDocLabel = sub?.kycDocLabel || null;
            entry.linkedinName = sub?.verified?.name || null;
            entry.linkedinTitle = sub?.verified?.title || null;
        }
        res.json({ sessions: list, count: list.length });
    } catch (error) {
        console.error('History error:', error);
        res.status(500).json({ error: 'Failed to load history' });
    }
});

// Lightweight polling endpoint — returns attestations responded since a timestamp
// Used by Hermes and other agents to efficiently check for new results
app.get('/api/me/poll', authenticateToken, async (req, res) => {
    try {
        const since = req.query.since ? new Date(req.query.since) : new Date(Date.now() - 30000);
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user) return res.json({ attestations: [] });
        const email = user.email.toLowerCase();
        const Attestation = require('./models/Attestation');
        const atts = await Attestation.find({
            $or: [
                { requesterEmail: email, respondedAt: { $gt: since }, status: { $in: ['completed', 'declined'] } },
                { targetEmail: email, respondedAt: { $gt: since }, status: { $in: ['completed', 'declined'] } }
            ]
        })
        .select('_id prompt type amount currency status response respondedAt targetEmail requesterEmail')
        .sort({ respondedAt: -1 })
        .limit(20)
        .lean();
        res.json({
            attestations: atts.map(a => ({
                id: String(a._id),
                prompt: a.prompt,
                type: a.type,
                amount: a.amount,
                currency: a.currency,
                status: a.status,
                response: a.response,
                respondedAt: a.respondedAt,
                targetEmail: a.targetEmail,
                requesterEmail: a.requesterEmail
            }))
        });
    } catch (error) {
        console.error('Poll error:', error);
        res.status(500).json({ error: 'Failed to poll' });
    }
}); // end poll

// Save/update Telegram chat ID for the current user
app.put('/api/me/telegram', authenticateToken, async (req, res) => {
    try {
        const { chatId } = req.body;
        if (chatId !== null && chatId !== undefined && !/^\d+$/.test(String(chatId))) {
            return res.status(400).json({ error: 'Invalid Telegram chat ID' });
        }
        const val = chatId ? String(chatId).trim() : null;
        await User.findOneAndUpdate({ firebaseUid: req.user.uid }, { telegramChatId: val });
        res.json({ ok: true, telegramChatId: val });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Read Telegram chat ID for the current user
app.get('/api/me/telegram', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid }).select('telegramChatId').lean();
        res.json({ telegramChatId: user?.telegramChatId || null });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Helper function to download and save LinkedIn profile photo
async function downloadAndSaveLinkedInPhoto(linkedinId, firebaseUid) {
  try {
    const photoUrl = extractLinkedInPhotoUrl(linkedinId);
    if (!photoUrl) return null;

    // Create 'p' directory if it doesn't exist
    const pDir = path.join(__dirname, '../p');
    if (!fs.existsSync(pDir)) {
      fs.mkdirSync(pDir, { recursive: true });
    }

    const filePath = path.join(pDir, `${firebaseUid}.jpg`);

    return new Promise((resolve, reject) => {
      const options = {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Referer': 'https://www.linkedin.com/',
          'sec-ch-ua': '"Google Chrome";v="91", "Chromium";v="91"',
          'sec-ch-ua-mobile': '?0',
          'Sec-Fetch-Dest': 'image',
          'Sec-Fetch-Mode': 'no-cors',
          'Sec-Fetch-Site': 'cross-site'
        }
      };

      https.get(photoUrl, options, (response) => {
        if (response.statusCode !== 200) {
          console.error('Failed to download image:', {
            statusCode: response.statusCode,
            headers: response.headers,
            url: photoUrl
          });
          reject(new Error(`Failed to download image: ${response.statusCode}`));
          return;
        }

        const fileStream = fs.createWriteStream(filePath);
        response.pipe(fileStream);

        fileStream.on('finish', () => {
          fileStream.close();
          resolve(filePath);
        });

        fileStream.on('error', (err) => {
          fs.unlink(filePath, () => {}); // Delete the file if there's an error
          reject(err);
        });
      }).on('error', (err) => {
        console.error('Network error while downloading image:', err);
        reject(err);
      });
    });
  } catch (error) {
    console.error('Error downloading LinkedIn photo:', error);
    return null;
  }
}

// Function to update user's verified data in background
async function updateUserVerifiedData(userId, linkedinId) {
    try {
        const username = linkedinId.split('/').pop().split('?')[0];
        const verified = await getLinkedInProfileData(username);
        
        // Update user with verified data
        await User.findByIdAndUpdate(userId, { verified });
        console.log('Successfully updated verified data for user:', userId);
    } catch (error) {
        console.error('Error updating verified data in background:', error);
    }
}

// Login endpoint
function normalizeRegistrationDisplayName(value) {
    if (typeof value !== 'string') return '';
    return value.trim().slice(0, 100);
}

function normalizeLoginFrom(value) {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim().slice(0, 64);
    if (!trimmed || !/^[a-zA-Z0-9._/-]+$/.test(trimmed)) return null;
    return trimmed;
}

function resolveAuthProvider({ explicitProvider, signInProvider, isLinkedInLogin, isEntraLogin, isFacebookLogin }) {
    if (isEntraLogin) return 'microsoft.com';
    if (isLinkedInLogin) return 'linkedin.com';
    if (isFacebookLogin) return 'facebook.com';
    if (signInProvider === 'password') return 'password';
    if (explicitProvider) return explicitProvider;
    return signInProvider || 'unknown';
}

function resolveAuthLevel(provider) {
    if (!provider || provider === 'unknown') return 'none';
    if (provider === 'linkedin.com') return 'linkedin';
    if (provider === 'microsoft.com') return 'entra';
    if (['password', 'google.com', 'facebook.com', 'github.com', 'apple.com'].includes(provider)) return 'oauth';
    return 'firebase';
}

function applyEntraCompany(user, companyName, email) {
    const company = deriveEntraCompanyName({ companyName, email });
    if (!company) return;
    if (!user.company || !String(user.company).trim()) {
        user.company = company;
    }
}

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const {
      idToken,
      linkedinId,
      entraOid,
      entraTenantId,
      interviewOnly,
      inviteCode,
      inviteSecret,
      provider: explicitProvider,
      displayName: requestedDisplayNameRaw,
      loginFrom: loginFromRaw,
      companyName: entraCompanyNameRaw
    } = req.body;
    const requestedDisplayName = normalizeRegistrationDisplayName(requestedDisplayNameRaw);
    const loginFrom = normalizeLoginFrom(loginFromRaw);
    const entraCompanyName = typeof entraCompanyNameRaw === 'string' ? entraCompanyNameRaw.trim().slice(0, 200) : '';
    
    if (!idToken) {
      return res.status(400).json({ error: 'ID token is required' });
    }

    const decodedToken = await verifyFirebaseIdToken(idToken);
    const customToken = await admin.auth().createCustomToken(decodedToken.uid);
    const signInProvider = decodedToken.firebase?.sign_in_provider;

    // Get or create user in MongoDB
    let user = await User.findOne({ firebaseUid: decodedToken.uid });
    
    // If not found by firebaseUid, check by email to handle existing user properly
    if (!user && decodedToken.email) {
      user = await User.findOne({ email: decodedToken.email.toLowerCase() });
      if (user) {
        console.log('🔗 Found existing user by email during login:', {
          email: decodedToken.email,
          existingFirebaseUid: user.firebaseUid,
          newFirebaseUid: decodedToken.uid
        });
        
        if (user.firebaseUid !== decodedToken.uid) {
          const tokenEmail = decodedToken.email.toLowerCase();
          const userEmail = (user.email || '').toLowerCase();
          if (signInProvider === 'password' && userEmail === tokenEmail) {
            user.firebaseUid = decodedToken.uid;
            await user.save();
            console.log('🔗 Reconciled Firebase UID for password login:', userEmail, '->', decodedToken.uid);
          } else {
            console.log('⚠️ Firebase UID mismatch during login - frontend should use linkWithCredential');
            return res.status(409).json({ 
              error: 'Account already exists',
              message: 'An account with this email already exists. Please use the upgrade flow.',
              existingUser: {
                email: user.email,
                displayName: user.displayName
              },
              requiresUpgrade: true
            });
          }
        }
      }
    }
    
    // Check if user is authenticating via Facebook
    // Firebase tokens can have provider info in different places depending on platform (web vs mobile)
    const hasFacebookIdentity = decodedToken.identities && decodedToken.identities.facebook;
    const hasFirebaseFacebookIdentity = decodedToken.firebase?.identities && decodedToken.firebase.identities.facebook;
    
    // Check for explicit provider from frontend (useful for mobile)
    const isExplicitFacebook = explicitProvider === 'facebook' || explicitProvider === 'facebook.com';
    
    // Detect Facebook login from token or explicit parameter
    const isFacebookLogin = isExplicitFacebook ||
                           signInProvider === 'facebook.com' || 
                           hasFacebookIdentity || 
                           hasFirebaseFacebookIdentity ||
                           false;
    
    const provider = explicitProvider || signInProvider || (hasFacebookIdentity ? 'facebook.com' : 'unknown');
    
    // Detect LinkedIn login from token
    const hasLinkedInIdentity = decodedToken.identities && decodedToken.identities.linkedin;
    const hasFirebaseLinkedInIdentity = decodedToken.firebase?.identities && decodedToken.firebase.identities.linkedin;
    const isExplicitLinkedIn = explicitProvider === 'linkedin.com' || explicitProvider === 'linkedin';
    const isLinkedInLogin = isExplicitLinkedIn || signInProvider === 'linkedin.com' || hasLinkedInIdentity || hasFirebaseLinkedInIdentity;

    const isExplicitEntra = explicitProvider === 'microsoft.com'
        || explicitProvider === 'entra'
        || explicitProvider === 'azuread';
    const isEntraLogin = isExplicitEntra;
    const authProvider = resolveAuthProvider({
      explicitProvider,
      signInProvider,
      isLinkedInLogin,
      isEntraLogin,
      isFacebookLogin
    });
    
    // Check if request is from mobile device
    const userAgent = req.headers['user-agent'] || '';
    const isMobile = /Mobile|Android|iPhone|iPad/i.test(userAgent);
    
    // Log full token structure for debugging mobile issues
    console.log('🔍 Login attempt:', {
      firebaseUid: decodedToken.uid,
      email: decodedToken.email,
      existingUser: !!user,
      inviteCode: inviteCode || 'none provided',
      provider: provider,
      explicitProvider: explicitProvider,
      sign_in_provider: signInProvider,
      identities: decodedToken.identities ? Object.keys(decodedToken.identities) : null,
      firebase_identities: decodedToken.firebase?.identities ? Object.keys(decodedToken.firebase.identities) : null,
      isFacebookLogin: isFacebookLogin,
      isLinkedInLogin: isLinkedInLogin,
      isEntraLogin: isEntraLogin,
      authProvider,
      loginFrom: loginFrom || 'unknown',
      isMobile: isMobile,
      userAgent: userAgent.substring(0, 50) // Limit user agent length
    });
    
    const isNewUser = !user;
    let pendingPreRegCode = null;
    let hasCompletedEnrollment = false;

    if (!user) {
      console.log('📝 New user registration');

      // Check for existing completed pre-registration
      let hasCompletedPreReg = false;
      let completedPreRegAtSignup = null;
      try {
          const PreReg = require('./models/Enrollment');
          completedPreRegAtSignup = await PreReg.findOne({
              email: decodedToken.email.toLowerCase(),
              baselineSubmittedAt: { $ne: null },
              ...notRevokedFilter()
          }).sort({ baselineSubmittedAt: -1 });
          if (completedPreRegAtSignup) {
              hasCompletedPreReg = true;
              hasCompletedEnrollment = true;
              console.log('✅ Existing completed pre-registration found, skipping pre-reg email');
          }
      } catch (e) { console.error("Forget-me mobile lookup failed:", e.message); }

      // Create Mongo user first so concurrent /api/login calls cannot orphan enrollment codes.
      try {
          user = await User.create({
            firebaseUid: decodedToken.uid,
            email: decodedToken.email,
            displayName: requestedDisplayName || decodedToken.name || (isLinkedInLogin ? 'LinkedIn User' : isEntraLogin ? 'Entra User' : ''),
            lastLogin: new Date(),
            signupProvider: authProvider,
            lastLoginProvider: authProvider,
            lastLoginFrom: loginFrom,
            linkedinId: linkedinId || null,
            verified: null,
            emailVerified: hasCompletedPreReg || undefined,
            mobile: completedPreRegAtSignup?.mobile || undefined,
            welcomeHelpdesk: false,
            plan: (signInProvider === 'password' || isLinkedInLogin || isFacebookLogin || isEntraLogin) ? 'helpdesk' : null,
            tier: (signInProvider === 'password' || isLinkedInLogin || isFacebookLogin || isEntraLogin) ? 'individual' : null,
            photoURL: linkedinId ? extractLinkedInPhotoUrl(linkedinId) : (isLinkedInLogin && decodedToken.picture ? decodedToken.picture : null),
            entraOid: entraOid || null,
            entraTenantId: entraTenantId || null,
            authLevel: resolveAuthLevel(authProvider),
            interviewOnly: interviewOnly || false
          });
          if (isEntraLogin) {
            applyEntraCompany(user, entraCompanyName, decodedToken.email);
            await user.save();
          }
      } catch (createErr) {
          if (createErr.code === 11000 && decodedToken.email) {
              user = await User.findOne({ email: decodedToken.email.toLowerCase() });
              if (!user) throw createErr;
              if (user.firebaseUid !== decodedToken.uid) {
                  const tokenEmail = decodedToken.email.toLowerCase();
                  const userEmail = (user.email || '').toLowerCase();
                  if (signInProvider === 'password' && userEmail === tokenEmail) {
                      user.firebaseUid = decodedToken.uid;
                      await user.save();
                      console.log('🔗 Reconciled Firebase UID for password login:', userEmail, '->', decodedToken.uid);
                  } else {
                      return res.status(409).json({
                          error: 'Account already exists',
                          message: 'An account with this email already exists. Please use the upgrade flow.',
                          existingUser: { email: user.email, displayName: user.displayName },
                          requiresUpgrade: true
                      });
                  }
              }
          } else {
              throw createErr;
          }
      }
      
      // Check if this user was previously added as a candidate by someone else
      const existingCandidate = await Candidate.findOne({ 
        email: decodedToken.email.toLowerCase(),
        interviewer: { $ne: user._id } // Not owned by this user
      });
      
      if (existingCandidate) {
        console.log('🔗 User was previously added as candidate, adding as additional interviewer');
        
        // Add the new user as an additional interviewer to their own candidate record
        const currentInterviewers = existingCandidate.interviewers || '';
        const interviewersList = currentInterviewers.split(',').filter(email => email.trim() !== '');
        
        if (!interviewersList.includes(decodedToken.email.toLowerCase())) {
          interviewersList.push(decodedToken.email.toLowerCase());
          existingCandidate.interviewers = interviewersList.join(',');
          await existingCandidate.save();
          
          console.log('✅ Added user as additional interviewer to their own candidate record');
        }
      }
      console.log('New user created with ID:', user._id);

      recordAuditEventAsync({
        action: 'ACCOUNT_CREATED',
        actor: actorFromUser(user),
        target: actorFromUser(user),
        metadata: {
          provider: provider || null,
          interviewOnly: !!interviewOnly,
          hasCompletedEnrollment: !!hasCompletedPreReg
        }
      });

      if (requestedDisplayName && !decodedToken.name) {
        admin.auth().updateUser(decodedToken.uid, { displayName: requestedDisplayName }).catch((err) => {
          console.warn('Could not sync Firebase displayName for new user:', err.message);
        });
      }

      // If LinkedIn ID is provided, start background verification
      if (signInProvider === 'password' && (!user.plan || !user.tier)) { user.plan = user.plan || 'helpdesk'; user.tier = user.tier || 'individual'; }
      if (linkedinId) {
        console.log('Starting background LinkedIn verification for user:', user._id);
        updateUserVerifiedData(user._id, linkedinId).catch(error => {
            console.error('Background verification failed:', error);
        });

        // Download and save profile photo if LinkedIn ID is provided
        downloadAndSaveLinkedInPhoto(linkedinId, decodedToken.uid).catch(error => {
            console.error('Error downloading profile photo:', error);
        });
      }

      if (isFacebookLogin) {
        console.log('New user registered via Facebook (no invite code required):', user.email);
      } else if (isEntraLogin) {
        console.log('New user registered via Entra (no invite code required):', user.email);
      } else {
        console.log('New user registered with invite code:', user.email);
      }
    } else {
      // Update last login and LinkedIn ID for existing user
      user.lastLogin = new Date();
      user.lastLoginProvider = authProvider;
      if (loginFrom) user.lastLoginFrom = loginFrom;
      if (!user.signupProvider) user.signupProvider = authProvider;
      
      // Enrich LinkedIn profile data from decoded token (handles placeholder users)
      if (isLinkedInLogin) {
        if (!user.displayName || user.displayName === 'LinkedIn User') {
          if (decodedToken.name) {
            user.displayName = decodedToken.name;
            console.log('LinkedIn name populated for existing user:', decodedToken.name);
          }
        }
        if (!user.photoURL && decodedToken.picture) {
          user.photoURL = decodedToken.picture;
          console.log('LinkedIn photo populated for existing user');
        }
      }
      
      if (isLinkedInLogin && (!user.plan || !user.tier)) {
        user.plan = user.plan || 'helpdesk';
        user.tier = user.tier || 'individual';
      }
      if (isEntraLogin && (!user.plan || !user.tier)) {
        user.plan = user.plan || 'helpdesk';
        user.tier = user.tier || 'individual';
      }
      if (isEntraLogin) {
        if (!user.displayName || user.displayName === 'Entra User') {
          if (requestedDisplayName) user.displayName = requestedDisplayName;
          else if (decodedToken.name) user.displayName = decodedToken.name;
        }
        if (entraOid) user.entraOid = entraOid;
        if (entraTenantId) user.entraTenantId = entraTenantId;
        applyEntraCompany(user, entraCompanyName, decodedToken.email);
      }
      if (signInProvider === 'password' && (!user.plan || !user.tier)) { user.plan = user.plan || 'helpdesk'; user.tier = user.tier || 'individual'; }
      if (linkedinId) {
        user.linkedinId = linkedinId;
        user.photoURL = extractLinkedInPhotoUrl(linkedinId);
        
        // Start background verification for existing user
        console.log('Starting background LinkedIn verification for existing user:', user._id);
        updateUserVerifiedData(user._id, linkedinId).catch(error => {
            console.error('Background verification failed:', error);
        });

        // Download and save new profile photo
        downloadAndSaveLinkedInPhoto(linkedinId, decodedToken.uid).catch(error => {
            console.error('Error downloading profile photo:', error);
        });
      }
      await user.save();
    }

    const isSsoAutoRegister = isNewUser && (isLinkedInLogin || isEntraLogin || isFacebookLogin);
    const enrollmentEmail = (user?.email || decodedToken.email || '').toLowerCase().trim();

    if (user && enrollmentEmail && !enrollmentEmail.includes('@placeholder.com')) {
        try {
            const completedPreReg = await PreRegistration.findOne({
                email: enrollmentEmail,
                baselineSubmittedAt: { $ne: null },
                ...notRevokedFilter()
            }).sort({ baselineSubmittedAt: -1 });

            if (completedPreReg) {
                hasCompletedEnrollment = true;
                if (!user.emailVerified) {
                    user.emailVerified = true;
                    if (completedPreReg.mobile && !user.mobile) {
                        user.mobile = completedPreReg.mobile;
                    }
                    await user.save();
                }
            } else if (!user.emailVerified) {
                const preReg = await ensureSelfEnrollmentInvite(
                    enrollmentEmail,
                    'XCHK Verify',
                    { sendEmail: true, forceResend: isSsoAutoRegister }
                );
                if (preReg) {
                    pendingPreRegCode = preReg.code;
                    console.log('Enrollment invite ensured for:', enrollmentEmail, 'code:', preReg.code, 'ssoSignup:', isSsoAutoRegister);
                }
            }
        } catch (enrollErr) {
            console.error('Enrollment provisioning failed:', enrollErr.message);
        }
    }

    let needsBaselineRegistration = false;
    let preRegistrationUrl = null;
    if (user && !user.emailVerified && enrollmentEmail) {
        try {
            let activePreReg = pendingPreRegCode
                ? await PreRegistration.findOne({ code: pendingPreRegCode })
                : null;
            if (!activePreReg) {
                activePreReg = await PreRegistration.findOne({
                    email: enrollmentEmail,
                    baselineSubmittedAt: null,
                    expirationDate: { $gt: new Date() },
                    ...notRevokedFilter()
                }).sort({ dateInvited: -1 });
            }
            if (activePreReg) {
                needsBaselineRegistration = true;
                const frontendOrigin = (process.env.FRONTEND_URL || 'https://in.xchk.io').replace(/\/$/, '');
                preRegistrationUrl = `${frontendOrigin}/enroll.html?r=${encodeURIComponent(activePreReg.code)}`;
            }
        } catch (e) {
            console.error('Baseline registration lookup failed:', e.message);
        }
    }

    const registrationConfirmed = !!(user && (user.emailVerified || user.siteAdmin));

    let teamInviteAccepted = false;
    if (inviteCode && user) {
        try {
            const result = await acceptTeamInvite(user, inviteCode, inviteSecret);
            if (result) teamInviteAccepted = true;
        } catch (teamErr) {
            console.error('Team invite accept failed:', teamErr.message);
            if (teamErr.status === 403) {
                return res.status(403).json({ error: teamErr.message });
            }
        }
    }

    if (
        user?.email
        && !user.email.endsWith('@anon')
        && shouldSendSignupWelcomeOnLogin({
            needsBaselineRegistration,
            registrationConfirmed
        })
    ) {
        try {
            const { team } = await getTeamForUser(user);
            sendSignupWelcome(user, {
                teamInviteAccepted,
                teamName: team?.name || user.company || null
            }).catch((err) => {
                console.error('Signup welcome email failed:', err.message);
            });
        } catch (welcomeErr) {
            console.error('Signup welcome email setup failed:', welcomeErr.message);
        }
    }

    res.json({
      customToken,
      isNewUser,
      siteAdmin: !!(user && user.siteAdmin),
      plan: user ? user.plan : null,
      welcomeHelpdesk: user ? !!user.welcomeHelpdesk : false,
      needsBaselineRegistration,
      preRegistrationUrl,
      registrationConfirmed,
      registrationPending: !registrationConfirmed && needsBaselineRegistration,
      teamInviteAccepted,
      user: {
        uid: decodedToken.uid,
        email: decodedToken.email,
        name: decodedToken.name,
        displayName: user.displayName,
        linkedinId: user.linkedinId,
        emailVerified: !!user.emailVerified,
        plan: user.plan,
        verified: user.verified
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Helper function to extract LinkedIn profile photo URL
function extractLinkedInPhotoUrl(linkedinId) {
  try {
    // Extract the profile ID from the LinkedIn ID
    const profileId = linkedinId.split('/in/')[1]?.split('/')[0];
    if (!profileId) return null;

    // Construct the profile photo URL
    return `https://media.licdn.com/dms/image/v2/C4E03AQEfMaYttx2tFw/profile-displayphoto-shrink_800_800/profile-displayphoto-shrink_800_800/0/${profileId}?e=1755129600&v=beta&t=y9gQaj5AHjMzsZRQXu31x3_UfcOVPxzxJ6T9Jey_D9o`;
  } catch (error) {
    console.error('Error extracting LinkedIn photo URL:', error);
    return null;
  }
}

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ firebaseUid: req.user.uid });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Resolve helpdesk subject by email/mobile without creating session or candidate
app.post('/api/helpdesk/resolve-subject', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user || !user.plan) {
            return res.status(403).json({ error: 'Registration required' });
        }
        const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
        const mobile = typeof req.body?.mobile === 'string' ? req.body.mobile.trim() : '';
        if (!email && !mobile) {
            return res.status(400).json({ error: 'email or mobile required' });
        }
        const resolved = await resolveHelpdeskSubject(user, email, mobile);
        res.json({
            candidateId: resolved.candidateId,
            candidateEmail: resolved.candidateEmail,
            expectedLocation: resolved.expectedLocation,
            preRegEmail: resolved.preRegEmail,
            matched: !!resolved.candidateId,
            phoneIdentity: resolved.phoneIdentity || null
        });
    } catch (error) {
        console.error('helpdesk resolve-subject error:', error);
        res.status(500).json({ error: 'Failed to resolve helpdesk subject' });
    }
});

// Look up a completed PreRegistration's mobile by email
app.get('/api/preregister-mobile', authenticateToken, async (req, res) => {
  try {
    const email = (req.query.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ error: 'email required' });
    const { findCompletedPreRegistration } = require('./utils/enrollmentUtils');
    const preReg = await findCompletedPreRegistration(email, null);
    // Return masked only — never expose real number to frontend
    const real = preReg?.mobile || null;
    const masked = real ? '••••••' + real.slice(-4) : null;
    res.json({ mobile: masked, hasMobile: !!real });
  } catch (error) {
    console.error('preregister-mobile error:', error);
    res.status(500).json({ error: 'Failed to look up mobile' });
  }
});


// Verify email via pre-registration completion
app.post('/api/verify-email', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.emailVerified) return res.json({ verified: true });
        const PreReg = require('./models/Enrollment');
        const preReg = await PreReg.findOne({
            email: user.email,
            baselineSubmittedAt: { $ne: null },
            ...notRevokedFilter()
        });
        if (preReg) {
            user.emailVerified = true;
            if (preReg.mobile && !user.mobile) user.mobile = preReg.mobile;
            await user.save();
            return res.json({ verified: true });
        }
        res.status(400).json({ error: 'Verification not complete. Finish mobile verification first.' });
    } catch (error) { console.error(error); res.status(500).json({ error: 'Verification failed' }); }
});

// Resend enrollment — creates User + PreRegistration from Firebase identity if missing
app.post('/api/resend-verification', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        if (user && user.emailVerified) return res.json({ verified: true });
        if (user && user.email) {
            const preReg = await ensureSelfEnrollmentInvite(user.email, 'XCHK Verify', { sendEmail: true, forceResend: true });
            if (!preReg) return res.status(500).json({ error: 'Failed to create enrollment invite' });
            return res.json({ sent: true });
        }
        // No MongoDB user — create one from Firebase identity
        const firebaseUser = req.user;
        if (!firebaseUser.email) return res.status(400).json({ error: 'No email on Firebase account' });
        const newUser = await User.create({
            firebaseUid: firebaseUser.uid,
            email: firebaseUser.email.toLowerCase(),
            displayName: firebaseUser.name || '',
            lastLogin: new Date(),
            welcomeHelpdesk: false,
            plan: 'helpdesk',
            tier: 'individual',
            emailVerified: false
        });
        const preReg = await ensureSelfEnrollmentInvite(newUser.email, 'XCHK Verify', { sendEmail: true, forceResend: true });
        if (!preReg) return res.status(500).json({ error: 'Failed to create enrollment invite' });
        res.json({ sent: true });
    } catch (error) { console.error(error); res.status(500).json({ error: 'Failed to resend' }); }
});

// --- Admin Routes ---
const { isAdmin, requireTier, requireFeature, requireTestQuota } = require('./middleware/auth');

/** Admin user delete: account plus all subject history for this user's email. */
async function adminUserDeletionScope(user) {
    return getUserDeletionScope(user);
}

function collectAdminScreenshotKeys(sessions) {
    return collectScreenshotKeys(sessions);
}

async function purgeBunnyCacheKeys(keys, timeoutMs = 4000) {
    const bunnyApiKey = process.env.BUNNYCDN_API_KEY;
    const bunnyPullZoneId = process.env.BUNNYCDN_PULLZONE_ID;
    if (!bunnyApiKey || !bunnyPullZoneId || !keys.size) return 0;

    const https = require('https');
    const hostname = process.env.BUNNYCDN_HOSTNAME || 'xchk-cdn.b-cdn.net';
    let purged = 0;
    for (const key of keys) {
        try {
            await new Promise((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error('bunny purge timeout')), timeoutMs);
                const purgedUrl = 'https://' + hostname + '/' + key;
                const req = https.request({
                    hostname: 'api.bunny.net',
                    path: '/pullzone/' + bunnyPullZoneId + '/purgeCache?url=' + encodeURIComponent(purgedUrl),
                    method: 'POST',
                    headers: { AccessKey: bunnyApiKey, 'Content-Length': '0' },
                    timeout: timeoutMs
                }, (res) => {
                    res.resume();
                    res.on('end', () => {
                        clearTimeout(timer);
                        resolve();
                    });
                });
                req.on('error', (err) => {
                    clearTimeout(timer);
                    reject(err);
                });
                req.on('timeout', () => {
                    req.destroy(new Error('bunny purge timeout'));
                });
                req.end();
            });
            purged++;
        } catch (e) {
            console.warn('Bunny purge skipped for', key, e.message);
        }
    }
    return purged;
}

async function deleteAdminScreenshotAssets(b2Keys, sDir) {
    let deletedLocal = 0;
    for (const key of b2Keys) {
        try {
            const fp = path.join(sDir, key);
            if (fs.existsSync(fp)) {
                fs.unlinkSync(fp);
                deletedLocal++;
            }
        } catch (e) { console.error("Forget-me mobile lookup failed:", e.message); }
    }

    let deletedB2 = 0;
    const b2Bucket = process.env.B2_BUCKET || 'xchk-main';
    if (b2Keys.size && process.env.B2_ACCESS_KEY_ID && process.env.B2_SECRET_ACCESS_KEY) {
        const { S3Client, DeleteObjectCommand } = require('@aws-sdk/client-s3');
        const s3 = new S3Client({
            endpoint: process.env.B2_ENDPOINT || 'https://s3.us-east-005.backblazeb2.com',
            region: process.env.B2_REGION || 'us-east-005',
            credentials: {
                accessKeyId: process.env.B2_ACCESS_KEY_ID,
                secretAccessKey: process.env.B2_SECRET_ACCESS_KEY
            },
            forcePathStyle: false
        });
        const keyList = [...b2Keys];
        const batchSize = 25;
        for (let i = 0; i < keyList.length; i += batchSize) {
            const batch = keyList.slice(i, i + batchSize);
            const results = await Promise.allSettled(batch.map((key) =>
                s3.send(new DeleteObjectCommand({ Bucket: b2Bucket, Key: key }))
            ));
            deletedB2 += results.filter((r) => r.status === 'fulfilled').length;
        }
    }

    let purgedBunny = 0;
    if (b2Keys.size <= 100) {
        purgedBunny = await purgeBunnyCacheKeys(b2Keys, 3000);
    } else {
        console.log(`Admin delete: skipping Bunny purge for ${b2Keys.size} keys (CDN TTL will expire)`);
    }

    return { deletedLocal, deletedB2, purgedBunny };
}

function queueAdminScreenshotCleanup(b2Keys, auditContext) {
    if (!b2Keys.size) return;
    const sDir = path.join(__dirname, '../s');
    setImmediate(() => {
        deleteAdminScreenshotAssets(b2Keys, sDir)
            .then((result) => {
                console.log(JSON.stringify({
                    audit: 'USER_DELETE_FILE_CLEANUP',
                    ...auditContext,
                    removed: result,
                    timestamp: new Date().toISOString()
                }));
            })
            .catch((error) => {
                console.error('Admin delete file cleanup error:', error.message);
            });
    });
}


// List all users (admin only)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find(
            {},
            'email displayName company siteAdmin tier plan addons createdAt lastLogin owner monthlyTestCount monthReset testLimit helpdeskSubject emailVerified signupProvider lastLoginProvider entraOid companyName'
        )
            .sort({ createdAt: -1 })
            .lean();

        // Attach enrollment photo info for users with preregistration baseline photos
        const userEmails = [...new Set(users.map(u => u.email).filter(Boolean))];
        const preregs = userEmails.length > 0
            ? await mongoose.connection.db.collection('preregistrations')
                .find({ email: { $in: userEmails }, baselinePhotos: { $exists: true, $not: { $size: 0 } } })
                .project({ email: 1, baselinePhotos: 1 })
                .toArray()
            : [];
        const enrollmentByEmail = {};
        for (const p of preregs) {
            enrollmentByEmail[p.email] = (p.baselinePhotos || []).map(bp => bp.url);
        }
        for (const u of users) {
            u.enrollmentPhotos = enrollmentByEmail[u.email] || [];
        }

        // Attach LinkedIn info from candidates collection
        const candidatesWithLinkedIn = userEmails.length > 0
            ? await Candidate.find({ email: { $in: userEmails }, linkedinId: { $nin: [null, ''] } })
                .select('email linkedinId verified')
                .lean()
            : [];
        const linkedinByEmail = {};
        for (const c of candidatesWithLinkedIn) {
            linkedinByEmail[c.email] = {
                linkedinId: c.linkedinId,
                verified: c.verified ? true : false
            };
        }
        for (const u of users) {
            u.linkedin = linkedinByEmail[u.email] || null;
        }

        res.json(users);
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Update user plan/addons (admin only)
app.patch('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { plan, addons, siteAdmin, tier, monthlyTestCount, testLimit } = req.body;
        const before = await User.findById(req.params.id)
            .select('email displayName company siteAdmin tier plan addons testLimit monthlyTestCount')
            .lean();
        if (!before) return res.status(404).json({ error: 'User not found' });

        const update = {};
        if (plan !== undefined) update.plan = plan;
        if (addons !== undefined) update.addons = addons;
        if (siteAdmin !== undefined) update.siteAdmin = siteAdmin;
        if (tier !== undefined) update.tier = tier;
        if (testLimit !== undefined) {
            update.testLimit = parseInt(testLimit) || 5;
            update.monthlyTestCount = 0;
            update.monthReset = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        }
        if (monthlyTestCount !== undefined) {
            update.testLimit = parseInt(monthlyTestCount) || 5;
            update.monthlyTestCount = 0;
            update.monthReset = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        }
        
        const user = await User.findByIdAndUpdate(req.params.id, { $set: update }, { new: true })
            .select('email displayName company siteAdmin tier plan addons owner');

        const changes = {};
        for (const key of Object.keys(update)) {
            if (key === 'monthReset') continue;
            const prev = before[key];
            const next = user[key];
            if (JSON.stringify(prev) !== JSON.stringify(next)) {
                changes[key] = { from: prev, to: next };
            }
        }
        if (Object.keys(changes).length) {
            recordAuditEventAsync({
                action: 'ACCOUNT_ADMIN_UPDATED',
                actor: actorFromUser(req.user),
                target: {
                    type: 'user',
                    email: user.email,
                    mongoId: String(user._id),
                    label: user.displayName || user.email
                },
                metadata: { changes }
            });
        }

        res.json(user);
    } catch (error) {
        console.error('Admin update error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

// Preview user deletion
app.get('/api/admin/users/:id/preview', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('email displayName firebaseUid');
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { candidates, sessions } = await adminUserDeletionScope(user);
        let localFiles = 0;
        const sDir = path.join(__dirname, '../s');
        for (const s of sessions) for (const shot of (s.screenshots || [])) if (shot.shortname) for (const ext of ['.png', '-ov.png']) try { if (fs.existsSync(path.join(sDir, shot.shortname + ext))) localFiles++; } catch (e) {}
        res.json({ user: { email: user.email, displayName: user.displayName || user.email }, candidates: candidates.length, sessions: sessions.length, localFiles });
    } catch (error) { console.error('Admin preview error:', error); res.status(500).json({ error: 'Failed to preview' }); }
});

// Delete user and all associated data
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const result = await deleteUserAndAllData(user, {
            auditSource: 'USER_DELETED',
            initiatorEmail: req.user.email
        });

        queueAdminScreenshotCleanup(result.b2Keys, result.audit);

        console.log(JSON.stringify(result.audit));

        res.json({
            deleted: true,
            candidates: result.candidates,
            sessions: result.sessions,
            screenshotFilesQueued: result.screenshotCount,
            fileCleanup: 'background',
            teamCleanup: result.teamCleanup
        });
    } catch (error) { console.error('Admin delete error:', error); res.status(500).json({ error: 'Failed to delete user' }); }
});

// List audit events (admin only)
app.get('/api/admin/audit-events', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await listAuditEvents({
            limit: req.query.limit,
            before: req.query.before,
            action: req.query.action,
            email: req.query.email
        });
        res.json(result);
    } catch (error) {
        console.error('Admin audit events error:', error);
        res.status(500).json({ error: 'Failed to fetch audit events' });
    }
});

// Resend enrollment invite (admin only)
app.post('/api/admin/users/:id/resend-enrollment', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.emailVerified) return res.json({ verified: true, message: 'Already verified' });
        const preReg = await ensureSelfEnrollmentInvite(user.email, 'XCHK Verify', { sendEmail: true, forceResend: true });
        if (!preReg) {
            return res.status(500).json({ error: 'Failed to create enrollment invite' });
        }
        res.json({ sent: true, email: user.email });
    } catch (error) {
        console.error('Admin resend enrollment error:', error);
        res.status(500).json({ error: 'Failed to resend enrollment' });
    }
});

// List all checks — sessions and candidate interviews (admin only)
app.get('/api/admin/checks', authenticateToken, isAdmin, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 200, 500);

        // Sessions: only non-interview checks (interviews are in candidates table)
        const sessions = await Session.find({ source: { $ne: 'interview' } })
            .select('email uuid source operatorEmail operatorName status createdAt helpdeskResult liveness threatAssessment screenshots')
            .sort({ createdAt: -1 })
            .limit(limit)
            .lean();

        // Resolve uuid -> email for who initiated
        const uids = [...new Set(sessions.map(s => s.uuid).filter(Boolean))];
        const users = uids.length > 0
            ? await User.find({ firebaseUid: { $in: uids } }).select('firebaseUid email displayName').lean()
            : [];
        const uidMap = {};
        for (const u of users) uidMap[u.firebaseUid] = { email: u.email, displayName: u.displayName };

        const checks = sessions.map(s => ({
            _id: s._id,
            subject: s.email,
            source: s.source,
            shortname: (s.screenshots && s.screenshots.length > 0) ? s.screenshots[0].shortname : null,
            operatorName: s.operatorName || null,
            operatorEmail: s.operatorEmail || null,
            initiatedBy: uidMap[s.uuid] || null,
            status: s.status || 'active',
            createdAt: s.createdAt,
            liveness: s.liveness,
            helpdeskResult: s.helpdeskResult || null,
            threatLevel: s.threatAssessment?.threatLevel || null,
            badAsn: extractBadAsnSignal(s.threatAssessment)
        }));

        // Helper: extract bad ASN or TOR signal details from threat assessment
        function extractBadAsnSignal(ta) {
            if (!ta?.derivedSignals) return null;
            const sig = ta.derivedSignals.find(s => s.code === 'bad-asn-match' || s.code === 'tor-exit-node');
            if (!sig) return null;
            return { asn: sig.message.match(/ASN (\d+)/)?.[1] || null, message: sig.message, severity: sig.severity, code: sig.code };
        }

        // Look up preregistration enrollment photos for all check subjects
        const checkEmails = [...new Set(checks.map(c => c.subject).filter(Boolean))];
        const preregs = checkEmails.length > 0
            ? await mongoose.connection.db.collection('preregistrations')
                .find({ email: { $in: checkEmails }, baselinePhotos: { $exists: true, $not: { $size: 0 } } })
                .project({ email: 1, baselinePhotos: 1 })
                .toArray()
            : [];
        const enrollmentByEmail = {};
        for (const p of preregs) {
            enrollmentByEmail[p.email] = (p.baselinePhotos || []).map(bp => bp.url);
        }
        for (const c of checks) {
            c.enrollmentPhotos = enrollmentByEmail[c.subject] || [];
        }

        // Candidates
        const candidates = await Candidate.find({})
            .select('email name interviewer interviewers interviewCount lastInterview source city createdAt mobile linkedinId rating helpdeskCount verified')
            .sort({ lastInterview: -1 })
            .limit(limit)
            .lean();

        // Resolve interviewer user references manually
        const interviewerIds = [...new Set(candidates.map(c => c.interviewer).filter(Boolean))];
        const interviewerUsers = interviewerIds.length > 0
            ? await User.find({ _id: { $in: interviewerIds } }).select('_id email displayName').lean()
            : [];
        const interviewerMap = {};
        for (const u of interviewerUsers) {
            interviewerMap[String(u._id)] = { email: u.email, displayName: u.displayName };
        }

        // Get associated sessions for candidates (for interview history links)
        const candidateIds = candidates.map(c => c._id);
        const candidateSessions = candidateIds.length > 0
            ? await Session.find({ candidateId: { $in: candidateIds } })
                .select('candidateId screenshots createdAt source')
                .sort({ createdAt: -1 })
                .lean()
            : [];
        const sessionsByCandidate = {};
        for (const s of candidateSessions) {
            const cid = s.candidateId.toString();
            if (!sessionsByCandidate[cid]) sessionsByCandidate[cid] = [];
            const shortname = (s.screenshots && s.screenshots.length > 0) ? s.screenshots[0].shortname : null;
            sessionsByCandidate[cid].push({
                shortname: shortname,
                createdAt: s.createdAt,
                source: s.source
            });
        }

        const candidateChecks = candidates.map(c => ({
            _id: c._id,
            subject: c.email,
            name: c.name,
            source: 'candidate_' + (c.source || 'interview'),
            interviewer: interviewerMap[c.interviewer ? c.interviewer.toString() : ''] || null,
            interviewers: c.interviewers || null,
            interviewCount: c.interviewCount || 0,
            lastInterview: c.lastInterview,
            city: c.city,
            createdAt: c.createdAt,
            sessions: sessionsByCandidate[c._id.toString()] || []
        }));

        res.json({ checks, candidates: candidateChecks });
    } catch (error) {
        console.error('Admin checks error:', error);
        res.status(500).json({ error: 'Failed to fetch checks' });
    }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { displayName } = req.body;
    const before = await User.findOne({ firebaseUid: req.user.uid }).select('email displayName').lean();
    const user = await User.findOneAndUpdate(
      { firebaseUid: req.user.uid },
      { displayName },
      { new: true }
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (before && before.displayName !== user.displayName) {
      recordAuditEventAsync({
        action: 'ACCOUNT_PROFILE_UPDATED',
        actor: actorFromUser(req.user),
        target: actorFromUser(user),
        metadata: {
          changes: {
            displayName: { from: before.displayName || '', to: user.displayName || '' }
          }
        }
      });
    }
    res.json(user);
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

// Update user location
app.post('/api/location', authenticateToken, async (req, res) => {
    try {
        const { longitude, latitude } = req.body;
        
        if (!longitude || !latitude) {
            return res.status(400).json({ error: 'Longitude and latitude are required' });
        }

        const user = await User.findOneAndUpdate(
            { firebaseUid: req.user.uid },
            {
                location: {
                    type: 'Point',
                    coordinates: [longitude, latitude],
                    lastUpdated: new Date()
                }
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user.location);
    } catch (error) {
        console.error('Location update error:', error);
        res.status(500).json({ error: 'Failed to update location' });
    }
});

// Create new session
app.post('/api/session', authenticateToken, async (req, res) => {
    const operatorFields = resolveHelpdeskOperatorFields(req);
    console.log('📝 Creating new session for user:', req.user.uid, operatorFields.operatorEmail
        ? `(operator: ${operatorFields.operatorEmail})`
        : '');
    try {
        let user = await User.findOne({ firebaseUid: req.user.uid });
        
        // Check if this is from a mobile device (anonymous person being verified)
        const userAgent = req.headers['user-agent'] || '';
        const isMobile = /Mobile|Android|iPhone/i.test(userAgent);
        
        // If user doesn't exist, create anonymous user
        let isAnonymous = false;
        if (!user) {
            console.log('👤 User not found, creating anonymous user:', req.user.uid);
            isAnonymous = true;
            const anonymousEmail = `${req.user.uid}@anon`;
            user = await User.create({
                firebaseUid: req.user.uid,
                email: anonymousEmail,
                name: 'Anonymous User',
                createdAt: new Date(),
                updatedAt: new Date()
            });
            console.log('✅ Created anonymous user:', anonymousEmail);
        } else {
            // Check if user is anonymous by email pattern OR if this is from mobile device
            isAnonymous = (user.email && user.email.endsWith('@anon')) || isMobile;
            if (isMobile && !user.email.endsWith('@anon')) {
                console.log('📱 Mobile device detected, treating as anonymous verification session');
            }
        }

        const { sessionId: bodySessionId, email: bodyEmail, mobile: bodyMobile, source: bodySource } = req.body || {};
        const isZendeskExternal = req.body?.external?.system === "zendesk";
        const sessionSource = req.authMethod === "api_key" || isZendeskExternal ? "zendesk" : normalizeSessionSource(bodySource);

        // Helpdesk / Zendesk: subject identified by email; session id from client (anon-...) for mobile PeerJS
        if (isHelpdeskSource(sessionSource)) {
            if (!user || !user.plan) {
                return res.status(403).json({ error: 'Registration required' });
            }
            if (typeof bodyEmail !== 'string' || !bodyEmail.trim()) {
                return res.status(400).json({ error: 'Email is required for helpdesk sessions' });
            }

            const sessionMobileRaw = (typeof bodyMobile === 'string' && bodyMobile.trim())
                ? bodyMobile.trim()
                : null;
            // Normalize: strip non-digits; if 11 digits starting with 1, strip the leading 1 (US country code)
            let sessionMobile = null;
            if (sessionMobileRaw) {
                const digits = sessionMobileRaw.replace(/\D/g, '');
                if (digits.length >= 10) {
                    sessionMobile = (digits.length === 11 && digits.startsWith('1')) ? digits.slice(1) : digits;
                }
            }
            if (!sessionMobile && bodyEmail) {
                const suffixRaw = req.body?.mobileSuffix;
                const suffixDigits = typeof suffixRaw === 'string' ? suffixRaw.replace(/\D/g, '') : '';
                if (/^\d{4}$/.test(suffixDigits)) {
                    const baseMobile = await resolveRealMobileForEmail(bodyEmail.trim().toLowerCase());
                    sessionMobile = applyMobileSuffixOverride(baseMobile, suffixDigits);
                }
                if (!sessionMobile) {
                    sessionMobile = await resolveRealMobileForEmail(bodyEmail.trim().toLowerCase());
                }
            }
            let candidate;
            try {
                candidate = await findOrCreateHelpdeskCandidate(user, bodyEmail, sessionMobile);
            } catch (candidateError) {
                if (candidateError.code === 'MOBILE_REQUIRED_FOR_TICKET_EMAIL') {
                    return res.status(400).json({ error: candidateError.message });
                }
                throw candidateError;
            }
            // Close expired sessions and old active sessions for this email
            try {
                const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
                // Close all expired sessions globally
                const coll = mongoose.connection.db.collection("sessions");
      const expired = await coll.updateMany(
                    { status: { $ne: 'closed' }, createdAt: { $lt: fiveMinAgo } },
                    { $set: { status: 'closed', closedAt: new Date() } }
                );
                if (expired.modifiedCount > 0) {
                    console.log(`Closed ${expired.modifiedCount} expired sessions (>5min)`);
                }
                // Close old sessions for this email
                const oldSessions = await Session.find({
                    email: candidate.email,
                    source: 'helpdesk',
                    status: { $ne: 'closed' }
                });
                for (const old of oldSessions) {
                    await Session.findByIdAndUpdate(old._id, { status: 'closed', closedAt: new Date() });
                }
                if (oldSessions.length > 0) {
                    console.log(`Closed ${oldSessions.length} old helpdesk sessions for ${candidate.email}`);
                }
            } catch(e) { console.error('Session cleanup error:', e); }
            const sessionId = resolveHelpdeskSessionId(bodySessionId);
            const shortname = generateShortname();
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

            const { clientIP } = await getBestIP(req);
            const ipLocation = await getIPLocation(clientIP);
            const ipApiInfo = await getIPApiInfo(clientIP);

            const sessionData = {
                sessionId,
                shortname,
                uuid: req.user.uid,
                email: bodyEmail && bodyEmail.trim().toLowerCase() !== candidate.email
                    ? bodyEmail.trim().toLowerCase()
                    : candidate.email,
                mobile: sessionMobile || usableContactMobile(candidate.mobile) || null,
                candidateId: candidate._id,
                source: sessionSource,
                createdAt: new Date(),
                date: new Date(),
                expiresAt,
                checksumOK: false,
                screenshots: [],
                ipaddr: clientIP,
                iplocation: {
                    country: ipLocation.country,
                    region: ipLocation.region,
                    city: ipLocation.city,
                    lat: ipLocation.lat,
                    lon: ipLocation.lon,
                    timezone: ipLocation.timezone,
                    isp: ipLocation.isp,
                    lastUpdated: new Date()
                }
            };
            if (ipApiInfo) {
                sessionData.ipapi = ipApiInfo;
            }

            const ext = req.body?.external;
            if (ext && typeof ext === 'object' && ext.system === 'zendesk') {
                sessionData.external = {
                    system: 'zendesk',
                    ticketId: ext.ticketId != null ? String(ext.ticketId).trim() : null,
                    subdomain: ext.subdomain
                        ? String(ext.subdomain).trim().replace(/\.zendesk\.com$/i, '')
                        : null
                };
                const requesterEmail = bodyEmail.trim().toLowerCase();
                if (requesterEmail && requesterEmail !== candidate.email) {
                    sessionData.external.requesterEmail = requesterEmail;
                }
            }
            if (operatorFields.operatorEmail) sessionData.operatorEmail = operatorFields.operatorEmail;
            if (operatorFields.operatorName) sessionData.operatorName = operatorFields.operatorName;

            const session = await Session.create(sessionData);

            user.sessionId = sessionId;
            await user.save();

            await Candidate.findByIdAndUpdate(candidate._id, {
                sessionId: session.sessionId,
                updatedAt: new Date()
            });
            await recordCandidateSessionStarted(candidate._id, sessionSource);
            await recordHelpdeskPhoneEmailLink(
                user._id,
                sessionData.mobile,
                candidate.email,
                session.sessionId,
                sessionSource
            );

            console.log('✅ Created helpdesk session for candidate:', {
                sessionId: session.sessionId,
                candidateId: candidate._id,
                email: candidate.email,
                operatorEmail: session.operatorEmail || null,
                external: session.external || null
            });

            return res.json({
                sessionId: session.sessionId,
                candidateId: candidate._id,
                source: session.source,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt
            });
        }

        // Generate a new session (allow client-provided sessionId for other flows)
        const sessionId = (typeof bodySessionId === 'string' && bodySessionId.trim())
            ? bodySessionId.trim()
            : generateSessionId(req.user.uid);
        const shortname = generateShortname();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
        const sessionEmail = (typeof bodyEmail === 'string' && bodyEmail.trim())
            ? bodyEmail.trim().toLowerCase()
            : user.email;
        const sessionMobile = (typeof bodyMobile === 'string' && bodyMobile.trim())
            ? bodyMobile.trim()
            : null;

        console.log('📦 Generated session:', { sessionId, shortname, expiresAt, isAnonymous, sessionEmail, sessionMobile, sessionSource });

        // Create new session (omit placeholder GPS until mobile reports real coordinates)
        const sessionFields = {
            sessionId,
            shortname,
            uuid: req.user.uid,
            email: sessionEmail,
            mobile: sessionMobile,
            source: sessionSource,
            createdAt: new Date(),
            expiresAt,
            checksumOK: false,
            screenshots: []
        };
        if (isValidGpsCoordinates(user.location?.coordinates)) {
            sessionFields.location = user.location;
        }

        const session = await Session.create(sessionFields);

        console.log('✅ Created session:', session._id);

        // Update user with current session ID
        user.sessionId = sessionId;
        await user.save();

        console.log('✅ Updated user with session ID');

        res.json({
            sessionId: session.sessionId,
            source: session.source,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt
        });
    } catch (error) {
        console.error('❌ Session creation error:', error);
        res.status(500).json({ error: 'Failed to create session' });
    }
});

// Start verification — called when mobile connects (PeerJS stream event)
// Counter increments here: per-verification-attempt billing (fairer than per-session)
app.post('/api/session/:sessionId/start', authenticateToken, requireTestQuota, async (req, res) => {
    console.log('📱 Verification started for session:', req.params.sessionId);
    try {
        const Session = require('./models/Session');
        const session = await Session.findOne({ 
            sessionId: req.params.sessionId,
            $or: [
                { uuid: req.user.uid },
                { 'interviewers.email': req.user.email }
            ]
        });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Start verification error:', error);
        res.status(500).json({ error: 'Failed to start verification' });
    }
});

// Create Stripe checkout session for XCHK subscription plans
app.post('/api/payment/create-checkout-session', authenticateToken, async (req, res) => {
    console.log('💳 Creating checkout session for user:', req.user.uid);
    try {
        const { plan, successUrl, cancelUrl } = req.body;
        
        // Map plan names to Stripe Price IDs (create these in Stripe Dashboard)
        const PRICE_MAP = {
            individual: process.env.STRIPE_PRICE_INDIVIDUAL || 'price_placeholder_individual',
            team: process.env.STRIPE_PRICE_TEAM || 'price_placeholder_team'
        };
        
        const priceId = PRICE_MAP[plan];
        if (!priceId || priceId.startsWith('price_placeholder')) {
            return res.json({ error: 'Stripe product not yet configured. Checkout coming soon.' });
        }
        
        const user = await User.findOne({ firebaseUid: req.user.uid });
        
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: plan === 'individual' ? 'payment' : 'subscription',
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: successUrl || `${req.protocol}://${req.get('host')}/helpdesk.html?payment=success&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: cancelUrl || `${req.protocol}://${req.get('host')}/pricing.html?canceled=true`,
            customer_email: user?.email || req.user.email,
            metadata: { plan: plan, firebaseUid: req.user.uid }
        });
        
        res.json({ success: true, url: session.url });
    } catch (error) {
        console.error('Stripe checkout error:', error.message);
        res.json({ error: error.message });
    }
});

// KYC checkout — $1 one-time payment for identity verification
// Creates a Stripe Checkout Session — PaymentIntent captured on Didit success
app.post('/api/payment/kyc-checkout', authenticateToken, async (req, res) => {
    console.log('🔑 Creating KYC checkout for user:', req.user.uid);
    try {
        const KYC_PRICE = 'price_1TljdC9fSWIgfZBP5J10BAdT';
        const user = await User.findOne({ firebaseUid: req.user.uid });
        
        // Cancel any pending PaymentIntent from a previous KYC attempt
        if (user?.kycPaymentIntentId) {
            try {
                const existing = await stripe.paymentIntents.retrieve(user.kycPaymentIntentId);
                if (existing.status === 'requires_capture') {
                    await stripe.paymentIntents.cancel(user.kycPaymentIntentId);
                    console.log('🔄 Cancelled previous KYC PaymentIntent:', user.kycPaymentIntentId);
                }
            } catch (_) {}
            await User.updateOne({ _id: user._id }, { $unset: { kycPaymentIntentId: '' } });
        }
        
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'payment',
            payment_intent_data: { capture_method: 'manual' },
            line_items: [{ price: KYC_PRICE, quantity: 1 }],
            success_url: `${req.protocol}://${req.get('host')}/api/payment/kyc-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.protocol}://${req.get('host')}/helpdesk.html?kyc=canceled`,
            customer_email: user?.email || req.user.email,
            metadata: { type: 'kyc', firebaseUid: req.user.uid, email: user?.email }
        });
        
        res.json({ success: true, url: session.url });
    } catch (error) {
        console.error('KYC checkout error:', error.message);
        res.json({ error: error.message });
    }
});

// KYC payment success — redirects to Didit KYC after payment
app.get('/api/payment/kyc-success', async (req, res) => {
    const { session_id } = req.query;
    if (!session_id) {
        return res.redirect('/helpdesk.html?kyc=error');
    }
    try {
        // Retrieve the Checkout Session to get the PaymentIntent ID and firebaseUid
        const checkoutSession = await stripe.checkout.sessions.retrieve(session_id);
        const metadata = checkoutSession.metadata || {};
        const firebaseUid = metadata.firebaseUid;
        const paymentIntentId = checkoutSession.payment_intent;
        
        if (paymentIntentId && firebaseUid) {
            // Store the PaymentIntent ID on the user so Didit webhook can capture it
            await User.updateOne(
                { firebaseUid },
                { $set: { kycPaymentIntentId: paymentIntentId } }
            );
            console.log('💳 Stored PaymentIntent for capture on Didit success:', paymentIntentId, 'user:', firebaseUid);
        }
        
        if (!firebaseUid) {
            return res.redirect('/helpdesk.html?kyc=error');
        }
        // Create a Firebase custom token so we can authenticate the Didit session
        // without requiring an active browser session
        const user = await User.findOne({ firebaseUid });
        if (!user) {
            return res.redirect('/helpdesk.html?kyc=error');
        }
        
        // Generate a short-lived token for the Didit session
        const auth = admin.auth();
        const customToken = await auth.createCustomToken(firebaseUid);
        
        // Create Didit session
        const apiKey = process.env.DIDIT_API_KEY;
        if (!apiKey) {
            return res.redirect('/helpdesk.html?kyc=error');
        }
        const diditWorkflowId = process.env.DIDIT_WORKFLOW_ID || 'f3e45146-6050-47d1-8dcd-a0252d8e1fc7';
        const diditRes = await fetch('https://verification.didit.me/v3/session/', {
            method: 'POST',
            headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                workflow_id: diditWorkflowId,
                vendor_data: user.email,
                callback_url: `https://in.xchk.io/api/didit/webhook`,
            }),
        });
        if (!diditRes.ok) {
            console.error('Didit session create failed:', await diditRes.text());
            return res.redirect('/helpdesk.html?kyc=error');
        }
        const sessionData = await diditRes.json();
        const diditUrl = sessionData.url;
        
        if (diditUrl) {
            res.redirect(diditUrl);
        } else {
            res.redirect('/helpdesk.html?kyc=error');
        }
    } catch (e) {
        console.error('KYC success redirect error:', e.message);
        res.redirect('/helpdesk.html?kyc=error');
    }
});

// Stripe webhook handler — defined as hoisted function so it can be registered before express.json()
async function handleStripeWebhook(req, res) {
    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
    
    if (!endpointSecret) {
        return res.status(400).send('Webhook secret not configured');
    }
    
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    } catch (err) {
        console.error('Stripe webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const metadata = session.metadata || {};
        
        if (metadata.plan && metadata.firebaseUid) {
            const firebaseUid = metadata.firebaseUid;
            if (firebaseUid) {
                const user = await User.findOne({ firebaseUid });
                if (user) {
                    user.stripeSubscriptionId = session.subscription || null;
                    user.stripeCustomerId = session.customer || null;
                    await user.save();
                    console.log('✅ Plan subscribed via Stripe for:', user.email, '- Plan:', metadata.plan);
                }
            }
        }
    }
    
    res.json({ received: true });
}



// Get current session or create new one
app.get('/api/session', authenticateToken, async (req, res) => {
    console.log('🔍 Getting session for user:', req.user.uid);
    try {
        const { candidateId, source: querySource } = req.query; // Get optional candidateId and source from query params
        const sessionSource = normalizeSessionSource(querySource);
        
        let user = await User.findOne({ firebaseUid: req.user.uid });
        
        // If user doesn't exist, create anonymous user
        let isAnonymous = false;
        if (!user) {
            console.log('👤 User not found, creating anonymous user:', req.user.uid);
            isAnonymous = true;
            const anonymousEmail = `${req.user.uid}@anon`;
            user = await User.create({
                firebaseUid: req.user.uid,
                email: anonymousEmail,
                name: 'Anonymous User',
                createdAt: new Date(),
                updatedAt: new Date()
            });
            console.log('✅ Created anonymous user:', anonymousEmail);
        } else {
            // Check if user is anonymous by email pattern
            isAnonymous = user.email && user.email.endsWith('@anon');
        }

        // Check if request is from mobile device
        const userAgent = req.headers['user-agent'] || '';
        const isMobile = /Mobile|Android|iPhone/i.test(userAgent);
        
        if (isMobile) {
            console.log('📱 Mobile device detected');
            
            // For anonymous users on mobile, they should use /api/checkin with sessionId from URL
            // Don't create a new session here - they need to check in to an existing session
            if (isAnonymous && !user.sessionId) {
                console.log('⚠️ Anonymous user has no sessionId - mobile client should use /api/checkin with sessionId from URL');
                return res.status(404).json({ 
                    error: 'No session found. Please use /api/checkin with the sessionId from the verification link.' 
                });
            }
            
            if (!user.sessionId) {
                return res.status(404).json({ error: 'No session found for mobile device' });
            }
            
            // Find the session and update candidate's lastInterview if associated
            const session = await Session.findOne({ sessionId: user.sessionId });
            if (!session) {
                console.log('⚠️ Session not found in database:', user.sessionId);
                return res.status(404).json({ error: 'Session not found in database' });
            }
            
            if (session && session.candidateId) {
                try {
                    await recordCandidateSessionStarted(session.candidateId, session.source);
                    console.log(`📱 Updated last interaction for candidate: ${session.candidateId} (${session.source || 'interview'})`);
                } catch (error) {
                    console.error('Error updating candidate interaction timestamp:', error);
                }
            }
            
            return res.json({
                sessionId: session.sessionId,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt,
                screenshots: session.screenshots || []
            });
        }

        let session;
        
        // If candidateId is provided, return existing session or create one
        if (candidateId) {
            if (!mongoose.Types.ObjectId.isValid(candidateId)) {
                return res.status(400).json({ error: 'Invalid candidate ID format' });
            }
            const candidate = await Candidate.findById(candidateId);
            if (!candidate) return res.status(404).json({ error: 'Candidate not found' });
            const isPrimaryInterviewer = candidate.interviewer.toString() === user._id.toString();
            const isListedInterviewer = candidate.interviewers && candidate.interviewers.includes(user.email);
            if (!isPrimaryInterviewer && !isListedInterviewer) {
                return res.status(403).json({ error: 'Access denied to this candidate' });
            }

            // Find existing open session for this candidate that hasn't been used yet
            const existing = await Session.findOne({
                candidateId: candidate._id,
                source: sessionSource,
                status: { $ne: 'closed' },
                closedAt: null,
                startedAt: null,
                'screenshots.0': { $exists: false }
            }).sort({ createdAt: -1 }).lean();
            if (existing) {
                console.log('♻️ Reusing existing open session for candidate:', candidateId, existing.sessionId);
                return res.json({ sessionId: existing.sessionId });
            }

            // No open session — create one
            const sessionId = generateSessionId(req.user.uid);
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
            const { clientIP, source } = await getBestIP(req);
            const ipLocation = await getIPLocation(clientIP);
            const ipApiInfo = await getIPApiInfo(clientIP);
            session = await Session.create({
                sessionId, uuid: req.user.uid, email: candidate.email, mobile: candidate.mobile || null,
                candidateId: candidate._id, source: sessionSource, createdAt: new Date(), date: new Date(),
                expiresAt, checksumOK: false, screenshots: [], ipaddr: clientIP,
                iplocation: { country: ipLocation.country, region: ipLocation.region, city: ipLocation.city,
                    lat: ipLocation.lat, lon: ipLocation.lon, timezone: ipLocation.timezone,
                    isp: ipLocation.isp, lastUpdated: new Date() },
                ipapi: ipApiInfo || undefined, operatorEmail: req.user?.email || null, operatorName: req.user?.name || null
            });
            console.log('✅ Created NEW session:', { sessionId: session.sessionId, candidateId: candidate._id });
            user.sessionId = sessionId;
            await user.save();
            await Candidate.findByIdAndUpdate(candidateId, {
                sessionId: session.sessionId,
                updatedAt: new Date()
            });
            await recordCandidateSessionStarted(candidateId, sessionSource);
        }
        // If no session or session expired, create a new one (for non-candidate sessions)
        else if (!user.sessionId) {
            console.log('📝 Creating new session for user (no user.sessionId):', req.user.uid);
            console.log('📊 User state:', { 
                firebaseUid: req.user.uid, 
                email: user.email, 
                hasSessionId: false,
                isAnonymous: isAnonymous 
            });
            
            // Generate a new session
            const sessionId = generateSessionId(req.user.uid);
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now

            console.log('📦 Generated session:', { sessionId, expiresAt, isAnonymous });

            // Get client IP address and perform lookups
            const { clientIP, source } = await getBestIP(req);
            console.log('🌐 Client IP:', { clientIP, source });
            const ipLocation = await getIPLocation(clientIP);
            const ipApiInfo = await getIPApiInfo(clientIP);

            // Create new session
            const sessionData = {
                sessionId,
                uuid: req.user.uid,
                email: user.email,
                source: sessionSource,
                createdAt: new Date(),
                expiresAt,
                checksumOK: false,
                screenshots: [],
                ipaddr: clientIP,
                iplocation: {
                    country: ipLocation.country,
                    region: ipLocation.region,
                    city: ipLocation.city,
                    lat: ipLocation.lat,
                    lon: ipLocation.lon,
                    timezone: ipLocation.timezone,
                    isp: ipLocation.isp,
                    lastUpdated: new Date()
                }
            };

            // Add ipapi.is data if available
            if (ipApiInfo) {
                sessionData.ipapi = ipApiInfo;
                console.log('✅ Added ipapi data to session');
            }

            // Check for any recently created valid session (within last 5 seconds) to prevent duplicates
            console.log('🔍 Checking for recently created sessions (race condition protection)');
            const recentSession = await Session.findOne({
                uuid: req.user.uid,
                createdAt: { $gte: new Date(Date.now() - 5000) },
                expiresAt: { $gt: new Date() }
            }).sort({ createdAt: -1 });
            
            if (recentSession) {
                console.log('✅ Found recently created session, using it:', {
                    sessionId: recentSession.sessionId,
                    createdAt: recentSession.createdAt,
                    age: Date.now() - recentSession.createdAt.getTime() + 'ms'
                });
                session = recentSession;
                // Update user with the recent session ID
                console.log('💾 Updating user.sessionId to:', recentSession.sessionId);
                user.sessionId = recentSession.sessionId;
                await user.save();
                console.log('✅ Updated user.sessionId');
            } else {
                console.log('ℹ️ No recently created session found, creating new one');
                session = await Session.create(sessionData);

                console.log('✅ Created session:', {
                    _id: session._id,
                    sessionId: session.sessionId,
                    expiresAt: session.expiresAt
                });

                // Update user with session ID
                console.log('💾 Updating user.sessionId to:', sessionId);
                user.sessionId = sessionId;
                await user.save();
                console.log('✅ Updated user.sessionId');
            }
        } else {
            console.log('🔍 Looking for existing session:', user.sessionId);
            console.log('📊 User state:', { 
                firebaseUid: req.user.uid, 
                email: user.email, 
                hasSessionId: !!user.sessionId,
                isAnonymous: isAnonymous 
            });
            
            // FIRST: If user has a sessionId, try to use that session (this is the source of truth)
            if (user.sessionId) {
                console.log('🔎 Looking up session by user.sessionId:', user.sessionId);
                session = await Session.findOne({ 
                    sessionId: user.sessionId,
                    expiresAt: { $gt: new Date() }
                });
                
                if (session) {
                    console.log('✅ Found existing session from user.sessionId:', {
                        sessionId: session.sessionId,
                        expiresAt: session.expiresAt,
                        candidateId: session.candidateId || 'none',
                        createdAt: session.createdAt
                    });
                } else {
                    // Check if session exists but is expired
                    const expiredSession = await Session.findOne({ sessionId: user.sessionId });
                    if (expiredSession) {
                        console.log('⚠️ Session found but expired:', {
                            sessionId: expiredSession.sessionId,
                            expiresAt: expiredSession.expiresAt,
                            now: new Date()
                        });
                    } else {
                        console.log('⚠️ Session not found in database:', user.sessionId);
                    }
                }
            } else {
                console.log('ℹ️ No user.sessionId to look up');
            }

            // If session not found or expired, check for recently created sessions (race condition protection)
            if (!session) {
                console.log('🔍 Checking for recently created sessions (race condition protection)');
                const recentSessionQuery = {
                    uuid: req.user.uid,
                    createdAt: { $gte: new Date(Date.now() - 5000) },
                    expiresAt: { $gt: new Date() }
                };
                
                console.log('🔍 Recent session query:', {
                    uuid: recentSessionQuery.uuid,
                    timeWindow: '5 seconds'
                });
                
                const recentSession = await Session.findOne(recentSessionQuery).sort({ createdAt: -1 });
                
                if (recentSession) {
                    console.log('✅ Found recently created session (race condition check):', {
                        sessionId: recentSession.sessionId,
                        createdAt: recentSession.createdAt,
                        age: Date.now() - recentSession.createdAt.getTime() + 'ms'
                    });
                    session = recentSession;
                    // Update user with the recent session ID
                    console.log('💾 Updating user.sessionId to:', recentSession.sessionId);
                    user.sessionId = recentSession.sessionId;
                    await user.save();
                    console.log('✅ Updated user.sessionId');
                } else {
                    console.log('ℹ️ No recently created session found');
                }
            }

            // Only create a new session if we don't have one
            if (!session) {
                console.log('📝 Creating new session (no existing session found):', req.user.uid);
                
                // Generate a new session
                const sessionId = generateSessionId(req.user.uid);
                const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

                console.log('📦 Generated session:', { sessionId, expiresAt, isAnonymous });

                // Create new session
                session = await Session.create({
                    sessionId,
                    uuid: req.user.uid,
                    email: user.email,
                    source: sessionSource,
                    createdAt: new Date(),
                    expiresAt,
                    checksumOK: false,
                    screenshots: []
                });

                console.log('✅ Created session:', {
                    _id: session._id,
                    sessionId: session.sessionId,
                    source: session.source,
                    expiresAt: session.expiresAt
                });

                // Update user with new session ID
                console.log('💾 Updating user.sessionId to:', sessionId);
                user.sessionId = sessionId;
                await user.save();
                console.log('✅ Updated user.sessionId');
            }
        }
        
        // Log final session state
        console.log('📊 Final session state:', {
            sessionId: session.sessionId,
            expiresAt: session.expiresAt,
            candidateId: session.candidateId || 'none',
            userSessionId: user.sessionId,
            match: session.sessionId === user.sessionId ? '✅' : '⚠️ MISMATCH'
        });

        // Note: candidateId handling is now done above when creating new sessions
        // No need to update existing sessions with candidateId here

        const response = {
            sessionId: session.sessionId,
            source: session.source || 'interview',
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            screenshots: session.screenshots
        };
        
        console.log('📤 Returning session to client:', {
            sessionId: response.sessionId,
            source: response.source,
            expiresAt: response.expiresAt,
            screenshotsCount: response.screenshots?.length || 0,
            userSessionId: user.sessionId,
            match: response.sessionId === user.sessionId ? '✅' : '⚠️ MISMATCH'
        });
        
        res.json(response);
    } catch (error) {
        console.error('❌ Session error:', error);
        res.status(500).json({ error: 'Failed to get/create session' });
    }
});

// Get notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ firebaseUid: req.user.uid });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user.notifications);
    } catch (error) {
        console.error('Notifications fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch notifications' });
    }
});

// Add notification
app.post('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const { type, title, message } = req.body;
        
        if (!type || !title || !message) {
            return res.status(400).json({ error: 'Type, title, and message are required' });
        }

        const user = await User.findOneAndUpdate(
            { firebaseUid: req.user.uid },
            {
                $push: {
                    notifications: {
                        type,
                        title,
                        message,
                        createdAt: new Date()
                    }
                }
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user.notifications[user.notifications.length - 1]);
    } catch (error) {
        console.error('Notification creation error:', error);
        res.status(500).json({ error: 'Failed to create notification' });
    }
});

// Mark notification as read
app.put('/api/notifications/:notificationId', authenticateToken, async (req, res) => {
    try {
        const { notificationId } = req.params;
        
        const user = await User.findOneAndUpdate(
            {
                firebaseUid: req.user.uid,
                'notifications._id': notificationId
            },
            {
                $set: {
                    'notifications.$.read': true
                }
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ error: 'User or notification not found' });
        }

        res.json({ message: 'Notification marked as read' });
    } catch (error) {
        console.error('Notification update error:', error);
        res.status(500).json({ error: 'Failed to update notification' });
    }
});

// Find nearby users
app.get('/api/nearby', authenticateToken, async (req, res) => {
    try {
        const { longitude, latitude, maxDistance = 10000 } = req.query; // maxDistance in meters
        
        if (!longitude || !latitude) {
            return res.status(400).json({ error: 'Longitude and latitude are required' });
        }

        const nearbyUsers = await User.find({
            firebaseUid: { $ne: req.user.uid },
            location: {
                $near: {
                    $geometry: {
                        type: 'Point',
                        coordinates: [parseFloat(longitude), parseFloat(latitude)]
                    },
                    $maxDistance: parseInt(maxDistance)
                }
            }
        }).select('-notifications -sessionId');

        res.json(nearbyUsers);
    } catch (error) {
        console.error('Nearby users fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch nearby users' });
    }
});

// Upload screenshot and overlay
app.post('/api/screenshot', authenticateToken, upload.fields([
    { name: 'screenshot', maxCount: 1 },
    { name: 'overlay', maxCount: 1 }
]), async (req, res) => {
    try {
        if (!req.files || (!req.files.screenshot && !req.files.overlay)) {
            return res.status(400).json({ error: 'At least one file (screenshot or overlay) is required' });
        }

        let shortname;
        let sha256;

        // Handle screenshot if present
        if (req.files.screenshot) {
            const screenshotFile = req.files.screenshot[0];
            // Read the screenshot file and generate SHA256 checksum
            const fileBuffer = fs.readFileSync(screenshotFile.path);
            sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            
            // Generate a short unique name (first 8 characters of the checksum)
            shortname = sha256.substring(0, 8);
            
            // Create new filename with the shortname
            const newScreenshotPath = path.join('s', `${shortname}.png`);
            
            // Rename the file
            fs.renameSync(screenshotFile.path, newScreenshotPath);
        }

        // Handle overlay if present
        if (req.files.overlay) {
            const overlayFile = req.files.overlay[0];
            // If we don't have a shortname yet (no screenshot), generate one
            if (!shortname) {
                const fileBuffer = fs.readFileSync(overlayFile.path);
                sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
                shortname = sha256.substring(0, 8);
            }
            
            // Create new filename with the shortname
            const newOverlayPath = path.join('s', `${shortname}-ov.png`);
            
            // Rename the file
            fs.renameSync(overlayFile.path, newOverlayPath);
        }

        // Get user information
        const existingUser = await User.findOne({ firebaseUid: req.user.uid });
        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!existingUser.sessionId) {
            return res.status(400).json({ error: 'No active session found' });
        }

        // Find the existing session
        const session = await Session.findOne({ sessionId: existingUser.sessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        // Add the screenshot to the session's screenshots array
        session.screenshots.push({
            shortname: shortname,
            sha256: sha256,
            createdAt: new Date()
        });

        // Add overlay entry if present and overlayChecksum is provided
        if (req.body.overlayChecksum) {
            const overlayShortname = req.body.overlayChecksum.substring(0, 8);
            session.screenshots.push({
                shortname: overlayShortname,
                sha256: req.body.overlayChecksum,
                createdAt: new Date()
            });
        }

        // Update the session
        await session.save();

        const sessionDuration = calculateSessionDurationMinutes(session.screenshots);
        if (sessionDuration > 0) {
            await Session.findByIdAndUpdate(session._id, {
                sessionTime: sessionDuration
            });
            console.log(`⏱️ Updated session ${session.sessionId} duration: ${sessionDuration} minutes`);
        }

        if (session.candidateId) {
            try {
                await recordCandidateInteractionComplete(
                    session.candidateId,
                    sessionDuration,
                    session.source
                );
            } catch (error) {
                console.error('Error updating candidate interaction stats:', error);
            }
        }

        // qrCode = proof page for embedding on screenshots / checksum chain
        const legacyOrigin = (process.env.FRONTEND_URL || 'https://in.xchk.io').replace(/\/$/, '');
        const connectUrl = proofPageUrl(legacyOrigin, shortname);
        const bridgeUrl = qrConnectBridgeUrl(legacyOrigin, shortname);
        const qrOpts = { errorCorrectionLevel: 'H', margin: 1, width: 150, height: 150 };
        const [qrCodeBase64, qrCodeBridgeBase64] = await Promise.all([
            QRCode.toDataURL(connectUrl, qrOpts),
            QRCode.toDataURL(bridgeUrl, qrOpts)
        ]);

        const response = {
            success: true,
            session: session,
            qrCode: qrCodeBase64,
            qrCodeBridge: qrCodeBridgeBase64
        };

        // Add screenshot info if present
        if (req.files.screenshot) {
            response.screenshot = {
                filename: `${shortname}.png`,
                url: `https://xchk.io/s/${shortname}.png`
            };
        }

        // Add overlay info if present
        if (req.files.overlay) {
            response.overlay = {
                filename: `${shortname}-ov.png`,
                url: `https://xchk.io/s/${shortname}-ov.png`
            };
        }

        res.json(response);
    } catch (error) {
        console.error('Screenshot upload error:', error);
        // Clean up the temporary files if they exist
        if (req.files) {
            Object.values(req.files).flat().forEach(file => {
                if (fs.existsSync(file.path)) {
                    fs.unlinkSync(file.path);
                }
            });
        }
        res.status(500).json({ error: 'Failed to process screenshot' });
    }
});

const {
    prepareScreenshotUpload,
    commitScreenshotUpload,
    registerCommittedScreenshot
} = require('./utils/screenshotUploadUtils');

async function afterHelpdeskScreenshotRegistered(session) {
    const sessionDuration = calculateSessionDurationMinutes(session.screenshots);
    if (sessionDuration > 0) {
        await Session.findByIdAndUpdate(session._id, {
            sessionTime: sessionDuration
        });
        console.log(`⏱️ Updated session ${session.sessionId} duration: ${sessionDuration} minutes`);
    }
    if (session.candidateId) {
        try {
            await recordCandidateInteractionComplete(
                session.candidateId,
                sessionDuration,
                session.source
            );
        } catch (error) {
            console.error('Error updating candidate interaction stats:', error);
        }
    }
}

// Sign screenshot URLs for bunny.net
app.post('/api/signScreenshot', authenticateToken, async (req, res) => {
    try {
        const { screenshotURL, screenshotChecksum, overlayURL, sessionId: bodySessionId } = req.body;

        if (!screenshotURL || !screenshotChecksum) {
            return res.status(400).json({ error: 'screenshotURL and screenshotChecksum are required' });
        }

        // Generate shortname from checksum (first 8 characters)
        const shortname = screenshotChecksum.substring(0, 8);

        // Get user information
        const existingUser = await User.findOne({ firebaseUid: req.user.uid });
        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const resolvedSessionId = (typeof bodySessionId === 'string' && bodySessionId.trim())
            ? bodySessionId.trim()
            : existingUser.sessionId;
        if (!resolvedSessionId) {
            return res.status(400).json({ error: 'No active session found' });
        }

        // Find the existing session
        const session = await Session.findOne({ sessionId: resolvedSessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        let ownsSession = session.uuid === req.user.uid
            || resolvedSessionId === existingUser.sessionId
            || resolvedSessionId.startsWith(`${req.user.uid}_`);
        // Allow candidate to access their own session by email match
        if (!ownsSession && session.email && existingUser.email &&
            session.email.toLowerCase() === existingUser.email.toLowerCase()) {
            ownsSession = true;
        }
        if (!ownsSession && session.candidateId) {
            const shotCandidate = await Candidate.findById(session.candidateId).select('interviewer interviewers');
            if (shotCandidate) {
                ownsSession = (shotCandidate.interviewer && shotCandidate.interviewer.toString() === existingUser._id.toString())
                    || (shotCandidate.interviewers && shotCandidate.interviewers.toLowerCase().includes(existingUser.email.toLowerCase()));
            }
        }
        if (!ownsSession) {
            return res.status(403).json({ error: 'Access denied to this session' });
        }

        const frontendOrigin = (process.env.FRONTEND_URL || 'https://in.xchk.io').replace(/\/$/, '');
        const connectUrl = proofPageUrl(frontendOrigin, shortname);
        const bridgeUrl = qrConnectBridgeUrl(frontendOrigin, shortname);
        const qrOpts = { errorCorrectionLevel: 'H', margin: 1, width: 150, height: 150 };
        const [qrCodeBase64, qrCodeBridgeBase64] = await Promise.all([
            QRCode.toDataURL(connectUrl, qrOpts),
            QRCode.toDataURL(bridgeUrl, qrOpts)
        ]);

        // Import the token signing function
        const { signUrl } = require('./utils/token');

        // Extract key from screenshotURL
        const screenshotUrlObj = new URL(screenshotURL);
        let screenshotKey = screenshotUrlObj.pathname;
        if (screenshotKey.startsWith('/')) screenshotKey = screenshotKey.slice(1);
        // Remove bucket name from key if present
        if (screenshotKey.startsWith('xchk-main/')) screenshotKey = screenshotKey.slice('xchk-main/'.length);
        // Strip xchk/<DBNAME>/ prefix so code sees s/pending/... etc.
        const dbPrefix = `xchk/${(process.env.DBNAME || 'xchk').replace(/[^a-zA-Z0-9_-]/g, '_')}`;
        if (screenshotKey.startsWith(dbPrefix + '/')) screenshotKey = screenshotKey.slice((dbPrefix + '/').length);
        const endpoint = process.env.S3_ENDPOINT.replace(/\/$/, '');
        const bucket = 'xchk-main';

        // Always use the generic endpoint for signing
        const genericEndpoint = 'https://s3.us-east-005.backblazeb2.com';
        const screenshotURLForSigning = `${genericEndpoint}/${screenshotKey}`;
        const publicEndpoint = process.env.S3_ENDPOINT.replace(/\/$/, '');

        // Await the signUrl function for screenshot (PUT only)
        const screenshotToken = await signUrl(screenshotURLForSigning, process.env.BUNNYKEY, 3600, null, false, null, null, null, 'putObject');

        const response = {
            success: true,
            qrCode: qrCodeBase64,
            qrCodeBridge: qrCodeBridgeBase64,
            screenshot: {
                filename: `${shortname}.jpg`,
                url: `${publicEndpoint}/${screenshotKey}`,
                token: screenshotToken
            }
        };

        // Add overlay info if present (PUT only)
        if (overlayURL) {
            const overlayUrlObj = new URL(overlayURL);
            let overlayKey = overlayUrlObj.pathname;
            if (overlayKey.startsWith('/')) overlayKey = overlayKey.slice(1);
            if (overlayKey.startsWith(bucket + '/')) overlayKey = overlayKey.slice(bucket.length + 1);
            const overlayURLForSigning = `${genericEndpoint}/${overlayKey}`;
            const overlayToken = await signUrl(overlayURLForSigning, process.env.BUNNYKEY, 3600, null, false, null, null, null, 'putObject');
            response.overlay = {
                filename: `${shortname}-ov.jpg`,
                url: `${publicEndpoint}/${overlayKey}`,
                token: overlayToken
            };
        }

        res.json(response);
    } catch (error) {
        console.error('Screenshot signing error:', error);
        res.status(500).json({ error: 'Failed to sign screenshot URLs' });
    }
});

app.post('/api/signScreenshot/commit', authenticateToken, async (req, res) => {
    try {
        const result = await registerCommittedScreenshot(
            req.user,
            req.body.sessionId,
            req.body.screenshotChecksum,
            { User, Session, Candidate },
            { afterScreenshotRegistered: afterHelpdeskScreenshotRegistered }
        );
        if (result.error) {
            return res.status(result.error.status).json({ error: result.error.message });
        }
        res.json(result);
    } catch (error) {
        console.error('signScreenshot commit error:', error);
        res.status(500).json({ error: 'Failed to commit screenshot' });
    }
});

app.post('/api/prepareScreenshotUpload', authenticateToken, async (req, res) => {
    try {
        const result = await prepareScreenshotUpload(req.user, req.body.sessionId, {
            User,
            Session,
            Candidate
        });
        if (result.error) {
            return res.status(result.error.status).json({ error: result.error.message });
        }
        res.json(result);
    } catch (error) {
        console.error('prepareScreenshotUpload error:', error);
        res.status(500).json({ error: 'Failed to prepare screenshot upload' });
    }
});

app.post('/api/commitScreenshot', authenticateToken, async (req, res) => {
    try {
        const result = await commitScreenshotUpload(
            req.user,
            req.body.sessionId,
            req.body.uploadId,
            { User, Session, Candidate },
            { afterScreenshotRegistered: afterHelpdeskScreenshotRegistered }
        );
        if (result.error) {
            return res.status(result.error.status).json({ error: result.error.message });
        }
        res.json(result);
    } catch (error) {
        console.error('commitScreenshot error:', error);
        res.status(500).json({ error: 'Failed to commit screenshot' });
    }
});

// Set user location
app.post('/api/setLocation', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, sessionId: bodySessionId } = req.body;
        
        // Validate coordinates
        if (typeof latitude !== 'number' || typeof longitude !== 'number') {
            return res.status(400).json({ error: 'Invalid coordinates' });
        }
        
        if (latitude === 0 && longitude === 0) {
            return res.status(400).json({ error: 'Invalid coordinates' });
        }
        
        if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
            return res.status(400).json({ error: 'Coordinates out of valid range' });
        }

        // Check if user exists in User collection
        let user = await User.findOne({ firebaseUid: req.user.uid });
        let isAnonymous = false;
        let candidate = null;

        // Check if they're an anonymous candidate (regardless of whether they exist in User collection)
        candidate = await Candidate.findOne({ firebaseUid: req.user.uid });
        if (candidate) {
            isAnonymous = true;
            if (process.env.DEBUG) {
                console.log('🗺️ Anonymous candidate found:', {
                    candidateId: candidate._id,
                    name: candidate.name,
                    email: candidate.email
                });
            }
        } else if (!user) {
            // If no candidate found and no user found, return error
            return res.status(404).json({ error: 'User not found in User or Candidate collections' });
        }

        // Get current city from appropriate record
        const currentCity = isAnonymous ? candidate.city : user.city;
        const storedSessionId = isAnonymous ? candidate.sessionId : user.sessionId;
        const lastMapboxUpdateSession = isAnonymous ? candidate.lastMapboxUpdateSession : user.lastMapboxUpdateSession;
        // Use the sessionId from the request body, falling back to stored sessionId
        const currentSessionId = bodySessionId || storedSessionId;

        // Return immediately with current location
        res.json({
            success: true,
            location: {
                type: 'Point',
                coordinates: [longitude, latitude],
                lastUpdated: new Date()
            },
            city: currentCity,
            isAnonymous: isAnonymous
        });

        // Process location update asynchronously
        (async () => {
            try {
                // Only update city if we don't have one or if it's a new session
                let city = currentCity;
                if (process.env.DEBUG) {
                    console.log('🗺️ City update check:', {
                        currentCity: city,
                        bodySessionId: bodySessionId,
                        storedSessionId: storedSessionId,
                        currentSessionId: currentSessionId,
                        lastMapboxUpdateSession: lastMapboxUpdateSession,
                        shouldUpdate: !city || city === 'Unknown' || currentSessionId !== lastMapboxUpdateSession,
                        isAnonymous: isAnonymous
                    });
                }
                
                if (!city || city === 'Unknown' || city === 'Local' || currentSessionId !== lastMapboxUpdateSession) {
                    if (process.env.DEBUG) {
                        console.log('🗺️ Mapbox geocoding request:', {
                            coordinates: [longitude, latitude],
                            currentCity: city,
                            sessionId: currentSessionId,
                            lastMapboxUpdateSession: lastMapboxUpdateSession,
                            isAnonymous: isAnonymous
                        });
                    }

                    // Get city from coordinates using Mapbox
                    const geoResult = await geocodingService.reverseGeocode({
                        query: [longitude, latitude],
                        types: ['place'],
                        limit: 5
                    }).send();

                    if (process.env.DEBUG) {
                        console.log('🗺️ Mapbox geocoding response:', {
                            features: geoResult.body.features?.map(f => ({
                                text: f.text,
                                place_name: f.place_name,
                                relevance: f.relevance
                            }))
                        });
                    }

                    // Try to find the city in the features
                    if (geoResult.body.features && geoResult.body.features.length > 0) {
                        // Use the first feature's text as it should be the most relevant place
                        city = geoResult.body.features[0].text;
                        // Extract rich location data from Mapbox response
                        const mapboxData = geoResult.body.features[0];
                        const mapboxLocation = {
                            city: mapboxData.text,
                            region: mapboxData.context?.find(c => c.id.startsWith('region'))?.text || null,
                            country: mapboxData.context?.find(c => c.id.startsWith('country'))?.text || null,
                            coordinates: [longitude, latitude],
                            place_name: mapboxData.place_name,
                            context: mapboxData.context?.map(c => c.text) || [],
                            lastUpdated: new Date()
                        };
                        if (process.env.DEBUG) {
                            console.log('🗺️ Selected city from Mapbox:', city);
                            console.log('🗺️ Mapbox location data:', mapboxLocation);
                        }

                        // Also update the session's mapboxLocation so verify endpoint can surface GPS city
                        try {
                            await Session.findOneAndUpdate(
                                { sessionId: currentSessionId },
                                { mapboxLocation }
                            );
                        } catch (sessionErr) {
                            // non-fatal: candidate/user update still succeeded
                            if (process.env.DEBUG) console.warn('⚠️ Could not update session mapboxLocation:', sessionErr.message);
                        }
                    }
                } else {
                    if (process.env.DEBUG) {
                        console.log('🗺️ Using existing city:', city);
                    }
                }

                if (process.env.DEBUG) {
                    console.log('🗺️ Final city value before database update:', {
                        city: city,
                        coordinates: [longitude, latitude],
                        isAnonymous: isAnonymous,
                        willUpdateCandidate: isAnonymous && candidate
                    });
                }

                // Update location in appropriate collection
                if (isAnonymous && candidate) {
                    if (process.env.DEBUG) {
                        console.log('🗺️ Updating anonymous candidate with city:', {
                            firebaseUid: req.user.uid,
                            city: city,
                            currentSessionId: currentSessionId,
                            coordinates: [longitude, latitude]
                        });
                    }

                    // Update candidate location
                    const updateData = {
                        location: {
                            type: 'Point',
                            coordinates: [longitude, latitude],
                            lastUpdated: new Date()
                        },
                        city: city,
                        sessionId: currentSessionId,
                        lastMapboxUpdateSession: currentSessionId
                    };

                    if (process.env.DEBUG) {
                        console.log('🗺️ Candidate update data:', JSON.stringify(updateData, null, 2));
                    }

                    const updatedCandidate = await Candidate.findOneAndUpdate(
                        { firebaseUid: req.user.uid },
                        updateData,
                        { new: true }
                    );

                    if (updatedCandidate) {
                        if (process.env.DEBUG) {
                            console.log('🗺️ Anonymous candidate location update complete:', {
                                candidateId: updatedCandidate._id,
                                name: updatedCandidate.name,
                                email: updatedCandidate.email,
                                city: updatedCandidate.city,
                                coordinates: updatedCandidate.location.coordinates,
                                lastUpdated: updatedCandidate.location.lastUpdated
                            });
                            
                            // Verify the update worked
                            console.log('🗺️ Candidate location verification:', {
                                before: {
                                    city: candidate.city,
                                    coordinates: candidate.location.coordinates
                                },
                                after: {
                                    city: updatedCandidate.city,
                                    coordinates: updatedCandidate.location.coordinates
                                }
                            });
                        }
                    } else {
                        if (process.env.DEBUG) {
                            console.log('⚠️ Failed to update candidate location for firebaseUid:', req.user.uid);
                        }
                    }
                } else if (user) {
                    // Update user location
                    const updatedUser = await User.findOneAndUpdate(
                        { firebaseUid: req.user.uid },
                        {
                            location: {
                                type: 'Point',
                                coordinates: [longitude, latitude],
                                lastUpdated: new Date()
                            },
                            city: city,
                            sessionId: currentSessionId,
                            lastMapboxUpdateSession: currentSessionId
                        },
                        { new: true }
                    );

                    if (updatedUser) {
                        if (process.env.DEBUG) {
                            console.log('🗺️ User location update complete:', {
                                userId: updatedUser.firebaseUid,
                                email: updatedUser.email,
                                city: updatedUser.city,
                                coordinates: updatedUser.location.coordinates,
                                lastUpdated: updatedUser.location.lastUpdated
                            });
                        }
                    }
                }

                // Also update the session location if user has an active session
                if (currentSessionId) {
                    const sessionUpdateData = {
                        location: {
                            type: 'Point',
                            coordinates: [longitude, latitude],
                            lastUpdated: new Date()
                        }
                    };
                    
                    // Add mapboxLocation if we have it from the geocoding
                    // Only try to access geoResult if it was defined (when geocoding was performed)
                    if (typeof geoResult !== 'undefined' && geoResult?.body?.features?.length > 0) {
                        const mapboxData = geoResult.body.features[0];
                        sessionUpdateData.mapboxLocation = {
                            city: mapboxData.text,
                            region: mapboxData.context?.find(c => c.id.startsWith('region'))?.text || null,
                            country: mapboxData.context?.find(c => c.id.startsWith('country'))?.text || null,
                            coordinates: [longitude, latitude],
                            place_name: mapboxData.place_name,
                            context: mapboxData.context?.map(c => c.text) || [],
                            lastUpdated: new Date()
                        };
                    }
                    
                    const sessionUpdate = await Session.findOneAndUpdate(
                        { sessionId: currentSessionId },
                        sessionUpdateData,
                        { new: true }
                    );

                    if (sessionUpdate) {
                        if (process.env.DEBUG) {
                            console.log('🗺️ Session location updated:', {
                                sessionId: sessionUpdate.sessionId,
                                coordinates: sessionUpdate.location.coordinates,
                                lastUpdated: sessionUpdate.location.lastUpdated
                            });
                        }
                    } else {
                        if (process.env.DEBUG) {
                            console.log('⚠️ No active session found to update location for sessionId:', currentSessionId);
                        }
                    }
                }
            } catch (error) {
                console.error('Error in async location update:', error);
            }
        })();
    } catch (error) {
        console.error('Error in location update:', error);
        res.status(500).json({ error: 'Failed to update location' });
    }
});

// Update LinkedIn profile
app.post('/api/updateLinkedIn', authenticateToken, async (req, res) => {
    try {
        const { linkedinId } = req.body;

        // Basic URL validation
        if (!linkedinId) {
            return res.status(400).json({ error: 'LinkedIn ID is required' });
        }

        // Update user's LinkedIn ID immediately
        const updatedUser = await User.findOneAndUpdate(
            { firebaseUid: req.user.uid },
            { linkedinId },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Start background verification
        updateUserVerifiedData(updatedUser._id, linkedinId).catch(error => {
            console.error('Background verification failed:', error);
        });

        res.json({
            success: true,
            linkedinId: updatedUser.linkedinId,
            verified: updatedUser.verified
        });
    } catch (error) {
        console.error('Error updating LinkedIn profile:', error);
        res.status(500).json({ error: 'Failed to update LinkedIn profile' });
    }
});

// Test notification subscription
app.post('/api/notifications/test-subscribe', authenticateToken, async (req, res) => {
    try {
        console.log('🧪 Test notification subscription called');
        console.log('User from token:', req.user.uid);
        
        // Test update with a dummy key
        const testKey = 'test-notification-key-' + Date.now();
        
        const updateResult = await User.updateOne(
            { firebaseUid: req.user.uid },
            { 
                $set: { 
                    notificationKey: testKey,
                    notificationSubscribed: true,
                    notificationSubscribedAt: new Date(),
                    notificationUnsubscribedAt: null
                }
            }
        );

        console.log('Test update result:', JSON.stringify(updateResult, null, 2));

        // Verify the update
        const updatedUser = await User.findOne({ firebaseUid: req.user.uid });
        console.log('User after test update:', JSON.stringify(updatedUser, null, 2));

        res.json({
            success: true,
            message: 'Test subscription completed',
            updateResult,
            user: updatedUser
        });
    } catch (error) {
        console.error('Test subscription error:', error);
        res.status(500).json({ error: 'Test subscription failed' });
    }
});

// Subscribe to notifications
app.post('/api/notifications/subscribe', authenticateToken, async (req, res) => {
    try {
        console.log('🔔 Notification subscribe called for user:', req.user.uid);
        console.log('Request body:', JSON.stringify(req.body, null, 2));
        
        // Accept both fcmToken and notificationKey field names
        const fcmToken = req.body.fcmToken || req.body.notificationKey;
        
        if (!fcmToken) {
            console.log('❌ No FCM token provided in request');
            return res.status(400).json({ error: 'FCM token is required' });
        }

        // Validate FCM token format
        if (!fcmToken.match(/^[A-Za-z0-9-_]+:[A-Za-z0-9-_]+$/)) {
            console.log('❌ Invalid FCM token format');
            return res.status(400).json({ error: 'Invalid FCM token format' });
        }

        // First get the current user state
        const currentUser = await User.findOne({ firebaseUid: req.user.uid });
        if (!currentUser) {
            console.log('❌ User not found:', req.user.uid);
            return res.status(404).json({ error: 'User not found' });
        }

        // Update user's devices array
        // If the token already exists, update its lastUsed timestamp
        // If it doesn't exist, add it as a new device
        const updateResult = await User.findOneAndUpdate(
            { 
                firebaseUid: req.user.uid,
                'devices.token': fcmToken 
            },
            { 
                $set: { 
                    'devices.$.lastUsed': new Date(),
                    notificationSubscribed: true,
                    notificationSubscribedAt: new Date(),
                    notificationUnsubscribedAt: null
                }
            },
            { new: true }
        );

        // If the token wasn't found (updateResult is null), add it as a new device
        if (!updateResult) {
            const updateResult = await User.findOneAndUpdate(
                { firebaseUid: req.user.uid },
                { 
                    $push: { 
                        devices: {
                            token: fcmToken,
                            lastUsed: new Date()
                        }
                    },
                    $set: {
                        notificationSubscribed: true,
                        notificationSubscribedAt: new Date(),
                        notificationUnsubscribedAt: null
                    }
                },
                { new: true }
            );
        }

        // Get the updated user to verify changes
        const updatedUser = await User.findOne({ firebaseUid: req.user.uid });
        if (!updatedUser) {
            console.log('❌ User not found after update:', req.user.uid);
            return res.status(404).json({ error: 'User not found after update' });
        }

        // Verify the device was added/updated correctly
        const device = updatedUser.devices.find(d => d.token === fcmToken);
        if (!device) {
            console.error('❌ FCM token was not stored correctly');
            return res.status(500).json({ error: 'Failed to store FCM token correctly' });
        }

        console.log('✅ Notifications registered:', {
            email: updatedUser.email,
            device: fcmToken.substring(0, 20) + '...',
            subscribed: updatedUser.notificationSubscribed,
            at: updatedUser.notificationSubscribedAt,
            devicesCount: updatedUser.devices.length
        });

        res.json({ 
            success: true, 
            message: 'Successfully subscribed to notifications',
            subscribed: true,
            subscribedAt: updatedUser.notificationSubscribedAt,
            devicesCount: updatedUser.devices.length
        });
    } catch (error) {
        console.error('❌ Notification subscription error:', error);
        res.status(500).json({ error: 'Failed to subscribe to notifications' });
    }
});

// Unsubscribe from notifications
app.post('/api/notifications/unsubscribe', authenticateToken, async (req, res) => {
    try {
        console.log('🔕 Notification unsubscribe called for user:', req.user.uid);
        
        // Accept both fcmToken and notificationKey field names
        const fcmToken = req.body.fcmToken || req.body.notificationKey;
        
        // First get the current user state
        const currentUser = await User.findOne({ firebaseUid: req.user.uid });
        console.log('Current user state before unsubscribe:', {
            userId: currentUser?.firebaseUid,
            subscribed: currentUser?.notificationSubscribed,
            devicesCount: currentUser?.devices?.length || 0,
            subscribedAt: currentUser?.notificationSubscribedAt,
            unsubscribedAt: currentUser?.notificationUnsubscribedAt
        });

        let updateQuery;
        if (fcmToken) {
            // If a token is provided, only remove that specific device
            updateQuery = {
                $pull: { devices: { token: fcmToken } }
            };
        } else {
            // If no token is provided, remove all devices
            updateQuery = {
                $set: { devices: [] }
            };
        }

        // Add unsubscribe fields to the update
        updateQuery.$set = {
            ...updateQuery.$set,
            notificationSubscribed: false,
            notificationUnsubscribedAt: new Date()
        };

        const user = await User.findOneAndUpdate(
            { firebaseUid: req.user.uid },
            updateQuery,
            { new: true }
        );

        if (!user) {
            console.log('❌ User not found:', req.user.uid);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log('✅ Successfully unsubscribed user from notifications:', {
            userId: user.firebaseUid,
            subscribed: user.notificationSubscribed,
            remainingDevices: user.devices.length,
            unsubscribedAt: user.notificationUnsubscribedAt
        });

        res.json({ 
            success: true, 
            message: fcmToken ? 'Successfully unsubscribed device from notifications' : 'Successfully unsubscribed all devices from notifications',
            subscribed: false,
            unsubscribedAt: user.notificationUnsubscribedAt,
            remainingDevices: user.devices.length
        });
    } catch (error) {
        console.error('❌ Notification unsubscription error:', error);
        res.status(500).json({ error: 'Failed to unsubscribe from notifications' });
    }
});

// Get notification subscription status
app.get('/api/notifications/status', authenticateToken, async (req, res) => {
    try {
        console.log('📊 Getting notification status for user:', req.user.uid);
        
        const user = await User.findOne({ firebaseUid: req.user.uid });
        
        if (!user) {
            console.log('❌ User not found:', req.user.uid);
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if user has a valid subscription
        const isSubscribed = user.notificationSubscribed && 
                           user.notificationKey && 
                           (!user.notificationUnsubscribedAt || 
                            user.notificationSubscribedAt > user.notificationUnsubscribedAt);

        console.log('✅ User notification status:', {
            userId: user.firebaseUid,
            subscribed: user.notificationSubscribed,
            hasNotificationKey: !!user.notificationKey,
            subscribedAt: user.notificationSubscribedAt,
            unsubscribedAt: user.notificationUnsubscribedAt,
            calculatedSubscriptionStatus: isSubscribed
        });

        res.json({
            subscribed: isSubscribed,
            subscribedAt: user.notificationSubscribedAt,
            unsubscribedAt: user.notificationUnsubscribedAt,
            hasNotificationKey: !!user.notificationKey
        });
    } catch (error) {
        console.error('❌ Notification status error:', error);
        res.status(500).json({ error: 'Failed to get notification status' });
    }
});

// Send notification
app.post('/api/notifications/send', authenticateToken, async (req, res) => {
    try {
        const { title, body, data } = req.body;
        
        if (!title || !body) {
            return res.status(400).json({ error: 'Title and body are required' });
        }

        console.log('📤 Sending notification:', {
            to: req.user.uid,
            title,
            body,
            data
        });

        // Get the user's notification tokens
        const user = await User.findOne({ 
            firebaseUid: req.user.uid,
            notificationSubscribed: true,
            'devices.0': { $exists: true }
        });

        if (!user || !user.devices.length) {
            return res.status(400).json({ error: 'User has no notification tokens registered' });
        }

        // Send to each device individually
        const results = await Promise.allSettled(
            user.devices.map(device => 
                admin.messaging().send({
                    notification: {
                        title: title,
                        body: body
                    },
                    data: convertDataToStrings(data || {}),
                    token: device.token
                })
            )
        );

        // Process results
        const successCount = results.filter(r => r.status === 'fulfilled').length;
        const failureCount = results.filter(r => r.status === 'rejected').length;

        // Clean up any invalid tokens
        const failedTokens = results
            .map((result, idx) => result.status === 'rejected' ? user.devices[idx].token : null)
            .filter(token => token !== null);

        if (failedTokens.length > 0) {
            console.log('Removing invalid tokens:', failedTokens);
            await User.updateOne(
                { firebaseUid: req.user.uid },
                { $pull: { devices: { token: { $in: failedTokens } } } }
            );
        }

        console.log('✅ Notifications sent:', {
            to: req.user.uid,
            devicesCount: user.devices.length,
            successCount,
            failureCount,
            invalidTokensRemoved: failedTokens.length
        });

        res.json({ 
            success: true, 
            message: 'Notifications sent successfully',
            devicesCount: user.devices.length,
            successCount,
            failureCount,
            invalidTokensRemoved: failedTokens.length
        });
    } catch (error) {
        console.error('❌ Error sending notification:', error);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

// Helper function to detect mobile device type from device info string
function coerceDeviceInfoString(deviceInfo) {
    if (!deviceInfo) return null;
    if (typeof deviceInfo === 'string') return deviceInfo;
    if (typeof deviceInfo === 'object') {
        return deviceInfo.userAgent || deviceInfo.ua || deviceInfo.agent || null;
    }
    return String(deviceInfo);
}

function detectMobileDevice(deviceInfo) {
    const deviceInfoText = coerceDeviceInfoString(deviceInfo);
    if (!deviceInfoText) {
        return {
            isMobile: false,
            deviceType: 'Unknown',
            details: null
        };
    }

    const deviceInfoLower = deviceInfoText.toLowerCase();
    let isMobile = false;
    let deviceType = 'Desktop/Web';
    let details = null;

    // Check for mobile indicators
    const mobileIndicators = [
        'mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 
        'windows phone', 'opera mini', 'opera mobi', 'palm', 'symbian'
    ];

    isMobile = mobileIndicators.some(indicator => deviceInfoLower.includes(indicator));

    if (isMobile) {
        // Detect specific device types
        if (deviceInfoLower.includes('iphone')) {
            deviceType = 'iPhone';
            // Extract iPhone model if available
            const iphoneMatch = deviceInfoText.match(/iPhone(\d+,\d+|;\s*CPU iPhone OS)/i);
            if (iphoneMatch) {
                details = iphoneMatch[0];
            }
        } else if (deviceInfoLower.includes('ipad')) {
            deviceType = 'iPad';
            const ipadMatch = deviceInfoText.match(/iPad[^;]*/i);
            if (ipadMatch) {
                details = ipadMatch[0];
            }
        } else if (deviceInfoLower.includes('android')) {
            deviceType = 'Android';
            // Extract Android version and device model if available
            const androidMatch = deviceInfoText.match(/Android\s[\d.]+|SM-[A-Z0-9]+|[A-Z]+-[A-Z0-9]+/gi);
            if (androidMatch && androidMatch.length > 0) {
                details = androidMatch.join(', ');
            }
        } else if (deviceInfoLower.includes('windows phone')) {
            deviceType = 'Windows Phone';
        } else if (deviceInfoLower.includes('blackberry')) {
            deviceType = 'BlackBerry';
        } else {
            deviceType = 'Mobile (Other)';
        }
    } else {
        // Check for desktop/browser indicators
        if (deviceInfoLower.includes('chrome')) {
            deviceType = 'Desktop (Chrome)';
        } else if (deviceInfoLower.includes('firefox')) {
            deviceType = 'Desktop (Firefox)';
        } else if (deviceInfoLower.includes('safari') && !deviceInfoLower.includes('chrome')) {
            deviceType = 'Desktop (Safari)';
        } else if (deviceInfoLower.includes('edge')) {
            deviceType = 'Desktop (Edge)';
        } else if (deviceInfoLower.includes('opera')) {
            deviceType = 'Desktop (Opera)';
        }
    }

    return {
        isMobile,
        deviceType,
        details: details || (deviceInfoText.length > 100 ? deviceInfoText.substring(0, 100) + '...' : deviceInfoText)
    };
}

// Format a location string, skipping Unknown and Local values
function formatLocationCity(iplocation) {
    if (!iplocation) return null;
    const parts = [];
    if (iplocation.city && iplocation.city !== 'Unknown' && iplocation.city !== 'Local') parts.push(iplocation.city);
    if (iplocation.region && iplocation.region !== 'Unknown' && iplocation.region !== 'Local') parts.push(iplocation.region);
    if (iplocation.country && iplocation.country !== 'Unknown' && iplocation.country !== 'Local') parts.push(iplocation.country);
    return parts.length > 0 ? parts.join(', ') : null;
}

function isValidGpsCoordinates(coordinates) {
    if (!Array.isArray(coordinates) || coordinates.length !== 2) return false;
    const [lon, lat] = coordinates;
    if (typeof lon !== 'number' || typeof lat !== 'number') return false;
    if (!Number.isFinite(lon) || !Number.isFinite(lat)) return false;
    if (lon === 0 && lat === 0) return false;
    if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return false;
    return true;
}

function getValidSessionGpsCoordinates(session) {
    if (isValidGpsCoordinates(session?.mapboxLocation?.coordinates)) {
        return session.mapboxLocation.coordinates;
    }
    if (isValidGpsCoordinates(session?.location?.coordinates)) {
        return session.location.coordinates;
    }
    return null;
}

function computeLocationMismatch(session) {
    const ip = session.iplocation;
    const gps = getValidSessionGpsCoordinates(session);
    if (!ip || !gps || ip.lat == null || ip.lon == null) return false;
    const dlat = (gps[1] - ip.lat) * 111;
    const dlon = (gps[0] - ip.lon) * 111 * Math.cos(ip.lat * Math.PI / 180);
    return Math.sqrt(dlat * dlat + dlon * dlon) > 100;
}

function buildSessionGpsLocation(session) {
    const coords = getValidSessionGpsCoordinates(session);
    if (!coords) {
        if (session?.mapboxLocation?.city) {
            const mb = session.mapboxLocation;
            const result = {
                city: mb.city,
                region: mb.region || null,
                country: mb.country || null,
                lastUpdated: mb.lastUpdated
            };
            if (isValidGpsCoordinates(mb.coordinates)) {
                result.lat = mb.coordinates[1];
                result.lon = mb.coordinates[0];
                result.coordinates = mb.coordinates;
            }
            return result;
        }
        return null;
    }
    const [lon, lat] = coords;
    const result = {
        lat,
        lon,
        coordinates: coords,
        lastUpdated: session.mapboxLocation?.lastUpdated || session.location?.lastUpdated
    };
    if (session.mapboxLocation?.city) {
        result.city = session.mapboxLocation.city;
        result.region = session.mapboxLocation.region || null;
        result.country = session.mapboxLocation.country || null;
    }
    return result;
}

function formatCoordinateCity(coordinates) {
    if (!coordinates || coordinates.length !== 2) {
        return null;
    }
    const [lon, lat] = coordinates;
    return `${Math.abs(lat).toFixed(1)}°${lat >= 0 ? 'N' : 'S'}, ${Math.abs(lon).toFixed(1)}°${lon >= 0 ? 'E' : 'W'}`;
}

function resolveSessionDisplayCity(session, gpsCity) {
    const ipCity = formatLocationCity(session.iplocation);
    const ipapiCity = session.ipapi?.location
        ? formatLocationCity({
            city: session.ipapi.location.city,
            region: session.ipapi.location.state,
            country: session.ipapi.location.country
        })
        : null;
    const networkCity = ipCity || ipapiCity;
    const gps = getValidSessionGpsCoordinates(session);

    if (gps && session.iplocation?.lat != null && session.iplocation?.lon != null) {
        const dlat = (gps[1] - session.iplocation.lat) * 111;
        const dlon = (gps[0] - session.iplocation.lon) * 111 * Math.cos(session.iplocation.lat * Math.PI / 180);
        if (Math.sqrt(dlat * dlat + dlon * dlon) > 100) {
            if (gpsCity) return gpsCity;
            return formatCoordinateCity(gps);
        }
    }

    if (gpsCity) {
        return gpsCity;
    }
    if (networkCity) {
        return networkCity;
    }
    return formatCoordinateCity(gps);
}

// Facebook profile picture proxy — resolves handle to numeric ID via page scrape, then redirects to Graph API picture
app.get('/api/facebook/picture/:handle', async (req, res) => {
    try {
        const { handle } = req.params;
        // Validate handle: alphanumeric, dots, hyphens, 1-50 chars
        if (!handle || !/^[a-zA-Z0-9.-]{1,50}$/.test(handle)) {
            return res.status(400).json({ error: 'Invalid handle' });
        }
        
        // Fetch the public profile page to extract numeric user ID
        const pageResp = await fetch(`https://www.facebook.com/${encodeURIComponent(handle)}`, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
            redirect: 'follow'
        });
        if (!pageResp.ok) return res.status(404).json({ error: 'Profile not found' });
        
        const html = await pageResp.text();
        const userIdMatch = html.match(/"userID":"(\d+)"/);
        if (!userIdMatch) return res.status(404).json({ error: 'Could not resolve user ID' });
        
        const userId = userIdMatch[1];
        res.redirect(302, `https://graph.facebook.com/${userId}/picture?type=large`);
    } catch (error) {
        console.error('Facebook picture proxy error:', error.message);
        res.status(500).json({ error: 'Failed to fetch profile picture' });
    }
});

// Helpdesk polling endpoint — returns verification data by sessionId
app.get('/api/helpdesk/session/:sessionId/photos', authenticateToken, requireFeature('helpdesk'), async (req, res) => {
    try {
        const { sessionId } = req.params;
        const session = await Session.findOne({ sessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        if (!session.candidateId) {
            return res.json({
                success: true,
                candidateId: null,
                currentSessionId: sessionId,
                sessions: [],
                baselinePhotos: [],
                totalSessions: 0
            });
        }

        const { user, userId, authEmail } = await resolveHistoryUser(req);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const candidate = await Candidate.findById(session.candidateId);
        if (!candidate) {
            return res.status(404).json({ error: 'Candidate not found' });
        }

        const allowed = await canAccessCandidatePhotoHistory(user, candidate, {
            userId,
            authEmail,
            session
        });
        if (!allowed) {
            return res.status(403).json({ error: 'Access denied to this candidate' });
        }

        const isPrimaryInterviewer = candidate.interviewer
            && candidate.interviewer.toString() === user._id.toString();
        const payload = await buildCandidatePhotoHistory(
            candidate,
            String(session.candidateId),
            sessionId,
            { userId, isPrimaryInterviewer }
        );
        return res.json(payload);
    } catch (error) {
        console.error('Helpdesk session photos error:', error);
        res.status(500).json({ error: 'Failed to retrieve session photos' });
    }
});

// Helpdesk polling endpoint — returns verification data by sessionId
app.get('/api/verify/placeholder', authenticateToken, async (req, res) => {
    try {
        const { sessionId } = req.query;
        if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
        const session = await Session.findOne({ sessionId });
        if (!session) return res.status(404).json({ error: 'Session not found' });
        const mobileDeviceInfo = detectMobileDevice(session.deviceInfo);
        let candidate = null;
        if (session.candidateId) {
            candidate = await Candidate.findById(session.candidateId);
        }
        const checkingInUser = await resolveCheckingInUserForVerification(session, candidate);
        const pinRequirement = await getSessionPinRequirement(session, candidate, checkingInUser);
        const preRegistration = await resolvePreRegistrationForSession(session, candidate, checkingInUser);
        const verificationFields = await buildSessionVerificationFields(session, pinRequirement, checkingInUser, candidate);
        // Reverse-geocode GPS coords to city name if not already cached
        let gpsCity = session.mapboxLocation?.city || null;
        if (!gpsCity && isValidGpsCoordinates(session.location?.coordinates)) {
            try {
                const geoResp = await geocodingService.reverseGeocode({
                    query: [session.location.coordinates[0], session.location.coordinates[1]],
                    types: ["place"],
                    limit: 1
                }).send();
                if (geoResp.body.features?.length > 0) {
                    gpsCity = geoResp.body.features[0].text;
                }
            } catch(e) { console.error("GPS reverse geocode failed:", e.message); }
        }
        const resp = {
            city: resolveSessionDisplayCity(session, gpsCity),
            ipInfo: session.ipaddr ? {
                address: session.ipaddr,
                location: (session.iplocation && session.iplocation.city !== 'Unknown' && session.iplocation.city !== 'Local')
                    ? session.iplocation
                    : (session.ipapi?.location ? {
                        country: session.ipapi.location.country,
                        region: session.ipapi.location.state,
                        city: session.ipapi.location.city,
                        timezone: session.ipapi.location.timezone,
                        isp: session.ipapi.company?.name || null
                    } : session.iplocation || null)
            } : null,
            mobileDevice: mobileDeviceInfo,
            livenessScore: getSessionLivenessScore(session, pinRequirement),
            ...verificationFields,
            networkInfo: session.networkInfo || null,
            browserInfo: session.browserInfo || null,
            ipapi: session.ipapi || null,
            sessionId: session.sessionId,
            source: session.source || 'helpdesk',
            email: session.email || null,
            mobile: session.mobile || null,
            deviceFingerprint: session.deviceFingerprint || null,
            gpsLocation: buildSessionGpsLocation(session),
            gpsCity: gpsCity,
            locationMismatch: computeLocationMismatch(session)
        };
        if (session.candidateId) {
            resp.candidateId = String(session.candidateId);
        }
        if (candidate) {
                const persistBaseline = isHelpdeskMobileCheckedIn(session, candidate);
                resp.verified = await buildSessionVerifiedIdentity({
                    candidate,
                    verificationFields,
                    preRegistration,
                    persistBaseline
                });
                resp.expectedLocation = resolveExpectedLocation(candidate, preRegistration);
        } else if (session.email && !session.email.endsWith('@anon')) {
            if (verificationFields.verifiedEmail && verificationFields.emailConfirmed) {
                resp.verified = mergeEmailVerification(null, verificationFields.verifiedEmail, {
                    confirmed: true,
                    method: verificationFields.emailVerificationMethod
                });
            }
        }
        resp.identityRisk = await computeIdentityRisk({
            session,
            candidate,
            verificationFields,
            checkingInUser
        });
        // Compute descriptive confidence indicator
        const deviceMatch = !!(resp.verified?.verifications || []).includes('device_match')
            || (session?.deviceFingerprint && checkingInUser?.deviceFingerprint === session.deviceFingerprint);
        const userEmail = verificationFields?.verifiedEmail || session?.email || candidate?.email || null;
        const consistency = userEmail ? await computeConsistency(userEmail) : null;
        resp.confidenceIndicator = await computeConfidenceIndicator({
            session,
            candidate,
            checkingInUser,
            verificationFields: { ...verificationFields, identityRisk: resp.identityRisk },
            livenessScore: resp.livenessScore,
            deviceMatch,
            consistency
        });
        // Look up Didit KYC for session email (independent of mobile checkin)
        const sessionEmail = (session?.email || candidate?.email || '').toLowerCase().trim();
        if (sessionEmail && !sessionEmail.endsWith('@anon')) {
            const diditUser = await User.findOne({ email: sessionEmail }).select('diditVerified authLevel kycDocType kycDocLabel linkedinId').lean();
            resp.diditVerified = !!(diditUser?.diditVerified);
            resp.authLevel = diditUser?.authLevel || null;
            resp.kycDocType = diditUser?.kycDocType || null;
            resp.kycDocLabel = diditUser?.kycDocLabel || null;
            // Lazy-fetch LinkedIn if linkedinId is set but no verified data yet
            if (!resp.verified && diditUser?.linkedinId && !diditUser.diditVerified) {
                (async () => {
                    try {
                        const { getLinkedInProfileData } = require('./utils/linkedinUtils');
                        const username = diditUser.linkedinId.split('/').pop().split('?')[0];
                        const linkedinData = await getLinkedInProfileData(username);
                        if (linkedinData && (linkedinData.name || linkedinData.title)) {
                            const updatedVerified = {
                                name: linkedinData.name || null,
                                title: linkedinData.title || null,
                                location: linkedinData.location || null,
                                verifications: ['xchk verified: ' + sessionEmail]
                            };
                            await User.findByIdAndUpdate(diditUser._id, { verified: updatedVerified });
                            if (candidate && candidate.email === sessionEmail) {
                                await Candidate.findByIdAndUpdate(candidate._id, { verified: updatedVerified });
                            }
                        }
                    } catch(e) { console.error('LinkedIn lazy-fetch failed for', sessionEmail, e.message); }
                })();
            }
        } else {
            resp.diditVerified = false;
        }
        Object.assign(resp, await attachVerificationTelemetry(session, {
            mobile: resp.mobile || session.mobile
        }));
        const threatResult = await attachThreatAssessment(session, {
            session,
            candidate,
            verificationFields,
            pinRequirement,
            preRegistration,
            checkingInUser,
            identityRisk: resp.identityRisk,
            verified: resp.verified,
            expectedLocation: resp.expectedLocation || null,
            displayCity: resp.city,
            gpsCity,
            mobileDevice: mobileDeviceInfo,
            livenessScore: resp.livenessScore,
            locationMismatch: resp.locationMismatch,
            verifyData: resp
        });
        Object.assign(resp, threatResult);
        res.json(resp);
    } catch (error) {
        console.error('Helpdesk verify error:', error.message);
        res.status(500).json({ error: 'Failed to fetch verification data' });
    }
});

// Get verification information by shortcode or sessionId
app.get('/api/verify/:shortcode', authenticateToken, async (req, res) => {
    try {
        const { shortcode } = req.params;
        const { sessionId } = req.query;

        let session;

        if (sessionId) {
            session = await Session.findOne({ sessionId });
        } else {
            session = await Session.findOne({ 'screenshots.shortname': shortcode });
        }

        if (!session) {
            return res.status(404).json({ error: 'Verification not found' });
        }

        // Find the specific screenshot and its neighbors in the session
        const screenshots = (session.screenshots || []).sort((a, b) => a.createdAt - b.createdAt);
        let currentIndex = -1;
        let screenshot = null;

        if (sessionId) {
            screenshot = screenshots.length > 0 ? screenshots[0] : null;
            currentIndex = 0;
        } else {
            currentIndex = screenshots.findIndex(s => s.shortname === shortcode);
            screenshot = currentIndex >= 0 ? screenshots[currentIndex] : null;
        }

        // Profile user (session owner) — may be operator before helpdesk mobile check-in
        const profileUser = session.uuid
            ? await User.findOne({ firebaseUid: session.uuid })
            : null;
        if (!profileUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // If session has candidateId, get candidate information instead of user
        let linkedinId, photoURL, verified, city;
        let candidate = null;
        if (session.candidateId) {
            candidate = await Candidate.findById(session.candidateId);
            if (candidate) {
                linkedinId = candidate.linkedinId;
                photoURL = candidate.photoURL;
                verified = candidate.verified ? {
                    name: candidate.verified.name,
                    title: candidate.verified.title,
                    location: candidate.verified.location,
                    verifications: candidate.verified.verifications || []
                } : null;
                city = candidate.city || null;
            } else {
                // Fallback to user data if candidate not found
                linkedinId = profileUser.linkedinId;
                photoURL = profileUser.photoURL;
                verified = profileUser.verified ? {
                    name: profileUser.verified.name,
                    title: profileUser.verified.title,
                    location: profileUser.verified.location,
                    verifications: profileUser.verified.verifications || []
                } : null;
                city = profileUser.city || null;
            }
        } else {
            // Use user data if no candidateId
            linkedinId = profileUser.linkedinId;
            photoURL = profileUser.photoURL;
            verified = profileUser.verified ? {
                name: profileUser.verified.name,
                title: profileUser.verified.title,
                location: profileUser.verified.location,
                verifications: profileUser.verified.verifications || []
            } : null;
            city = profileUser.city || null;
        }

        // Get the screenshot creation time from session data
        let screenshotDate = null;
        if (screenshot && screenshot.createdAt) {
            screenshotDate = screenshot.createdAt;
        }
        
        // Get previous and next shortnames
        const prevShortname = currentIndex > 0 ? screenshots[currentIndex - 1].shortname : null;
        const nextShortname = currentIndex < screenshots.length - 1 ? screenshots[currentIndex + 1].shortname : null;

        // Detect mobile device info
        const mobileDeviceInfo = detectMobileDevice(session.deviceInfo);
        const checkingInUser = await resolveCheckingInUserForVerification(session, candidate);
        const pinRequirement = await getSessionPinRequirement(session, candidate, checkingInUser);
        const preRegistration = await resolvePreRegistrationForSession(session, candidate, checkingInUser);
        const verificationFields = await buildSessionVerificationFields(session, pinRequirement, checkingInUser, candidate);
        if (candidate) {
            if (!isPlaceholderLocation(candidate.city)) {
                city = candidate.city;
            }
            verified = await buildSessionVerifiedIdentity({
                candidate,
                verificationFields,
                preRegistration,
                persistBaseline: isHelpdeskMobileCheckedIn(session, candidate)
            });
        } else if (verificationFields.emailConfirmed && verificationFields.verifiedEmail) {
            verified = mergeEmailVerification(profileUser.verified, verificationFields.verifiedEmail, {
                confirmed: true,
                method: verificationFields.emailVerificationMethod
            });
        }
        const identityRisk = await computeIdentityRisk({
            session,
            candidate,
            verificationFields,
            checkingInUser
        });
        // Reverse-geocode GPS coords to city name if not already cached
        let gpsCity = session.mapboxLocation?.city || null;
        if (!gpsCity && isValidGpsCoordinates(session.location?.coordinates)) {
            try {
                const geoResp = await geocodingService.reverseGeocode({
                    query: [session.location.coordinates[0], session.location.coordinates[1]],
                    types: ["place"],
                    limit: 1
                }).send();
                if (geoResp.body.features?.length > 0) {
                    gpsCity = geoResp.body.features[0].text;
                }
            } catch(e) { console.error("GPS reverse geocode failed:", e.message); }
        }

        let subjectEmail = session.email || null;
        let subjectMobile = session.mobile || null;
        if (candidate) {
            subjectEmail = candidate.email || subjectEmail;
            subjectMobile = candidate.mobile || subjectMobile;
        }

        const response = {
            linkedinId: linkedinId,
            photoURL: photoURL,
            verified: verified,
            screenshotDate,
            city: resolveSessionDisplayCity(session, gpsCity) || city,
            email: subjectEmail,
            mobile: subjectMobile,
            sha256: screenshot ? screenshot.sha256 : null,
            navigation: {
                prev: prevShortname,
                next: nextShortname
            },
            mobileDevice: mobileDeviceInfo,
            livenessScore: getSessionLivenessScore(session, pinRequirement),
            ...verificationFields,
            transcripts: session.transcripts || false,
            sessionId: session.sessionId,
            source: session.source || 'interview',
            rating: session.rating || null,
            candidateId: session.candidateId ? String(session.candidateId) : null,
            helpdeskResult: session.helpdeskResult || null,
            helpdeskVerified: session.helpdeskResult === "pass" ? true : null,
            helpdeskResultAt: session.helpdeskResultAt || null,
            identityRisk
        };

        // Compute descriptive confidence indicator
        const deviceMatch = !!(verified?.verifications || []).includes('device_match')
            || (session?.deviceFingerprint && checkingInUser?.deviceFingerprint === session.deviceFingerprint);
        const userEmail = verificationFields?.verifiedEmail || session?.email || candidate?.email || null;
        const consistency = userEmail ? await computeConsistency(userEmail) : null;
        response.confidenceIndicator = await computeConfidenceIndicator({
            session,
            candidate,
            checkingInUser,
            verificationFields: { ...verificationFields, identityRisk },
            livenessScore: response.livenessScore,
            deviceMatch,
            consistency
        });

        // Look up subject user for identity badges (authLevel, diditVerified)
        const subjectUserEmail = subjectEmail && !subjectEmail.endsWith('@anon') ? subjectEmail : null;
        if (subjectUserEmail) {
            try {
                const subjectUser = await User.findOne({ email: subjectUserEmail })
                    .select('authLevel diditVerified diditVerifiedAt kycDocType kycDocLabel linkedinId')
                    .lean();
                if (subjectUser) {
                    response.authLevel = subjectUser.authLevel || null;
                    response.diditVerified = !!subjectUser.diditVerified;
                    response.kycDocType = subjectUser.kycDocType || null;
                    response.kycDocLabel = subjectUser.kycDocLabel || null;
                    // Lazy-fetch LinkedIn profile data if linkedinId is set but verified data is missing
                    if (!verified && !response.verified && subjectUser.linkedinId && !subjectUser.diditVerified) {
                        (async () => {
                            try {
                                const { getLinkedInProfileData } = require('./utils/linkedinUtils');
                                const username = subjectUser.linkedinId.split('/').pop().split('?')[0];
                                const linkedinData = await getLinkedInProfileData(username);
                                if (linkedinData && (linkedinData.name || linkedinData.title)) {
                                    const updatedVerified = {
                                        name: linkedinData.name || null,
                                        title: linkedinData.title || null,
                                        location: linkedinData.location || null,
                                        verifications: ['xchk verified: ' + subjectUserEmail]
                                    };
                                    await User.findByIdAndUpdate(subjectUser._id, { verified: updatedVerified });
                                    // If candidate exists, update that too
                                    if (candidate && candidate.email === subjectUserEmail) {
                                        await Candidate.findByIdAndUpdate(candidate._id, { verified: updatedVerified });
                                    }
                                    console.log('✅ Lazy-fetched LinkedIn data for', subjectUserEmail);
                                }
                            } catch(e) { console.error('LinkedIn lazy-fetch failed for', subjectUserEmail, e.message); }
                        })();
                    }
                }
            } catch(e) { console.error('Subject user lookup failed:', e.message); }
        }

        // Add network information if available
        if (session.networkInfo) {
            response.networkInfo = {
                type: session.networkInfo.type,
                effectiveType: session.networkInfo.effectiveType,
                downlink: session.networkInfo.downlink,
                rtt: session.networkInfo.rtt
            };
            
            // Include ipapi data within networkInfo if available
            if (session.ipapi) {
                response.networkInfo.ipapi = {
                    is_vpn: session.ipapi.is_vpn,
                    is_proxy: session.ipapi.is_proxy,
                    is_datacenter: session.ipapi.is_datacenter,
                    is_tor: session.ipapi.is_tor,
                    is_mobile: session.ipapi.is_mobile,
                    is_satellite: session.ipapi.is_satellite,
                    is_crawler: session.ipapi.is_crawler,
                    is_bogon: session.ipapi.is_bogon,
                    is_abuser: session.ipapi.is_abuser,
                    datacenter: session.ipapi.datacenter,
                    company: session.ipapi.company,
                    asn: session.ipapi.asn,
                    location: session.ipapi.location
                };
                
                if (process.env.DEBUG) {
                    console.log(`📤 Sending ipapi data within networkInfo in verify response:`, JSON.stringify(response.networkInfo.ipapi, null, 2));
                }
            }
        }

        Object.assign(response, await attachVerificationTelemetry(session, { mobile: subjectMobile }));

        // Add IP address and geolocation information if available
        if (session.ipaddr) {
            response.ipInfo = {
                address: session.ipaddr,
                location: session.iplocation ? {
                    country: session.iplocation.country,
                    region: session.iplocation.region,
                    city: session.iplocation.city,
                    timezone: session.iplocation.timezone,
                    isp: session.iplocation.isp
                } : null
            };
        }

        // Add ipapi.is information if available
        if (session.ipapi) {
            response.ipapi = {
                is_vpn: session.ipapi.is_vpn,
                is_proxy: session.ipapi.is_proxy,
                is_datacenter: session.ipapi.is_datacenter,
                is_tor: session.ipapi.is_tor,
                is_mobile: session.ipapi.is_mobile, // Network-level mobile detection takes priority
                is_satellite: session.ipapi.is_satellite,
                is_crawler: session.ipapi.is_crawler,
                is_bogon: session.ipapi.is_bogon,
                is_abuser: session.ipapi.is_abuser,
                datacenter: session.ipapi.datacenter,
                company: session.ipapi.company,
                asn: session.ipapi.asn,
                location: session.ipapi.location
            };
            
            if (process.env.DEBUG) {
                console.log(`📤 Sending ipapi data in verify response for session ${session.sessionId}:`, JSON.stringify(response.ipapi, null, 2));
            }
        } else if (process.env.DEBUG) {
            console.log(`⚠️ No ipapi data found in session ${session.sessionId} for verify response`);
        }

        // Add browser information if available
        if (session.browserInfo && (session.browserInfo.languages || session.browserInfo.timezone)) {
            response.browserInfo = {
                languages: session.browserInfo.languages || [],
                timezone: session.browserInfo.timezone || null,
                lastUpdated: session.browserInfo.lastUpdated || null
            };
        }

        const gpsLocation = buildSessionGpsLocation(session);
        if (gpsLocation) {
            response.gpsLocation = gpsLocation;
        }
        response.locationMismatch = computeLocationMismatch(session);
        if (gpsCity) {
            response.gpsCity = gpsCity;
        }

        const expectedLocation = candidate
            ? resolveExpectedLocation(candidate, preRegistration)
            : null;
        const threatResult = await attachThreatAssessment(session, {
            session,
            candidate,
            verificationFields,
            pinRequirement,
            preRegistration,
            checkingInUser,
            identityRisk: response.identityRisk,
            verified: response.verified,
            expectedLocation,
            displayCity: response.city,
            gpsCity,
            mobileDevice: mobileDeviceInfo,
            livenessScore: response.livenessScore,
            locationMismatch: response.locationMismatch,
            verifyData: response
        });
        Object.assign(response, threatResult);

        res.json(response);
    } catch (error) {
        console.error('Verification info error:', error);
        res.status(500).json({ error: 'Failed to get verification information' });
    }
});

// Generate QR code for verification
app.post('/api/generateQR', authenticateToken, async (req, res) => {
    try {
        // Generate a random 8-character code
        const shortcode = Math.random().toString(36).substring(2, 10);
        
        // Create a new session
        const session = await Session.create({
            uuid: req.user.uid,
            shortname: shortcode,
            created: new Date()
        });

        // Generate QR code with the new URL format
        const qrData = `https://xchk.io/verify.html?code=${shortcode}`;
        const qrCode = await QRCode.toDataURL(qrData, {
            width: 150,
            height: 150
        });

        res.json({
            qrCode,
            shortcode
        });
    } catch (error) {
        console.error('QR generation error:', error);
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

// Get current session for a user
app.get('/api/getsession', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const decodedToken = await verifyFirebaseIdToken(token);
        const uuid = decodedToken.uid;

        // Get the user to find their current sessionId
        const user = await User.findOne({ firebaseUid: uuid });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.sessionId) {
            return res.status(404).json({ error: 'No active session found' });
        }

        // Find the session using the sessionId from the user
        const session = await Session.findOne({ sessionId: user.sessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        res.json({
            sessionId: session.sessionId,
            screenshots: session.screenshots || [],
            createdAt: session.createdAt,
            date: session.date
        });
    } catch (error) {
        console.error('Get session error:', error);
        res.status(500).json({ error: 'Failed to get session' });
    }
});

// Network info endpoint
app.post('/api/networkinfo', authenticateToken, async (req, res) => {
    try {
        const { networkInfo, sessionId } = req.body;
        
        console.log('📡 Network info request:', {
            firebaseUid: req.user.uid,
            providedSessionId: sessionId || 'none',
            hasNetworkInfo: !!networkInfo
        });

        // Validate required fields
        if (!networkInfo || typeof networkInfo !== 'object') {
            return res.status(400).json({ error: 'Network info is required and must be an object' });
        }

        // Validate network info structure
        const { type, effectiveType, downlink, rtt, saveData, measuredRtt } = networkInfo;
        
        const resolvedRtt = rtt ?? measuredRtt ?? null;
        const rttSource = rtt != null
            ? 'client'
            : (measuredRtt != null ? 'measured' : null);
        
        if (type && !['bluetooth', 'cellular', 'ethernet', 'none', 'wifi', 'wimax', 'other', 'unknown'].includes(type)) {
            return res.status(400).json({ error: 'Invalid network type' });
        }
        
        if (effectiveType && !['slow-2g', '2g', '3g', '4g', 'unknown'].includes(effectiveType)) {
            return res.status(400).json({ error: 'Invalid effective type' });
        }

        let session = null;

        if (sessionId) {
            console.log('🔍 Looking up session by provided sessionId:', sessionId);
            
            // Find session by exact sessionId match
            session = await Session.findOne({ sessionId });
            
            if (!session) {
                console.log('❌ Session not found:', sessionId);
                return res.status(404).json({ error: 'Session not found' });
            }
            
            console.log('✅ Found session:', session.sessionId);

            // Verify the session belongs to the authenticated user
            const user = await User.findOne({ firebaseUid: req.user.uid });
            const isAnonymousUser = user && user.email && user.email.endsWith('@anon');
            const isVerificationOnly = !session.candidateId;
            
            // Check if user is the candidate for candidate-based sessions
            let isCandidate = false;
            let candidate = null;
            if (session.candidateId) {
                candidate = await Candidate.findById(session.candidateId);
                if (candidate) {
                    // Check if user is the candidate by firebaseUid or email
                    isCandidate = (candidate.firebaseUid === req.user.uid) || 
                                  (candidate.email && user && candidate.email.toLowerCase() === user.email.toLowerCase());
                }
            }
            
            console.log('🔐 Session access check:', {
                sessionUuid: session.uuid,
                requestUuid: req.user.uid,
                sessionEmail: session.email,
                userEmail: user?.email,
                isAnonymousUser: isAnonymousUser,
                isVerificationOnly: isVerificationOnly,
                userSessionId: user?.sessionId,
                sessionCandidateId: session.candidateId,
                isCandidate: isCandidate,
                candidateEmail: candidate?.email
            });
            
            // Allow access if:
            // 1. Session UUID matches request UUID, OR
            // 2. Session email matches user email, OR
            // 3. For verification-only sessions: user has this sessionId stored (shared session), OR
            // 4. For verification-only sessions: sessionId starts with user's Firebase UID (session creator), OR
            // 5. For candidate-based sessions: user is the candidate
            const uuidMatch = session.uuid === req.user.uid;
            const emailMatch = user && session.email === user.email;
            // Candidate can access by email even when User.findOne fails (de-anonymized, no MongoDB User)
            const candidateEmailMatch = candidate && session.email && candidate.email &&
                session.email.toLowerCase() === candidate.email.toLowerCase();
            const sharedSessionMatch = isVerificationOnly && user && user.sessionId === session.sessionId;
            const sessionCreatorMatch = isVerificationOnly && session.sessionId && session.sessionId.startsWith(req.user.uid + '_');
            const candidateMatch = isCandidate;
            
            if (!uuidMatch && !emailMatch && !candidateEmailMatch && !sharedSessionMatch && !sessionCreatorMatch && !candidateMatch) {
                console.log('❌ Session access denied - no matching criteria');
                return res.status(403).json({ error: 'Access denied to this session' });
            }
            
            console.log('✅ Session access granted for sessionId:', session.sessionId);
        } else {
            // If no sessionId provided, find the user's current active session
            console.log('🔍 No sessionId provided, looking up user session');
            const user = await User.findOne({ firebaseUid: req.user.uid });
            if (!user || !user.sessionId) {
                console.log('❌ No active session found for user:', req.user.uid);
                return res.status(404).json({ error: 'No active session found' });
            }

            console.log('🔍 Looking up user.sessionId:', user.sessionId);
            session = await Session.findOne({ sessionId: user.sessionId });
            if (!session) {
                console.log('❌ Active session not found in database:', user.sessionId);
                return res.status(404).json({ error: 'Active session not found' });
            }
            
            console.log('✅ Found user session:', session.sessionId);
        }

        // Get the best IP for this request
        const { clientIP, source } = await getBestIP(req, session.sessionId);
        console.log(`🔍 Using IP for ipapi.is lookup: ${clientIP} (source: ${source})`);
        
        let ipApiInfo = null;
        let securityFlags = {};

        // Fetch ipapi.is data if we have an IP
        if (clientIP && clientIP !== 'unknown') {
            try {
                ipApiInfo = await getIPApiInfo(clientIP);
                
                if (ipApiInfo) {
                    // Check for security flags
                    securityFlags = {
                        is_bogon: ipApiInfo.is_bogon || false,
                        is_mobile: ipApiInfo.is_mobile || false, // Network-level mobile detection takes priority
                        is_satellite: ipApiInfo.is_satellite || false,
                        is_crawler: ipApiInfo.is_crawler || false,
                        is_datacenter: ipApiInfo.is_datacenter || false,
                        is_tor: ipApiInfo.is_tor || false,
                        is_proxy: ipApiInfo.is_proxy || false,
                        is_vpn: ipApiInfo.is_vpn || false,
                        is_abuser: ipApiInfo.is_abuser || false
                    };

                    // Log security flags if any are true
                    const trueFlags = Object.entries(securityFlags)
                        .filter(([key, value]) => value === true)
                        .map(([key]) => key);

                    if (trueFlags.length > 0) {
                        console.log(`🔒 Security flags detected for IP ${clientIP}: ${trueFlags.join(', ')}`);
                    }
                }
            } catch (error) {
                console.error('Failed to fetch ipapi.is data:', error.message);
            }
        }

        // Prepare update data
        const updateData = {
            networkInfo: {
                type: type || 'unknown',
                effectiveType: effectiveType || 'unknown',
                downlink: downlink || null,
                rtt: resolvedRtt,
                rttSource,
                saveData: saveData || false,
                lastUpdated: new Date()
            }
        };

        // Only add ipapi data if the session doesn't already have valid ipapi data
        if (ipApiInfo && (!session.ipapi || !session.ipapi.ip)) {
            // Structure the data to match the Session schema
            updateData.ipapi = {
                ip: ipApiInfo.ip,
                rir: ipApiInfo.rir,
                is_bogon: ipApiInfo.is_bogon,
                is_mobile: ipApiInfo.is_mobile,
                is_satellite: ipApiInfo.is_satellite,
                is_crawler: ipApiInfo.is_crawler,
                is_datacenter: ipApiInfo.is_datacenter,
                is_tor: ipApiInfo.is_tor,
                is_proxy: ipApiInfo.is_proxy,
                is_vpn: ipApiInfo.is_vpn,
                is_abuser: ipApiInfo.is_abuser,
                datacenter: ipApiInfo.datacenter,
                company: ipApiInfo.company,
                asn: ipApiInfo.asn, // This should be a Number, not an object
                location: ipApiInfo.location,
                elapsed_ms: ipApiInfo.elapsed_ms,
                lastUpdated: new Date()
            };
        }

        // Update session with network info and ipapi data
        console.log('💾 Updating session with network info:', {
            sessionId: session.sessionId,
            sessionUuid: session.uuid,
            sessionEmail: session.email,
            networkType: type,
            effectiveType: effectiveType
        });
        
        const updatedSession = await Session.findOneAndUpdate(
            { sessionId: session.sessionId },
            updateData,
            { new: true }
        );

        if (!updatedSession) {
            console.log('❌ Failed to update session - session not found after lookup');
            return res.status(500).json({ error: 'Failed to update session' });
        }

        // Verify the update went to the correct session
        console.log(`✅ Network info updated for session ${session.sessionId}: type=${type}, effectiveType=${effectiveType}, downlink=${downlink}Mbps, rtt=${resolvedRtt}ms (${rttSource || 'none'})`);
        console.log(`🔍 Verification - Updated session details:`, {
            sessionId: updatedSession.sessionId,
            uuid: updatedSession.uuid,
            email: updatedSession.email,
            networkInfoType: updatedSession.networkInfo?.type,
            networkInfoEffectiveType: updatedSession.networkInfo?.effectiveType,
            networkInfoLastUpdated: updatedSession.networkInfo?.lastUpdated
        });

        // Prepare response
        const response = {
            success: true,
            sessionId: session.sessionId,
            networkInfo: {
                type: type || 'unknown',
                effectiveType: effectiveType || 'unknown',
                downlink: downlink || null,
                rtt: rtt || null,
                saveData: saveData || false
            },
            updatedAt: new Date().toISOString(),
            message: 'Network information stored successfully'
        };
        
        // Include ipapi data within networkInfo if available
        if (ipApiInfo) {
            response.networkInfo.ipapi = {
                is_vpn: ipApiInfo.is_vpn,
                is_proxy: ipApiInfo.is_proxy,
                is_datacenter: ipApiInfo.is_datacenter,
                is_tor: ipApiInfo.is_tor,
                is_mobile: ipApiInfo.is_mobile,
                is_satellite: ipApiInfo.is_satellite,
                is_crawler: ipApiInfo.is_crawler,
                is_bogon: ipApiInfo.is_bogon,
                is_abuser: ipApiInfo.is_abuser,
                datacenter: ipApiInfo.datacenter,
                company: ipApiInfo.company,
                asn: ipApiInfo.asn,
                location: ipApiInfo.location
            };
            
            if (process.env.DEBUG) {
                console.log(`📤 Sending ipapi data within networkInfo in networkinfo response:`, JSON.stringify(response.networkInfo.ipapi, null, 2));
            }
        }

        // Add security information if available
        if (Object.keys(securityFlags).length > 0) {
            response.securityFlags = securityFlags;
        }
        


        res.json(response);

    } catch (error) {
        console.error('Network info storage error:', error);
        res.status(500).json({ error: 'Failed to store network information' });
    }
});



// Device info endpoint
app.post('/api/deviceinfo', authenticateToken, async (req, res) => {
    try {
        const { deviceInfo, sessionId, deviceFingerprint } = req.body;
        
        console.log('📱 Device info request:', {
            firebaseUid: req.user.uid,
            providedSessionId: sessionId || 'none',
            hasDeviceInfo: !!deviceInfo
        });

        // Validate required fields
        if (!deviceInfo || typeof deviceInfo !== 'string') {
            return res.status(400).json({ error: 'Device info is required and must be a string' });
        }

        let session = null;

        if (sessionId) {
            console.log('🔍 Looking up session by provided sessionId:', sessionId);
            
            // Find session by exact sessionId match
            session = await Session.findOne({ sessionId });
            
            if (!session) {
                console.log('❌ Session not found:', sessionId);
                return res.status(404).json({ error: 'Session not found' });
            }
            
            console.log('✅ Found session:', session.sessionId);

            // Verify the session belongs to the authenticated user
            const user = await User.findOne({ firebaseUid: req.user.uid });
            const isAnonymousUser = user && user.email && user.email.endsWith('@anon');
            const isVerificationOnly = !session.candidateId;
            
            // Check if user is the candidate for candidate-based sessions
            let isCandidate = false;
            let candidate = null;
            if (session.candidateId) {
                candidate = await Candidate.findById(session.candidateId);
                if (candidate) {
                    // Check if user is the candidate by firebaseUid or email
                    isCandidate = (candidate.firebaseUid === req.user.uid) || 
                                  (candidate.email && user && candidate.email.toLowerCase() === user.email.toLowerCase());
                }
            }
            
            console.log('🔐 Session access check:', {
                sessionUuid: session.uuid,
                requestUuid: req.user.uid,
                sessionEmail: session.email,
                userEmail: user?.email,
                isAnonymousUser: isAnonymousUser,
                isVerificationOnly: isVerificationOnly,
                userSessionId: user?.sessionId,
                sessionCandidateId: session.candidateId,
                isCandidate: isCandidate,
                candidateEmail: candidate?.email
            });
            
            // Allow access if:
            // 1. Session UUID matches request UUID, OR
            // 2. Session email matches user email, OR
            // 3. For verification-only sessions: user has this sessionId stored (shared session), OR
            // 4. For verification-only sessions: sessionId starts with user's Firebase UID (session creator), OR
            // 5. For candidate-based sessions: user is the candidate
            const uuidMatch = session.uuid === req.user.uid;
            const emailMatch = user && session.email === user.email;
            // Candidate can access by email even when User.findOne fails (de-anonymized, no MongoDB User)
            const candidateEmailMatch = candidate && session.email && candidate.email &&
                session.email.toLowerCase() === candidate.email.toLowerCase();
            const sharedSessionMatch = isVerificationOnly && user && user.sessionId === session.sessionId;
            const sessionCreatorMatch = isVerificationOnly && session.sessionId && session.sessionId.startsWith(req.user.uid + '_');
            const candidateMatch = isCandidate;
            
            if (!uuidMatch && !emailMatch && !candidateEmailMatch && !sharedSessionMatch && !sessionCreatorMatch && !candidateMatch) {
                console.log('❌ Session access denied - no matching criteria');
                return res.status(403).json({ error: 'Access denied to this session' });
            }
            
            console.log('✅ Session access granted for sessionId:', session.sessionId);
        } else {
            // If no sessionId provided, find the user's current active session
            console.log('🔍 No sessionId provided, looking up user session');
            const user = await User.findOne({ firebaseUid: req.user.uid });
            if (!user || !user.sessionId) {
                console.log('❌ No active session found for user:', req.user.uid);
                return res.status(404).json({ error: 'No active session found' });
            }

            console.log('🔍 Looking up user.sessionId:', user.sessionId);
            session = await Session.findOne({ sessionId: user.sessionId });
            if (!session) {
                console.log('❌ Active session not found in database:', user.sessionId);
                return res.status(404).json({ error: 'Active session not found' });
            }
            
            console.log('✅ Found user session:', session.sessionId);
        }

        // Update session with device info
        console.log('💾 Updating session with device info:', {
            sessionId: session.sessionId,
            sessionUuid: session.uuid,
            sessionEmail: session.email
        });
        
        const updatedSession = await Session.findOneAndUpdate(
            { sessionId: session.sessionId },
            { 
                deviceInfo: deviceInfo,
                deviceInfoUpdatedAt: new Date(),
                ...(typeof deviceFingerprint === 'string' && deviceFingerprint
                    ? { deviceFingerprint }
                    : {})
            },
            { new: true }
        );

        if (!updatedSession) {
            console.log('❌ Failed to update session - session not found after lookup');
            return res.status(500).json({ error: 'Failed to update session' });
        }

        console.log(`✅ Device info updated for session ${session.sessionId}: ${deviceInfo.substring(0, 100)}...`);

        res.json({
            success: true,
            sessionId: session.sessionId,
            deviceInfo: deviceInfo,
            updatedAt: new Date().toISOString(),
            message: 'Device information stored successfully'
        });

    } catch (error) {
        console.error('Device info storage error:', error);
        res.status(500).json({ error: 'Failed to store device information' });
    }
});

// Browser info endpoint
app.post('/api/browserinfo', authenticateToken, async (req, res) => {
    try {
        const { languages, timezone, sessionId } = req.body;
        
        console.log('🌐 Browser info request:', {
            firebaseUid: req.user.uid,
            providedSessionId: sessionId || 'none',
            languages: languages,
            timezone: timezone
        });

        // Validate required fields
        if (!languages || !Array.isArray(languages)) {
            return res.status(400).json({ error: 'Languages is required and must be an array' });
        }

        if (!timezone || typeof timezone !== 'string') {
            return res.status(400).json({ error: 'Timezone is required and must be a string' });
        }

        // Validate languages array contains strings
        if (!languages.every(lang => typeof lang === 'string')) {
            return res.status(400).json({ error: 'All languages must be strings' });
        }

        let session = null;

        if (sessionId) {
            console.log('🔍 Looking up session by provided sessionId:', sessionId);
            
            // Find session by exact sessionId match
            session = await Session.findOne({ sessionId });
            
            if (!session) {
                console.log('❌ Session not found:', sessionId);
                return res.status(404).json({ error: 'Session not found' });
            }
            
            console.log('✅ Found session:', session.sessionId);

            // Verify the session belongs to the authenticated user
            const user = await User.findOne({ firebaseUid: req.user.uid });
            const isAnonymousUser = user && user.email && user.email.endsWith('@anon');
            const isVerificationOnly = !session.candidateId;
            
            // Check if user is the candidate for candidate-based sessions
            let isCandidate = false;
            let candidate = null;
            if (session.candidateId) {
                candidate = await Candidate.findById(session.candidateId);
                if (candidate) {
                    // Check if user is the candidate by firebaseUid or email
                    isCandidate = (candidate.firebaseUid === req.user.uid) || 
                                  (candidate.email && user && candidate.email.toLowerCase() === user.email.toLowerCase());
                }
            }
            
            console.log('🔐 Session access check:', {
                sessionUuid: session.uuid,
                requestUuid: req.user.uid,
                sessionEmail: session.email,
                userEmail: user?.email,
                isAnonymousUser: isAnonymousUser,
                isVerificationOnly: isVerificationOnly,
                userSessionId: user?.sessionId,
                sessionCandidateId: session.candidateId,
                isCandidate: isCandidate,
                candidateEmail: candidate?.email
            });
            
            // Allow access if:
            // 1. Session UUID matches request UUID, OR
            // 2. Session email matches user email, OR
            // 3. For verification-only sessions: user has this sessionId stored (shared session), OR
            // 4. For verification-only sessions: sessionId starts with user's Firebase UID (session creator), OR
            // 5. For candidate-based sessions: user is the candidate
            const uuidMatch = session.uuid === req.user.uid;
            const emailMatch = user && session.email === user.email;
            // Candidate can access by email even when User.findOne fails (de-anonymized, no MongoDB User)
            const candidateEmailMatch = candidate && session.email && candidate.email &&
                session.email.toLowerCase() === candidate.email.toLowerCase();
            const sharedSessionMatch = isVerificationOnly && user && user.sessionId === session.sessionId;
            const sessionCreatorMatch = isVerificationOnly && session.sessionId && session.sessionId.startsWith(req.user.uid + '_');
            const candidateMatch = isCandidate;
            
            if (!uuidMatch && !emailMatch && !candidateEmailMatch && !sharedSessionMatch && !sessionCreatorMatch && !candidateMatch) {
                console.log('❌ Session access denied - no matching criteria');
                return res.status(403).json({ error: 'Access denied to this session' });
            }
            
            console.log('✅ Session access granted for sessionId:', session.sessionId);
        } else {
            // If no sessionId provided, find the user's current active session
            console.log('🔍 No sessionId provided, looking up user session');
            const user = await User.findOne({ firebaseUid: req.user.uid });
            if (!user || !user.sessionId) {
                console.log('❌ No active session found for user:', req.user.uid);
                return res.status(404).json({ error: 'No active session found' });
            }

            console.log('🔍 Looking up user.sessionId:', user.sessionId);
            session = await Session.findOne({ sessionId: user.sessionId });
            if (!session) {
                console.log('❌ Active session not found in database:', user.sessionId);
                return res.status(404).json({ error: 'Active session not found' });
            }
            
            console.log('✅ Found user session:', session.sessionId);
        }

        // Update session with browser info
        console.log('💾 Updating session with browser info:', {
            sessionId: session.sessionId,
            sessionUuid: session.uuid,
            sessionEmail: session.email,
            languages: languages,
            timezone: timezone
        });
        
        const updatedSession = await Session.findOneAndUpdate(
            { sessionId: session.sessionId },
            { 
                browserInfo: {
                    languages: languages,
                    timezone: timezone,
                    lastUpdated: new Date()
                }
            },
            { new: true }
        );

        if (!updatedSession) {
            console.log('❌ Failed to update session - session not found after lookup');
            return res.status(500).json({ error: 'Failed to update session' });
        }

        console.log(`✅ Browser info updated for session ${session.sessionId}: languages=${languages.join(', ')}, timezone=${timezone}`);

        res.json({
            success: true,
            sessionId: updatedSession.sessionId,
            browserInfo: updatedSession.browserInfo
        });
    } catch (error) {
        console.error('Browser info storage error:', error);
        res.status(500).json({ error: 'Failed to store browser information' });
    }
});

async function getSessionAccessContext(session, firebaseUid) {
    const user = await User.findOne({ firebaseUid });
    const isVerificationOnly = !session.candidateId;
    let isCandidate = false;
    let candidate = null;

    if (session.candidateId) {
        candidate = await Candidate.findById(session.candidateId);
        if (candidate) {
            isCandidate = candidate.firebaseUid === firebaseUid
                || (candidate.email && user && candidate.email.toLowerCase() === user.email.toLowerCase());
        }
    }

    const uuidMatch = session.uuid === firebaseUid;
    const emailMatch = user && session.email === user.email;
    const candidateEmailMatch = candidate && session.email && candidate.email &&
        session.email.toLowerCase() === candidate.email.toLowerCase();
    const sharedSessionMatch = isVerificationOnly && user && user.sessionId === session.sessionId;
    const mobileCheckInMatch = user && user.sessionId === session.sessionId;
    const sessionCreatorMatch = isVerificationOnly && session.sessionId && session.sessionId.startsWith(`${firebaseUid}_`);
    const candidateMatch = isCandidate;

    return {
        allowed: uuidMatch || emailMatch || candidateEmailMatch || sharedSessionMatch || mobileCheckInMatch || sessionCreatorMatch || candidateMatch,
        user,
        candidate
    };
}

async function resolveSessionSubjectContact(session, candidate, user) {
    let email = null;
    let mobile = null;

    if (session.email && !session.email.endsWith('@anon')) {
        email = session.email.toLowerCase().trim();
    }
    if (session.mobile) {
        mobile = session.mobile.trim().replace(/\s+/g, '');
    }

    if (candidate) {
        if (!email && candidate.email) {
            email = candidate.email.toLowerCase().trim();
        }
        if (!mobile && candidate.mobile) {
            mobile = candidate.mobile.trim().replace(/\s+/g, '');
        }
    }

    if (user?.email && !user.email.endsWith('@anon')) {
        email = email || user.email.toLowerCase().trim();
    }

    return { email, mobile };
}

app.post('/api/session/:sessionId/pin', authenticateToken, authLimiter, async (req, res) => {
    try {
        const { pin } = req.body || {};
        const session = await Session.findOne({ sessionId: req.params.sessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        const access = await getSessionAccessContext(session, req.user.uid);
        if (!access.allowed) {
            return res.status(403).json({ error: 'Access denied to this session' });
        }

        if (!isValidPin(pin)) {
            return res.status(400).json({ error: 'PIN must be 4-6 digits' });
        }

        const contact = await resolveSessionSubjectContact(session, access.candidate, access.user);
        const checkingInUser = await resolveCheckingInUserForVerification(session, access.candidate);
        const preRegistration = await resolvePreRegistrationForSession(session, access.candidate, checkingInUser);
        const verified = preRegistration ? verifyPin(pin, preRegistration.hashedPin) : false;
        const now = new Date();
        const sessionUpdate = {
            requiresPin: true,
            liveness: 100,
            pinVerification: {
                submittedAt: now,
                verified
            }
        };

        if (preRegistration?.email && session.email?.endsWith('@anon')) {
            sessionUpdate.email = preRegistration.email;
        }

        await Session.findOneAndUpdate(
            { sessionId: session.sessionId },
            sessionUpdate
        );

        if (access.candidate) {
            const candidateUpdate = {};
            const candidateEmail = access.candidate.email?.toLowerCase().trim();
            if (preRegistration?.email && candidateEmail && preRegistration.email.toLowerCase().trim() === candidateEmail) {
                candidateUpdate.verified = sanitizeCandidateVerified(
                    mergeBaselineVerification(access.candidate.verified, preRegistration),
                    candidateEmail
                );
                const baselineLocation = resolveExpectedLocation(access.candidate, preRegistration);
                if (baselineLocation && isPlaceholderLocation(access.candidate.city)) {
                    candidateUpdate.city = baselineLocation;
                }
            }
            if (Object.keys(candidateUpdate).length > 0) {
                await Candidate.findByIdAndUpdate(access.candidate._id, candidateUpdate);
            }
        }

        return res.json({ success: true });
    } catch (error) {
        console.error('Session PIN submission error:', error);
        res.status(500).json({ error: 'Failed to submit PIN' });
    }
});

// Liveness detection endpoint
app.post('/api/liveness', authenticateToken, async (req, res) => {
    try {
        const { sessionId, accelerationData, deviceInfo } = req.body;

        // Validate required fields
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }

        if (!accelerationData || !Array.isArray(accelerationData)) {
            return res.status(400).json({ error: 'Acceleration data must be an array' });
        }

        // Validate acceleration data structure
        const isValidData = accelerationData.every(point => 
            point && 
            typeof point.x === 'number' && 
            typeof point.y === 'number' && 
            typeof point.z === 'number' && 
            typeof point.timestamp === 'number'
        );

        if (!isValidData) {
            return res.status(400).json({ 
                error: 'Invalid acceleration data format. Each point must have x, y, z, and timestamp properties' 
            });
        }

        console.log('📊 Liveness request:', {
            firebaseUid: req.user.uid,
            providedSessionId: sessionId,
            accelerationDataPoints: accelerationData?.length || 0
        });

        // Find the session by exact sessionId match
        console.log('🔍 Looking up session by provided sessionId:', sessionId);
        let session = await Session.findOne({ sessionId });
        
        if (!session) {
            console.log('❌ Session not found:', sessionId);
            return res.status(404).json({ error: 'Session not found' });
        }
        
        console.log('✅ Found session:', session.sessionId);

        // Verify the session belongs to the authenticated user
        const user = await User.findOne({ firebaseUid: req.user.uid });
        const isAnonymousUser = user && user.email && user.email.endsWith('@anon');
        const isVerificationOnly = !session.candidateId;
        
        // Check if user is the candidate for candidate-based sessions
        let isCandidate = false;
        let candidate = null;
        if (session.candidateId) {
            candidate = await Candidate.findById(session.candidateId);
            if (candidate) {
                // Check if user is the candidate by firebaseUid or email
                isCandidate = (candidate.firebaseUid === req.user.uid) || 
                              (candidate.email && user && candidate.email.toLowerCase() === user.email.toLowerCase());
            }
        }
        
        console.log('🔐 Session access check:', {
            sessionUuid: session.uuid,
            requestUuid: req.user.uid,
            sessionEmail: session.email,
            userEmail: user?.email,
            isAnonymousUser: isAnonymousUser,
            isVerificationOnly: isVerificationOnly,
            userSessionId: user?.sessionId,
            sessionCandidateId: session.candidateId,
            isCandidate: isCandidate,
            candidateEmail: candidate?.email
        });
        
        // Allow access if:
        // 1. Session UUID matches request UUID, OR
        // 2. Session email matches user email, OR
        // 3. For verification-only sessions: user has this sessionId stored (shared session), OR
        // 4. For verification-only sessions: sessionId starts with user's Firebase UID (session creator), OR
        // 5. For candidate-based sessions: user is the candidate
        const uuidMatch = session.uuid === req.user.uid;
        const emailMatch = user && session.email === user.email;
        const candidateEmailMatch = candidate && session.email && candidate.email &&
            session.email.toLowerCase() === candidate.email.toLowerCase();
        const sharedSessionMatch = isVerificationOnly && user && user.sessionId === session.sessionId;
        const sessionCreatorMatch = isVerificationOnly && session.sessionId && session.sessionId.startsWith(req.user.uid + '_');
        const candidateMatch = isCandidate;
        
        if (!uuidMatch && !emailMatch && !candidateEmailMatch && !sharedSessionMatch && !sessionCreatorMatch && !candidateMatch) {
            console.log('❌ Session access denied - no matching criteria');
            return res.status(403).json({ error: 'Access denied to this session' });
        }

        console.log('✅ Liveness session access granted for sessionId:', session.sessionId);

        // Calculate liveness score based on acceleration data
        let livenessScore = calculateLivenessScore(accelerationData);
        if (req.body.dataType === 'touch' && accelerationData.length >= 3) {
            livenessScore = Math.max(livenessScore, 1);
        }

        // Validate tap targets if client provided tapData
        let tapTargetsValid = null;
        if (req.body.tapData && Array.isArray(req.body.tapData) && req.body.tapData.length === 3) {
            const storedTargets = session.livenessTapTargets;
            if (storedTargets && Array.isArray(storedTargets) && storedTargets.length === 3) {
                let allValid = true;
                for (let i = 0; i < 3; i++) {
                    const tap = req.body.tapData[i];
                    const target = storedTargets[i];
                    const dx = (tap.nx || 0) - target.x;
                    const dy = (tap.ny || 0) - target.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist > TAP_TARGET_TOLERANCE) {
                        allValid = false;
                        break;
                    }
                }
                tapTargetsValid = allValid;
                if (!allValid) {
                    livenessScore = Math.min(livenessScore, 25); // cap score if targets missed
                }
            }
        }

        // Update session with liveness data (use the actual sessionId from the found session)
        console.log('💾 Updating session with liveness data:', {
            sessionId: session.sessionId,
            sessionUuid: session.uuid,
            sessionEmail: session.email,
            livenessScore: livenessScore
        });
        
        const updatedSession = await Session.findOneAndUpdate(
            { sessionId: session.sessionId },
            { 
                liveness: livenessScore,
                deviceInfo: deviceInfo || session.deviceInfo,
                deviceFingerprint: req.body.deviceFingerprint || session.deviceFingerprint || null,
                lastLivenessUpdate: new Date()
            },
            { new: true }
        );
        
        if (!updatedSession) {
            console.log('❌ Failed to update session - session not found after lookup');
            return res.status(500).json({ error: 'Failed to update session' });
        }
        
        console.log('✅ Liveness data updated for session:', session.sessionId);

        // Also update user/candidate if they exist
        // Note: user is already declared above in the access check
        // Find candidate by firebaseUid (may be different from session.candidateId)
        const candidateByUid = await Candidate.findOne({ firebaseUid: req.user.uid });
        
        if (candidateByUid) {
            await Candidate.findOneAndUpdate(
                { firebaseUid: req.user.uid },
                { 
                    liveness: livenessScore,
                    lastLivenessUpdate: new Date()
                }
            );
            if (process.env.DEBUG) {
                console.log('🔍 Candidate liveness updated:', {
                    candidateId: candidateByUid._id,
                    livenessScore,
                    status: getLivenessStatus(livenessScore)
                });
            }
        } else if (user) {
            await User.findOneAndUpdate(
                { firebaseUid: req.user.uid },
                { 
                    liveness: livenessScore,
                    lastLivenessUpdate: new Date()
                }
            );
            if (process.env.DEBUG) {
                console.log('🔍 User liveness updated:', {
                    userId: user.firebaseUid,
                    livenessScore,
                    status: getLivenessStatus(livenessScore)
                });
            }
        }

        // Determine liveness status
        const livenessStatus = getLivenessStatus(livenessScore);

        if (process.env.DEBUG) {
            console.log(`Liveness update for session ${sessionId}: score=${livenessScore}, status=${livenessStatus}`);
        }

        res.json({
            success: true,
            sessionId: session.sessionId,
            livenessScore,
            livenessStatus,
            dataPointsProcessed: accelerationData.length,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Liveness detection error:', error);
        res.status(500).json({ error: 'Failed to process liveness data' });
    }
});

// Generate 3 random normalized tap target positions (0-1 range relative to viewport)
function generateTapTargets() {
    const targets = [];
    const margin = 0.1; // 10% margin from edges
    for (let i = 0; i < 3; i++) {
        targets.push({
            x: +(margin + Math.random() * (1 - 2 * margin)).toFixed(3),
            y: +(margin + Math.random() * (1 - 2 * margin)).toFixed(3)
        });
    }
    return targets;
}

const TAP_TARGET_TOLERANCE = 0.15; // normalized distance — ~15% of viewport

// Helper function to calculate liveness score from acceleration data
function calculateLivenessScore(accelerationData) {
    if (!accelerationData || accelerationData.length === 0) {
        return 0;
    }

    let totalMovement = 0;
    let significantMovements = 0;
    let previousPoint = null;
    let rapidChanges = 0;
    let orientationChanges = 0;

    // Movement thresholds
    const MOVEMENT_THRESHOLD = 0.5; // m/s²
    const SIGNIFICANT_MOVEMENT_THRESHOLD = 2.0; // m/s²
    const RAPID_CHANGE_THRESHOLD = 4.0; // m/s²

    for (let i = 0; i < accelerationData.length; i++) {
        const point = accelerationData[i];
        
        // Calculate magnitude of acceleration
        const magnitude = Math.sqrt(point.x * point.x + point.y * point.y + point.z * point.z);
        
        if (previousPoint) {
            // Calculate change in acceleration
            const deltaX = point.x - previousPoint.x;
            const deltaY = point.y - previousPoint.y;
            const deltaZ = point.z - previousPoint.z;
            const deltaTime = (point.timestamp - previousPoint.timestamp) / 1000; // Convert to seconds
            
            if (deltaTime > 0) {
                const deltaMagnitude = Math.sqrt(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
                const acceleration = deltaMagnitude / deltaTime;
                
                totalMovement += acceleration;
                
                // Count significant movements
                if (acceleration > SIGNIFICANT_MOVEMENT_THRESHOLD) {
                    significantMovements++;
                }
                
                // Count rapid changes (indicating human-like movement)
                if (acceleration > RAPID_CHANGE_THRESHOLD) {
                    rapidChanges++;
                }
                
                // Detect orientation changes (device rotation)
                const orientationChange = Math.abs(Math.atan2(point.y, point.x) - Math.atan2(previousPoint.y, previousPoint.x));
                if (orientationChange > 0.1) { // ~5.7 degrees
                    orientationChanges++;
                }
            }
        }
        
        previousPoint = point;
    }

    // Calculate various metrics
    const avgMovement = totalMovement / (accelerationData.length - 1);
    const movementVariability = significantMovements / accelerationData.length;
    const rapidChangeRatio = rapidChanges / accelerationData.length;
    const orientationChangeRatio = orientationChanges / accelerationData.length;

    // Weighted scoring system (0-100)
    let score = 0;
    
    // Base movement score (0-30 points)
    score += Math.min(avgMovement * 10, 30);
    
    // Variability score (0-25 points) - human movement has natural variability
    score += movementVariability * 25;
    
    // Rapid changes score (0-25 points) - indicates intentional human movement
    score += rapidChangeRatio * 25;
    
    // Orientation changes score (0-20 points) - indicates device handling
    score += orientationChangeRatio * 20;

    // Normalize to 0-100 and round
    return Math.round(Math.min(Math.max(score, 0), 100));
}

// Helper function to determine liveness status
function getLivenessStatus(score) {
    if (score >= 75) {
        return 'high';
    } else if (score >= 50) {
        return 'medium';
    } else if (score >= 25) {
        return 'low';
    } else {
        return 'insufficient';
    }
}

// Helper function to convert all data values to strings for Firebase messaging
function convertDataToStrings(data) {
    if (!data || typeof data !== 'object') {
        return {};
    }
    
    const stringData = {};
    for (const [key, value] of Object.entries(data)) {
        if (value !== null && value !== undefined) {
            stringData[key] = String(value);
        }
    }
    return stringData;
}

// Helper function to get IP address from request
function getClientIP(req) {
    // Debug: Log all available IP-related headers and values
    if (process.env.DEBUG) {
        console.log('🔍 IP Debug - All headers:', Object.keys(req.headers).filter(key => 
            key.toLowerCase().includes('ip') || 
            key.toLowerCase().includes('forward') || 
            key.toLowerCase().includes('real')
        ));
        
        console.log('🔍 IP Debug - X-Forwarded-For:', req.headers['x-forwarded-for']);
        console.log('🔍 IP Debug - X-Real-IP:', req.headers['x-real-ip']);
        console.log('🔍 IP Debug - X-Forwarded:', req.headers['x-forwarded']);
        console.log('🔍 IP Debug - X-Client-IP:', req.headers['x-client-ip']);
        console.log('🔍 IP Debug - CF-Connecting-IP:', req.headers['cf-connecting-ip']);
        console.log('🔍 IP Debug - req.connection.remoteAddress:', req.connection?.remoteAddress);
        console.log('🔍 IP Debug - req.socket.remoteAddress:', req.socket?.remoteAddress);
        console.log('🔍 IP Debug - req.ip:', req.ip);
    }

    // Helper function to check if IP is private
        const isPrivateIP = (ip) => {
        let normalized = ip;
        if (normalized.startsWith('::ffff:')) { normalized = normalized.slice(7); }
        if (!ip) return false;
        if (normalized.startsWith('10.')) return true;
        if (normalized.startsWith('192.168.')) return true;
        if (normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost') return true;
        // Only treat 172.16.0.0 - 172.31.255.255 as private
        const match = normalized.match(/^172\.(\d{1,3})\./);
        if (match) {
            const secondOctet = parseInt(match[1], 10);
            if (secondOctet >= 16 && secondOctet <= 31) return true;
        }
        return false;
    };

    // Always use X-Real-IP if present and public (set by our own nginx)
    if (req.headers['x-real-ip'] && !isPrivateIP(req.headers['x-real-ip'])) {
        console.log('✅ Selected IP from X-Real-IP:', req.headers['x-real-ip']);
        return req.headers['x-real-ip'];
    }

    // Helper function to find the first public IP from a list
    const findFirstPublicIP = (ips) => {
        if (!ips) return null;
        const ipList = Array.isArray(ips) ? ips : ips.split(',').map(ip => ip.trim());
        
        for (const ip of ipList) {
            if (!isPrivateIP(ip)) {
                return ip;
            }
        }
        return null;
    };

    // Check X-Forwarded-For first (most common proxy header)
    if (req.headers['x-forwarded-for']) {
        const publicIP = findFirstPublicIP(req.headers['x-forwarded-for']);
        if (publicIP) {
            console.log('✅ Selected IP from X-Forwarded-For:', publicIP);
            return publicIP;
        }
    }

    // Check other common proxy headers
    const otherHeaders = ['x-forwarded', 'x-client-ip', 'cf-connecting-ip'];
    for (const header of otherHeaders) {
        if (req.headers[header] && !isPrivateIP(req.headers[header])) {
            console.log(`✅ Selected IP from ${header}:`, req.headers[header]);
            return req.headers[header];
        }
    }

    // Fallback to connection addresses (avoiding private IPs)
    const connectionIPs = [req.connection?.remoteAddress, req.socket?.remoteAddress, req.ip];
    for (const ip of connectionIPs) {
        if (ip && !isPrivateIP(ip)) {
            console.log('✅ Selected IP from connection:', ip);
            return ip;
        }
    }

    // If all else fails, return the first available IP (even if private)
    let fallbackIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                      req.headers['x-real-ip'] ||
                      req.connection?.remoteAddress ||
                      req.socket?.remoteAddress ||
                      req.ip ||
                      'unknown';
    
    if (fallbackIP.startsWith('::ffff:')) { fallbackIP = fallbackIP.slice(7); }
    console.log('⚠️ Using fallback IP (may be private):', fallbackIP);
    return fallbackIP;
}

// Centralized function to get the best IP for a request, with session fallback
async function getBestIP(req, sessionId = null) {
    let clientIP = null;
    let source = 'current';
    
    // If sessionId is provided, try to get the stored IP first
    if (sessionId) {
        try {
            const session = await Session.findOne({ sessionId });
            if (session && session.ipaddr && session.ipaddr !== 'unknown') {
                clientIP = session.ipaddr;
                source = 'stored';
                console.log(`🌐 Using stored IP from session: ${clientIP}`);
            } else {
                console.log(`🌐 No stored IP found for session ${sessionId}, will use current IP detection`);
            }
        } catch (error) {
            console.warn('⚠️ Could not retrieve session for IP lookup:', error.message);
        }
    }
    
    // If no stored IP, use current IP detection
    if (!clientIP) {
        clientIP = getClientIP(req);
        source = 'current';
        console.log(`🌐 Using current IP detection: ${clientIP}`);
    }
    
    return { clientIP, source };
}

// Global variable to store the MaxMind reader
let maxmindReader = null;

// Initialize MaxMind database reader
async function initializeMaxMind() {
    try {
        const dbPath = process.env.MAXMIND || path.join(__dirname, '../maxmind/GeoLite2-City.mmdb');
        maxmindReader = await maxmind.open(dbPath);
        console.log('✅ MaxMind GeoLite2 City database loaded successfully');
        console.log('📁 Database path:', dbPath);
    } catch (error) {
        console.error('❌ Failed to load MaxMind database:', error.message);
        console.log('📁 Expected path:', process.env.MAXMIND || path.join(__dirname, '../maxmind/GeoLite2-City.mmdb'));
        console.log('💡 Set MAXMIND environment variable to specify custom database path');
    }
}

// Helper function to check if IP is private
function isPrivateIP(ip) {
    let normalized = ip;
    if (normalized.startsWith('::ffff:')) { normalized = normalized.slice(7); }
    if (!ip) return false;
    if (normalized.startsWith('10.')) return true;
    if (normalized.startsWith('192.168.')) return true;
    if (normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost') return true;
    // Only treat 172.16.0.0 - 172.31.255.255 as private
    const match = normalized.match(/^172\.(\d{1,3})\./);
    if (match) {
        const secondOctet = parseInt(match[1], 10);
        if (secondOctet >= 16 && secondOctet <= 31) return true;
    }
    return false;
}

function normalizeIpForLookup(ip) {
    if (ip == null) {
        return null;
    }
    let cleaned = typeof ip === 'string' ? ip.trim() : String(ip).trim();
    if (!cleaned || cleaned === 'unknown' || cleaned === 'null' || cleaned === 'undefined') {
        return null;
    }

    const zoneIdx = cleaned.indexOf('%');
    if (zoneIdx !== -1) {
        cleaned = cleaned.slice(0, zoneIdx);
    }
    if (cleaned.startsWith('::ffff:')) {
        cleaned = cleaned.slice(7);
    }
    if (/^\d+\.\d+\.\d+\.\d+:\d+$/.test(cleaned)) {
        cleaned = cleaned.split(':')[0];
    }

    return net.isIP(cleaned) ? cleaned : null;
}

// Helper function to perform IP geolocation lookup using local MaxMind database
async function getIPLocation(ip) {
    try {
        // Use isPrivateIP to skip lookup for localhost and private IPs
        if (isPrivateIP(ip) || ip === 'unknown') {
            return {
                country: 'Local',
                region: 'Local',
                city: 'Local',
                lat: null,
                lon: null,
                timezone: 'Local',
                isp: 'Local'
            };
        }

        // Check if MaxMind reader is initialized
        if (!maxmindReader) {
            console.warn('⚠️ MaxMind database not loaded, initializing...');
            await initializeMaxMind();
        }

        if (!maxmindReader) {
            throw new Error('MaxMind database not available');
        }

        // Lookup IP in MaxMind database
        const result = maxmindReader.get(ip);
        
        // Debug: Dump the full MaxMind result object
        if (process.env.DEBUG) {
            console.log(`🐞 Full MaxMind result for ${ip}:`, JSON.stringify(result, null, 2));
        }
        
        if (result) {
            if (process.env.DEBUG) {
                console.log(`📍 MaxMind lookup for ${ip}:`, {
                    city: result.city?.names?.en,
                    country: result.country?.names?.en,
                    region: result.subdivisions?.[0]?.names?.en,
                    timezone: result.location?.time_zone,
                    lat: result.location?.latitude,
                    lon: result.location?.longitude
                });
            }

            return {
                country: result.country?.names?.en || 'Unknown',
                region: result.subdivisions?.[0]?.names?.en || 'Unknown',
                city: result.city?.names?.en || 'Unknown',
                lat: result.location?.latitude || null,
                lon: result.location?.longitude || null,
                timezone: result.location?.time_zone || 'Unknown',
                isp: 'Unknown' // MaxMind GeoLite2 doesn't include ISP data
            };
        } else {
            if (process.env.DEBUG) {
                console.log(`⚠️ No MaxMind data found for IP: ${ip}`);
            }
        }
    } catch (error) {
        console.error('IP geolocation lookup failed:', error.message);
    }

    // Return default values if lookup fails
    return {
        country: 'Unknown',
        region: 'Unknown',
        city: 'Unknown',
        lat: null,
        lon: null,
        timezone: 'Unknown',
        isp: 'Unknown'
    };
}

// Helper function to perform IP lookup using ipapi.is
async function getIPApiInfo(ip) {
    try {
        const normalizedIp = normalizeIpForLookup(ip);
        if (!normalizedIp || isPrivateIP(normalizedIp)) {
            if (process.env.DEBUG) {
                console.log(`⚠️ Skipping ipapi.is lookup for invalid or non-public IP: ${ip}`);
            }
            return null;
        }

        const apiKey = process.env.ISAPI;
        if (!apiKey) {
            console.warn('⚠️ ISAPI environment variable not set, skipping ipapi.is lookup');
            return null;
        }
        
        console.log(`🔑 Using ISAPI key: ${apiKey.substring(0, 8)}...`);

        // Use the bulk lookup format to ensure they use our specific IP
        const url = 'https://api.ipapi.is';
        const requestBody = {
            ips: [normalizedIp],
            key: apiKey
        };

        if (process.env.DEBUG) {
            console.log(`🔍 ipapi.is request URL: ${url}`);
            console.log(`🔍 ipapi.is request body:`, JSON.stringify(requestBody, null, 2));
        }

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            console.error(`❌ ipapi.is API responded with status: ${response.status}`);
            const errorText = await response.text();
            console.error(`❌ ipapi.is error response: ${errorText}`);
            throw new Error(`ipapi.is API responded with status: ${response.status}: ${errorText}`);
        }

        const result = await response.json();
        
        if (process.env.DEBUG) {
            console.log(`📍 ipapi.is full response for ${normalizedIp}:`, JSON.stringify(result, null, 2));
        }

        // Check if we got a valid response
        if (!result || typeof result !== 'object') {
            console.error('❌ ipapi.is returned invalid response:', result);
            return null;
        }

        // Extract the IP info from the response
        // The response format is: { "IP_ADDRESS": { data }, "total_elapsed_ms": number }
        const ipInfo = result[normalizedIp];
        
        if (!ipInfo || typeof ipInfo !== 'object') {
            console.error(`❌ ipapi.is returned invalid IP info for ${normalizedIp}:`, ipInfo);
            return null;
        }
        
        // Log only key information
        const location = ipInfo.location || {};
        const security = {
            is_vpn: ipInfo.is_vpn,
            is_proxy: ipInfo.is_proxy,
            is_datacenter: ipInfo.is_datacenter,
            is_tor: ipInfo.is_tor
        };
        console.log(`📊 IP info: ${normalizedIp} → ${location.city || 'Unknown'}, ${location.country || 'Unknown'} | VPN:${security.is_vpn} Proxy:${security.is_proxy} DC:${security.is_datacenter}`);

        if (process.env.DEBUG) {
            console.log(`📍 ipapi.is processed data for ${normalizedIp}:`, {
                ip: ipInfo.ip,
                is_datacenter: ipInfo.is_datacenter,
                is_vpn: ipInfo.is_vpn,
                is_proxy: ipInfo.is_proxy,
                is_tor: ipInfo.is_tor,
                location: ipInfo.location ? {
                    country: ipInfo.location.country,
                    city: ipInfo.location.city,
                    timezone: ipInfo.location.timezone
                } : null,
                elapsed_ms: ipInfo.elapsed_ms
            });
        }

        return {
            ...ipInfo,
            lastUpdated: new Date()
        };

    } catch (error) {
        console.error('ipapi.is lookup failed:', error.message);
        return null;
    }
}

// Get session history for a specific candidate
app.get('/api/sessions/history/:candidateId', authenticateToken, async (req, res) => {
    try {
        const { candidateId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(candidateId)) {
            return res.status(400).json({ error: 'Invalid candidate ID format' });
        }

        const { user, userId, authEmail } = await resolveHistoryUser(req);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const candidate = await Candidate.findById(candidateId);
        if (!candidate) {
            return res.status(404).json({ error: 'Candidate not found' });
        }

        const allowed = await canAccessCandidatePhotoHistory(user, candidate, {
            userId,
            authEmail
        });
        if (!allowed) {
            return res.status(403).json({ error: 'Access denied to this candidate' });
        }

        const isPrimaryInterviewer = candidate.interviewer
            && candidate.interviewer.toString() === user._id.toString();

        console.log('🔍 Session history query:', {
            userId,
            candidateId,
            authEmail,
            isPrimaryInterviewer
        });

        const payload = await buildCandidatePhotoHistory(
            candidate,
            candidateId,
            req.query.currentSessionId || null,
            { userId, isPrimaryInterviewer }
        );

        const sessionsWithProof = payload.sessions.filter((entry) => entry.shortcode).length;
        console.log(`📊 Retrieved session history for user ${userId} and candidate ${candidateId}: ${payload.sessions.length} sessions (${sessionsWithProof} with screenshots)`);

        res.json(payload);
    } catch (error) {
        console.error('Session history retrieval error:', error);
        res.status(500).json({ error: 'Failed to retrieve session history' });
    }
});

// Check-in endpoint for candidates to link their Firebase account with existing session
app.post('/api/checkin', authLimiter, async (req, res) => {
    try {
        const { sessionId } = req.body;
        
        // Get token from Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const idToken = authHeader.split(' ')[1];
        
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }

        // Get the best IP for this request
        const { clientIP, source } = await getBestIP(req);
        console.log(`🌐 Client IP detected: ${clientIP} (source: ${source})`);

        // Perform IP geolocation lookup
        const ipLocation = await getIPLocation(clientIP);
        console.log(`📍 IP location: ${ipLocation.city}, ${ipLocation.region}, ${ipLocation.country}`);

        // Perform ipapi.is lookup for additional IP intelligence
        console.log(`🔍 Calling getIPApiInfo with IP: ${clientIP}`);
        const ipApiInfo = await getIPApiInfo(clientIP);
        if (ipApiInfo) {
            console.log(`🔍 ipapi.is info: VPN=${ipApiInfo.is_vpn}, Proxy=${ipApiInfo.is_proxy}, Datacenter=${ipApiInfo.is_datacenter}`);
        } else {
            console.log(`⚠️ getIPApiInfo returned null for IP: ${clientIP}`);
        }

        // Verify the Firebase token
        const decodedToken = await verifyFirebaseIdToken(idToken);
        
        // Find the session by exact sessionId match
        let session = await Session.findOne({ sessionId });
        if (!session) {
            console.log('❌ Session not found:', sessionId);
            return res.status(404).json({ error: 'Session not found' });
        }

        session = await attachHelpdeskCandidateToSession(session);
        
        console.log('✅ Found session:', session.sessionId);

        // Check if this is a verification-only session (no candidateId)
        const isVerificationOnly = !session.candidateId;
        
        // For verification-only sessions, handle anonymous user check-in
        if (isVerificationOnly) {
            // Get or create anonymous user
            let user = await User.findOne({ firebaseUid: decodedToken.uid });
            let isAnonymous = false;
            
            const subjectEmail = session.email && !session.email.endsWith('@anon')
                ? session.email.trim().toLowerCase()
                : null;
            const anonDisplayName = helpdeskSubjectDisplayName(null, subjectEmail, session.mobile);

            if (!user) {
                isAnonymous = true;
                const anonymousEmail = `${decodedToken.uid}@anon`;
                user = await User.create({
                    firebaseUid: decodedToken.uid,
                    email: anonymousEmail,
                    displayName: anonDisplayName,
                    createdAt: new Date(),
                    updatedAt: new Date()
                });
                console.log('✅ Created anonymous user for verification-only session:', anonymousEmail);
            } else {
                isAnonymous = user.email && user.email.endsWith('@anon');
                if (isAnonymous && subjectEmail && user.displayName === subjectEmail) {
                    user.displayName = anonDisplayName;
                    user.updatedAt = new Date();
                    await user.save();
                }
            }
            
            // Keep subject email on session when helpdesk identified the candidate by email
            const sessionUpdate = {
                uuid: decodedToken.uid
            };
            if (subjectEmail) {
                sessionUpdate.email = subjectEmail;
            } else {
                sessionUpdate.email = user.email;
            }
            
            await Session.findByIdAndUpdate(session._id, sessionUpdate);
            
            // Update the anonymous user's sessionId reference (not the interviewer's)
            user.sessionId = session.sessionId;
            await user.save();
            
            // Update session with IP info
            const sessionUpdateData = {
                ipaddr: clientIP,
                iplocation: {
                    country: ipLocation.country,
                    region: ipLocation.region,
                    city: ipLocation.city,
                    lat: ipLocation.lat,
                    lon: ipLocation.lon,
                    timezone: ipLocation.timezone,
                    isp: ipLocation.isp,
                    lastUpdated: new Date()
                }
            };
            if (req.headers['user-agent']) {
                sessionUpdateData.deviceInfo = req.headers['user-agent'];
                sessionUpdateData.deviceInfoUpdatedAt = new Date();
            }
            
            if (ipApiInfo && (!session.ipapi || !session.ipapi.ip)) {
                sessionUpdateData.ipapi = ipApiInfo;
            }
            
            await Session.findByIdAndUpdate(session._id, sessionUpdateData);
            
            console.log(`✅ Anonymous user ${decodedToken.uid} checked in to verification-only session ${session.sessionId} from ${ipLocation.city}, ${ipLocation.country}`);

            const refreshedSession = await Session.findById(session._id);
            const subjectEmailForPin = refreshedSession.email && !refreshedSession.email.endsWith('@anon')
                ? refreshedSession.email.trim().toLowerCase()
                : null;
            let resolvedMobileForPin = usableContactMobile(refreshedSession.mobile)
                || (subjectEmailForPin ? await resolveRealMobileForEmail(subjectEmailForPin) : null);
            const pinRequirement = await getSessionPinRequirement(
                refreshedSession,
                null,
                user,
                { email: subjectEmailForPin, mobile: resolvedMobileForPin }
            );
            const verificationFields = await buildSessionVerificationFields(refreshedSession, pinRequirement, user, null);

            // Generate session-specific tap targets for liveness
            const tapTargets = generateTapTargets();
            await Session.findByIdAndUpdate(session._id, {
                livenessTapTargets: tapTargets,
                deviceFingerprint: req.body.deviceFingerprint || session.deviceFingerprint || null,
            });
            if (resolvedMobileForPin && !usableContactMobile(refreshedSession.mobile)) {
                await Session.findByIdAndUpdate(session._id, { mobile: resolvedMobileForPin });
            }
            
            return res.json({
                success: true,
                sessionId: session.sessionId,
                isVerificationOnly: true,
                isAnonymous: isAnonymous,
                email: user.email,
                verifiedEmail: verificationFields.verifiedEmail,
                ...verificationFields,
                tapTargets,
                ipAddress: clientIP,
                location: {
                    city: ipLocation.city,
                    region: ipLocation.region,
                    country: ipLocation.country,
                    timezone: ipLocation.timezone,
                    isp: ipLocation.isp
                },
                ipapi: ipApiInfo ? {
                    is_vpn: ipApiInfo.is_vpn,
                    is_proxy: ipApiInfo.is_proxy,
                    is_datacenter: ipApiInfo.is_datacenter,
                    is_tor: ipApiInfo.is_tor,
                    is_mobile: ipApiInfo.is_mobile,
                    is_satellite: ipApiInfo.is_satellite,
                    is_crawler: ipApiInfo.is_crawler,
                    is_bogon: ipApiInfo.is_bogon,
                    is_abuser: ipApiInfo.is_abuser,
                    datacenter: ipApiInfo.datacenter,
                    company: ipApiInfo.company,
                    asn: ipApiInfo.asn,
                    location: ipApiInfo.location
                } : null,
                message: 'Successfully checked in to verification-only session'
            });
        }

        // Find the candidate (for candidate-based sessions)
        let candidate = await Candidate.findById(session.candidateId);
        if (!candidate) {
            return res.status(404).json({ error: 'Candidate not found' });
        }

        if (isHelpdeskSource(session.source) && isPlaceholderTicketEmail(candidate.email)) {
            const mobileForLookup = session.mobile || candidate.mobile;
            if (mobileForLookup) {
                const matched = await findCandidateByMobileForInterviewer(candidate.interviewer, mobileForLookup);
                if (matched) {
                    console.log('🔄 Helpdesk check-in: upgraded placeholder candidate via mobile:', {
                        fromEmail: candidate.email,
                        toEmail: matched.email,
                        candidateId: matched._id
                    });
                    candidate = matched;
                }
            }
        }

        // Check if there's already a user with this email to handle de-anonymization
        let existingUser = null;
        let customToken = null;

        if (isHelpdeskSource(session.source) && candidate.email) {
            const ticketEmail = session.external?.requesterEmail || session.email;
            existingUser = await ensureHelpdeskSubjectUserRecord(decodedToken, candidate, ticketEmail);
            if (existingUser && existingUser.firebaseUid !== decodedToken.uid) {
                customToken = await admin.auth().createCustomToken(existingUser.firebaseUid);
                candidate.firebaseUid = existingUser.firebaseUid;
                console.log('🔄 Helpdesk check-in: de-anonymize to existing user by email');
                cleanupAnonUser(decodedToken.uid).catch(err => console.error('cleanupAnonUser failed:', err.message));
            }
        }
        
        if (candidate.email && !existingUser) {
            existingUser = await User.findOne({ email: candidate.email.toLowerCase() });
            if (existingUser) {
                console.log('🔗 Found existing user by email during checkin:', {
                    email: candidate.email,
                    existingFirebaseUid: existingUser.firebaseUid,
                    newFirebaseUid: decodedToken.uid,
                    candidateId: candidate._id
                });
                
                // Create custom token for existing user to de-anonymize them
                customToken = await admin.auth().createCustomToken(existingUser.firebaseUid);
                console.log('🔄 Created custom token for existing user to de-anonymize');
                
                // Update the candidate to use the existing user's Firebase UID
                candidate.firebaseUid = existingUser.firebaseUid;
                cleanupAnonUser(decodedToken.uid).catch(err => console.error('cleanupAnonUser failed:', err.message));
                
                // Update the existing user with any missing information from the candidate
                const updates = {};
                if (!existingUser.displayName && candidate.name) {
                    updates.displayName = candidate.name;
                }
                if (!existingUser.linkedinId && candidate.linkedinId) {
                    updates.linkedinId = candidate.linkedinId;
                }
                if (!existingUser.verified && candidate.verified) {
                    updates.verified = candidate.verified;
                }
                if (!existingUser.photoURL && candidate.photoURL) {
                    updates.photoURL = candidate.photoURL;
                }
                if (!existingUser.city || existingUser.city === 'Unknown') {
                    updates.city = candidate.city;
                }

                if (Object.keys(updates).length > 0) {
                    await User.findByIdAndUpdate(existingUser._id, updates);
                    console.log('✅ Updated existing user with candidate data:', updates);
                }
            } else {
                // Verify that the Firebase UID actually exists in Firebase
                try {
                    await admin.auth().getUser(decodedToken.uid);
                    
                    // Create new user from candidate data
                    const newUser = await User.create({
                        firebaseUid: decodedToken.uid,
                        email: candidate.email,
                        displayName: candidate.name,
                        linkedinId: candidate.linkedinId,
                        verified: candidate.verified,
                        photoURL: candidate.photoURL,
                        city: candidate.city,
                        lastLogin: new Date()
                    });
                    
                    console.log('✅ Created new user from candidate:', newUser._id);
                    
                    // Create custom token for new user
                    customToken = await admin.auth().createCustomToken(decodedToken.uid);
                } catch (firebaseError) {
                    console.error('❌ Firebase UID does not exist:', decodedToken.uid, firebaseError.message);
                    
                    // Create a new Firebase user for this candidate
                    try {
                        const firebaseUser = await admin.auth().createUser({
                            email: candidate.email,
                            displayName: candidate.name,
                            photoURL: candidate.photoURL
                        });
                        
                        console.log('✅ Created new Firebase user for candidate:', firebaseUser.uid);
                        
                        // Create new user with the new Firebase UID
                        const newUser = await User.create({
                            firebaseUid: firebaseUser.uid,
                            email: candidate.email,
                            displayName: candidate.name,
                            linkedinId: candidate.linkedinId,
                            verified: candidate.verified,
                            photoURL: candidate.photoURL,
                            city: candidate.city,
                            lastLogin: new Date()
                        });
                        
                        console.log('✅ Created new user from candidate with new Firebase UID:', newUser._id);
                        
                        // Create custom token for new user
                        customToken = await admin.auth().createCustomToken(firebaseUser.uid);
                        
                        // Update candidate with the new Firebase UID
                        candidate.firebaseUid = firebaseUser.uid;
                        await candidate.save();
                        
                    } catch (createError) {
                        console.error('❌ Failed to create Firebase user for candidate:', createError);
                        return res.status(500).json({ error: 'Failed to create user account' });
                    }
                }
            }
        }

        // Update the candidate with the appropriate Firebase UID
        candidate.firebaseUid = existingUser ? existingUser.firebaseUid : decodedToken.uid;
        await candidate.save();

        // Get the final Firebase UID for the candidate
        const finalFirebaseUid = existingUser ? existingUser.firebaseUid : decodedToken.uid;
        
        // Get the candidate's email
        // If there's an existing user, use their email
        // Otherwise, check if this is an anonymous check-in (anonymous Firebase UID)
        // For anonymous check-ins, use anonymous email; otherwise use candidate's email
        let candidateEmail;
        if (isHelpdeskSource(session.source)) {
            const authEmail = (existingUser?.email && !existingUser.email.endsWith('@anon'))
                ? existingUser.email
                : (decodedToken.email && !decodedToken.email.endsWith('@anon') ? decodedToken.email : null);
            candidateEmail = authEmail || candidate.email;
        } else if (existingUser) {
            candidateEmail = existingUser.email;
        } else {
            const isAnonymousCheckIn = !decodedToken.email || decodedToken.email.endsWith('@anon');
            if (isAnonymousCheckIn) {
                candidateEmail = `${decodedToken.uid}@anon`;
            } else {
                candidateEmail = candidate.email;
            }
        }

        // Update session with candidate's identity and IP address/geolocation information
        const checkingInUser = await User.findOne({ firebaseUid: decodedToken.uid });
        const sessionForPin = await Session.findById(session._id);
        const subjectEmailForPin = resolveSessionSubjectEmail(sessionForPin, checkingInUser, candidate);
        let resolvedMobileForPin = usableContactMobile(sessionForPin?.mobile)
            || usableContactMobile(candidate.mobile)
            || (subjectEmailForPin ? await resolveRealMobileForEmail(subjectEmailForPin) : null);
        const pinRequirement = await getSessionPinRequirement(
            sessionForPin,
            candidate,
            checkingInUser,
            { email: subjectEmailForPin, mobile: resolvedMobileForPin }
        );
        const verificationFields = await buildSessionVerificationFields(sessionForPin, pinRequirement, checkingInUser, candidate);

        // Generate session-specific tap targets for liveness
        const tapTargetsCheckin = generateTapTargets();

        const sessionUpdateData = {
            email: candidateEmail,
            uuid: finalFirebaseUid,
            candidateId: candidate._id,
            requiresPin: verificationFields.requiresPin,
            livenessTapTargets: tapTargetsCheckin,
            deviceFingerprint: req.body.deviceFingerprint || session.deviceFingerprint || null,
            mobile: resolvedMobileForPin || usableContactMobile(sessionForPin?.mobile) || null,
            ipaddr: clientIP,
            iplocation: {
                country: ipLocation.country,
                region: ipLocation.region,
                city: ipLocation.city,
                lat: ipLocation.lat,
                lon: ipLocation.lon,
                timezone: ipLocation.timezone,
                isp: ipLocation.isp,
                lastUpdated: new Date()
            }
        };
        if (req.headers['user-agent']) {
            sessionUpdateData.deviceInfo = req.headers['user-agent'];
            sessionUpdateData.deviceInfoUpdatedAt = new Date();
        }

        if (process.env.DEBUG) {
            console.log(`🌐 Session update - clientIP: ${clientIP}, source: ${source}`);
            console.log(`🌐 Session update - ipaddr will be set to: ${clientIP}`);
        }

        // Add ipapi.is data if available and doesn't already exist
        if (ipApiInfo) {
            sessionUpdateData.ipapi = ipApiInfo;
            if (process.env.DEBUG) {
                console.log('💾 Storing ipapi.is data in session:', JSON.stringify(ipApiInfo, null, 2));
                console.log(`💾 Session ID: ${sessionId}`);
            }
        } else if (process.env.DEBUG) {
            console.log(`⚠️ No ipapi.is data to store for IP: ${clientIP} (already exists or no data available)`);
        }

        await Session.findByIdAndUpdate(session._id, sessionUpdateData);

        const sanitizedVerified = sanitizeCandidateVerified(candidate.verified, candidate.email);
        if (JSON.stringify(sanitizedVerified) !== JSON.stringify(candidate.verified || null)) {
            candidate.verified = sanitizedVerified;
            await candidate.save();
        }

        await recordHelpdeskPhoneEmailLink(
            candidate.interviewer,
            sessionUpdateData.mobile,
            candidateEmail,
            session.sessionId,
            session.source
        );

        if (checkingInUser) {
            checkingInUser.sessionId = session.sessionId;
            checkingInUser.lastLogin = new Date();
            await checkingInUser.save();
        }
        
        if (process.env.DEBUG) {
            console.log('💾 Session update completed');
        }
        console.log(`✅ Candidate ${candidate._id} checked in with Firebase UID ${finalFirebaseUid} via session ${sessionId} from ${ipLocation.city}, ${ipLocation.country}`);

        const refreshedSession = await Session.findById(session._id);

        res.json({
            success: true,
            candidateId: candidate._id,
            sessionId: session.sessionId,
            candidateName: candidate.name,
            candidateEmail: candidate.email,
            verifiedEmail: verificationFields.verifiedEmail,
            ...verificationFields,
            tapTargets: tapTargetsCheckin,
            ipAddress: clientIP,
            location: {
                city: ipLocation.city,
                region: ipLocation.region,
                country: ipLocation.country,
                timezone: ipLocation.timezone,
                isp: ipLocation.isp
            },
            ipapi: ipApiInfo ? {
                is_vpn: ipApiInfo.is_vpn,
                is_proxy: ipApiInfo.is_proxy,
                is_datacenter: ipApiInfo.is_datacenter,
                is_tor: ipApiInfo.is_tor,
                is_mobile: ipApiInfo.is_mobile,
                is_satellite: ipApiInfo.is_satellite,
                is_crawler: ipApiInfo.is_crawler,
                is_bogon: ipApiInfo.is_bogon,
                is_abuser: ipApiInfo.is_abuser,
                datacenter: ipApiInfo.datacenter,
                company: ipApiInfo.company,
                asn: ipApiInfo.asn,
                location: ipApiInfo.location
            } : null,
            message: 'Successfully checked in',
            customToken: customToken,
            firebaseUid: finalFirebaseUid,
            isDeAnonymized: !!customToken
        });
    } catch (error) {
        console.error('Check-in error:', error);
        res.status(500).json({ error: 'Failed to check in' });
    }
});

// Waitlist endpoint
app.post('/api/waitlist', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        
        // Validate email
        if (!email || typeof email !== 'string') {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Check if email already exists in waitlist
        const existingEntry = await Waitlist.findOne({ email: email.toLowerCase() });
        if (existingEntry) {
            return res.status(409).json({ 
                error: 'Email already on waitlist',
                status: existingEntry.status,
                createdAt: existingEntry.createdAt
            });
        }
        
        // Add email to waitlist
        const waitlistEntry = await Waitlist.create({
            email: email.toLowerCase(),
            createdAt: new Date()
        });
        
        console.log(`✅ Added email to waitlist: ${email}`);
        
        // Send welcome email to the person who joined the waitlist
        try {
            await sendWaitlistWelcome(waitlistEntry);
            console.log(`✅ Welcome email sent to ${waitlistEntry.email}`);
        } catch (welcomeEmailError) {
            console.error('❌ Failed to send waitlist welcome email:', welcomeEmailError);
            // Don't fail the request if welcome email fails, just log it
        }
        
        res.json({
            success: true,
            message: 'Successfully added to waitlist',
            email: waitlistEntry.email,
            status: waitlistEntry.status,
            createdAt: waitlistEntry.createdAt
        });
        
    } catch (error) {
        console.error('Waitlist error:', error);
        res.status(500).json({ error: 'Failed to add to waitlist' });
    }
});

// Get invitation code endpoint (POST - for creating new invites)
app.post('/api/getInvite', authenticateToken, async (req, res) => {
    try {
        const { email } = req.body;
        
        // Validate email
        if (!email || typeof email !== 'string') {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Get the user
        let user = await User.findOne({ firebaseUid: req.user.uid });
        console.log(`🔍 Looking for user with firebaseUid: ${req.user.uid}`);
        console.log(`🔍 User found: ${!!user}`);
        
        if (!user) {
            console.log(`❌ User not found for firebaseUid: ${req.user.uid}`);
            return res.status(404).json({ error: 'User not found' });
        }
        
        console.log(`🔍 User invite fields: invites=${user.invites}, invitesLeft=${user.invitesLeft}`);
        
        // If user doesn't have invite fields set, initialize them
        if (user.invites === undefined || user.invitesLeft === undefined) {
            user.invites = 1;
            user.invitesLeft = 1;
            await user.save();
            console.log(`✅ Initialized invite fields for user ${req.user.uid}: invites=${user.invites}, invitesLeft=${user.invitesLeft}`);
        }
        
        // Check if user has invites left
        console.log(`🔍 Checking invitesLeft: ${user.invitesLeft} <= 0 = ${user.invitesLeft <= 0}`);
        if (user.invitesLeft <= 0) {
            console.log(`❌ No invites left for user ${req.user.uid}: invites=${user.invites}, invitesLeft=${user.invitesLeft}`);
            return res.status(403).json({ 
                error: 'No invites left',
                invites: user.invites,
                invitesLeft: user.invitesLeft
            });
        }
        
        // Generate unique 6-digit numeric code
        const generateCode = () => {
            return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
        };
        
        // Generate code and ensure it's unique
        let code;
        let isUnique = false;
        let attempts = 0;
        const maxAttempts = 10;
        
        while (!isUnique && attempts < maxAttempts) {
            code = generateCode();
            const existingInvite = await Invite.findOne({ code });
            if (!existingInvite) {
                isUnique = true;
            }
            attempts++;
        }
        
        if (!isUnique) {
            return res.status(500).json({ error: 'Failed to generate unique invitation code' });
        }
        
        // Set expiration date (24 hours from now)
        const expirationDate = new Date();
        expirationDate.setHours(expirationDate.getHours() + 24);
        
        // Create invitation
        console.log('Creating invite with data:', {
            code,
            emailSponsor: email.toLowerCase(),
            email: email.toLowerCase(), // Set to the invited user's email
            dateInvited: new Date(),
            invitedBy: req.user.uid,
            dateUsed: null,
            expirationDate
        });
        
        const invite = await Invite.create({
            code,
            emailSponsor: email.toLowerCase(),
            email: email.toLowerCase(), // Set to the invited user's email
            dateInvited: new Date(),
            invitedBy: req.user.uid,
            dateUsed: null,
            expirationDate
        });
        
        // Decrement user's invites left
        await User.findByIdAndUpdate(user._id, {
            $inc: { invitesLeft: -1 }
        });
        
        console.log(`✅ Generated invite code ${code} for ${email} by user ${req.user.uid}`);
        
        res.json({
            code,
            invitesLeft: user.invitesLeft - 1
        });
        
    } catch (error) {
        console.error('Get invite error:', error);
        res.status(500).json({ error: 'Failed to generate invitation code' });
    }
});

async function handlePreRegisterInvites(req, res) {
    try {
        const body = req.body || {};
        const emails = body.emails !== undefined
            ? body.emails
            : (body.email !== undefined ? [body.email] : []);

        if (normalizeEmailList(emails).length === 0) {
            return res.status(400).json({ error: 'At least one valid email is required' });
        }

        const inviterUser = await resolveInviterUser(req.user);
        if (!inviterUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const { results, summary } = await invitePreRegistrationBatch(emails, inviterUser, req.user.uid);
        const publicResults = results.map(({ email, status, existing, emailSent, emailSkipped, emailError, expirationDate }) => ({
            email,
            status,
            existing,
            emailSent,
            emailSkipped,
            emailError,
            expirationDate
        }));

        let webhook = null;
        try {
            webhook = await dispatchIntegratorWebhook(inviterUser, 'preregister.batch.completed', {
                summary,
                results: publicResults
            });
        } catch (webhookError) {
            console.error('Pre-register webhook dispatch failed:', webhookError);
            webhook = { dispatched: false, reason: webhookError.message || 'webhook_failed' };
        }

        const single = normalizeEmailList(emails).length === 1;
        return res.json({
            success: true,
            summary,
            results: publicResults,
            webhook,
            ...(single ? {
                email: publicResults[0]?.email,
                existing: publicResults[0]?.existing,
                emailSent: publicResults[0]?.emailSent,
                emailError: publicResults[0]?.emailError,
                message: publicResults[0]?.emailSent
                    ? 'Enrollment request sent'
                    : (publicResults[0]?.emailError
                        ? 'Enrollment created but email could not be sent'
                        : 'Enrollment request processed')
            } : {
                message: `Processed ${summary.total} enrollment(s): ${summary.sent} sent, ${summary.skipped} skipped, ${summary.failed} failed`
            })
        });
    } catch (error) {
        if (error.message && error.message.includes('Maximum')) {
            return res.status(400).json({ error: error.message });
        }
        console.error('Pre-register batch error:', error);
        res.status(500).json({ error: 'Failed to create enrollment invitations' });
    }
}

// Pre-register subject(s): email invite with enroll.html?r=code
app.post('/api/preregister', authenticateToken, handlePreRegisterInvites);
app.post('/api/preregister/batch', authenticateToken, handlePreRegisterInvites);

// External API: invite list of emails (API key or Firebase token)
app.post('/api/v1/preregister/invites', authenticateFirebaseOrApiKey, handlePreRegisterInvites);

function preregPageUrl(code) {
    const frontendOrigin = (process.env.FRONTEND_URL || 'https://in.xchk.io').replace(/\/$/, '');
    return `${frontendOrigin}/enroll.html?r=${encodeURIComponent(code)}`;
}

// Public: validate pre-registration invite code (mobile baseline flow)
app.get('/api/preregister/:code', async (req, res) => {
    try {
        const normalizedCode = normalizePreregCode(req.params.code);
        if (!normalizedCode) {
            return res.status(404).json({ valid: false, error: 'Invalid or expired enrollment code' });
        }

        let preRegistration = await findActivePreRegistration(normalizedCode);
        if (!preRegistration) {
            const completed = await findCompletedPreRegistrationByCode(normalizedCode);
            if (completed) {
                return res.json({
                    valid: true,
                    code: completed.code,
                    alreadySubmitted: true,
                    ...preRegistrationClientFlags(completed)
                });
            }
            const revoked = await findRevokedPreRegistrationByCode(normalizedCode);
            if (revoked) {
                return res.status(410).json({
                    valid: false,
                    replaced: true,
                    error: 'This enrollment link is no longer valid. Sign in at xChk to receive a new enrollment email.'
                });
            }
            return res.status(404).json({ valid: false, error: 'Invalid or expired enrollment code' });
        }

        preRegistration = await recordDesktopEnrollmentLinkOpen(preRegistration, req.headers['user-agent']);

        return res.json({
            valid: true,
            code: preRegistration.code,
            expirationDate: preRegistration.expirationDate,
            registrationUrl: preregPageUrl(preRegistration.code),
            alreadySubmitted: !!preRegistration.baselineSubmittedAt,
            requiresInvitedEmail: !!preRegistration.email,
            ...preRegistrationClientFlags(preRegistration)
        });
    } catch (error) {
        console.error('Pre-register lookup error:', error);
        res.status(500).json({ valid: false, error: 'Failed to look up enrollment' });
    }
});

// Public: verify invited email and phone before baseline capture
app.post('/api/preregister/:code/verify-contact', async (req, res) => {
    try {
        const preRegistration = await findActivePreRegistration(req.params.code);
        if (!preRegistration) {
            return res.status(404).json({ error: 'Invalid or expired enrollment code' });
        }
        if (preRegistration.baselineSubmittedAt) {
            return res.status(409).json({ error: 'Enrollment baseline already submitted' });
        }

        const { email, mobile } = req.body || {};
        const normalizedMobile = usableContactMobile(mobile) || '';
        let normalizedEmail = preRegistration.email
            || (typeof email === 'string' ? email.toLowerCase().trim() : '');

        if (!normalizedEmail) {
            return res.status(400).json({ error: 'Email is required' });
        }
        if (!normalizedMobile) {
            return res.status(400).json({ error: 'Phone number is required' });
        }
        if (preRegistration.email && preRegistration.email !== normalizedEmail) {
            return res.status(400).json({ error: 'Email does not match the enrollment request' });
        }

        const now = new Date();
        preRegistration.email = normalizedEmail;
        preRegistration.mobile = normalizedMobile;
        preRegistration.emailVerifiedAt = now;
        await preRegistration.save();

        return res.json({
            success: true,
            emailVerified: true,
            email: normalizedEmail
        });
    } catch (error) {
        console.error('Pre-register verify-contact error:', error);
        res.status(500).json({ error: 'Failed to verify contact details' });
    }
});

// Public: presigned PUT URLs for baseline photo burst
app.post('/api/preregister/:code/sign-photos', async (req, res) => {
    try {
        const preRegistration = await findActivePreRegistration(req.params.code);
        if (!preRegistration) {
            return res.status(404).json({ error: 'Invalid or expired enrollment code' });
        }
        if (preRegistration.baselineSubmittedAt) {
            return res.status(409).json({ error: 'Enrollment baseline already submitted' });
        }

        const uploads = await signBaselinePhotoUploads(preRegistration.code);
        return res.json({ success: true, uploads, photoCount: BASELINE_PHOTO_COUNT });
    } catch (error) {
        console.error('Pre-register sign-photos error:', error);
        res.status(500).json({ error: 'Failed to sign photo uploads' });
    }
});

// Public: submit baseline (contact info, photos, device/network/geo metadata)
app.post('/api/preregister/:code/submit', async (req, res) => {
    try {
        const preRegistration = await findActivePreRegistration(req.params.code);
        if (!preRegistration) {
            return res.status(404).json({ error: 'Invalid or expired enrollment code' });
        }
        if (preRegistration.baselineSubmittedAt) {
            return res.status(409).json({ error: 'Enrollment baseline already submitted' });
        }

        const {
            email,
            mobile,
            pin,
            photos,
            deviceFingerprint,
            deviceInfo,
            browserInfo,
            networkInfo,
            clientGeo
        } = req.body || {};

        const normalizedEmail = preRegistration.email
            || (typeof email === 'string' ? email.toLowerCase().trim() : '');
        const normalizedMobile = usableContactMobile(mobile) || '';

        if (!normalizedEmail) {
            return res.status(400).json({ error: 'Email is required' });
        }
        if (!normalizedMobile) {
            return res.status(400).json({ error: 'Phone number is required' });
        }
        if (!isValidPin(pin)) {
            return res.status(400).json({ error: 'PIN must be 4-6 digits' });
        }
        if (preRegistration.email && preRegistration.email !== normalizedEmail) {
            return res.status(400).json({ error: 'Email does not match the enrollment request' });
        }
        if (!photoUrlsMatchCode(photos, preRegistration.code)) {
            return res.status(400).json({ error: `Exactly ${BASELINE_PHOTO_COUNT} baseline photos are required` });
        }

        const { clientIP } = await getBestIP(req);
        const ipLocation = await getIPLocation(clientIP);
        const ipApiInfo = await getIPApiInfo(clientIP);
        const now = new Date();

        preRegistration.email = normalizedEmail;
        preRegistration.mobile = normalizedMobile;
        preRegistration.hashedPin = hashPin(pin);
        preRegistration.deviceFingerprint = typeof deviceFingerprint === 'string' ? deviceFingerprint : null;
        preRegistration.deviceInfo = typeof deviceInfo === 'string' ? deviceInfo : null;
        preRegistration.browserInfo = {
            languages: Array.isArray(browserInfo?.languages) ? browserInfo.languages : [],
            timezone: browserInfo?.timezone || null
        };
        preRegistration.networkInfo = {
            type: networkInfo?.type || 'unknown',
            effectiveType: networkInfo?.effectiveType || 'unknown',
            downlink: networkInfo?.downlink ?? null,
            rtt: networkInfo?.rtt ?? null,
            saveData: !!networkInfo?.saveData
        };
        preRegistration.clientGeo = {
            lat: clientGeo?.lat ?? null,
            lon: clientGeo?.lon ?? null,
            accuracy: clientGeo?.accuracy ?? null
        };
        preRegistration.ipaddr = clientIP;
        preRegistration.iplocation = {
            ...ipLocation,
            lastUpdated: now
        };
        preRegistration.ipapi = ipApiInfo || null;
        preRegistration.baselinePhotos = photos.map((url, index) => ({
            index,
            url,
            key: buildBaselinePhotoKey(preRegistration.code, index),
            capturedAt: now
        }));
        preRegistration.baselineSubmittedAt = now;
        preRegistration.emailVerifiedAt = now;
        preRegistration.dateUsed = now;

        await preRegistration.save();
        await syncPreRegistrationToCandidate(preRegistration);
        try { const lu = await User.findOne({ email: normalizedEmail }); if (lu) { if (!lu.emailVerified) lu.emailVerified = true; if (preRegistration.mobile && !lu.mobile) lu.mobile = preRegistration.mobile; await lu.save(); } } catch (e) {}

        console.log(`✅ Pre-registration baseline submitted for ${normalizedEmail} (code ${preRegistration.code})`);

        sendEnrollmentWelcome(preRegistration).catch((err) => {
            console.error('Enrollment welcome email failed:', err.message);
        });

        return res.json({
            success: true,
            code: preRegistration.code,
            email: preRegistration.email,
            mobile: preRegistration.mobile,
            emailVerified: !!preRegistration.emailVerifiedAt,
            baselineSubmittedAt: preRegistration.baselineSubmittedAt,
            ...preRegistrationClientFlags(preRegistration)
        });
    } catch (error) {
        console.error('Pre-register submit error:', error);
        res.status(500).json({ error: 'Failed to submit enrollment baseline' });
    }
});

// Update session transcripts
app.patch('/api/session/:sessionId/transcripts', authenticateToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }

        // Find the session
        const session = await Session.findOne({ sessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        // Update the session to set transcripts to true
        const updatedSession = await Session.findOneAndUpdate(
            { sessionId },
            { transcripts: true },
            { new: true }
        );

        console.log(`✅ Updated session ${sessionId} transcripts to true`);

        res.json({
            success: true,
            sessionId: updatedSession.sessionId,
            transcripts: updatedSession.transcripts
        });

    } catch (error) {
        console.error('Session transcripts update error:', error);
        res.status(500).json({ error: 'Failed to update session transcripts' });
    }
});

// Get session transcripts
app.get('/api/session/:sessionId/transcripts', authenticateToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { type } = req.query;
        
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }

        if (!type || !['json', 'txt', 'pcm'].includes(type)) {
            return res.status(400).json({ error: 'Type parameter is required and must be one of: json, txt, pcm' });
        }

        // Find the session
        const session = await Session.findOne({ sessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        // Check if transcripts are enabled for this session
        if (!session.transcripts) {
            return res.status(404).json({ error: 'Transcripts not enabled for this session' });
        }

        // Check if file exists in /tmp first
        const tmpFilePath = `/tmp/${sessionId}.${type}`;
        const cdnUrl = `https://cdn.xchk.io/transcripts/${sessionId}.${type}`;
        
        let fileExists = fs.existsSync(tmpFilePath);
        let source = fileExists ? 'local' : 'cdn';
        
        console.log(`📄 Transcript request - Session: ${sessionId}, Type: ${type} (${fileExists ? 'local' : 'cdn'})`);

        switch (type) {
            case 'json':
                if (fileExists) {
                    // Read and return JSON file from /tmp
                    const jsonData = fs.readFileSync(tmpFilePath, 'utf8');
                    try {
                        const parsedJson = JSON.parse(jsonData);
                        res.json(parsedJson);
                    } catch (parseError) {
                        console.error('Error parsing JSON transcript:', parseError);
                        res.status(500).json({ error: 'Invalid JSON in transcript file' });
                    }
                } else {
                    // Fetch from CDN and serve
                    try {
                        const response = await fetch(cdnUrl);
                        if (response.ok) {
                            const jsonData = await response.text();
                            try {
                                const parsedJson = JSON.parse(jsonData);
                                res.json(parsedJson);
                            } catch (parseError) {
                                console.error('Error parsing JSON from CDN:', parseError);
                                res.status(500).json({ error: 'Invalid JSON in transcript file' });
                            }
                        } else {
                            console.error(`❌ CDN returned ${response.status} for ${cdnUrl}`);
                            res.status(404).json({ error: 'Transcript file not found on CDN' });
                        }
                    } catch (fetchError) {
                        console.error('Error fetching from CDN:', fetchError);
                        res.status(500).json({ error: 'Failed to fetch transcript from CDN' });
                    }
                }
                break;

            case 'txt':
                if (fileExists) {
                    // Read and return text content from /tmp
                    const textContent = fs.readFileSync(tmpFilePath, 'utf8');
                    res.json({
                        sessionId: sessionId,
                        transcript: textContent,
                        type: 'txt'
                    });
                } else {
                    // Fetch from CDN and serve
                    try {
                        const response = await fetch(cdnUrl);
                        if (response.ok) {
                            const textContent = await response.text();
                            res.json({
                                sessionId: sessionId,
                                transcript: textContent,
                                type: 'txt'
                            });
                        } else {
                            console.error(`❌ CDN returned ${response.status} for ${cdnUrl}`);
                            res.status(404).json({ error: 'Transcript file not found on CDN' });
                        }
                    } catch (fetchError) {
                        console.error('Error fetching from CDN:', fetchError);
                        res.status(500).json({ error: 'Failed to fetch transcript from CDN' });
                    }
                }
                break;

            case 'pcm':
                if (fileExists) {
                    // Convert PCM to MP3 and stream from /tmp
                    const mp3Path = `/tmp/${sessionId}.mp3`;
                    
                    // Check if MP3 already exists
                    if (!fs.existsSync(mp3Path)) {
                        // Convert PCM to MP3 using ffmpeg
                        try {
                            await execAsync(`ffmpeg -f s16le -ar 16000 -ac 1 -i ${tmpFilePath} -acodec mp3 ${mp3Path}`);
                            console.log(`✅ Converted PCM to MP3: ${mp3Path}`);
                        } catch (conversionError) {
                            console.error('Error converting PCM to MP3:', conversionError);
                            return res.status(500).json({ error: 'Failed to convert audio format' });
                        }
                    }

                    // Stream the MP3 file
                    const stat = fs.statSync(mp3Path);
                    const fileSize = stat.size;
                    const range = req.headers.range;

                    if (range) {
                        const parts = range.replace(/bytes=/, "").split("-");
                        const start = parseInt(parts[0], 10);
                        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
                        const chunksize = (end - start) + 1;
                        const file = fs.createReadStream(mp3Path, { start, end });
                        const head = {
                            'Content-Range': `bytes ${start}-${end}/${fileSize}`,
                            'Accept-Ranges': 'bytes',
                            'Content-Length': chunksize,
                            'Content-Type': 'audio/mpeg',
                        };
                        res.writeHead(206, head);
                        file.pipe(res);
                    } else {
                        const head = {
                            'Content-Length': fileSize,
                            'Content-Type': 'audio/mpeg',
                        };
                        res.writeHead(200, head);
                        fs.createReadStream(mp3Path).pipe(res);
                    }
                } else {
                    // For PCM files, check if MP3 already exists, otherwise download and convert
                    const mp3Path = `/tmp/${sessionId}.mp3`;
                    
                    // Check if MP3 file already exists
                    if (fs.existsSync(mp3Path)) {
                        // Stream the existing MP3 file
                        const stat = fs.statSync(mp3Path);
                        const fileSize = stat.size;
                        const range = req.headers.range;

                        if (range) {
                            const parts = range.replace(/bytes=/, "").split("-");
                            const start = parseInt(parts[0], 10);
                            const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
                            const chunksize = (end - start) + 1;
                            const file = fs.createReadStream(mp3Path, { start, end });
                            const head = {
                                'Content-Range': `bytes ${start}-${end}/${fileSize}`,
                                'Accept-Ranges': 'bytes',
                                'Content-Length': chunksize,
                                'Content-Type': 'audio/mpeg',
                            };
                            res.writeHead(206, head);
                            file.pipe(res);
                        } else {
                            const head = {
                                'Content-Length': fileSize,
                                'Content-Type': 'audio/mpeg',
                            };
                            res.writeHead(200, head);
                            fs.createReadStream(mp3Path).pipe(res);
                        }
                    } else {
                        // Download from CDN, convert to MP3, then stream
                        const pcmCdnUrl = `https://cdn.xchk.io/transcripts/${sessionId}.pcm`;
                        try {
                            const response = await fetch(pcmCdnUrl);
                            if (response.ok) {
                                const pcmBuffer = await response.arrayBuffer();
                                
                                // Save PCM to temporary file
                                const tempPcmPath = `/tmp/${sessionId}_temp.pcm`;
                                
                                await fs.promises.writeFile(tempPcmPath, Buffer.from(pcmBuffer));
                                console.log(`💾 Saved PCM to temp file: ${tempPcmPath}`);
                                
                                // Convert PCM to MP3 using ffmpeg
                                try {
                                    await execAsync(`ffmpeg -f s16le -ar 16000 -ac 1 -i ${tempPcmPath} -acodec mp3 ${mp3Path}`);
                                    console.log(`✅ Converted PCM to MP3: ${mp3Path}`);
                                    
                                    // Clean up temp PCM file
                                    await fs.promises.unlink(tempPcmPath);
                                    console.log(`🗑️ Cleaned up temp PCM file: ${tempPcmPath}`);
                                    
                                    // Stream the MP3 file
                                    const stat = fs.statSync(mp3Path);
                                    const fileSize = stat.size;
                                    const range = req.headers.range;

                                    if (range) {
                                        const parts = range.replace(/bytes=/, "").split("-");
                                        const start = parseInt(parts[0], 10);
                                        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
                                        const chunksize = (end - start) + 1;
                                        const file = fs.createReadStream(mp3Path, { start, end });
                                        const head = {
                                            'Content-Range': `bytes ${start}-${end}/${fileSize}`,
                                            'Accept-Ranges': 'bytes',
                                            'Content-Length': chunksize,
                                            'Content-Type': 'audio/mpeg',
                                        };
                                        res.writeHead(206, head);
                                        file.pipe(res);
                                    } else {
                                        const head = {
                                            'Content-Length': fileSize,
                                            'Content-Type': 'audio/mpeg',
                                        };
                                        res.writeHead(200, head);
                                        fs.createReadStream(mp3Path).pipe(res);
                                    }
                                    
                                } catch (conversionError) {
                                    console.error('Error converting PCM to MP3:', conversionError);
                                    // Clean up temp file on error
                                    try {
                                        await fs.promises.unlink(tempPcmPath);
                                    } catch (cleanupError) {
                                        console.error('Error cleaning up temp PCM file:', cleanupError);
                                    }
                                    res.status(500).json({ error: 'Failed to convert audio format' });
                                }
                            } else {
                                console.error(`❌ CDN returned ${response.status} for ${pcmCdnUrl}`);
                                res.status(404).json({ error: 'Transcript file not found on CDN' });
                            }
                        } catch (fetchError) {
                            console.error('Error fetching PCM from CDN:', fetchError);
                            res.status(500).json({ error: 'Failed to fetch transcript from CDN' });
                        }
                    }
                }
                break;

            default:
                res.status(400).json({ error: 'Invalid transcript type' });
        }

    } catch (error) {
        console.error('Get transcripts error:', error);
        res.status(500).json({ error: 'Failed to retrieve transcripts' });
    }
});

// Close session endpoint
app.get('/api/session/:sessionId/status', async (req, res) => { // No auth — sessionId is unguessable
    try {
        const { sessionId } = req.params;
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }

        const session = await Session.findOne({ sessionId })
            .select('sessionId status closedAt expiresAt operatorEmail operatorName uuid')
            .lean();
        if (!session) {
            return res.status(404).json({ error: 'Session not found', active: false });
        }

        const closed = session.status === 'closed' || !!session.closedAt;
        const expired = session.expiresAt && new Date(session.expiresAt) < new Date();
        const active = !closed && !expired;

        // Look up operator for company/name display on mobile
        let operatorName = session.operatorName || null;
        let operatorCompany = null;
        let isCorporate = false;
        if (session.uuid) {
            try {
                const opUser = await User.findOne({ firebaseUid: session.uuid })
                    .select('company plan email displayName')
                    .lean();
                if (opUser) {
                    operatorName = operatorName || opUser.displayName || null;
                    operatorCompany = opUser.company || null;
                    isCorporate = opUser.plan === 'company' || opUser.plan === 'enterprise';
                }
            } catch (e) { /* ignore lookup failure */ }
        }

        res.json({
            sessionId: session.sessionId,
            status: session.status || (closed ? 'closed' : 'open'),
            active,
            closedAt: session.closedAt || null,
            operatorName,
            operatorCompany,
            isCorporate
        });
    } catch (error) {
        console.error('Session status error:', error);
        res.status(500).json({ error: 'Failed to read session status' });
    }
});

app.post('/api/session/:sessionId/webrtc-stats', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { role, stats } = req.body || {};

        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }
        if (!stats || typeof stats !== 'object') {
            return res.status(400).json({ error: 'Stats object is required' });
        }

        const roleKey = role === 'CLI' || role === 'mobile' ? 'mobile' : 'operator';
        const candidateTypes = stats.candidateTypes && typeof stats.candidateTypes === 'object'
            ? {
                local: Array.isArray(stats.candidateTypes.local) ? stats.candidateTypes.local : [],
                remote: Array.isArray(stats.candidateTypes.remote) ? stats.candidateTypes.remote : []
            }
            : { local: [], remote: [] };
        const sanitized = {
            rttMs: Number.isFinite(Number(stats.rttMs)) ? Math.round(Number(stats.rttMs)) : null,
            localCandidateType: stats.localCandidateType || null,
            remoteCandidateType: stats.remoteCandidateType || null,
            relayUsed: !!stats.relayUsed,
            localIp: stats.localIp || null,
            localPort: Number.isFinite(Number(stats.localPort)) ? Number(stats.localPort) : null,
            localRelatedAddress: stats.localRelatedAddress || null,
            localRelatedPort: Number.isFinite(Number(stats.localRelatedPort)) ? Number(stats.localRelatedPort) : null,
            remoteIp: stats.remoteIp || null,
            remotePort: Number.isFinite(Number(stats.remotePort)) ? Number(stats.remotePort) : null,
            candidateTypes,
            iceGatheringMs: Number.isFinite(Number(stats.iceGatheringMs)) ? Math.round(Number(stats.iceGatheringMs)) : null,
            packetsLost: Number.isFinite(Number(stats.packetsLost)) ? Number(stats.packetsLost) : null,
            jitterMs: Number.isFinite(Number(stats.jitterMs)) ? Math.round(Number(stats.jitterMs)) : null,
            bytesReceived: Number.isFinite(Number(stats.bytesReceived)) ? Number(stats.bytesReceived) : null,
            connectionState: stats.connectionState || null,
            iceConnectionState: stats.iceConnectionState || null,
            collectedAt: stats.collectedAt ? new Date(stats.collectedAt) : new Date()
        };

        const updated = await Session.findOneAndUpdate(
            { sessionId },
            { $set: { [`webrtcStats.${roleKey}`]: sanitized } },
            { new: true }
        ).select('sessionId webrtcStats turnStats ipaddr ipapi createdAt');

        if (!updated) {
            return res.status(404).json({ error: 'Session not found' });
        }

        let turnStats = updated.turnStats || null;
        if (updated.webrtcStats?.mobile || updated.webrtcStats?.operator) {
            turnStats = await ensureTurnStatsForSession(updated) || turnStats;
        }

        console.log(`📶 WebRTC stats saved for ${sessionId} (${roleKey}): rtt=${sanitized.rttMs}ms relay=${sanitized.relayUsed} localIp=${sanitized.localIp || 'n/a'} turn=${turnStats?.allocations?.length || 0}`);
        res.json({ success: true, sessionId, role: roleKey, webrtcStats: updated.webrtcStats, turnStats });
    } catch (error) {
        console.error('WebRTC stats error:', error);
        res.status(500).json({ error: 'Failed to save WebRTC stats' });
    }
});

app.post('/api/session/:sessionId/close', authenticateToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        
        if (!sessionId) {
            return res.status(400).json({ error: 'Session ID is required' });
        }

        // Find the session
        const session = await Session.findOne({ sessionId });
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        // Update session status to closed (but preserve all existing data including ipapi)
        const updatedSession = await Session.findOneAndUpdate(
            { sessionId },
            { 
                status: 'closed',
                closedAt: new Date(),
                updatedAt: new Date()
            },
            { new: true }
        );

        console.log(`✅ Session ${sessionId} closed successfully`);

        res.json({
            success: true,
            sessionId: updatedSession.sessionId,
            status: updatedSession.status,
            closedAt: updatedSession.closedAt,
            message: 'Session closed successfully'
        });

    } catch (error) {
        console.error('Session close error:', error);
        res.status(500).json({ error: 'Failed to close session' });
    }
});

app.post('/api/helpdesk/session/:sessionId/result', authenticateToken, requireFeature('helpdesk'), async (req, res) => {
    try {
        const { sessionId } = req.params;
        const result = String(req.body?.result || '').toLowerCase();
        if (!['pass', 'fail'].includes(result)) {
            return res.status(400).json({ error: 'result must be pass or fail' });
        }

        const [user, session] = await Promise.all([
            User.findOne({ firebaseUid: req.user.uid }),
            Session.findOne({ sessionId })
        ]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const integratorUser = await resolveIntegratorUser(user);
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }

        let candidate = null;
        if (session.candidateId) {
            candidate = await Candidate.findById(session.candidateId);
        }
        const ownsSession = session.sessionId?.startsWith(`${req.user.uid}_`)
            || session.uuid === req.user.uid
            || (candidate?.interviewer && candidate.interviewer.toString() === user._id.toString())
            || (candidate?.interviewers && candidate.interviewers.toLowerCase().includes(user.email.toLowerCase()));
        if (!ownsSession) {
            return res.status(403).json({ error: 'Access denied to this session' });
        }

        const operatorFields = resolveHelpdeskOperatorFields(req);
        if (operatorFields.operatorEmail) {
            session.operatorEmail = operatorFields.operatorEmail;
            if (operatorFields.operatorName) {
                session.operatorName = operatorFields.operatorName;
            }
        }

        session.helpdeskResult = result;
        session.helpdeskResultAt = new Date();
        await session.save();

        // If this is an interview, also update the candidate's status
        if (session.source === 'interview' && candidate) {
            try {
                candidate.status = result === 'pass' ? 'approved' : 'rejected';
                await candidate.save();
            } catch (_) {}
        }

        const checkingInUser = await resolveCheckingInUserForVerification(session, candidate);
        const pinRequirement = await getSessionPinRequirement(session, candidate, checkingInUser);
        const verificationFields = await buildSessionVerificationFields(session, pinRequirement, checkingInUser, candidate);
        const identityRisk = await computeIdentityRisk({
            session,
            candidate,
            verificationFields,
            checkingInUser
        });
        const latestScreenshot = (session.screenshots || [])
            .slice()
            .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))[0];
        const proofShortcode = latestScreenshot?.shortname || session.shortname || null;
        const proofUrl = proofShortcode ? `https://in.xchk.io/v.html?c=${encodeURIComponent(proofShortcode)}` : null;
        const networkIpapi = session.ipapi || null;
        const networkFlags = networkIpapi ? {
            vpn: !!networkIpapi.is_vpn,
            proxy: !!networkIpapi.is_proxy,
            datacenter: !!networkIpapi.is_datacenter,
            tor: !!networkIpapi.is_tor,
            mobile: !!networkIpapi.is_mobile,
            satellite: !!networkIpapi.is_satellite,
            crawler: !!networkIpapi.is_crawler,
            bogon: !!networkIpapi.is_bogon,
            abuser: !!networkIpapi.is_abuser
        } : null;

        const subject = {
            email: verificationFields.verifiedEmail || session.email || candidate?.email || null,
            mobile: session.mobile || candidate?.mobile || null,
            name: candidate?.name || checkingInUser?.displayName || null
        };
        const { ticketId: zendeskTicketId, subdomain: zendeskSubdomain, requesterId: zendeskRequesterId } = resolveZendeskTicketContext(req.body, session);
        if (zendeskTicketId && session.external?.ticketId !== zendeskTicketId) {
            session.external = {
                system: 'zendesk',
                ticketId: zendeskTicketId,
                subdomain: zendeskSubdomain,
                requesterId: zendeskRequesterId || undefined
            };
            if (session.source === 'helpdesk') session.source = 'zendesk';
            await session.save();
        }

        const resultLabel = result.toUpperCase();
        const operatorLabel = resolveHelpdeskOperatorLabel(req, user, session);
        recordAuditEventAsync({
            action: 'VERIFICATION_COMPLETED',
            actor: actorFromUser(req.user),
            target: {
                type: 'verification',
                email: subject.email ? String(subject.email).toLowerCase() : null,
                label: subject.name || subject.email || session.sessionId
            },
            metadata: {
                result,
                sessionId: session.sessionId,
                subjectName: subject.name || null,
                subjectMobile: subject.mobile || null,
                source: session.source || null,
                operatorLabel,
                zendeskTicketId: zendeskTicketId || null
            }
        });
        const zendeskTicketUrl = (zendeskTicketId && zendeskSubdomain)
            ? `https://${zendeskSubdomain}.zendesk.com/agent/tickets/${encodeURIComponent(zendeskTicketId)}`
            : null;
        const resultColor = result === 'pass' ? '#2e7d32' : '#c62828';
        const resultEmoji = result === 'pass' ? '✅' : '❌';
        const commentBody = [
            `XCHK verification ${resultLabel}`,
            zendeskTicketId ? `Zendesk ticket: #${zendeskTicketId}` : null,
            operatorLabel ? `Operator: ${operatorLabel}` : null,
            subject.mobile ? `Mobile: ${subject.mobile}` : null,
            proofUrl ? `Proof: ${proofUrl}` : 'Proof: not available yet',
            `Session: ${session.sessionId}`,
            `Liveness: ${session.liveness ?? 0}`,
            verificationFields.requiresPin
                ? `PIN: ${verificationFields.pinVerified === true ? 'passed' : (verificationFields.pinSubmitted ? 'failed' : 'pending')}`
                : 'PIN: not required'
        ].filter(Boolean).join('\n');
        const commentHtmlBody = [
            `<p><strong>${resultEmoji} XCHK verification <span style="color:${resultColor}">${resultLabel}</span></strong></p>`,
            zendeskTicketId ? `<p>Zendesk ticket: #${zendeskTicketId}</p>` : null,
            operatorLabel ? `<p>Operator: ${operatorLabel}</p>` : null,
            subject.mobile ? `<p>Mobile: ${subject.mobile}</p>` : null,
            proofUrl ? `<p>Proof: <a href="${proofUrl}">${proofUrl}</a></p>` : '<p>Proof: not available yet</p>',
            `<p>Session: ${session.sessionId}</p>`,
            `<p>Liveness: ${session.liveness ?? 0}</p>`,
            verificationFields.requiresPin
                ? `<p>PIN: ${verificationFields.pinVerified === true ? 'passed' : (verificationFields.pinSubmitted ? 'failed' : 'pending')}</p>`
                : '<p>PIN: not required</p>'
        ].filter(Boolean).join('');

        const payload = {
            result,
            status: result,
            source: 'xchk_helpdesk',
            zendesk: {
                ticket_id: zendeskTicketId,
                subdomain: zendeskSubdomain,
                ticket_url: zendeskTicketUrl,
                tags: [`xchk_${result}`],
                comment: {
                    public: false,
                    body: commentBody
                },
                custom_fields: [
                    { id: 'xchk_result', value: result },
                    { id: 'xchk_proof_url', value: proofUrl },
                    { id: 'xchk_session_id', value: session.sessionId }
                ]
            },
            xchk: {
                result,
                proofUrl,
                sessionId: session.sessionId,
                candidateId: candidate?._id || null,
                external: zendeskTicketId
                    ? { system: 'zendesk', ticketId: zendeskTicketId, subdomain: zendeskSubdomain }
                    : null,
                subject,
                checks: {
                    email: {
                        status: verificationFields.emailConfirmed ? 'passed' : (verificationFields.verifiedEmail ? 'unverified' : 'unknown'),
                        value: verificationFields.verifiedEmail || subject.email,
                        registrationConfirmed: !!verificationFields.registrationConfirmed,
                        method: verificationFields.emailVerificationMethod || null
                    },
                    pin: {
                        required: verificationFields.requiresPin,
                        submitted: verificationFields.pinSubmitted,
                        verified: verificationFields.pinVerified
                    },
                    liveness: {
                        score: session.liveness ?? 0,
                        status: verificationFields.requiresPin && !verificationFields.pinSubmitted
                            ? 'not_applicable_until_pin'
                            : ((session.liveness || verificationFields.pinSubmitted) ? 'passed' : 'failed')
                    },
                    location: {
                        city: session.mapboxLocation?.city || session.iplocation?.city || networkIpapi?.location?.city || null,
                        gps: (() => {
                            const coords = getValidSessionGpsCoordinates(session);
                            if (!coords) return null;
                            return {
                                lat: coords[1],
                                lon: coords[0],
                                lastUpdated: session.mapboxLocation?.lastUpdated || session.location?.lastUpdated
                            };
                        })(),
                        network: session.iplocation || networkIpapi?.location || null
                    },
                    network: {
                        type: session.networkInfo?.type || null,
                        effectiveType: session.networkInfo?.effectiveType || null,
                        downlink: session.networkInfo?.downlink ?? null,
                        rtt: session.networkInfo?.rtt ?? null,
                        flags: networkFlags
                    },
                    identity: {
                        status: identityRisk.suspicious ? identityRisk.status : 'passed',
                        suspicious: identityRisk.suspicious,
                        reasons: identityRisk.reasons,
                        message: identityRisk.message,
                        otherEmailsOnPhone: identityRisk.otherEmailsOnPhone
                    }
                }
            }
        };

        let webhook = { dispatched: false, reason: 'no_integrator_user' };
        let zendeskSync = { dispatched: false, reason: 'no_integrator_user' };
        if (integratorUser) {
            try {
                webhook = await dispatchIntegratorWebhook(integratorUser, 'helpdesk.verification.result', payload);
            } catch (webhookError) {
                console.error('Helpdesk result webhook dispatch error:', webhookError);
                webhook = { dispatched: false, reason: webhookError.message || 'webhook_dispatch_failed' };
            }
            try {
                zendeskSync = await syncZendeskTicketResult({
                    user: integratorUser,
                    ticketId: zendeskTicketId,
                    subdomain: zendeskSubdomain,
                    result,
                    commentBody,
                    commentHtmlBody,
                    requesterId: zendeskRequesterId
                });
            } catch (zendeskError) {
                console.error('Helpdesk Zendesk sync error:', zendeskError);
                zendeskSync = { dispatched: false, reason: zendeskError.message || 'zendesk_sync_failed' };
            }
        }
        console.log(`📨 Helpdesk ${resultLabel} submitted for ${session.sessionId}:`, {
            webhook,
            zendeskSync,
            proofUrl,
            subject,
            zendeskTicketId: zendeskTicketId || null,
            zendeskTicketUrl
        });

        res.json({
            success: true,
            result,
            proofUrl,
            webhook,
            zendeskSync,
            payload
        });
    } catch (error) {
        console.error('Helpdesk result webhook error:', error);
        res.status(500).json({ error: error.message || 'Failed to send helpdesk result' });
    }
});

// Client logging endpoint for mobile.html messages
app.post('/api/clientLog', async (req, res) => {
    try {
        const { sessionId, message, role } = req.body;
        
        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        // Log the client message with timestamp, role, and prominent icon
        const timestamp = new Date().toISOString();
        const sessionInfo = sessionId ? `[Session: ${sessionId}]` : '[No Session]';
        const roleInfo = role ? `[${role}]` : '[Unknown Role]';
        console.log(`🌐 ${roleInfo} ${sessionInfo} ${message} (${timestamp})`);
        
        res.json({ success: true, logged: true });
    } catch (error) {
        console.error('Client logging error:', error);
        res.status(500).json({ error: 'Failed to log client message' });
    }
});

// Contact form submission endpoint
app.post('/api/contact', authLimiter, async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        
        // Validate required fields
        if (!name || !email || !subject || !message) {
            return res.status(400).json({ 
                error: 'All fields are required: name, email, subject, message' 
            });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                error: 'Invalid email format' 
            });
        }
        
        // Get client information
        const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
        const userAgent = req.headers['user-agent'];
        const referrer = req.headers.referer;
        
        // Create contact record
        const contact = await Contact.create({
            name: name.trim(),
            email: email.trim().toLowerCase(),
            subject: subject.trim(),
            message: message.trim(),
            ipAddress,
            userAgent,
            referrer
        });
        
        console.log(`📧 Contact form submitted: ${name} (${email}) - ${subject}`);
        
        // Send email notification to sean@maclawran.ca
        try {
            await sendContactFormNotification(contact);
            
            // Update contact record to mark email as sent
            await Contact.findByIdAndUpdate(contact._id, {
                emailSent: true,
                emailSentAt: new Date()
            });
            
            console.log(`✅ Contact form email sent to sean@maclawran.ca`);
        } catch (emailError) {
            console.error('❌ Failed to send contact form email:', emailError);
            // Don't fail the request if email fails, just log it
        }
        
        // Send welcome email to the person who submitted the form
        try {
            await sendContactFormWelcome(contact);
            console.log(`✅ Welcome email sent to ${contact.email}`);
        } catch (welcomeEmailError) {
            console.error('❌ Failed to send welcome email:', welcomeEmailError);
            // Don't fail the request if welcome email fails, just log it
        }
        
        res.json({ 
            success: true, 
            message: 'Contact form submitted successfully',
            contactId: contact._id
        });
        
    } catch (error) {
        console.error('❌ Contact form submission error:', error);
        res.status(500).json({ 
            error: 'Failed to submit contact form. Please try again.' 
        });
    }
});

// Get contact form submissions (admin endpoint)
app.get('/api/contact', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const skip = (page - 1) * limit;
        
        // Build query
        const query = {};
        if (status) {
            query.status = status;
        }
        
        // Get contacts with pagination
        const contacts = await Contact.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .select('-__v');
        
        // Get total count
        const total = await Contact.countDocuments(query);
        
        res.json({
            success: true,
            contacts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching contact submissions:', error);
        res.status(500).json({ 
            error: 'Failed to fetch contact submissions' 
        });
    }
});

// Update contact status (admin endpoint)
app.patch('/api/contact/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        if (!status || !['new', 'read', 'replied', 'archived'].includes(status)) {
            return res.status(400).json({ 
                error: 'Valid status is required: new, read, replied, or archived' 
            });
        }
        
        const contact = await Contact.findByIdAndUpdate(
            id,
            { status, updatedAt: new Date() },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({ 
                error: 'Contact submission not found' 
            });
        }
        
        console.log(`📝 Contact status updated: ${id} -> ${status}`);
        
        res.json({
            success: true,
            contact
        });
        
    } catch (error) {
        console.error('❌ Error updating contact status:', error);
        res.status(500).json({ 
            error: 'Failed to update contact status' 
        });
    }
});

// Transcript cleanup function - runs every 5 minutes
async function cleanupTranscripts() {
    try {
        const fs = require('fs').promises;
        const path = require('path');
        
        // List all .pcm and .mp3 files in /tmp
        const tmpDir = '/tmp';
        const files = await fs.readdir(tmpDir);
        const pcmFiles = files.filter(file => file.endsWith('.pcm'));
        const mp3Files = files.filter(file => file.endsWith('.mp3'));
        
        console.log(`🧹 Found ${pcmFiles.length} PCM files and ${mp3Files.length} MP3 files to check`);
        
        for (const pcmFile of pcmFiles) {
            try {
                const filePath = path.join(tmpDir, pcmFile);
                const stats = await fs.stat(filePath);
                const fileAge = Date.now() - stats.mtime.getTime();
                const fiveMinutes = 5 * 60 * 1000; // 5 minutes in milliseconds
                
                // Check if file is over 5 minutes old
                if (fileAge > fiveMinutes) {
                    const sessionId = pcmFile.replace('.pcm', '');
                    
                    // Check if sessionId exists in database
                    const session = await Session.findOne({ sessionId });
                    
                    if (session) {
                        console.log(`📤 Uploading transcript files for session: ${sessionId}`);
                        
                        // Upload all transcript files for this session
                        const transcriptFiles = [
                            { ext: '.txt', type: 'text/plain' },
                            { ext: '.json', type: 'application/json' },
                            { ext: '.pcm', type: 'audio/pcm' }
                        ];
                        
                        for (const fileType of transcriptFiles) {
                            const transcriptFile = path.join(tmpDir, `${sessionId}${fileType.ext}`);
                            
                            try {
                                // Check if file exists
                                await fs.access(transcriptFile);
                                
                                // Read file content
                                const fileContent = await fs.readFile(transcriptFile);
                                
                                // Upload to bunny.net/transcripts
                                const key = `transcripts/${sessionId}${fileType.ext}`;
                                const endpoint = 'https://s3.us-east-005.backblazeb2.com';
                                const url = `${endpoint}/${key}`;
                                
                                // Get signed URL for upload
                                const { signUrl } = require('./utils/token');
                                const uploadUrl = await signUrl(url, process.env.BUNNYKEY, 3600, null, false, null, null, null, 'putObject');
                                
                                // Upload file using signed URL
                                const uploadResponse = await fetch(uploadUrl, {
                                    method: 'PUT',
                                    body: fileContent,
                                    headers: {
                                        'Content-Type': fileType.type
                                    }
                                });
                                
                                if (uploadResponse.ok) {
                                    console.log(`✅ Uploaded ${fileType.ext} for session ${sessionId}`);
                                    
                                    // For PCM files, calculate audio duration and update session
                                    if (fileType.ext === '.pcm') {
                                        try {
                                            // Get audio duration using ffprobe with PCM format specification
                                            // PCM format: signed 16-bit little-endian, 16kHz, mono
                                            const { stdout } = await execAsync(`ffprobe -f s16le -ar 16000 -ac 1 -v quiet -show_entries format=duration -of csv=p=0 ${transcriptFile}`);
                                            const audioDurationSeconds = parseFloat(stdout.trim());
                                            const audioDurationMinutes = Math.round(audioDurationSeconds / 60);
                                            
                                            if (audioDurationMinutes > 0) {
                                                // Update session with audio-based duration if it's more accurate
                                                await Session.findOneAndUpdate(
                                                    { sessionId },
                                                    { sessionTime: audioDurationMinutes }
                                                );
                                                console.log(`🎵 Updated session ${sessionId} with audio duration: ${audioDurationMinutes} minutes`);
                                            }
                                        } catch (audioError) {
                                            console.error(`⚠️ Could not calculate audio duration for ${sessionId}:`, audioError.message);
                                        }
                                    }
                                    
                                    // Delete local file after successful upload
                                    await fs.unlink(transcriptFile);
                                    console.log(`🗑️ Deleted local ${fileType.ext} for session ${sessionId}`);
                                } else {
                                    console.error(`❌ Failed to upload ${fileType.ext} for session ${sessionId}: ${uploadResponse.status}`);
                                }
                                
                            } catch (fileError) {
                                // File doesn't exist or other error, skip
                                if (fileError.code !== 'ENOENT') {
                                    console.error(`⚠️ Error processing ${fileType.ext} for session ${sessionId}:`, fileError.message);
                                }
                            }
                        }
                        
                    } else {
                        console.log(`⚠️ Session ${sessionId} not found in database, skipping upload`);
                        
                        // Delete the PCM file even if session doesn't exist
                        const filePath = path.join(tmpDir, pcmFile);
                        await fs.unlink(filePath);
                        console.log(`🗑️ Deleted orphaned PCM file: ${pcmFile}`);
                    }
                }
            } catch (fileError) {
                console.error(`❌ Error processing PCM file ${pcmFile}:`, fileError.message);
            }
        }
        
        // Clean up old MP3 files (over 4 hours old)
        for (const mp3File of mp3Files) {
            try {
                const filePath = path.join(tmpDir, mp3File);
                const stats = await fs.stat(filePath);
                const fileAge = Date.now() - stats.mtime.getTime();
                const fourHours = 4 * 60 * 60 * 1000; // 4 hours in milliseconds
                
                // Check if file is over 4 hours old
                if (fileAge > fourHours) {
                    await fs.unlink(filePath);
                    console.log(`🗑️ Deleted old MP3 file: ${mp3File} (age: ${Math.round(fileAge / (60 * 60 * 1000))} hours)`);
                }
            } catch (fileError) {
                console.error(`❌ Error processing MP3 file ${mp3File}:`, fileError.message);
            }
        }
        
    } catch (error) {
        console.error('❌ Transcript cleanup error:', error);
    }
}

// Start server
app.listen(port, async () => {
  console.log(`Server is running on port ${port}`);

  try {
    const { assertSsoLaunchSecretConfigured } = require('./utils/ssoLaunchToken');
    assertSsoLaunchSecretConfigured();
  } catch (e) {
    console.error('❌ SSO launch secret misconfigured:', e.message);
    process.exit(1);
  }
  
  // Run transcript cleanup on startup
  console.log('🧹 Running initial transcript cleanup...');
  await cleanupTranscripts();
  
  // Start transcript cleanup interval (every 5 minutes)
  setInterval(cleanupTranscripts, 5 * 60 * 1000);

  

  // Start session cleanup interval (every 5 minutes)
  setInterval(async () => {
    try {
      const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
      const coll = mongoose.connection.db.collection("sessions");
      const expired = await coll.updateMany(
        { status: { $ne: 'closed' }, createdAt: { $lt: fiveMinAgo } },
        { $set: { status: 'closed', closedAt: new Date() } }
      );
      if (expired.modifiedCount > 0) {
        console.log(`Periodic cleanup: closed ${expired.modifiedCount} expired sessions`);
      }
    } catch(e) { console.error('Periodic session cleanup error:', e); }
  }, 5 * 60 * 1000);

  // Mark expired-pending attestations and auto-escalate timed-out levels (every 10 minutes)
  setInterval(async () => {
    try {
      const Attestation = require('./models/Attestation');
      const now = new Date();
      const expired = await Attestation.updateMany(
        { status: 'pending', expiresAt: { $lt: now } },
        { $set: { status: 'expired' } }
      );
      if (expired.modifiedCount > 0) {
        console.log(`Periodic cleanup: expired ${expired.modifiedCount} pending attestations`);
      }

      // Auto-escalate attestations that timed out at a level and have autoEscalate=true
      const stalled = await Attestation.find({
        status: { $in: ['pending', 'waiting'] },
        expiresAt: { $lt: now },
        'policyRules.0': { $exists: true },
      }).limit(20).lean();

      for (const att of stalled) {
        try {
          // This attestation expired — check if its current level has autoEscalate
          // and a next level available
          const { resolveRuleTarget } = require('./utils/approvalPolicyUtils');
          let currentLevelIdx = 0;
          let approvalsInLevel = 0;
          const approvalChain = att.approvalChain || [];

          for (let i = 0; i < (att.policyRules || []).length; i++) {
            const rule = att.policyRules[i];
            const approvedSoFar = approvalChain.filter(a => a.response === 'approved').length;
            if (approvalsInLevel + rule.n <= approvedSoFar) {
              approvalsInLevel += rule.n;
            } else {
              currentLevelIdx = i;
              break;
            }
          }

          const currentRule = att.policyRules[currentLevelIdx];
          if (currentRule && currentRule.autoEscalate !== false && currentLevelIdx + 1 < (att.policyRules || []).length) {
            const nextRule = att.policyRules[currentLevelIdx + 1];
            const available = await resolveRuleTarget(nextRule, null);
            if (available.length > 0) {
              // Pick preferred first, then first available
              let nextPerson = null;
              if (nextRule.preferred && nextRule.preferred.length > 0) {
                for (const pref of nextRule.preferred) {
                  const found = available.find(u => u.email.toLowerCase() === pref.toLowerCase());
                  if (found) { nextPerson = found; break; }
                }
              }
              if (!nextPerson) nextPerson = available[0];
              if (nextPerson) {
                await _createSiblingAttestation(att, nextPerson, null);
                console.log(`Auto-escalated attestation ${att._id} to next level: ${nextPerson.email}`);
              }
            }
          }
        } catch(e) {
          console.error(`Auto-escalation failed for ${att._id}:`, e.message);
        }
      }
    } catch(e) { console.error('Periodic attestation cleanup error:', e); }
  }, 10 * 60 * 1000);

  // Remove stale mobile check-in anon accounts (>90m, no open session)
  setInterval(() => {
    cleanupStaleAnonUsers().catch(e => console.error('Periodic anon user cleanup error:', e));
  }, 15 * 60 * 1000);

  // Verify email configuration on startup
  try {
    const emailConfigValid = await verifyEmailConfig();
    if (emailConfigValid) {
      console.log('✅ Email system configured successfully');
    } else {
      console.warn('⚠️ Email system not properly configured - interviewer invitations will not be sent');
    }

    // === Didit KYC Integration ===
    const crypto = require('crypto');
    const DIDIT_WORKFLOW_ID = 'f3e45146-6050-47d1-8dcd-a0252d8e1fc7';

    app.post('/api/didit/create-session', authenticateToken, async (req, res) => {
        try {
            const vendorData = req.user?.email || 'xchk-user';
            const apiKey = process.env.DIDIT_API_KEY;
            if (!apiKey) return res.status(500).json({ error: 'DIDIT_API_KEY not configured' });

            // Look up user name for expected_details sanity check
            const userRecord = await User.findOne({ email: vendorData }).select('displayName').lean();
            const expected = {};
            if (userRecord?.displayName) {
                const parts = userRecord.displayName.trim().split(/\s+/);
                expected.first_name = parts[0] || '';
                expected.last_name = parts.slice(1).join(' ') || '';
            }

            const diditRes = await fetch('https://verification.didit.me/v3/session/', {
                method: 'POST',
                headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    workflow_id: DIDIT_WORKFLOW_ID,
                    vendor_data: vendorData,
                    ...(expected.first_name ? { expected_details: expected } : {}),
                }),
            });
            if (!diditRes.ok) {
                const detail = await diditRes.text();
                return res.status(502).json({ error: 'session_create_failed', detail });
            }
            const session = await diditRes.json();
            return res.json({ url: session.url, session_id: session.session_id });
        } catch (e) {
            return res.status(500).json({ error: e.message });
        }
    });

    // Webhook receiver — verify X-Signature-V2 HMAC
    app.post('/api/didit/webhook', async (req, res) => {
        try {
            const sig = req.headers['x-signature-v2'] || '';
            const ts = Number(req.headers['x-timestamp']);
            const secret = process.env.DIDIT_WEBHOOK_SECRET;
            if (!secret) return res.status(500).send('not configured');
            if (!ts || Math.abs(Date.now() / 1000 - ts) > 300) return res.status(401).send('stale');

            function shortenFloats(v) {
                if (Array.isArray(v)) return v.map(shortenFloats);
                if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k,x]) => [k,shortenFloats(x)]));
                if (typeof v === 'number' && !Number.isInteger(v) && v % 1 === 0) return Math.trunc(v);
                return v;
            }
            function sortKeys(v) {
                if (Array.isArray(v)) return v.map(sortKeys);
                if (v && typeof v === 'object') return Object.keys(v).sort().reduce((acc,k) => { acc[k]=sortKeys(v[k]); return acc; }, {});
                return v;
            }
            const canonical = JSON.stringify(sortKeys(shortenFloats(req.body)));
            const expected = crypto.createHmac('sha256', secret).update(canonical, 'utf8').digest('hex');
            if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) {
                return res.status(401).send('bad sig');
            }

            const { event_id, status, vendor_data, decision } = req.body;
            console.log(`Didit webhook: ${status} for ${vendor_data} (${event_id})`);

            // Store in dedicated collection
            const DiditEvent = require('./models/DiditEvent');
            await DiditEvent.create({
                event_id, session_id: req.body.session_id,
                status, vendor_data, decision,
                receivedAt: new Date(),
            });

            // Update user record if Approved
            if (status === 'Approved' && vendor_data) {
                const idVerification = decision?.id_verifications?.[0] || {};
                const verifiedName = [idVerification.first_name, idVerification.last_name].filter(Boolean).join(' ') || null;
                const docType = idVerification.document_subtype || null;
                const docLabel = idVerification.document_type || null;
                
                // Capture the KYC PaymentIntent if one exists
                const user = await User.findOne({ email: vendor_data }).select('kycPaymentIntentId').lean();
                if (user?.kycPaymentIntentId) {
                    try {
                        await stripe.paymentIntents.capture(user.kycPaymentIntentId);
                        console.log('✅ Captured KYC PaymentIntent:', user.kycPaymentIntentId, 'for', vendor_data);
                    } catch (e) {
                        console.error('Failed to capture KYC PaymentIntent:', e.message);
                    }
                }
                
                await User.findOneAndUpdate(
                    { email: vendor_data },
                    {
                        diditVerified: true,
                        diditVerifiedAt: new Date(),
                        kycSessionId: req.body.session_id,
                        kycDocType: docType,
                        kycDocLabel: docLabel,
                        authLevel: 'didit',
                    },
                    { upsert: false }
                );
                // Always add KYC to candidate's verified verifications
                const userForName = await User.findOne({ email: vendor_data }).select('displayName').lean();
                const profileName = (userForName?.displayName || '').toLowerCase().replace(/[^a-z]/g, '');
                const diditName = (verifiedName || '').toLowerCase().replace(/[^a-z]/g, '');
                const namesMatch = profileName && diditName && (diditName.includes(profileName) || profileName.includes(diditName));
                await Candidate.findOneAndUpdate(
                    { email: vendor_data },
                    { $addToSet: { 'verified.verifications': namesMatch ? 'KYC: Verified by Didit' : 'KYC: Name mismatch — Didit' } },
                    { upsert: false }
                );
            } else if (vendor_data && status !== 'Expired') {
                // Didit failed or was cancelled — cancel the PaymentIntent
                const user = await User.findOne({ email: vendor_data }).select('kycPaymentIntentId').lean();
                if (user?.kycPaymentIntentId) {
                    try {
                        await stripe.paymentIntents.cancel(user.kycPaymentIntentId);
                        console.log('❌ Cancelled KYC PaymentIntent (Didit not approved):', user.kycPaymentIntentId, 'for', vendor_data);
                    } catch (e) {
                        console.error('Failed to cancel KYC PaymentIntent:', e.message);
                    }
                }
            }

            return res.send('ok');
        } catch (e) {
            return res.status(500).send(e.message);
        }
    });

    // Quick check: is the current user Didit-verified?
    app.get('/api/didit/my-status', authenticateToken, async (req, res) => {
        try {
            const email = req.user?.email;
            if (!email) return res.json({ diditVerified: false });
            const user = await User.findOne({ email }).select('diditVerified').lean();
            return res.json({ diditVerified: !!(user?.diditVerified) });
        } catch (e) { return res.json({ diditVerified: false }); }
    });

    // KYC session lookup — scoped to same company/owner hierarchy
    app.get('/api/kyc/session/:sessionId', authenticateToken, async (req, res) => {
        try {
            const { sessionId } = req.params;
            const target = await User.findOne({ kycSessionId: sessionId }).lean();
            if (!target) return res.status(404).json({ error: 'Session not found' });

            // Determine requester's effective company/ownership chain
            const reqEmail = req.user.email;
            const requester = await User.findOne({ email: reqEmail }).select('email company owner').lean();
            if (!requester) return res.status(403).json({ error: 'Requester not found' });

            // Same email — always allowed (user checking their own KYC)
            if (target.email === requester.email) return sendKycResponse(target);

            // Same company name — allowed (shared org visibility)
            if (target.company && requester.company
                && target.company.toLowerCase() === requester.company.toLowerCase()) {
                return sendKycResponse(target);
            }

            // Owner chain — parent account can see child's KYC, child can see parent's
            if (target.owner && requester._id && target.owner.toString() === requester._id.toString()
                || requester.owner && target._id && requester.owner.toString() === target._id.toString()) {
                return sendKycResponse(target);
            }

            // Check team membership — same team = allowed
            const Team = require('./models/Team');
            const inSameTeam = await Team.findOne({
                $or: [
                    { 'members.email': target.email, 'members.email': requester.email },
                    { owner: requester._id, 'members.email': target.email },
                    { owner: target._id, 'members.email': requester.email },
                ]
            }).lean();
            if (inSameTeam) return sendKycResponse(target);

            return res.status(403).json({ error: 'Not authorized — KYC session belongs to another organization' });
        } catch (e) { return res.status(500).json({ error: e.message }); }

        function sendKycResponse(u) {
            return res.json({
                ok: true,
                kycSessionId: u.kycSessionId,
                diditVerified: !!u.diditVerified,
                diditVerifiedAt: u.diditVerifiedAt,
                kycDocLabel: u.kycDocLabel,
                kycDocType: u.kycDocType,
                email: u.email,
                authLevel: u.authLevel,
            });
        }
    });
    // === End Didit ===

    // === Attestation API ===
    const Attestation = require('./models/Attestation');
    const {
        hashPinSessionToken,
        mintPinSessionToken,
        isPinLocked,
        isPinSessionValid,
        clearPinSession,
        MAX_PIN_FAILURES,
        LOCKOUT_MS
    } = require('./utils/attestationPinSession');

    function attestationPinSessionDenied(att, token, res) {
        if (isPinLocked(att)) {
            res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
            return true;
        }
        if (!isPinSessionValid(att, token)) {
            res.status(401).json({ error: 'PIN verification required' });
            return true;
        }
        return false;
    }

    // Cryptographic helpers for attestation integrity
    const ATTESTATION_SIGNING_KEY = crypto.createHash('sha256').update(process.env.ATTESTATION_SIGNING_SECRET || 'xchk-attestation-default-secret').digest('hex').slice(0, 32);

    function computeAttestationHash(att) {
        const canonical = JSON.stringify({
            id: String(att._id),
            targetEmail: att.targetEmail,
            prompt: att.prompt,
            type: att.type,
            response: att.response,
            status: att.status,
            photoUrls: att.photoUrls || [],
            deviceFingerprint: att.deviceFingerprint,
            clientGeo: att.clientGeo,
            networkInfo: att.networkInfo,
            browserInfo: att.browserInfo,
            deviceInfo: att.deviceInfo,
            createdAt: att.createdAt,
            respondedAt: att.respondedAt,
            expiresAt: att.expiresAt,
            authLevel: att.authLevel,
            kycSessionId: att.kycSessionId,
            previousHash: att.previousHash || null,
        });
        return crypto.createHash('sha256').update(canonical).digest('hex');
    }

    function signAttestationPayload(payload) {
        const hmac = crypto.createHmac('sha256', ATTESTATION_SIGNING_KEY);
        hmac.update(JSON.stringify(payload));
        return hmac.digest('hex');
    }

    // Ravencoin anchoring configuration
    const RVN_RPC_URL = process.env.RVN_RPC_URL || 'http://127.0.0.1:8766';
    const RVN_RPC_USER = process.env.RVN_RPC_USER || 'rvn';
    const RVN_RPC_PASS = process.env.RVN_RPC_PASS || '';

    // Ravencoin anchor queue — accumulates pending hashes and flushes periodically
    // Persisted in MongoDB via attestation.rvnQueuedAt (non-null = pending)
    let rvnBatchInterval = null;

    function queueRvnAnchor(sha256Hash, metadata = {}) {
        // Mark the attestation as queued in MongoDB
        Attestation.updateOne(
            { sha256: sha256Hash },
            { $set: { rvnQueuedAt: new Date() } }
        ).catch(() => {});
        console.log(`🕐 Queued RVN anchor: ${sha256Hash.slice(0, 8)}…`);
    }

    async function flushRvnAnchorQueue() {
        // Find all attestations that need anchoring (have sha256, no txid, queued or never attempted)
        const pending = await Attestation.find({
            sha256: { $ne: null },
            rvnTxId: null,
        }).select('sha256 _id prompt createdAt status type amount').sort({ createdAt: 1 }).lean().catch(() => []);
        if (pending.length === 0) return;
        console.log(`📦 Flushing ${pending.length} RVN anchors from DB...`);
        for (const att of pending) {
            try {
                const txid = await anchorToRavencoin(att.sha256, {
                    label: 'created',
                    prompt: (att.prompt || '').slice(0, 40),
                    attestationId: String(att._id),
                    status: att.status,
                    amount: att.amount || 0
                });
                if (txid) {
                    console.log(`✅ RVN anchored (batch): ${txid} for ${att.sha256.slice(0, 8)}…`);
                    await Attestation.updateOne(
                        { _id: att._id },
                        { $set: { rvnTxId: txid, rvnAnchoredAt: new Date() }, $unset: { rvnQueuedAt: '' } }
                    );
                } else {
                    // Mark as queued so we retry next batch
                    await Attestation.updateOne({ _id: att._id }, { $set: { rvnQueuedAt: new Date() } });
                }
            } catch (e) {
                console.error(`❌ RVN anchor failed (retry next batch): ${att.sha256.slice(0, 8)}…`, e.message);
                await Attestation.updateOne({ _id: att._id }, { $set: { rvnQueuedAt: new Date() } });
            }
        }
    }

    // Start periodic batch flush every 5 minutes (fallback for when node is unreachable)
    function startRvnBatchFlush() {
        if (rvnBatchInterval) return;
        rvnBatchInterval = setInterval(flushRvnAnchorQueue, 5 * 60 * 1000);
        console.log('⏰ RVN batch flush interval started (every 5 min)');
    }

    // Auto-cancel uncaptured KYC PaymentIntents older than 15 minutes
    async function cancelStaleKycPaymentIntents() {
        try {
            const stale = await User.find({
                kycPaymentIntentId: { $ne: null, $ne: '' }
            }).select('kycPaymentIntentId email').lean();
            for (const user of stale) {
                try {
                    const pi = await stripe.paymentIntents.retrieve(user.kycPaymentIntentId);
                    if (pi.status === 'requires_capture') {
                        const age = Date.now() - (pi.created * 1000);
                        if (age > 15 * 60 * 1000) {
                            await stripe.paymentIntents.cancel(user.kycPaymentIntentId);
                            console.log('⏰ Auto-cancelled stale KYC PaymentIntent:', user.kycPaymentIntentId, 'for', user.email);
                        }
                    } else if (pi.status !== 'processing' && pi.status !== 'succeeded') {
                        // Already cancelled, failed, or expired — clean up the reference
                    }
                    if (pi.status !== 'requires_capture') {
                        await User.updateOne(
                            { _id: user._id },
                            { $unset: { kycPaymentIntentId: '' } }
                        );
                    }
                } catch (e) {
                    console.error('Failed to check PaymentIntent:', user.kycPaymentIntentId, e.message);
                }
            }
        } catch (e) {
            console.error('KYC PaymentIntent sweep error:', e.message);
        }
    }
    setInterval(cancelStaleKycPaymentIntents, 15 * 60 * 1000);
    setTimeout(cancelStaleKycPaymentIntents, 60000); // first sweep after 1 minute

    // Also flush on server start after a short delay
    setTimeout(() => {
        startRvnBatchFlush();
        flushRvnAnchorQueue();
    }, 30000);

    async function anchorToRavencoin(sha256Hash, metadata = {}) {
        if (!RVN_RPC_PASS) {
            // Queue for later batch processing if no RPC configured
            queueRvnAnchor(sha256Hash, metadata);
            return null;
        }
        try {
            const { label, prompt, attestationId, status, amount } = metadata;

            // Build OP_RETURN: xCk magic + version + flags + attId prefix + sha256Hash + amount
            const prefix = Buffer.from('xCk', 'ascii'); // 3 bytes magic
            const versionBuf = Buffer.from([0x01]);     // 1 byte version
            let flags = 0;
            if (status === 'completed') flags |= 1;
            if (status === 'declined')  flags |= 2;
            if (amount && amount > 0)   flags |= 4;
            const flagsBuf = Buffer.from([flags]);       // 1 byte flags
            const idPrefix = attestationId
                ? Buffer.from(String(attestationId).slice(0, 4), 'ascii')
                : Buffer.from('????', 'ascii');           // 4 bytes att ID prefix
            const hashBytes = Buffer.from(sha256Hash, 'hex'); // 32 bytes
            const amountBytes = Buffer.alloc(8);
            if (amount && amount > 0) {
                // Write amount as big-endian uint64 (satoshis)
                let amtBig = BigInt(Math.round(amount * 1e8));
                for (let i = 7; i >= 0; i--) {
                    amountBytes[i] = Number(amtBig & BigInt(0xff));
                    amtBig >>= 8n;
                }
            }

            const opReturnData = Buffer.concat([prefix, versionBuf, flagsBuf, idPrefix, hashBytes, amountBytes]);
            const hexData = opReturnData.toString('hex');

            // Create raw transaction with OP_RETURN via RPC
            const rpcPayload = {
                jsonrpc: '1.0',
                id: 'xchk-attest-' + sha256Hash.slice(0, 8),
                method: 'createrawtransaction',
                params: [[], { data: hexData }]
            };
            const auth = Buffer.from(RVN_RPC_USER + ':' + RVN_RPC_PASS).toString('base64');
            const resp = await axios.post(RVN_RPC_URL, rpcPayload, {
                headers: { 'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json' },
                timeout: 10000
            });
            const txHex = resp.data.result;
            if (!txHex) return null;

            // Fund the transaction
            const fundResp = await axios.post(RVN_RPC_URL, {
                jsonrpc: '1.0', id: 'xchk-attest-fund-' + sha256Hash.slice(0, 8),
                method: 'fundrawtransaction',
                params: [txHex, { changePosition: 1, feeRate: 0.01 }]
            }, { headers: { 'Authorization': 'Basic ' + auth }, timeout: 10000 });
            const fundedHex = fundResp.data.result?.hex;
            if (!fundedHex) return null;

            // Sign
            const signResp = await axios.post(RVN_RPC_URL, {
                jsonrpc: '1.0', id: 'xchk-attest-sign-' + sha256Hash.slice(0, 8),
                method: 'signrawtransaction',
                params: [fundedHex]
            }, { headers: { 'Authorization': 'Basic ' + auth }, timeout: 10000 });
            const signedHex = signResp.data.result?.hex;
            if (!signedHex) return null;

            // Send
            const sendResp = await axios.post(RVN_RPC_URL, {
                jsonrpc: '1.0', id: 'xchk-attest-send-' + sha256Hash.slice(0, 8),
                method: 'sendrawtransaction',
                params: [signedHex]
            }, { headers: { 'Authorization': 'Basic ' + auth }, timeout: 10000 });

            return sendResp.data.result || null;
        } catch (e) {
            console.error('RVN anchoring failed:', e.message);
            // Queue for retry on transient failure
            queueRvnAnchor(sha256Hash, metadata);
            return null;
        }
    }

    // Upload attestation photo (Firebase token auth)
    app.post('/api/upload/attestation-photo', authenticateToken, upload.single('photo'), async (req, res) => {
        try {
            if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
            // Photos are stored temporarily and served via static /s/ path
            const url = `/s/${req.file.filename}`;
            return res.json({ ok: true, url });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Create an attestation request (API key or Firebase auth)
    app.post('/api/attestations', authenticateFirebaseOrApiKey, async (req, res) => {
        try {
            const { user, prompt, type, ttl, amount, currency, budget, parentId, idempotencyKey, validUntil, policyId, policyRules, escalationChain, policyName, levels } = req.body;
            if (!user || !prompt) return res.status(400).json({ error: 'user and prompt are required' });

            // Idempotency check — same key within expiry returns existing attestation
            if (idempotencyKey) {
                const existing = await Attestation.findOne({
                    idempotencyKey,
                    status: { $in: ['pending', 'completed'] },
                    targetEmail: user.toLowerCase().trim(),
                    createdAt: { $gt: new Date(Date.now() - 86400000) } // within 24h
                }).lean();
                if (existing) {
                    return res.status(200).json({
                        ok: true,
                        attestationId: String(existing._id),
                        status: existing.status,
                        type: existing.type,
                        sha256: existing.sha256,
                        previousHash: existing.previousHash,
                        signingKeyId: 'xchk-attestation-v1',
                        amount: existing.amount || null,
                        budget: existing.budget || null,
                        parentId: existing.parentId ? String(existing.parentId) : null,
                        duplicate: true
                    });
                }
            }

            // Verify the target user exists and is KYC'd
            const target = await User.findOne({ email: user.toLowerCase().trim() }).lean();
            if (!target) return res.status(404).json({ error: 'User not found' });

            const authLevel = target.authLevel || 'none';
            // Warn but allow if the user has no KYC — shown as red badge on attestation page
            const kycWarning = authLevel === 'none';

            const validTypes = ['t/f', 'text', 'photo', 'spending', 'standing_order'];
            let attType = validTypes.includes(type) ? type : 't/f';

            // Validate spending/standing order fields
            if (attType === 'spending' || attType === 'standing_order') {
                if (amount == null || amount <= 0) return res.status(400).json({ error: 'amount required for spending' });
                if (attType === 'standing_order') {
                    if (budget == null || budget <= 0) return res.status(400).json({ error: 'budget required for standing orders' });
                }
                if (attType === 'spending' && parentId) {
                    // Check parent standing order has budget remaining
                    const parent = await Attestation.findById(parentId).select('budget spent type status validUntil').lean();
                    if (!parent || parent.type !== 'standing_order') return res.status(400).json({ error: 'Invalid parent standing order' });
                    if (parent.status !== 'completed' || parent.response !== 'approved') return res.status(400).json({ error: 'Parent standing order not approved' });
                    if (parent.validUntil && new Date(parent.validUntil) < new Date()) return res.status(400).json({ error: 'Standing order has expired' });
                    const remaining = (parent.budget || 0) - (parent.spent || 0);
                    if (amount > remaining) return res.status(400).json({ error: 'Amount exceeds remaining budget of ' + remaining });
                }
            }

            const expiresIn = (typeof ttl === 'number' && ttl > 30 && ttl <= 86400) ? ttl : 600;

            // Build policy rules: either from a stored policy, inline rules, levels, or backward-compat escalationChain
            let resolvedPolicyRules = policyRules || [];
            let resolvedPolicyId = policyId || null;

            if (policyId && !policyRules) {
                // Load from stored policy by ID
                try {
                    const ApprovalPolicy = require('./models/ApprovalPolicy');
                    const storedPolicy = await ApprovalPolicy.findById(policyId).lean();
                    if (storedPolicy && storedPolicy.rules) {
                        resolvedPolicyRules = storedPolicy.rules;
                        resolvedPolicyId = storedPolicy._id;
                    }
                } catch (_) {}
            } else if (policyName && !policyRules) {
                // Load from stored policy by name
                try {
                    const ApprovalPolicy = require('./models/ApprovalPolicy');
                    const storedPolicy = await ApprovalPolicy.findOne({ name: policyName, active: true }).lean();
                    if (storedPolicy && storedPolicy.rules) {
                        resolvedPolicyRules = storedPolicy.rules;
                        resolvedPolicyId = storedPolicy._id;
                    }
                } catch (_) {}
            }

            // If levels format is provided, expand it into policyRules (overrides other formats)
            // e.g. [{ role: "manager", n: 2, preferred: ["sean@co.com"], autoEscalate: true }, { role: "vp", n: 1 }]
            // Each level is sequential — level N only fires after level N-1 is satisfied.
            // autoEscalate: if the level's N approvals can't be obtained within the TTL, move to next level.
            if (levels && Array.isArray(levels) && levels.length > 0) {
                const expandedRules = [];
                for (const level of levels) {
                    if (!level.role && !level.members) continue;
                    const n = level.n || 1;
                    if (n === 0) continue; // skip disabled levels
                    expandedRules.push({
                        label: level.label || level.role || 'unnamed',
                        n: n,
                        role: level.role || null,
                        members: level.members || [],
                        preferred: level.preferred || [],
                        autoEscalate: level.autoEscalate !== false, // default true
                        escalationChain: level.escalationChain || [],
                    });
                }
                if (expandedRules.length > 0) {
                    resolvedPolicyRules = expandedRules;
                }
            }

            // Backward compat: if escalationChain is provided without policy, convert to a single rule
            if (!resolvedPolicyRules || resolvedPolicyRules.length === 0) {
                if (escalationChain && escalationChain.length > 1) {
                    // Find this target's position in the chain
                    const targetIdx = escalationChain.indexOf(target.email);
                    if (targetIdx >= 0) {
                        resolvedPolicyRules = [{
                            label: 'approval chain',
                            n: 1,
                            members: [target.email],
                            escalationChain: escalationChain.slice(targetIdx),
                        }];
                    } else {
                        // Target not in chain — use entire chain as rule members
                        resolvedPolicyRules = [{
                            label: 'approval chain',
                            n: 1,
                            members: escalationChain,
                            escalationChain,
                        }];
                    }
                } else if (escalationChain && escalationChain.length === 1) {
                    resolvedPolicyRules = [{
                        label: 'single approver',
                        n: 1,
                        members: escalationChain,
                        escalationChain: escalationChain,
                    }];
                } else {
                    // Default: single rule for the target
                    resolvedPolicyRules = [{
                        label: 'default',
                        n: 1,
                        members: [target.email],
                        escalationChain: [target.email],
                    }];
                }
            }

            // Calculate required approvals from policy rules
            let calculatedApprovals = 0;
            for (const rule of resolvedPolicyRules) {
                calculatedApprovals += rule.n || 1;
            }

            const att = await Attestation.create({
                targetEmail: target.email,
                targetName: target.displayName || target.email,
                prompt,
                type: attType,
                status: 'pending',
                expiresAt: new Date(Date.now() + expiresIn * 1000),
                requestedBy: null,
                requesterEmail: req.user?.email || null,
                requesterName: req.user?.name || null,
                kycSessionId: target.kycSessionId,
                authLevel,
                kycWarning: authLevel === 'none',
                webhookUrl: null,
                amount: (attType === 'spending' || attType === 'standing_order') ? amount : null,
                currency: currency || 'USD',
                budget: attType === 'standing_order' ? budget : null,
                parentId: (attType === 'spending' && parentId) ? parentId : null,
                idempotencyKey: idempotencyKey || null,
                validUntil: attType === 'standing_order' ? (validUntil ? new Date(validUntil) : new Date(Date.now() + 365 * 86400000)) : null,
                // Policy routing
                policyId: resolvedPolicyId,
                policyRules: resolvedPolicyRules,
                requiredApprovals: calculatedApprovals,
            });

            // Compute cryptographic hash chained to previous attestation for this user
            try {
                const prevAtt = await Attestation.findOne({ targetEmail: target.email.toLowerCase(), _id: { $ne: att._id }, sha256: { $ne: null } })
                    .sort({ createdAt: -1 }).select('sha256 _id').lean();
                att.previousHash = prevAtt?.sha256 || null;
                att.previousAttestationId = prevAtt?._id || null;
                att.sha256 = computeAttestationHash(att.toObject ? att.toObject() : att);
                await att.save();
            } catch (e) {
                console.error('Attestation hash computation failed:', e.message);
            }

            // Anchor to Ravencoin (async, non-blocking)
            anchorToRavencoin(att.sha256, {
                label: 'created',
                prompt: att.prompt.slice(0, 40),
                attestationId: String(att._id),
                status: att.status,
                amount: att.amount || 0
            }).then(txid => {
                if (txid) {
                    console.log('✅ RVN anchored (create):', txid, 'for', att._id);
                    Attestation.updateOne({ _id: att._id }, { $set: { rvnTxId: txid, rvnAnchoredAt: new Date() } }).catch(() => {});
                } else {
                    // Mark as queued for batch retry
                    queueRvnAnchor(att.sha256);
                }
            }).catch(() => { queueRvnAnchor(att.sha256); });

            // Create a session so mobile.js handles PIN, camera, liveness etc.
            const { generateSessionId } = require('./utils/sessionUtils');
            const sessionId = generateSessionId(target.firebaseUid || 'attestation');
            const shortname = (target.displayName || target.email).replace(/[^a-zA-Z0-9]/g, '').slice(0, 20) || 'attest';
            const Session = require('./models/Session');

            // Minimal session for the attestation flow
            const session = await Session.create({
                sessionId,
                uuid: target.firebaseUid || 'anon',
                email: target.email,
                mobile: target.mobile || null,
                source: 'attestation',
                attestationId: att._id,
                date: new Date(),
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + expiresIn * 1000),
                checksumOK: false,
                screenshots: [],
                operatorEmail: req.user.email,
                operatorName: req.user.name,
            });
            await User.findOneAndUpdate({ email: target.email }, { sessionId });

            // Log for debugging
            console.log('✅ Created attestation session:', { sessionId, attestationId: String(att._id), target: target.email });

            // Fire push notification to the target user
            const notifData = {
                type: 'attestation',
                attestationId: String(att._id),
                url: `https://in.xchk.io/attest-reply.html?a=${att._id}`
            };
            try { await sendPushNotification(target.firebaseUid, 'xchk Attestation', prompt, notifData); } catch (_) {}

            // Audit log
            try {
                const { recordAuditEventAsync } = require('./services/auditLogService');
                recordAuditEventAsync({
                    action: 'ATTESTATION_CREATED',
                    actor: { email: req.user.email, uid: req.user?.uid },
                    target: { type: 'attestation', email: target.email, mongoId: String(att._id), label: prompt.slice(0, 80) },
                    metadata: { type: attType }
                }).catch(e => console.error('Audit log failed:', e.message));
            } catch (_) {}

            // Also send SMS if user has a mobile number
            if (target.mobile) {
                try {
                    const { sendMessage } = require('./utils/messagingUtils');
                    const attUrl = `https://in.xchk.io/attest-reply.html?a=${att._id}`;
                    const result = await sendMessage(target.mobile, `Attestation request: ${attUrl}`);
                    console.log('Attestation SMS sent to', target.mobile, result);
                } catch (smsErr) {
                    console.error('Attestation SMS failed:', smsErr.message);
                }
            }

            // If this is a multi-level attestation, also notify the next person in the pool
            // (preferred + 1 for sequential SMS approach)
            if (resolvedPolicyRules && resolvedPolicyRules.length > 0 && resolvedPolicyRules[0].n > 1) {
                // Create a minimal approval entry to track the first notification
                const notifEntry = { approverEmail: target.email, response: 'notified', respondedAt: new Date() };
                _notifyNextApprover(att, notifEntry).catch(e => console.error('Initial pool expansion failed:', e.message));
            }

            return res.status(201).json({
                ok: true,
                attestationId: String(att._id),
                status: 'pending',
                type: attType,
                expiresAt: att.expiresAt,
                sha256: att.sha256,
                previousHash: att.previousHash,
                signingKeyId: 'xchk-attestation-v1',
                amount: att.amount || null,
                budget: att.budget || null,
                parentId: att.parentId ? String(att.parentId) : null,
            });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // List attestations (API key or Firebase auth)
    app.get('/api/attestations', authenticateFirebaseOrApiKey, async (req, res) => {
        try {
            const filter = {};
            // Firebase auth — scope to user's email as requester or target
            if (req.user?.email) {
                filter.$or = [
                    { requesterEmail: req.user.email },
                    { targetEmail: req.user.email }
                ];
            }
            const attestations = await Attestation.find(filter)
                .sort({ createdAt: -1 }).limit(50).lean();
            return res.json({ ok: true, attestations });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Verify attestation PIN — returns a short-lived session token for respond/sign-photos
    app.post('/api/attestations/:id/verify-pin', authLimiter, async (req, res) => {
        try {
            const att = await Attestation.findById(req.params.id);
            if (!att) return res.status(404).json({ error: 'Attestation not found' });
            if (att.status !== 'pending') return res.status(400).json({ error: 'Already ' + att.status });
            if (att.expiresAt && new Date(att.expiresAt) < new Date()) {
                att.status = 'expired'; await att.save();
                return res.status(400).json({ error: 'Expired' });
            }
            if (isPinLocked(att)) {
                return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
            }
            const { pin } = req.body;
            if (!pin) return res.status(400).json({ error: 'PIN required' });
            const preReg = await mongoose.connection.db.collection('preregistrations').findOne({ email: att.targetEmail.toLowerCase() });
            if (!preReg || !preReg.hashedPin) return res.status(403).json({ error: 'No PIN set' });
            const { verifyPin } = require('./utils/enrollmentUtils');
            const isValid = verifyPin(pin, preReg.hashedPin);
            if (!isValid) {
                att.pinVerifyFailures = (att.pinVerifyFailures || 0) + 1;
                if (att.pinVerifyFailures >= MAX_PIN_FAILURES) {
                    att.pinLockedUntil = new Date(Date.now() + LOCKOUT_MS);
                }
                await att.save();
                return res.status(403).json({ error: 'Wrong PIN' });
            }
            const pinSessionToken = mintPinSessionToken();
            att.pinVerifyFailures = 0;
            att.pinLockedUntil = null;
            att.pinVerifiedAt = new Date();
            att.pinSessionTokenHash = hashPinSessionToken(pinSessionToken);
            await att.save();
            return res.json({
                ok: true,
                pinSessionToken,
                attestation: {
                    prompt: att.prompt,
                    type: att.type,
                    amount: att.amount,
                    budget: att.budget,
                    expiresAt: att.expiresAt,
                    validUntil: att.validUntil,
                    requesterEmail: att.requesterEmail,
                    requesterName: att.requesterName,
                    sha256: att.sha256,
                    rvnTxId: att.rvnTxId,
                    rvnQueuedAt: att.rvnQueuedAt
                }
            });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Sign photo uploads for attestation evidence (requires PIN session)
    app.post('/api/attestations/:id/sign-photos', async (req, res) => {
        try {
            const att = await Attestation.findById(req.params.id);
            if (!att) return res.status(404).json({ error: 'Not found' });
            if (att.status !== 'pending') return res.status(400).json({ error: 'Already ' + att.status });
            if (attestationPinSessionDenied(att, req.body.pinSessionToken, res)) return;

            const { signBaselinePhotoUploads } = require('./utils/enrollmentUtils');
            const allUploads = await signBaselinePhotoUploads('att_' + req.params.id);
            if (!allUploads || !allUploads.length) return res.status(500).json({ error: 'Failed to sign upload' });
            const uploads = [allUploads[0]];
            return res.json({ success: true, uploads, photoCount: 1 });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Helper: dispatch attestation webhook
    async function _dispatchAttestationWebhook(att) {
        if (!att.webhookUrl) return;
        try {
            const body = {
                event: att.status === 'declined' ? 'attestation.declined' : 'attestation.completed',
                attestation_id: String(att._id),
                target_email: att.targetEmail,
                target_name: att.targetName,
                prompt: att.prompt,
                type: att.type,
                response: att.response,
                photo_url: att.photoUrl,
                auth_level: att.authLevel,
                kyc_session_id: att.kycSessionId,
                expires_at: att.expiresAt,
                requester_email: att.requesterEmail,
                requester_name: att.requesterName,
                created_at: att.createdAt,
                responded_at: att.respondedAt,
                status: att.status,
            };
            const payload = JSON.stringify(body);
            const headers = { 'Content-Type': 'application/json', 'User-Agent': 'xchk-webhook/1.0' };
            const apiKeyDoc = await require('./models/ApiKey').findById(att.requestedBy).lean();
            if (apiKeyDoc?.webhookSecret) {
                const sig = crypto.createHmac('sha256', apiKeyDoc.webhookSecret).update(payload).digest('hex');
                headers['X-XCHK-Signature'] = `sha256=${sig}`;
            }
            const resp = await axios.post(att.webhookUrl, body, { headers, timeout: 15000, validateStatus: () => true });
            att.webhookSentAt = new Date();
            att.webhookStatus = (resp.status >= 200 && resp.status < 300) ? 'sent' : 'failed';
            att.webhookAttempts = (att.webhookAttempts || 0) + 1;
            await att.save();
        } catch (whErr) {
            att.webhookStatus = 'failed';
            att.webhookAttempts = (att.webhookAttempts || 0) + 1;
            await att.save().catch(() => {});
        }
    }

    // Helper: find the next eligible approver from the current level's pool
    // and create a sibling attestation for them. Uses sequential notification per level.
    async function _notifyNextApprover(att, approvalEntry) {
        if (!att.policyRules || att.policyRules.length === 0) return null;
        try {
            const { resolveRuleTarget, findAvailableApprovers, findNextEscalation } = require('./utils/approvalPolicyUtils');

            // Count how many approved in the current chain
            const totalApprovals = att.approvalChain.filter(a => a.response === 'approved').length;

            // If all required approvals are met, no need to notify next
            if (totalApprovals >= att.requiredApprovals) return null;

            // Find which rule/level we're in — the first rule whose N isn't fully satisfied
            let currentRuleIdx = 0;
            let approvalsInCurrentLevel = 0;
            for (let i = 0; i < att.policyRules.length; i++) {
                const rule = att.policyRules[i];
                const approvedForRule = att.approvalChain.filter(a => a.response === 'approved').length;
                if (approvalsInCurrentLevel + rule.n <= approvedForRule) {
                    approvalsInCurrentLevel += rule.n;
                } else {
                    currentRuleIdx = i;
                    approvalsInCurrentLevel = approvedForRule - approvalsInCurrentLevel;
                    break;
                }
            }

            const currentRule = att.policyRules[currentRuleIdx];
            if (!currentRule) return null;

            // Check if we need more approvals in the current level
            const approvedInThisLevel = att.approvalChain.filter(a =>
                a.response === 'approved' || a.response === 'wrong'
            ).length - approvalsInCurrentLevel;

            const neededForThisLevel = currentRule.n - approvedInThisLevel;

            if (neededForThisLevel > 0) {
                // Need more people from current level — find available approvers
                const available = await findAvailableApprovers(currentRule, att.approvalChain);

                // Filter to people who haven't been notified yet
                const notifiedEmails = new Set();
                const siblings = await require('./models/Attestation').find({
                    parentAttestationId: att._id || att.parentAttestationId || att._id,
                }).select('targetEmail').lean().catch(() => []);
                for (const sib of siblings) notifiedEmails.add(sib.targetEmail?.toLowerCase());

                const notYetNotified = available.filter(u => !notifiedEmails.has(u.email.toLowerCase()));

                // Pick the next person: preferred first, then rotate
                let nextPerson = null;
                if (currentRule.preferred && currentRule.preferred.length > 0) {
                    // Find preferred that hasn't been notified
                    for (const pref of currentRule.preferred) {
                        if (!notifiedEmails.has(pref.toLowerCase()) && available.some(u => u.email.toLowerCase() === pref.toLowerCase())) {
                            nextPerson = available.find(u => u.email.toLowerCase() === pref.toLowerCase());
                            break;
                        }
                    }
                }
                if (!nextPerson && notYetNotified.length > 0) {
                    nextPerson = notYetNotified[0];
                }

                if (nextPerson) {
                    return await _createSiblingAttestation(att, nextPerson, approvalEntry);
                }
            } else {
                // Current level satisfied — move to next level
                if (currentRuleIdx + 1 < att.policyRules.length) {
                    const nextRule = att.policyRules[currentRuleIdx + 1];
                    const available = await resolveRuleTarget(nextRule, null);
                    if (available.length > 0) {
                        // Pick preferred first, then first available
                        let nextPerson = null;
                        if (nextRule.preferred && nextRule.preferred.length > 0) {
                            for (const pref of nextRule.preferred) {
                                const found = available.find(u => u.email.toLowerCase() === pref.toLowerCase());
                                if (found) { nextPerson = found; break; }
                            }
                        }
                        if (!nextPerson) nextPerson = available[0];
                        if (nextPerson) {
                            return await _createSiblingAttestation(att, nextPerson, null);
                        }
                    }
                }
            }
        } catch (e) {
            console.error('Failed to notify next approver:', e.message);
        }
        return null;
    }

    // Helper: create a sibling attestation for a new approver
    async function _createSiblingAttestation(parentAtt, targetUser, approvalEntry) {
        const Attestation = require('./models/Attestation');
        const Session = require('./models/Session');

        const childAtt = await Attestation.create({
            targetEmail: targetUser.email,
            targetName: targetUser.displayName || targetUser.email,
            prompt: parentAtt.prompt,
            type: parentAtt.type,
            status: 'pending',
            expiresAt: parentAtt.expiresAt,
            parentAttestationId: parentAtt._id || parentAtt.parentAttestationId,
            requestedBy: parentAtt.requestedBy,
            requesterEmail: parentAtt.requesterEmail,
            requesterName: parentAtt.requesterName,
            kycSessionId: targetUser.kycSessionId,
            authLevel: targetUser.authLevel || 'none',
            requiredApprovals: parentAtt.requiredApprovals,
            policyId: parentAtt.policyId,
            policyRules: parentAtt.policyRules,
            approvalChain: parentAtt.approvalChain || [],
            amount: parentAtt.amount,
            currency: parentAtt.currency,
            budget: parentAtt.budget,
            webhookUrl: parentAtt.webhookUrl,
        });

        // Create session for the child
        const { generateSessionId } = require('./utils/sessionUtils');
        const childSessionId = generateSessionId(targetUser.firebaseUid || 'attestation');
        await Session.create({
            sessionId: childSessionId,
            uuid: targetUser.firebaseUid || 'anon',
            email: targetUser.email,
            source: 'attestation',
            attestationId: childAtt._id,
            date: new Date(),
            createdAt: new Date(),
            expiresAt: parentAtt.expiresAt,
            checksumOK: false,
            screenshots: [],
        });

        // Send notification (SMS primary, Telegram secondary)
        try {
            const { sendMessage } = require('./utils/messagingUtils');
            const attUrl = `https://in.xchk.io/attest-reply.html?a=${childAtt._id}`;
            const msg = `xChk: ${parentAtt.requesterEmail || 'Someone'} needs your approval:\n${parentAtt.prompt.slice(0, 120)}\n${attUrl}`;
            if (targetUser.mobile) sendMessage(targetUser.mobile, msg, 'sms').catch(e => console.error('Sibling SMS failed:', e.message));
            if (targetUser.telegramChatId) {
                axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
                    chat_id: targetUser.telegramChatId,
                    text: msg,
                    parse_mode: 'HTML',
                    disable_web_page_preview: true,
                }, { timeout: 10000 }).catch(e => console.error('Sibling Telegram failed:', e.message));
            }
        } catch (_) {}

        console.log('✅ Created sibling attestation for', targetUser.email, ':', childAtt._id);
        return childAtt;
    }

    // Helper: send Telegram notification on attestation response
    async function _sendAttestationTelegram(att) {
        if (!process.env.TELEGRAM_BOT_TOKEN) return;
        try {
            const requesterUser = await User.findOne({ email: att.requesterEmail?.toLowerCase() }).select('telegramChatId').lean();
            const chatId = requesterUser?.telegramChatId || process.env.TELEGRAM_CHAT_ID;
            if (!chatId) return;

            let emoji = '\u274c';
            let label = 'Declined';
            if (att.response === 'approved') { emoji = '\u2705'; label = 'Approved'; }
            else if (att.response === 'wrong') { emoji = '\u26a0\ufe0f'; label = 'Flagged Wrong'; }
            else if (att.response === 'escalated') { emoji = '\u2b06\ufe0f'; label = 'Escalated'; }

            const typeLabel = att.type === 'spending' ? 'Spending' : att.type === 'standing_order' ? 'Standing Order' : 'Attestation';
            const amountStr = att.amount ? ` \u2014 $${att.amount.toFixed(2)}` : '';
            const caption = `${emoji} ${label}: ${att.prompt}\n  By: ${att.targetEmail}\n  Type: ${typeLabel}${amountStr}\n  Status: ${att.status}\n  See: https://in.xchk.io/history.html`;

            const photoUrl = att.photoUrl || (att.photoUrls && att.photoUrls[0]);
            if (photoUrl) {
                await axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendPhoto`, {
                    chat_id: chatId, photo: photoUrl, caption: caption,
                    parse_mode: 'HTML', disable_web_page_preview: true
                }, { timeout: 15000 });
            } else {
                await axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
                    chat_id: chatId, text: caption,
                    parse_mode: 'HTML', disable_web_page_preview: true
                }, { timeout: 10000 });
            }
        } catch (_) {}
    }

    // Respond to an attestation (requires PIN session)
    app.post('/api/attestations/:id/respond', async (req, res) => {
        try {
            const att = await Attestation.findById(req.params.id);
            if (!att) return res.status(404).json({ error: 'Attestation not found' });
            if (att.status !== 'pending') return res.status(400).json({ error: 'Attestation already ' + att.status });
            if (att.expiresAt && new Date(att.expiresAt) < new Date()) {
                att.status = 'expired'; await att.save();
                return res.status(400).json({ error: 'Attestation has expired' });
            }
            if (attestationPinSessionDenied(att, req.body.pinSessionToken, res)) return;

            // Self-approval check: you cannot approve your own attestation (governance)
            // BUT: site admins (superadmins) can approve their own agent's attestations
            if (att.targetEmail && att.targetEmail.toLowerCase() === att.requesterEmail?.toLowerCase() && att.policyRules?.length > 0) {
                // Allow if it's a simple self-attestation (no governance policy)
                const governed = att.policyRules.length > 1 || (att.requiredApprovals || 1) > 1 ||
                    att.policyRules[0].role || (att.policyRules[0].escalationChain?.length > 1);
                if (governed) {
                    // Check if requester is a site admin — they can self-approve
                    const requester = await User.findOne({ email: att.requesterEmail.toLowerCase() }).select('siteAdmin').lean();
                    if (!requester?.siteAdmin) {
                        return res.status(400).json({ error: 'Self-approval not allowed for governed attestations. You cannot approve your own request.' });
                    }
                }
            }

            const { response, photoUrl, photoUrls, deviceFingerprint, deviceInfo, browserInfo, networkInfo, clientGeo } = req.body;
            if (!response && att.type !== 'photo') return res.status(400).json({ error: 'response is required' });

            const validResponses = ['approved', 'declined', 'wrong', 'escalated'];
            if (!validResponses.includes(response)) return res.status(400).json({ error: 'Invalid response value' });

            // Store evidence
            const photos = photoUrls || (photoUrl ? [photoUrl] : []);
            att.response = response || null;
            att.photoUrl = (photos.length ? photos[0] : photoUrl) || null;
            if (photos.length > 0) att.photoUrls = photos;
            att.deviceFingerprint = deviceFingerprint || null;
            att.deviceInfo = deviceInfo || null;
            att.browserInfo = browserInfo || null;
            att.networkInfo = networkInfo || null;
            att.clientGeo = clientGeo || null;
            att.respondedAt = new Date();

            // Record this approver's decision in the approval chain
            const approverEntry = {
                approverEmail: att.targetEmail,
                approverName: att.targetName,
                response: response,
                respondedAt: new Date(),
            };

            if (response === 'escalated') {
                // ESCALATED — route using policy rules to find next approver
                att.approvalChain.push(approverEntry);
                att.status = 'escalated';
                att.escalatedBy = att.targetEmail;
                att.escalatedAt = new Date();

                // Use policy-based routing to find the next approver
                const { findNextEscalation } = require('./utils/approvalPolicyUtils');
                const nextApproverEmail = await findNextEscalation(
                    att.policyRules || [],
                    att.targetEmail,
                    att.approvalChain
                );

                if (nextApproverEmail) {
                    att.escalatedTo = nextApproverEmail;
                    const nextUser = await User.findOne({ email: nextApproverEmail.toLowerCase() }).lean();
                    if (!nextUser) return res.status(404).json({ error: 'Next approver not found: ' + nextApproverEmail });

                    const childAtt = await Attestation.create({
                        targetEmail: nextUser.email,
                        targetName: nextUser.displayName || nextUser.email,
                        prompt: att.prompt,
                        type: att.type,
                        status: 'pending',
                        expiresAt: att.expiresAt,
                        parentAttestationId: att._id,
                        requestedBy: att.requestedBy,
                        requesterEmail: att.requesterEmail,
                        requesterName: att.requesterName,
                        kycSessionId: nextUser.kycSessionId,
                        authLevel: nextUser.authLevel || 'none',
                        requiredApprovals: att.requiredApprovals,
                        policyId: att.policyId,
                        policyRules: att.policyRules,
                        approvalChain: [approverEntry],
                        amount: att.amount,
                        currency: att.currency,
                        budget: att.budget,
                        webhookUrl: att.webhookUrl,
                    });

                    clearPinSession(att);
                    await att.save();

                    // Create session for child
                    const childSessionId = generateSessionId(nextUser.firebaseUid || 'attestation');
                    await Session.create({
                        sessionId: childSessionId,
                        uuid: nextUser.firebaseUid || 'anon',
                        email: nextUser.email,
                        source: 'attestation',
                        attestationId: childAtt._id,
                        date: new Date(),
                        createdAt: new Date(),
                        expiresAt: att.expiresAt,
                        checksumOK: false,
                        screenshots: [],
                    });

                    // Notify the next approver
                    try {
                        const { sendMessage } = require('./utils/messagingUtils');
                        const msg = `xChk: ${att.requesterEmail || 'Someone'} escalated approval for: ${att.prompt.slice(0, 120)}`;
                        if (nextUser.mobile) sendMessage(nextUser.mobile, msg, 'sms').catch(e => console.error('Escalation SMS failed:', e.message));
                        if (nextUser.telegramChatId) {
                            axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
                                chat_id: nextUser.telegramChatId,
                                text: `\u2b06\ufe0f Escalated to you\n\n${att.requesterEmail || 'Someone'} is asking:\n${att.prompt}\n\nhttps://in.xchk.io/attest-reply.html?a=${childAtt._id}`,
                                parse_mode: 'HTML'
                            }, { timeout: 10000 }).catch(e => console.error('Escalation Telegram failed:', e.message));
                        }
                    } catch (_) {}

                    return res.json({ ok: true, status: 'escalated', attestationId: String(att._id), escalatedTo: nextApproverEmail, childAttestationId: String(childAtt._id) });
                } else {
                    att.escalatedTo = null;
                    clearPinSession(att);
                    await att.save();
                    return res.json({ ok: true, status: 'escalated', attestationId: String(att._id), escalatedTo: null, message: 'No further escalation available.' });
                }
            }

            if (response === 'declined') {
                att.approvalChain.push(approverEntry);
                att.status = 'declined';
                clearPinSession(att);
                await att.save();
                _dispatchAttestationWebhook(att).catch(() => {});
                _sendAttestationTelegram(att).catch(() => {});
                return res.json({ ok: true, status: 'declined', attestationId: String(att._id) });
            }

            if (response === 'approved' || response === 'wrong') {
                att.approvalChain.push(approverEntry);

                const totalApprovals = att.approvalChain.filter(a => a.response === 'approved').length;

                if (totalApprovals >= att.requiredApprovals) {
                    att.status = 'completed';

                    try {
                        const prevAtt = await Attestation.findOne({ targetEmail: att.targetEmail.toLowerCase(), _id: { $ne: att._id }, sha256: { $ne: null } })
                            .sort({ createdAt: -1 }).select('sha256 _id').lean();
                        att.previousHash = prevAtt?.sha256 || null;
                        att.previousAttestationId = prevAtt?._id || null;
                    } catch (_) {}
                    att.sha256 = computeAttestationHash(att.toObject ? att.toObject() : att);
                    clearPinSession(att);
                    await att.save();

                    if (att.type === 'spending' && att.response === 'approved' && att.parentId && att.amount) {
                        try { await Attestation.findByIdAndUpdate(att.parentId, { $inc: { spent: att.amount } }); } catch (_) {}
                    }

                    try {
                        const { recordAuditEventAsync } = require('./services/auditLogService');
                        recordAuditEventAsync({
                            action: 'ATTESTATION_COMPLETED',
                            actor: { email: att.targetEmail },
                            target: { type: 'attestation', email: att.targetEmail, mongoId: String(att._id), label: (att.prompt || '').slice(0, 80) },
                            metadata: { response: att.response, totalApprovals }
                        });
                    } catch (_) {}

                    try {
                        await Session.findOneAndUpdate({ attestationId: att._id }, { helpdeskResult: response, helpdeskResultAt: new Date() });
                    } catch (_) {}

                    _dispatchAttestationWebhook(att).catch(() => {});
                    _sendAttestationTelegram(att).catch(() => {});

                    return res.json({ ok: true, status: 'completed', attestationId: String(att._id) });
                } else {
                    const remaining = att.requiredApprovals - totalApprovals;
                    att.status = 'waiting';
                    clearPinSession(att);
                    await att.save();

                    // Auto-expand the pool — notify the next approver in line
                    _notifyNextApprover(att, approverEntry).catch(e => console.error('Pool expansion failed:', e.message));

                    return res.json({ ok: true, status: 'waiting', attestationId: String(att._id), message: `Approved by ${att.targetEmail}. ${remaining} more approval(s) needed.`, approvalsRemaining: remaining });
                }
            }

            return res.status(400).json({ error: 'Invalid response combination' });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Get attestation details (pending requests redact PII until PIN session is verified)
    app.get('/api/attestations/:id', async (req, res) => {
        try {
            const att = await Attestation.findById(req.params.id);
            if (!att) return res.status(404).json({ error: 'Not found' });

            // Auto-expire if TTL has passed
            if ((att.status === 'pending' || att.status === 'waiting') && att.expiresAt && new Date(att.expiresAt) < new Date()) {
                att.status = 'expired';
                await att.save();
            }

            const attObj = att.toObject();
            const pinSessionToken = req.headers['x-attestation-pin-session'] || req.query.pinSession;
            const pinVerified = attObj.status === 'pending' && isPinSessionValid(attObj, pinSessionToken);
            const isViewOnly = !!req.query.d;
            if (attObj.status === 'pending' && !pinVerified && !isViewOnly) {
                return res.json({
                    ok: true,
                    attestationId: String(att._id),
                    status: att.status,
                    type: att.type,
                    expiresAt: att.expiresAt,
                    authLevel: att.authLevel,
                    pinRequired: true
                });
            }

            // Look up linked session for profile pic and identity status
            const Session = require('./models/Session');
            const Candidate = require('./models/Candidate');
            const session = await Session.findOne({ attestationId: att._id })
                .select('helpdeskResult email')
                .lean()
                .catch(() => null);

            // Build derived signals for the icon row (fingerprint comparison, etc.)
            const { buildDerivedSignals } = require('./utils/derivedSignalsUtils');
            let derivedSignals = null;
            const linkedSession = session ? await Session.findOne({ attestationId: att._id }).lean().catch(() => null) : null;
            if (linkedSession || att.targetEmail) {
                // Build a session-like object with attestation evidence
                const fpSession = {
                    ...(linkedSession || {}),
                    candidateId: linkedSession?.candidateId || null,
                    email: att.targetEmail || linkedSession?.email,
                    deviceFingerprint: att.deviceFingerprint || linkedSession?.deviceFingerprint,
                    deviceInfo: att.deviceInfo || linkedSession?.deviceInfo,
                    browserInfo: att.browserInfo || linkedSession?.browserInfo,
                    networkInfo: att.networkInfo || linkedSession?.networkInfo,
                    location: att.clientGeo ? { coordinates: [att.clientGeo.lon, att.clientGeo.lat], type: 'Point' } : linkedSession?.location,
                    ipapi: linkedSession?.ipapi || null,
                    iplocation: linkedSession?.iplocation || null,
                    mapboxLocation: linkedSession?.mapboxLocation || null,
                };
                // If no candidateId on session, look up by email
                if (!fpSession.candidateId && att.targetEmail) {
                    const candidateByEmail = await Candidate.findOne({ email: att.targetEmail.toLowerCase() }).select('_id').lean().catch(() => null);
                    if (candidateByEmail) {
                        fpSession.candidateId = candidateByEmail._id;
                    }
                }
                try {
                    derivedSignals = await buildDerivedSignals(fpSession);
                } catch(e) { console.error('Attestation derived signals failed:', e.message); }
            }

            let profilePicUrl = 'images/npc.png';
            let identityStatus = null;
            let kycDocInfo = null;
            if (att.targetEmail) {
                const candidate = await Candidate.findOne({ email: att.targetEmail.toLowerCase() })
                    .select('photoURL')
                    .lean()
                    .catch(() => null);
                if (candidate?.photoURL) {
                    profilePicUrl = candidate.photoURL;
                }
                // Fetch KYC document type from User record
                const userRec = await require('./models/User').findOne({ email: att.targetEmail.toLowerCase() })
                    .select('kycDocType kycDocLabel')
                    .lean()
                    .catch(() => null);
                if (userRec) {
                    kycDocInfo = userRec.kycDocType || userRec.kycDocLabel || null;
                }
            }
            if (session?.helpdeskResult) {
                identityStatus = session.helpdeskResult;
            }

            // Reverse-geocode GPS coords to city name
            let gpsCity = null;
            if (att.clientGeo?.lat && att.clientGeo?.lon) {
                try {
                    const geoResp = await geocodingService.reverseGeocode({
                        query: [att.clientGeo.lon, att.clientGeo.lat],
                        types: ["place"],
                        limit: 1
                    }).send();
                    if (geoResp.body.features?.length > 0) {
                        gpsCity = geoResp.body.features[0].text;
                    }
                } catch(e) { console.error("Attestation GPS reverse geocode failed:", e.message); }
            }

            // Build rich verification data matching helpdesk's verify/placeholder shape
            const mobileDeviceInfo = att.deviceInfo ? detectMobileDevice(typeof att.deviceInfo === 'string' ? { userAgent: att.deviceInfo } : att.deviceInfo) : null;
            const displayCity = gpsCity || 'Unknown';
            const responseData = {
                ok: true,
                attestationId: String(att._id),
                targetEmail: att.targetEmail,
                targetName: att.targetName,
                prompt: att.prompt,
                type: att.type,
                status: att.status,
                response: att.response,
                photoUrls: att.photoUrls || [],
                expiresAt: att.expiresAt,
                createdAt: att.createdAt,
                respondedAt: att.respondedAt,
                authLevel: att.authLevel,
                kycSessionId: att.kycSessionId,
                requesterEmail: att.requesterEmail,
                requesterName: att.requesterName,
                clientGeo: att.clientGeo || null,
                gpsCity: gpsCity,
                deviceInfo: att.deviceInfo || null,
                browserInfo: att.browserInfo || null,
                networkInfo: att.networkInfo || null,
                deviceFingerprint: att.deviceFingerprint || null,
                derivedSignals,
                profilePicUrl,
                identityStatus,
                kycDocInfo,
                // Icon row fields matching helpdesk's verify response
                city: displayCity,
                email: att.targetEmail || null,
                mobile: session?.mobile || null,
                mobileDevice: mobileDeviceInfo,
                source: 'attestation',
                gpsLocation: att.clientGeo ? { lat: att.clientGeo.lat, lng: att.clientGeo.lon } : null,
                locationMismatch: false,
                pin: { submitted: true, verified: true },
                requiresPin: false,
                emailConfirmed: true,
                verifiedEmail: att.targetEmail,
                // Cryptographic integrity
                sha256: att.sha256 || null,
                previousHash: att.previousHash || null,
                previousAttestationId: att.previousAttestationId ? String(att.previousAttestationId) : null,
                rvnTxId: att.rvnTxId || null,
                rvnAnchoredAt: att.rvnAnchoredAt || null,
                rvnQueuedAt: att.rvnQueuedAt || null,
                amount: att.amount || null,
                currency: att.currency || 'USD',
                budget: att.budget || null,
                spent: att.spent || 0,
                parentId: att.parentId ? String(att.parentId) : null,
                validUntil: att.validUntil || null,
                kycWarning: att.authLevel === 'none' || false,
                // Multi-approval and escalation chain
                governed: att.policyRules && att.policyRules.length > 0 && (
                    att.policyRules.length > 1 ||
                    (att.requiredApprovals || 1) > 1 ||
                    att.policyRules[0].role ||
                    (att.policyRules[0].escalationChain && att.policyRules[0].escalationChain.length > 1)
                ),
                requiredApprovals: att.requiredApprovals || 1,
                approvalChain: att.approvalChain || [],
                approvalsRemaining: Math.max(0, (att.requiredApprovals || 1) - (att.approvalChain || []).filter(a => a.response === 'approved').length),
                escalatedTo: att.escalatedTo || null,
                policyId: att.policyId ? String(att.policyId) : null,
                policyRules: att.policyRules || [],
                escalatedBy: att.escalatedBy || null,
                escalatedAt: att.escalatedAt || null,
                parentAttestationId: att.parentAttestationId ? String(att.parentAttestationId) : null,
                signature: null, // computed below
                signingKeyId: 'xchk-attestation-v1',
            };
            // Sign the response payload (excluding the signature field itself)
            responseData.signature = signAttestationPayload(responseData);
            return res.json(responseData);
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // --- Approval Policy CRUD ---
    const authenticateAdmin = async (req, res, next) => {
        if (req.user?.siteAdmin) { next(); return; }
        // Fallback: check API key admin flag
        const apiKeyId = req.apiKeyId;
        if (apiKeyId) {
            const ApiKey = require('./models/ApiKey');
            const key = await ApiKey.findById(apiKeyId).lean();
            if (key && key.admin) { next(); return; }
        }
        return res.status(403).json({ error: 'Admin access required' });
    };

    // List policies
    app.get('/api/approval-policies', authenticateFirebaseOrApiKey, async (req, res) => {
        try {
            const policies = await require('./models/ApprovalPolicy').find({ active: true })
                .select('name description rules requiredApprovals createdAt updatedAt')
                .sort({ name: 1 })
                .lean();
            return res.json({ ok: true, policies });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Get single policy
    app.get('/api/approval-policies/:id', authenticateFirebaseOrApiKey, async (req, res) => {
        try {
            const policy = await require('./models/ApprovalPolicy').findById(req.params.id).lean();
            if (!policy) return res.status(404).json({ error: 'Policy not found' });
            return res.json({ ok: true, policy });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Create policy
    app.post('/api/approval-policies', authenticateFirebaseOrApiKey, async (req, res) => {
        try {
            const { name, description, rules, requiredApprovals } = req.body;
            if (!name || !rules || !Array.isArray(rules) || rules.length === 0) {
                return res.status(400).json({ error: 'name and rules are required' });
            }
            const ApprovalPolicy = require('./models/ApprovalPolicy');
            const policy = await ApprovalPolicy.create({
                name,
                description: description || '',
                rules,
                requiredApprovals: requiredApprovals || null,
                ownerEmail: req.user?.email || null,
                active: true,
            });
            return res.status(201).json({ ok: true, policy: { _id: policy._id, name: policy.name } });
        } catch (e) {
            if (e.code === 11000) return res.status(400).json({ error: 'Policy name already exists' });
            return res.status(500).json({ error: e.message });
        }
    });

    // Update policy
    app.put('/api/approval-policies/:id', authenticateFirebaseOrApiKey, async (req, res) => {
        try {
            const { name, description, rules, requiredApprovals, active } = req.body;
            const update = {};
            if (name !== undefined) update.name = name;
            if (description !== undefined) update.description = description;
            if (rules !== undefined) update.rules = rules;
            if (requiredApprovals !== undefined) update.requiredApprovals = requiredApprovals;
            if (active !== undefined) update.active = active;
            update.updatedAt = new Date();

            const policy = await require('./models/ApprovalPolicy').findByIdAndUpdate(req.params.id, { $set: update }, { new: true }).lean();
            if (!policy) return res.status(404).json({ error: 'Policy not found' });
            return res.json({ ok: true, policy });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

    // Delete policy (soft)
    app.delete('/api/approval-policies/:id', authenticateFirebaseOrApiKey, async (req, res) => {
        try {
            const policy = await require('./models/ApprovalPolicy').findByIdAndUpdate(req.params.id, { $set: { active: false, updatedAt: new Date() } }, { new: true }).lean();
            if (!policy) return res.status(404).json({ error: 'Policy not found' });
            return res.json({ ok: true });
        } catch (e) { return res.status(500).json({ error: e.message }); }
    });

  } catch (error) {
    console.warn('⚠️ Email configuration verification failed:', error.message);
  }
}); 