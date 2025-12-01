// Load environment variables from .env (Render / local dono ke liye)
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const useragent = require('express-useragent');

const db = require('./db');

const app = express();

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  useragent.express()
);

// Security: basic helmet-like headers (optional lightweight)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ----- Config from ENV -----
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const META_ACCESS_TOKEN = process.env.META_ACCESS_TOKEN || '';
const DEFAULT_META_PIXEL_ID = process.env.DEFAULT_META_PIXEL_ID || '';
const DEFAULT_PUBLIC_LP_URL = process.env.DEFAULT_PUBLIC_LP_URL || 'https://example.com';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'DEV_ADMIN_SECRET';

// Session secret
const SESSION_SECRET = process.env.SESSION_SECRET || 'super_secret_session_key';

// Utility: simple session via signed cookies (minimal)
const sessions = new Map(); // { sessionId: { userId, role, ... } }

function createSession(res, user) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  sessions.set(sessionId, {
    userId: user.id,
    role: user.role,
    email: user.email,
    createdAt: Date.now()
  });

  res.cookie('sess_id', sessionId, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function getSession(req) {
  const sessId = req.cookies?.sess_id;
  if (!sessId) return null;
  const sess = sessions.get(sessId);
  if (!sess) return null;
  return sess;
}

function destroySession(req, res) {
  const sessId = req.cookies?.sess_id;
  if (sessId) {
    sessions.delete(sessId);
  }
  res.clearCookie('sess_id');
}

// Helper: password hashing
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Helper: random API key
function generateApiKey() {
  return 'key_' + crypto.randomBytes(24).toString('hex');
}

// Helper: slugify
function slugifyName(name) {
  return String(name || '')
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9\-]/g, '')
    .substring(0, 50);
}

// Helper: SHA256 for Meta external_id
function hashSha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

// Helper: random event_id
function generateEventId() {
  return crypto.randomBytes(16).toString('hex');
}

// Helper: format date (YYYY-MM-DD)
function formatDateYYYYMMDD(ts) {
  const d = new Date(ts * 1000);
  return d.toISOString().substring(0, 10);
}

// ----- Tracking Helpers -----

// Client IP detect (x-forwarded-for etc.)
function getClientIp(req) {
  const xfwd = req.headers['x-forwarded-for'];
  if (xfwd) {
    const ips = xfwd.split(',').map((s) => s.trim());
    if (ips[0]) return ips[0];
  }
  return req.connection.remoteAddress || req.socket.remoteAddress || null;
}

// Device / browser classification from user-agent
function classifyDevice(ua) {
  if (!ua) return { deviceType: null, browser: null, os: null };
  const info = reqUserAgent(ua);
  let deviceType = 'desktop';
  if (info.isMobile) deviceType = 'mobile';
  else if (info.isTablet) deviceType = 'tablet';

  return {
    deviceType,
    browser: info.browser || null,
    os: info.os || null
  };
}

// Because we imported express-useragent, we can also reuse its parser:
function reqUserAgent(uaString) {
  // quick parse using library
  return useragent.parse(uaString);
}

// Prepared statements for pre_leads
const insertPreLeadStmt = db.prepare(`
  INSERT INTO pre_leads (
    channel_id,
    fbc,
    fbp,
    ip,
    country,
    user_agent,
    device_type,
    browser,
    os,
    source,
    utm_source,
    utm_medium,
    utm_campaign,
    utm_content,
    utm_term,
    client_id,
    created_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const getRecentPreLeadStmt = db.prepare(`
  SELECT *
  FROM pre_leads
  WHERE channel_id = ?
    AND created_at >= ?
  ORDER BY created_at DESC
  LIMIT 1
`);

// Joins insert prepared statement (later we use dynamic but keep lines)
const insertJoinStmt = db.prepare(`
  INSERT INTO joins (
    telegram_user_id,
    telegram_username,
    channel_id,
    channel_title,
    joined_at,
    meta_event_id,
    ip,
    country,
    user_agent,
    device_type,
    browser,
    os,
    source,
    utm_source,
    utm_medium,
    utm_campaign,
    utm_content,
    utm_term,
    client_id
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

// ----- AUTH MIDDLEWARE -----
function requireAuth(req, res, next) {
  const sess = getSession(req);
  if (!sess) {
    return res.redirect('/auth/login');
  }
  const user = db
    .prepare('SELECT id, email, role FROM users WHERE id = ?')
    .get(sess.userId);
  if (!user) {
    destroySession(req, res);
    return res.redirect('/auth/login');
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const sess = getSession(req);
  if (!sess) {
    return res.redirect('/auth/login');
  }
  const user = db
    .prepare('SELECT id, email, role FROM users WHERE id = ?')
    .get(sess.userId);
  if (!user || user.role !== 'admin') {
    return res.status(403).send('Forbidden: Admin only');
  }
  req.user = user;
  next();
}

// ----- AUTH ROUTES (login/logout) -----

// GET /auth/login
app.get('/auth/login', (req, res) => {
  const sess = getSession(req);
  if (sess) {
    return res.redirect('/panel');
  }
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>Login - Telegram Tracker SaaS</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body {
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: radial-gradient(circle at top, #1f2937 0, #020617 55%);
          color: #e5e7eb;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0;
        }
        .card {
          background: rgba(15, 23, 42, 0.95);
          border-radius: 16px;
          padding: 24px;
          width: 100%;
          max-width: 360px;
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.45);
          border: 1px solid rgba(148, 163, 184, 0.2);
        }
        h1 {
          font-size: 20px;
          margin-bottom: 4px;
        }
        .muted {
          font-size: 12px;
          color: #9ca3af;
          margin-bottom: 16px;
        }
        label {
          display: block;
          font-size: 12px;
          margin-bottom: 4px;
          color: #cbd5f5;
        }
        input {
          width: 100%;
          padding: 8px 10px;
          border-radius: 8px;
          border: 1px solid #1f2937;
          background: #020617;
          color: #e5e7eb;
          font-size: 13px;
          margin-bottom: 12px;
        }
        button {
          width: 100%;
          padding: 10px;
          border-radius: 999px;
          border: none;
          background: linear-gradient(to right, #22c55e, #16a34a);
          color: white;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          margin-top: 4px;
        }
        button:hover {
          filter: brightness(1.06);
        }
        .footer {
          margin-top: 16px;
          font-size: 11px;
          color: #6b7280;
          text-align: center;
        }
        a {
          color: #38bdf8;
          text-decoration: none;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Login</h1>
        <div class="muted">Agency panel access ke liye email/password se login karein.</div>
        <form method="POST" action="/auth/login">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" required />

          <label for="password">Password</label>
          <input id="password" name="password" type="password" required />

          <button type="submit">Login</button>
        </form>
        <div class="footer">
          Seed admin banane ke liye <code>/dev/seed-admin?key=${ADMIN_SECRET}</code> once call karein.
        </div>
      </div>
    </body>
    </html>
  `);
});

// POST /auth/login
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.redirect('/auth/login');
  }
  const user = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(String(email).toLowerCase());
  if (!user) {
    return res.redirect('/auth/login');
  }
  const submittedHash = hashPassword(password);
  if (submittedHash !== user.password_hash) {
    return res.redirect('/auth/login');
  }
  createSession(res, user);
  return res.redirect('/panel');
});

// GET /auth/logout
app.get('/auth/logout', (req, res) => {
  destroySession(req, res);
  res.redirect('/auth/login');
});

// ----- LP TRACKING API: /api/v1/track/pageview -----

app.post('/api/v1/track/pageview', (req, res) => {
  try {
    const nowTs = Math.floor(Date.now() / 1000);

    const {
      channel_id,
      fbc,
      fbp,
      source,
      utm_source,
      utm_medium,
      utm_campaign,
      utm_content,
      utm_term,
      client_id
    } = req.body || {};

    if (!channel_id) {
      return res.status(400).json({ ok: false, error: 'channel_id is required' });
    }

    const ip = getClientIp(req);
    const ua = req.headers['user-agent'] || null;
    const country = req.headers['cf-ipcountry'] || null;

    let deviceType = null;
    let browser = null;
    let os = null;
    if (ua) {
      const info = classifyDevice(ua);
      deviceType = info.deviceType;
      browser = info.browser;
      os = info.os;
    }

    insertPreLeadStmt.run(
      String(channel_id),
      fbc || null,
      fbp || null,
      ip || null,
      country || null,
      ua || null,
      deviceType || null,
      browser || null,
      os || null,
      source || null,
      utm_source || null,
      utm_medium || null,
      utm_campaign || null,
      utm_content || null,
      utm_term || null,
      client_id || null,
      nowTs
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Error in /api/v1/track/pageview:', err);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// ----- TELEGRAM WEBHOOK -----

app.post(`/bot${TELEGRAM_BOT_TOKEN}`, async (req, res) => {
  try {
    const body = req.body;

    if (body.chat_join_request) {
      const joinRequest = body.chat_join_request;
      const user = joinRequest.from;
      console.log('Incoming join_request:', joinRequest);

      const approveUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/approveChatJoinRequest`;
      await axios.post(approveUrl, {
        chat_id: joinRequest.chat.id,
        user_id: user.id
      });
      console.log('✅ Approved join request for user:', user.id);

      const clientIdForChannel = (() => {
        const channelRow = db
          .prepare('SELECT client_id FROM channels WHERE telegram_chat_id = ?')
          .get(String(joinRequest.chat.id));
        if (channelRow && channelRow.client_id) {
          return channelRow.client_id;
        }
        return 1;
      })();

      try {
        await sendMetaLeadEvent(user, joinRequest);
      } catch (e) {
        console.error(
          '❌ Meta CAPI (outer try) error:',
          e.response?.data || e.message || e
        );
      }

      try {
        insertJoinStmt.run(
          String(user.id),
          user.username || null,
          String(joinRequest.chat.id),
          joinRequest.chat.title || null,
          Math.floor(Date.now() / 1000),
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          null,
          clientIdForChannel
        );
        console.log('✅ Join stored in joins table for user:', user.id);
      } catch (err) {
        console.error('❌ Error inserting into joins table:', err.message || err);
      }
    }

    res.sendStatus(200);
  } catch (err) {
    console.error(
      '❌ Error in webhook handler (outer):',
      err.response?.data || err.message || err
    );
    res.sendStatus(200);
  }
});

// ----- Helper: Ensure we have a channels row for each incoming join -----
function getOrCreateChannelConfigFromJoin(joinRequest, nowTs) {
  const chat = joinRequest.chat;
  const telegramChatId = String(chat.id);

  let channel = db
    .prepare('SELECT * FROM channels WHERE telegram_chat_id = ?')
    .get(telegramChatId);

  if (!channel) {
    const stmt = db.prepare(`
      INSERT INTO channels (
        client_id,
        telegram_chat_id,
        telegram_title,
        deep_link,
        pixel_id,
        meta_token,
        lp_url,
        created_at,
        is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    `);

    const info = stmt.run(
      1,
      telegramChatId,
      chat.title || null,
      null,
      null,
      null,
      DEFAULT_PUBLIC_LP_URL,
      nowTs
    );

    channel = {
      id: info.lastInsertRowid,
      client_id: 1,
      telegram_chat_id: telegramChatId,
      telegram_title: chat.title || null,
      deep_link: null,
      pixel_id: null,
      meta_token: null,
      lp_url: DEFAULT_PUBLIC_LP_URL,
      created_at: nowTs,
      is_active: 1
    };

    console.log('🆕 Auto-created channel row:', channel);
  } else {
    if (chat.title && chat.title !== channel.telegram_title) {
      db.prepare('UPDATE channels SET telegram_title = ? WHERE id = ?').run(
        chat.title,
        channel.id
      );
      channel.telegram_title = chat.title;
    }
  }

  return channel;
}
// ----- Helper: Meta CAPI Lead + DB insert -----
async function sendMetaLeadEvent(user, joinRequest) {
  const eventTime = Math.floor(Date.now() / 1000);
  const channelId = String(joinRequest.chat.id);

  const thirtyMinutesAgo = eventTime - 30 * 60;
  let fbcForThisLead = null;
  let fbpForThisLead = null;

  let ipForThisLead = null;
  let countryForThisLead = null;
  let uaForThisLead = null;
  let deviceTypeForThisLead = null;
  let browserForThisLead = null;
  let osForThisLead = null;
  let sourceForThisLead = null;
  let utmSourceForThisLead = null;
  let utmMediumForThisLead = null;
  let utmCampaignForThisLead = null;
  let utmContentForThisLead = null;
  let utmTermForThisLead = null;

  try {
    const row = getRecentPreLeadStmt.get(channelId, thirtyMinutesAgo);
    if (row) {
      if (row.fbc) fbcForThisLead = row.fbc;
      if (row.fbp) fbpForThisLead = row.fbp;

      ipForThisLead = row.ip || null;
      countryForThisLead = row.country || null;
      uaForThisLead = row.user_agent || null;
      deviceTypeForThisLead = row.device_type || null;
      browserForThisLead = row.browser || null;
      osForThisLead = row.os || null;
      sourceForThisLead = row.source || null;
      utmSourceForThisLead = row.utm_source || null;
      utmMediumForThisLead = row.utm_medium || null;
      utmCampaignForThisLead = row.utm_campaign || null;
      utmContentForThisLead = row.utm_content || null;
      utmTermForThisLead = row.utm_term || null;
    }
  } catch (err) {
    console.error(
      '❌ Error fetching pre_lead for channel_id',
      channelId,
      err.message || err
    );
  }

  console.log('Using fbcForThisLead:', fbcForThisLead, 'fbpForThisLead:', fbpForThisLead);
  console.log('Tracking for lead:', {
    ipForThisLead,
    countryForThisLead,
    uaForThisLead,
    deviceTypeForThisLead,
    browserForThisLead,
    osForThisLead,
    sourceForThisLead,
    utmSourceForThisLead,
    utmMediumForThisLead,
    utmCampaignForThisLead,
    utmContentForThisLead,
    utmTermForThisLead
  });

  // Channel config (pixel, LP, client)
  const channelConfig = getOrCreateChannelConfigFromJoin(
    joinRequest,
    eventTime
  );

  const lpUrl = channelConfig.lp_url || DEFAULT_PUBLIC_LP_URL;

  // Token + pixel priority resolution
  let clientForChannel = null;
  if (channelConfig.client_id) {
    try {
      clientForChannel = db
        .prepare('SELECT * FROM clients WHERE id = ?')
        .get(channelConfig.client_id);
    } catch (e) {
      console.error(
        '❌ Error fetching client for channel in sendMetaLeadEvent:',
        e.message || e
      );
    }
  }

  const pixelId =
    (channelConfig.pixel_id && channelConfig.pixel_id.trim()) ||
    (clientForChannel &&
      clientForChannel.default_pixel_id &&
      clientForChannel.default_pixel_id.trim()) ||
    null;  const tokenToUse =
  (channelConfig.meta_token && channelConfig.meta_token.trim()) ||
  (clientForChannel &&
    clientForChannel.default_meta_token &&
    clientForChannel.default_meta_token.trim()) ||
  null;

if (!pixelId || !tokenToUse) {
  console.log(
    'ℹ️ Skipping CAPI send because pixel or token missing for this channel/client.',
    {
      channel_id: channelConfig.telegram_chat_id,
      client_id: channelConfig.client_id,
      pixelPresent: !!pixelId,
      tokenPresent: !!tokenToUse
    }
  );
}

const url =
  pixelId && tokenToUse
    ? `https://graph.facebook.com/v18.0/${pixelId}/events?access_token=${tokenToUse}`
    : null;const externalIdHash = hashSha256(String(user.id));
  const eventId = generateEventId();

  const userData = {
    external_id: externalIdHash
  };

  if (fbcForThisLead) {
    userData.fbc = fbcForThisLead;
  }
  if (fbpForThisLead) {
    userData.fbp = fbpForThisLead;
  }
  if (ipForThisLead) {
    userData.client_ip_address = ipForThisLead;
  }
  if (uaForThisLead) {
    userData.client_user_agent = uaForThisLead;
  }

  const customData = {};

  if (sourceForThisLead) {
    customData.source = sourceForThisLead;
  }
  if (utmSourceForThisLead) {
    customData.utm_source = utmSourceForThisLead;
  }
  if (utmMediumForThisLead) {
    customData.utm_medium = utmMediumForThisLead;
  }
  if (utmCampaignForThisLead) {
    customData.utm_campaign = utmCampaignForThisLead;
  }
  if (utmContentForThisLead) {
    customData.utm_content = utmContentForThisLead;
  }
  if (utmTermForThisLead) {
    customData.utm_term = utmTermForThisLead;
  }

  const eventBody = {
    event_name: 'Lead',
    event_time: eventTime,
    event_id: eventId,
    event_source_url: lpUrl,
    action_source: 'website',
    user_data: userData,
    custom_data: customData
  };

  const payload = {
    data: [eventBody]
  };

  let metaEventIdToStore = null;

  if (url) {
    try {
      const res = await axios.post(url, payload);
      console.log('Meta CAPI response:', res.data);
      metaEventIdToStore = eventId;
    } catch (e) {
      console.error(
        '❌ Meta CAPI (outer try) error:',
        e.response?.data || e.message || e
      );
    }
  } else {
    console.log('ℹ️ CAPI URL null (no token). Skipping HTTP call.');
  }

  db.prepare(
    `
    INSERT INTO joins 
      (
        telegram_user_id,
        telegram_username,
        channel_id,
        channel_title,
        joined_at,
        meta_event_id,
        ip,
        country,
        user_agent,
        device_type,
        browser,
        os,
        source,
        utm_source,
        utm_medium,
        utm_campaign,
        utm_content,
        utm_term
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
  ).run(
    String(user.id),
    user.username || null,
    String(joinRequest.chat.id),
    joinRequest.chat.title || null,
    eventTime,
    metaEventIdToStore,
    ipForThisLead || null,
    countryForThisLead || null,
    uaForThisLead || null,
    deviceTypeForThisLead || null,
    browserForThisLead || null,
    osForThisLead || null,
    sourceForThisLead || null,
    utmSourceForThisLead || null,
    utmMediumForThisLead || null,
    utmCampaignForThisLead || null,
    utmContentForThisLead || null,
    utmTermForThisLead || null
  );

  console.log('✅ Join stored in DB for user:', user.id);
}

// ----- ADMIN: update channel config (pixel, LP, client, deep link) -----
app.post('/admin/update-channel', (req, res) => {
  try {
    const {
      admin_key,
      telegram_chat_id,
      client_id,
      pixel_id,
      lp_url,
      deep_link
    } = req.body || {};

    if (admin_key !== ADMIN_SECRET) {
      return res.status(403).json({ ok: false, error: 'bad admin key' });
    }

    if (!telegram_chat_id) {
      return res
        .status(400)
        .json({ ok: false, error: 'telegram_chat_id is required' });
    }

    const channel = db
      .prepare('SELECT * FROM channels WHERE telegram_chat_id = ?')
      .get(String(telegram_chat_id));

    if (!channel) {
      return res
        .status(404)
        .json({ ok: false, error: 'channel config not found' });
    }

    const newClientId = client_id ? parseInt(client_id, 10) : channel.client_id;
    const newPixelId = pixel_id || channel.pixel_id || null;
    const newLpUrl = lp_url || channel.lp_url || DEFAULT_PUBLIC_LP_URL;
    const newDeepLink = deep_link || channel.deep_link || null;

    db.prepare(
      `
      UPDATE channels
      SET client_id = ?, pixel_id = ?, lp_url = ?, deep_link = ?
      WHERE id = ?
    `
    ).run(newClientId, newPixelId, newLpUrl, newDeepLink, channel.id);

    console.log('✅ Updated channel config via /admin/update-channel:', {
      telegram_chat_id,
      newClientId,
      newPixelId,
      newLpUrl,
      newDeepLink
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Error in /admin/update-channel:', err);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// ----- DEV: Simple health check -----
app.get('/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});

// ===== PANEL / SAAS =====

// GET /panel - list of clients for logged-in user
app.get('/panel', requireAuth, (req, res) => {
  const user = req.user;
  const clients = db
    .prepare(
      `
      SELECT
        c.id,
        c.name,
        c.slug,
        c.plan,
        c.max_channels,
        c.is_active,
        c.created_at,
        c.public_key,
        c.secret_key
      FROM clients c
      WHERE c.owner_user_id = ?
      ORDER BY c.created_at DESC, c.id DESC
    `
    )
    .all(user.id);

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>Agency Panel - Telegram Tracker</title>
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <style>
        body {
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #020617;
          color: #e5e7eb;
          padding: 20px;
          margin: 0;
        }
        h1 {
          font-size: 22px;
          margin-bottom: 12px;
        }
        .top-bar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 16px;
        }
        .muted {
          font-size: 12px;
          color: #9ca3af;
        }
        a {
          color: #38bdf8;
          text-decoration: none;
          font-size: 13px;
        }
        .logout {
          font-size: 12px;
          color: #f97316;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 16px;
          font-size: 13px;
        }
        th, td {
          border: 1px solid #1f2937;
          padding: 8px;
          text-align: left;
        }
        th {
          background: #020617;
        }
        tr:nth-child(even) {
          background: #020617;
        }
        .badge {
          display: inline-block;
          padding: 2px 8px;
          border-radius: 999px;
          font-size: 11px;
          border: 1px solid #4b5563;
        }
        .badge-green {
          border-color: #22c55e;
          color: #22c55e;
        }
        .btn {
          background: #22c55e;
          border-radius: 999px;
          color: #fff;
          padding: 6px 12px;
          border: none;
          cursor: pointer;
          font-size: 12px;
        }
        .btn-secondary {
          background: #0ea5e9;
        }
        .row-actions a {
          margin-right: 8px;
        }
        .card {
          border: 1px solid #1f2937;
          border-radius: 12px;
          padding: 12px 14px;
          margin-bottom: 16px;
          background: radial-gradient(circle at top left, #0f172a 0, #020617 60%);
        }
        .card-title {
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 4px;
        }
        .card-sub {
          font-size: 12px;
          color: #9ca3af;
        }
        .badge-key {
          font-size: 11px;
          color: #9ca3af;
        }
      </style>
    </head>
    <body>
      <div class="top-bar">
        <div>
          <h1>Agency Panel</h1>
          <div class="muted">
            Logged in as <strong>${user.email}</strong> (${user.role})
          </div>
        </div>
        <div>
          <a href="/auth/logout" class="logout">Logout</a>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Create new client</div>
        <div class="card-sub">Ek client = ek agency / ek business jiske multiple Telegram channels ho sakte hain.</div>
        <form method="POST" action="/panel/new-client" style="margin-top:8px;">
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <div style="flex:1 1 180px;">
              <label style="font-size:12px;">Name</label>
              <input name="name" type="text" style="width:100%;padding:6px 8px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;font-size:12px;" placeholder="VeerBhai Agency" required />
            </div>
            <div style="flex:1 1 180px;">
              <label style="font-size:12px;">Slug (optional)</label>
              <input name="slug" type="text" style="width:100%;padding:6px 8px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;font-size:12px;" placeholder="veerbhai-agency" />
            </div>
            <div style="flex:1 1 180px;">
              <label style="font-size:12px;">Plan</label>
              <input name="plan" type="text" style="width:100%;padding:6px 8px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;font-size:12px;" placeholder="starter / pro" />
            </div>
            <div style="flex:1 1 120px;">
              <label style="font-size:12px;">Max channels</label>
              <input name="max_channels" type="number" style="width:100%;padding:6px 8px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;font-size:12px;" placeholder="10" />
            </div>
          </div>
          <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
            <div style="flex:1 1 220px;">
              <label style="font-size:12px;">Default Pixel ID (optional)</label>
              <input name="default_pixel_id" type="text" style="width:100%;padding:6px 8px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;font-size:12px;" placeholder="Meta Pixel ID" />
            </div>
            <div style="flex:1 1 260px;">
              <label style="font-size:12px;">Default Meta Access Token (optional)</label>
              <input name="default_meta_token" type="text" style="width:100%;padding:6px 8px;border-radius:8px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;font-size:12px;" placeholder="CAPI access token" />
            </div>
          </div>
          <div style="margin-top:8px;">
            <button type="submit" class="btn">Create client</button>
          </div>
        </form>
      </div>

      <h2 style="font-size:16px;margin-top:16px;">Your clients</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Slug</th>
            <th>Plan</th>
            <th>Max channels</th>
            <th>Status</th>
            <th>Keys</th>
            <th>Created</th>
            <th>Open</th>
          </tr>
        </thead>
        <tbody>
          ${
            clients.length === 0
              ? '<tr><td colspan="9" class="muted">No clients yet</td></tr>'
              : clients
                  .map((c) => {
                    const created = c.created_at
                      ? new Date(c.created_at * 1000).toISOString().substring(0, 10)
                      : '';
                    const status = c.is_active ? 'Active' : 'Inactive';
                    return `
            <tr>
              <td>${c.id}</td>
              <td>${c.name || ''}</td>
              <td><code>${c.slug || ''}</code></td>
              <td>${c.plan || ''}</td>
              <td>${c.max_channels || ''}</td>
              <td><span class="badge ${c.is_active ? 'badge-green' : ''}">${status}</span></td>
              <td>
                <div class="badge-key">PUB: <code>${c.public_key || ''}</code></div>
                <div class="badge-key">SEC: <code>${c.secret_key || ''}</code></div>
              </td>
              <td>${created}</td>
              <td class="row-actions">
                <a href="/panel/client/${c.id}">Open</a>
              </td>
            </tr>
          `;
                  })
                  .join('')
          }
        </tbody>
      </table>
    </body>
    </html>
  `);
});

// POST /panel/new-client
app.post('/panel/new-client', requireAuth, (req, res) => {
  try {
    const user = req.user;
    let {
      name,
      slug,
      plan,
      max_channels,
      default_pixel_id,
      default_meta_token
    } = req.body || {};

    name = (name || '').trim();
    slug = (slug || '').trim();
    plan = (plan || '').trim();
    default_pixel_id = (default_pixel_id || '').trim();
    default_meta_token = (default_meta_token || '').trim();

    if (!name) {
      return res.redirect('/panel?error=name');
    }

    if (!slug) {
      slug = slugifyName(name);
    }

    const maxChannels = max_channels
      ? parseInt(max_channels, 10) || 0
      : 0;

    const apiKey = generateApiKey();
    const publicKey = 'pub_' + crypto.randomBytes(12).toString('hex');
    const secretKey = 'sec_' + crypto.randomBytes(16).toString('hex');

    const now = Math.floor(Date.now() / 1000);

    db.prepare(
      `
      INSERT INTO clients (
        name,
        slug,
        owner_user_id,
        public_key,
        secret_key,
        default_pixel_id,
        default_meta_token,
        plan,
        max_channels,
        is_active,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
    ).run(
      name,
      slug,
      user.id,
      publicKey,
      secretKey,
      default_pixel_id || null,
      default_meta_token || null,
      plan || null,
      maxChannels,
      1,
      now
    );

    return res.redirect('/panel');
  } catch (err) {
    console.error('❌ Error in POST /panel/new-client:', err);
    return res.redirect('/panel?error=generic');
  }
});

// GET /panel/client/:id
app.get('/panel/client/:id', requireAuth, (req, res) => {
  try {
    const user = req.user;
    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.status(400).send('Invalid client id');
    }

    const client = db
      .prepare('SELECT * FROM clients WHERE id = ? AND owner_user_id = ?')
      .get(clientId, user.id);

    if (!client) {
      return res.status(404).send('Client not found');
    }

    const totalJoinsRow = db
      .prepare(
        `
        SELECT COUNT(*) as cnt
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
      `
      )
      .get(clientId);
    const totalJoins = totalJoinsRow?.cnt || 0;

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayTs = Math.floor(todayStart.getTime() / 1000);

    const todayJoinsRow = db
      .prepare(
        `
        SELECT COUNT(*) as cnt
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
          AND j.joined_at >= ?
      `
      )
      .get(clientId, todayTs);
    const todayJoins = todayJoinsRow?.cnt || 0;

    const sevenDaysAgo = Math.floor(
      (Date.now() - 7 * 24 * 60 * 60 * 1000) / 1000
    );
    const rows7 = db
      .prepare(
        `
        SELECT j.joined_at
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
          AND j.joined_at >= ?
        ORDER BY j.joined_at ASC
      `
      )
      .all(clientId, sevenDaysAgo);

    const byDateMap = {};
    for (const r of rows7) {
      const dateKey = formatDateYYYYMMDD(r.joined_at);
      byDateMap[dateKey] = (byDateMap[dateKey] || 0) + 1;
    }
    const graphPoints = Object.keys(byDateMap)
      .sort()
      .map((d) => ({ date: d, count: byDateMap[d] }));

    const channelConfigs = db
      .prepare(
        `
        SELECT
          id,
          telegram_chat_id,
          telegram_title,
          deep_link,
          pixel_id,
          meta_token,
          lp_url,
          is_active,
          created_at
        FROM channels
        WHERE client_id = ?
        ORDER BY created_at DESC, id DESC
      `
      )
      .all(clientId);

    const recentJoins = db
      .prepare(
        `
        SELECT
          j.id,
          j.telegram_username,
          j.channel_title,
          j.channel_id,
          j.joined_at,
          j.ip,
          j.country,
          j.user_agent,
          j.device_type,
          j.browser,
          j.os,
          j.source,
          j.utm_source,
          j.utm_medium,
          j.utm_campaign,
          j.utm_content,
          j.utm_term
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
        ORDER BY j.joined_at DESC
        LIMIT 50
      `
      )
      .all(clientId);

    const channelTotalsRows = db
      .prepare(
        `
        SELECT
          ch.telegram_chat_id,
          COUNT(j.id) as cnt
        FROM channels ch
        LEFT JOIN joins j ON j.channel_id = ch.telegram_chat_id
        WHERE ch.client_id = ?
        GROUP BY ch.telegram_chat_id
      `
      )
      .all(clientId);
    const channelTotalsMap = {};
    for (const r of channelTotalsRows) {
      channelTotalsMap[String(r.telegram_chat_id)] = r.cnt;
    }

    const trackerSnippet = `
&lt;script&gt;
  (function () {
    function getCookie(name) {
      const v = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
      return v ? v[2] : null;
    }

    function detectSource() {
      const ref = document.referrer || '';
      if (!ref) return 'direct';
      if (ref.indexOf('facebook.com') !== -1 || ref.indexOf('instagram.com') !== -1) return 'meta';
      if (ref.indexOf('google.') !== -1) return 'google';
      return 'other';
    }

    function getUtm(name) {
      const p = new URLSearchParams(window.location.search);
      return p.get(name) || null;
    }

    function sendPageview(channelId, clientId) {
      const fbc = getCookie('_fbc');
      const fbp = getCookie('_fbp');

      const payload = {
        channel_id: channelId,
        client_id: clientId,
        fbc: fbc || null,
        fbp: fbp || null,
        source: detectSource(),
        utm_source: getUtm('utm_source'),
        utm_medium: getUtm('utm_medium'),
        utm_campaign: getUtm('utm_campaign'),
        utm_content: getUtm('utm_content'),
        utm_term: getUtm('utm_term')
      };

      fetch('/api/v1/track/pageview', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      }).catch(function (err) {
        console.log('Track error:', err);
      });
    }

    window.TelegramTracker = {
      pageview: sendPageview
    };
  })();
&lt;/script&gt;
`.trim();

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Client Dashboard - ${client.name || ''}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
          body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #020617;
            color: #e5e7eb;
            padding: 20px;
            margin: 0;
          }
          a {
            color: #38bdf8;
            text-decoration: none;
            font-size: 13px;
          }
          .top-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
          }
          .muted {
            font-size: 12px;
            color: #9ca3af;
          }
          .cards {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 16px;
            margin-bottom: 16px;
          }
          .card {
            border-radius: 12px;
            border: 1px solid #1f2937;
            padding: 12px 14px;
            min-width: 150px;
            background: radial-gradient(circle at top left, #0f172a 0, #020617 60%);
          }
          .card h2 {
            font-size: 14px;
            margin: 0 0 4px 0;
          }
          .card .value {
            font-size: 20px;
            font-weight: 600;
          }
          .section-title {
            font-size: 14px;
            font-weight: 600;
            margin: 16px 0 4px 0;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 8px;
          }
          th, td {
            border: 1px solid #1f2937;
            padding: 6px 8px;
            text-align: left;
          }
          th {
            background: #020617;
          }
          tr:nth-child(even) {
            background: #020617;
          }
          code {
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 11px;
          }
          .pill {
            display: inline-flex;
            padding: 2px 8px;
            border-radius: 999px;
            border: 1px solid #4b5563;
            font-size: 11px;
            align-items: center;
            gap: 4px;
          }
          .pill-dot {
            width: 6px;
            height: 6px;
            border-radius: 999px;
            background: #22c55e;
          }
          .channels-form-row {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
          }
          .field {
            display: flex;
            flex-direction: column;
            flex: 1 1 180px;
          }
          .field label {
            font-size: 11px;
            color: #9ca3af;
            margin-bottom: 3px;
          }
          .field input {
            padding: 6px 8px;
            border-radius: 8px;
            border: 1px solid #1f2937;
            background: #020617;
            color: #e5e7eb;
            font-size: 12px;
          }
          .btn {
            background: #22c55e;
            border-radius: 999px;
            color: #fff;
            padding: 6px 12px;
            border: none;
            cursor: pointer;
            font-size: 12px;
            margin-top: 14px;
            align-self: flex-start;
          }
          .grid-two {
            display: grid;
            grid-template-columns: minmax(0, 2fr) minmax(0, 1.4fr);
            gap: 16px;
            margin-top: 16px;
          }
          @media (max-width: 900px) {
            .grid-two {
              grid-template-columns: minmax(0, 1fr);
            }
          }
        </style>
      </head>
      <body>
        <div class="top-bar">
          <div>
            <a href="/panel">&larr; Back to panel</a>
            <h1 style="margin-top:8px;">${client.name || 'Client'}</h1>
            <div class="muted">
              Slug: <code>${client.slug || ''}</code> · Plan: ${client.plan || ''} · Max channels: ${client.max_channels || ''}
            </div>
            <div class="muted">
              Public key: <code>${client.public_key || ''}</code> · Secret key: <code>${client.secret_key || ''}</code>
            </div>
          </div>
        </div>

        <div class="cards">
          <div class="card">
            <h2>Total joins</h2>
            <div class="value">${totalJoins}</div>
          </div>
          <div class="card">
            <h2>Today joins</h2>
            <div class="value">${todayJoins}</div>
          </div>
        </div>

        <div>
          <div class="section-title">Landing page integration snippet</div>
          <div class="muted">
            Paste this script into your landing page. Replace <code>CHANNEL_ID_HERE</code> with the Telegram channel_id /
            chat_id you configured below.
          </div>
          <pre style="margin-top:8px;background:#020617;border-radius:8px;border:1px solid #1f2937;padding:10px;font-size:11px;overflow-x:auto;">
<code>${trackerSnippet}</code>
          </pre>
          <div class="muted" style="margin-top:4px;">
            LP par call: <code>TelegramTracker.pageview('CHANNEL_ID_HERE', ${clientId});</code>
          </div>
        </div>

        <div class="grid-two">
          <div>
            <h2 class="section-title">Manage channels</h2>
            <div class="muted">
              Yahan per client ke saare Telegram channels ka config rakhen (pixel, LP, deep link, Meta token).
            </div>

            <form method="POST" action="/panel/client/${clientId}/channels/new">
          <div class="channels-form-row">
            <div class="field">
              <label for="telegram_title">Channel title</label>
              <input id="telegram_title" name="telegram_title" type="text" placeholder="My Telegram Channel" />
            </div>
            <div class="field">
              <label for="telegram_chat_id">Channel ID (chat_id)</label>
              <input id="telegram_chat_id" name="telegram_chat_id" type="text" required placeholder="-1001234567890" />
            </div>
            <div class="field">
              <label for="deep_link">Deep link (invite link)</label>
              <input id="deep_link" name="deep_link" type="text" placeholder="https://t.me/+xxxx" />
            </div>
            <div class="field">
              <label for="pixel_id">Pixel ID (optional)</label>
              <input id="pixel_id" name="pixel_id" type="text" placeholder="Use client/default if empty" />
            </div>
            <div class="field">
              <label for="meta_token">Meta Access Token (optional)</label>
              <input id="meta_token" name="meta_token" type="text" placeholder="Per-channel CAPI token" />
            </div>
            <div class="field">
              <label for="lp_url">Landing page URL (optional)</label>
              <input id="lp_url" name="lp_url" type="text" placeholder="https://..." />
            </div>
            <div class="field">
              <label>&nbsp;</label>
              <button type="submit" class="btn">Save channel</button>
            </div>
          </div>
        </form>

        <table>
          <thead>
            <tr>
              <th>Title</th>
              <th>Channel ID</th>
              <th>Deep link</th>
              <th>Pixel ID</th>
              <th>Meta token</th>
              <th>LP URL</th>
              <th>Status</th>
              <th>Total joins</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            ${
              channelConfigs.length === 0
                ? `<tr><td colspan="8" class="muted">No channel config yet</td></tr>`
                : channelConfigs
                    .map((ch) => {
                      const created = ch.created_at
                        ? new Date(ch.created_at * 1000).toISOString().substring(0, 10)
                        : '';
                      const status = ch.is_active ? 'Active' : 'Inactive';
                      const tot = channelTotalsMap[String(ch.telegram_chat_id)] || 0;
                      return `
              <tr>
                <td>${ch.telegram_title || '(no title)'}</td>
                <td>${ch.telegram_chat_id}</td>
                <td>${ch.deep_link || ''}</td>
                <td>${ch.pixel_id || ''}</td>
                <td>${ch.meta_token || ''}</td>
                <td>${ch.lp_url || ''}</td>
                <td>${status}</td>
                <td>${tot}</td>
                <td>${created}</td>
              </tr>`;
                    })
                    .join('')
            }
          </tbody>
        </table>
          </div>

          <div>
            <h2 class="section-title">Recent joins</h2>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Username</th>
                  <th>Channel</th>
                  <th>IP</th>
                  <th>Country</th>
                  <th>Device</th>
                  <th>Browser</th>
                  <th>OS</th>
                  <th>Source</th>
                  <th>UTM</th>
                </tr>
              </thead>
              <tbody>
                ${
                  recentJoins.length === 0
                    ? '<tr><td colspan="10" class="muted">No joins yet</td></tr>'
                    : recentJoins
                        .map((j) => {
                          const time = j.joined_at
                            ? new Date(j.joined_at * 1000).toISOString().replace('T', ' ').substring(0, 16)
                            : '';
                          const utmParts = [
                            j.utm_source ? 'src=' + j.utm_source : '',
                            j.utm_medium ? 'med=' + j.utm_medium : '',
                            j.utm_campaign ? 'cmp=' + j.utm_campaign : '',
                            j.utm_content ? 'cnt=' + j.utm_content : '',
                            j.utm_term ? 'term=' + j.utm_term : ''
                          ].filter(Boolean);
                          return `
                  <tr>
                    <td>${time}</td>
                    <td>${j.telegram_username || ''}</td>
                    <td>${j.channel_title || ''}</td>
                    <td>${j.ip || ''}</td>
                    <td>${j.country || ''}</td>
                    <td>${j.device_type || ''}</td>
                    <td>${j.browser || ''}</td>
                    <td>${j.os || ''}</td>
                    <td>${j.source || ''}</td>
                    <td>${utmParts.join(', ')}</td>
                  </tr>`;
                        })
                        .join('')
                }
              </tbody>
            </table>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('❌ Error in GET /panel/client/:id:', err);
    return res.status(500).send('Internal error');
  }
});

// POST /panel/client/:id/channels/new
app.post('/panel/client/:id/channels/new', requireAuth, (req, res) => {
  try {
    const user = req.user;
    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.status(400).send('Invalid client id');
    }

    const client = db
      .prepare('SELECT * FROM clients WHERE id = ? AND owner_user_id = ?')
      .get(clientId, user.id);
    if (!client) {
      return res.status(404).send('Client not found');
    }

    let { telegram_chat_id, telegram_title, deep_link, pixel_id, meta_token, lp_url } = req.body || {};
    telegram_chat_id = (telegram_chat_id || '').trim();
    telegram_title = (telegram_title || '').trim();
    deep_link = (deep_link || '').trim();
    pixel_id = (pixel_id || '').trim();
    meta_token = (meta_token || '').trim();
    lp_url = (lp_url || '').trim();

    if (!telegram_chat_id) {
      return res.status(400).send('telegram_chat_id is required');
    }

    const nowTs = Math.floor(Date.now() / 1000);
    const existing = db
      .prepare('SELECT * FROM channels WHERE telegram_chat_id = ?')
      .get(String(telegram_chat_id));

    if (existing) {
      db.prepare(
        `
        UPDATE channels
        SET telegram_title = ?, deep_link = ?, pixel_id = ?, meta_token = ?, lp_url = ?, client_id = ?, is_active = 1
        WHERE id = ?
      `
      ).run(
        telegram_title || existing.telegram_title,
        deep_link || existing.deep_link,
        pixel_id || existing.pixel_id,
        meta_token || existing.meta_token,
        lp_url || existing.lp_url,
        clientId,
        existing.id
      );
    } else {
      db.prepare(
        `
        INSERT INTO channels (
          client_id,
          telegram_chat_id,
          telegram_title,
          deep_link,
          pixel_id,
          meta_token,
          lp_url,
          created_at,
          is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
      `
      ).run(
        clientId,
        String(telegram_chat_id),
        telegram_title || null,
        deep_link || null,
        pixel_id || client.default_pixel_id || null,
        meta_token || null,
        lp_url || DEFAULT_PUBLIC_LP_URL,
        nowTs
      );
    }

    return res.redirect('/panel/client/' + clientId);
  } catch (err) {
    console.error('❌ Error in POST /panel/client/:id/channels/new:', err);
    return res.status(500).send('Internal error');
  }
});

// DEV: Seed admin + default client
app.get('/dev/seed-admin', async (req, res) => {
  try {
    const key = req.query.admin_secret || req.query.key;
    if (key !== ADMIN_SECRET) {
      return res.status(403).json({ ok: false, error: 'bad admin secret' });
    }

    const existingAdmin = db
      .prepare("SELECT * FROM users WHERE email = 'admin@example.com'")
      .get();
    let adminUser;
    if (!existingAdmin) {
      const password = 'admin123';
      const passwordHash = hashPassword(password);
      db.prepare(
        `
        INSERT INTO users (email, password_hash, role)
        VALUES (?, ?, 'admin')
      `
      ).run('admin@example.com', passwordHash);
      adminUser = db
        .prepare("SELECT * FROM users WHERE email = 'admin@example.com'")
        .get();
      console.log('✅ Seeded admin user: admin@example.com / admin123');
    } else {
      adminUser = existingAdmin;
    }

    const defaultClient = db
      .prepare("SELECT * FROM clients WHERE email = 'default@example.com'")
      .get();
    let client;
    if (!defaultClient) {
      const now = Math.floor(Date.now() / 1000);
      const name = 'Default Client (Seeded)';
      const slug = 'default-client';
      const apiKey = generateApiKey();
      const publicKey = 'pub_' + crypto.randomBytes(12).toString('hex');
      const secretKey = 'sec_' + crypto.randomBytes(16).toString('hex');
      const defaultPixelId = null;
      const defaultMetaToken = null;

      db.prepare(
        `
        INSERT INTO clients (
          name,
          slug,
          email,
          api_key,
          owner_user_id,
          public_key,
          secret_key,
          default_pixel_id,
          default_meta_token,
          plan,
          max_channels,
          is_active,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `
      ).run(
        name,
        slug,
        'default@example.com',
        apiKey,
        adminUser.id,
        publicKey,
        secretKey,
        defaultPixelId,
        defaultMetaToken,
        'starter',
        10,
        1,
        now
      );

      client = db
        .prepare("SELECT * FROM clients WHERE email = 'default@example.com'")
        .get();
      console.log('✅ Seeded default client for admin');
    } else {
      client = defaultClient;
    }

    return res.json({
      ok: true,
      message: 'Admin + client + keys created ✅ (one-time)',
      admin_login: {
        email: 'admin@example.com',
        password: 'admin123'
      },
      tracking_keys: {
        public_key: client.public_key,
        secret_key: client.secret_key
      }
    });
  } catch (err) {
    console.error('❌ Error in /dev/seed-admin:', err);
    return res.status(500).json({ ok: false, error: 'internal' });
  }
});

// Root
app.get('/', (req, res) => {
  res.send('Telegram funnel tracker running');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Server listening on', PORT);
});
