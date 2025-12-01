// Load environment variables from .env (Render / local dono ke liye)
require('dotenv').config();

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const db = require('./db'); // SQLite (better-sqlite3) DB connection
const geoip = require('geoip-lite');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 🔹 CORS allow for LP → backend calls
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // chahe to yaha Netlify domain daal sakte ho
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

// ----- Helper functions for tracking -----
// Client IP detect (x-forwarded-for etc.)
function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    return String(xff).split(',')[0].trim();
  }
  if (req.socket && req.socket.remoteAddress) {
    return req.socket.remoteAddress;
  }
  return null;
}

// Cloudflare / App Engine headers se country detect
function getCountryFromHeaders(req) {
  const cfCountry = req.headers['cf-ipcountry'];
  if (cfCountry && cfCountry !== 'XX') return String(cfCountry).toUpperCase();

  const gaeCountry = req.headers['x-appengine-country'];
  if (gaeCountry && gaeCountry !== 'ZZ') return String(gaeCountry).toUpperCase();

  // Fallback to geoip-lite using IP
  const ip = getClientIp(req);
  if (!ip) return null;

  const geo = geoip.lookup(ip);
  if (geo && geo.country) {
    return geo.country.toUpperCase();
  }

  return null;
}

// Simple user-agent parser (approx, but kaam ka)
function parseUserAgent(uaRaw) {
  const ua = (uaRaw || '').toLowerCase();

  let deviceType = 'unknown';
  if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
    deviceType = 'mobile';
  } else if (ua.includes('ipad') || ua.includes('tablet')) {
    deviceType = 'tablet';
  } else if (ua) {
    deviceType = 'desktop';
  }

  let browser = 'unknown';
  if (ua.includes('edg/')) browser = 'Edge';
  else if (ua.includes('chrome/')) browser = 'Chrome';
  else if (ua.includes('safari/') && !ua.includes('chrome/')) browser = 'Safari';
  else if (ua.includes('firefox/')) browser = 'Firefox';
  else if (ua.includes('opr/') || ua.includes('opera')) browser = 'Opera';

  let os = 'unknown';
  if (ua.includes('android')) os = 'Android';
  else if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) os = 'iOS';
  else if (ua.includes('windows')) os = 'Windows';
  else if (ua.includes('mac os') || ua.includes('macintosh')) os = 'macOS';
  else if (ua.includes('linux')) os = 'Linux';

  return { deviceType, browser, os };
}

// ----- Pre-lead (fbc/fbp + tracking) DB statements -----
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
    created_at
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const getRecentPreLeadStmt = db.prepare(`
  SELECT
    id,
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
    created_at
  FROM pre_leads
  WHERE channel_id = ?
    AND created_at >= ?
  ORDER BY created_at DESC
  LIMIT 1
`);

const markPreLeadUsedStmt = null; // used column optional; abhi hum use nahi kar rahe

// ----- Config from env -----
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const META_ACCESS_TOKEN = process.env.META_ACCESS_TOKEN;
const ADMIN_KEY = process.env.ADMIN_KEY || 'secret123';


// ----- Simple admin login + SaaS panel (multi-client) -----

function requireAuth(req, res, next) {
  try {
    const session = req.cookies && req.cookies.uts_admin;
    if (!session || session !== ADMIN_KEY) {
      return res.redirect('/login');
    }
    next();
  } catch (e) {
    console.error('Auth error:', e);
    return res.redirect('/login');
  }
}

app.get('/login', (req, res) => {
  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>UTS Login</title>
  <style>
    body { background:#050509; color:#fff; font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
    .card { background:#111827; padding:24px 28px; border-radius:16px; width:100%; max-width:360px; box-shadow:0 22px 45px rgba(0,0,0,0.55); }
    h1 { font-size:20px; margin:0 0 4px; }
    p { margin:0 0 16px; color:#9CA3AF; font-size:13px; }
    label { display:block; font-size:13px; margin-bottom:4px; color:#E5E7EB; }
    input { width:100%; padding:9px 10px; border-radius:10px; border:1px solid #1F2937; background:#020617; color:#E5E7EB; font-size:13px; outline:none; }
    input:focus { border-color:#3B82F6; box-shadow:0 0 0 1px rgba(59,130,246,0.4); }
    .field { margin-bottom:14px; }
    button { width:100%; padding:10px 12px; border-radius:999px; border:none; background:#3B82F6; color:white; font-weight:600; font-size:14px; cursor:pointer; }
    button:hover { filter:brightness(1.1); }
    .hint { margin-top:12px; font-size:11px; color:#6B7280; }
  </style>
</head>
<body>
  <div class="card">
    <h1>UTS Admin Login</h1>
    <p>Enter your admin key to access the panel.</p>
    <form method="POST" action="/login">
      <div class="field">
        <label for="key">Admin key</label>
        <input id="key" name="key" type="password" placeholder="Enter ADMIN_KEY" />
      </div>
      <button type="submit">Login</button>
    </form>
    <div class="hint">
      Use the <code>ADMIN_KEY</code> from your Render / .env settings.
    </div>
  </div>
</body>
</html>`);
});

app.post('/login', (req, res) => {
  const key = (req.body && req.body.key) || '';
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).send('<p style="font-family:sans-serif;color:#fff;background:#000;padding:20px;">Invalid key. <a href="/login" style="color:#3B82F6;">Try again</a>.</p>');
  }
  res.cookie('uts_admin', key, { httpOnly: true, sameSite: 'lax' });
  return res.redirect('/panel');
});

app.get('/logout', (req, res) => {
  res.clearCookie('uts_admin');
  res.redirect('/login');
});

// Panel home: list all clients
app.get('/panel', requireAuth, (req, res) => {
  try {
    const clients = db
      .prepare('SELECT * FROM clients ORDER BY id DESC')
      .all();

    const rows = clients
      .map((cl) => {
        const plan = cl.plan || '';
        const maxCh = cl.max_channels != null ? cl.max_channels : '';
        const status = cl.is_active === 0 ? 'Disabled' : 'Active';
        return `
        <tr>
          <td>${cl.id}</td>
          <td>${cl.name || ''}</td>
          <td>${cl.slug || ''}</td>
          <td>${cl.public_key || ''}</td>
          <td>${cl.secret_key || ''}</td>
          <td>${plan}</td>
          <td>${maxCh}</td>
          <td>${status}</td>
          <td>${cl.created_at || ''}</td>
          <td><a href="/panel/client/${cl.id}" style="color:#60A5FA;">Open</a></td>
        </tr>`;
      })
      .join('') || '<tr><td colspan="10" style="padding:12px;color:#6B7280;">No clients yet.</td></tr>';

    res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>UTS Panel</title>
  <style>
    body { background:#020617; color:#E5E7EB; font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin:0; padding:24px; }
    h1 { margin:0 0 4px; font-size:22px; }
    h2 { margin:24px 0 10px; font-size:16px; }
    .topbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
    .pill { font-size:12px; padding:4px 8px; border-radius:999px; background:#111827; color:#9CA3AF; }
    table { border-collapse:collapse; width:100%; font-size:13px; }
    th, td { border:1px solid #1F2937; padding:6px 8px; text-align:left; }
    th { background:#020617; }
    tr:nth-child(even) td { background:#020617; }
    tr:nth-child(odd) td { background:#030712; }
    .form-row { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }
    input, select { padding:6px 8px; border-radius:8px; border:1px solid #374151; background:#020617; color:#E5E7EB; font-size:12px; min-width:140px; }
    button { padding:7px 12px; border-radius:999px; border:none; background:#3B82F6; color:white; font-size:12px; cursor:pointer; }
  </style>
</head>
<body>
  <div class="topbar">
    <div>
      <h1>Universal Tracking Panel</h1>
      <div class="pill">Admin workspace</div>
    </div>
    <div>
      <a href="/dashboard" style="color:#9CA3AF;font-size:12px;margin-right:12px;">Global Dashboard</a>
      <a href="/logout" style="color:#F87171;font-size:12px;">Logout</a>
    </div>
  </div>

  <h2>Create new client</h2>
  <form method="POST" action="/panel/create-client">
    <div class="form-row">
      <input name="name" placeholder="Client name" required />
      <input name="slug" placeholder="Slug (optional)" />
      <select name="plan">
        <option value="starter">starter</option>
        <option value="pro">pro</option>
      </select>
      <input name="max_channels" type="number" placeholder="Max channels (optional)" />
    </div>
    <button type="submit">Create client</button>
  </form>

  <h2 style="margin-top:24px;">All clients</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Name</th>
        <th>Slug</th>
        <th>Public key</th>
        <th>Secret key</th>
        <th>Plan</th>
        <th>Max channels</th>
        <th>Status</th>
        <th>Created</th>
        <th>Open</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
</body>
</html>`);
  } catch (err) {
    console.error('❌ Error in /panel:', err);
    res.status(500).send('Internal panel error');
  }
});

app.post('/panel/create-client', requireAuth, (req, res) => {
  try {
    let { name, slug, plan, max_channels } = req.body || {};
    name = (name || '').trim();
    slug = (slug || '').trim() || null;
    plan = (plan || 'starter').trim();
    max_channels = max_channels ? Number(max_channels) : null;

    if (!name) {
      return res.status(400).send('Client name required');
    }

    const publicKey = 'PUB_' + Math.random().toString(36).slice(2, 10);
    const secretKey = 'SEC_' + Math.random().toString(36).slice(2, 10);
    const now = Math.floor(Date.now() / 1000);

    db.prepare(
      `
      INSERT INTO clients (
        name,
        slug,
        public_key,
        secret_key,
        plan,
        max_channels,
        is_active,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `
    ).run(name, slug, publicKey, secretKey, plan, max_channels, now);

    return res.redirect('/panel');
  } catch (err) {
    console.error('❌ Error in POST /panel/create-client:', err);
    return res.status(500).send('Error creating client');
  }
});

app.get('/panel/client/:id', requireAuth, (req, res) => {
  try {
    const clientId = Number(req.params.id);
    if (!clientId) {
      return res.status(400).send('Invalid client id');
    }

    const client = db
      .prepare('SELECT * FROM clients WHERE id = ?')
      .get(clientId);

    if (!client) {
      return res.status(404).send('Client not found');
    }

    const channels = db
      .prepare('SELECT * FROM channels WHERE client_id = ? ORDER BY id DESC')
      .all(clientId);

    // Join counts per channel (by telegram_chat_id)
    const joinCounts = {};
    channels.forEach((ch) => {
      const row = db
        .prepare(
          'SELECT COUNT(*) AS cnt FROM joins WHERE channel_id = ?'
        )
        .get(String(ch.telegram_chat_id));
      joinCounts[ch.id] = row && row.cnt ? row.cnt : 0;
    });

    const channelRows =
      channels
        .map((ch) => {
          const status = ch.is_active === 0 ? 'Disabled' : 'Active';
          const totalJoins = joinCounts[ch.id] || 0;
          const created = ch.created_at ? new Date(ch.created_at * 1000).toISOString() : '';
          return `
          <tr>
            <td>${ch.id}</td>
            <td>${ch.telegram_title || ''}</td>
            <td>${ch.telegram_chat_id || ''}</td>
            <td>${ch.deep_link || ''}</td>
            <td>${ch.pixel_id || ''}</td>
            <td>${ch.lp_url || ''}</td>
            <td>${status}</td>
            <td>${totalJoins}</td>
            <td>${created}</td>
          </tr>`;
        })
        .join('') ||
      '<tr><td colspan="9" style="padding:12px;color:#6B7280;">No channels for this client yet.</td></tr>';

    res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Client ${client.id} · UTS Panel</title>
  <style>
    body { background:#020617; color:#E5E7EB; font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin:0; padding:24px; }
    h1 { margin:0 0 4px; font-size:22px; }
    h2 { margin:24px 0 10px; font-size:16px; }
    .topbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
    .pill { font-size:12px; padding:4px 8px; border-radius:999px; background:#111827; color:#9CA3AF; }
    table { border-collapse:collapse; width:100%; font-size:13px; margin-top:12px; }
    th, td { border:1px solid #1F2937; padding:6px 8px; text-align:left; }
    th { background:#020617; }
    tr:nth-child(even) td { background:#020617; }
    tr:nth-child(odd) td { background:#030712; }
    .meta { font-size:12px; color:#9CA3AF; }
    .meta code { background:#020617; padding:2px 4px; border-radius:4px; }
  </style>
</head>
<body>
  <div class="topbar">
    <div>
      <h1>${client.name || 'Client'} (ID: ${client.id})</h1>
      <div class="pill">Slug: ${client.slug || '—'}</div>
    </div>
    <div>
      <a href="/panel" style="color:#9CA3AF;font-size:12px;margin-right:12px;">← Back to clients</a>
      <a href="/logout" style="color:#F87171;font-size:12px;">Logout</a>
    </div>
  </div>

  <div class="meta">
    <div>Public key: <code>${client.public_key || '—'}</code></div>
    <div>Secret key: <code>${client.secret_key || '—'}</code></div>
    <div>Default pixel: <code>${client.default_pixel_id || '—'}</code></div>
    <div>Default Meta token: <code>${client.default_meta_token || '—'}</code></div>
    <div>Plan: <code>${client.plan || '—'}</code> · Max channels: <code>${client.max_channels != null ? client.max_channels : '—'}</code></div>
  </div>

  <h2>Channels for this client</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Channel title</th>
        <th>Chat ID</th>
        <th>Deep link</th>
        <th>Pixel ID</th>
        <th>LP URL</th>
        <th>Status</th>
        <th>Total joins</th>
        <th>Created</th>
      </tr>
    </thead>
    <tbody>
      ${channelRows}
    </tbody>
  </table>
</body>
</html>`);
  } catch (err) {
    console.error('❌ Error in GET /panel/client/:id:', err);
    res.status(500).send('Internal client panel error');
  }
});


// Default Pixel & LP (fallback)
const DEFAULT_META_PIXEL_ID = '1430358881781923';
const DEFAULT_PUBLIC_LP_URL = 'btcapi.netlify.app/';

const TELEGRAM_API = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;
const PORT = process.env.PORT || 3000;

// ----- Helpers -----

// Meta user_data ke liye hash
function hashSha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// Date ko YYYY-MM-DD string me
function formatDateYYYYMMDD(timestamp) {
  const d = new Date(timestamp * 1000);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

// Random event_id for Meta dedup
function generateEventId() {
  return crypto.randomBytes(16).toString('hex');
}

// ----- Basic health route -----
app.get('/', (req, res) => {
  res.send('Telegram Funnel Bot running ✅');
});

// ----- Debug: last joins -----
app.get('/debug-joins', (req, res) => {
  try {
    const rows = db
      .prepare('SELECT * FROM joins ORDER BY id DESC LIMIT 20')
      .all();
    res.json(rows);
  } catch (err) {
    console.error('❌ Error reading joins:', err.message);
    res.status(500).json({ error: 'DB error' });
  }
});

// ----- Debug: channels table -----
app.get('/debug-channels', (req, res) => {
  try {
    const rows = db
      .prepare('SELECT * FROM channels ORDER BY id DESC LIMIT 20')
      .all();
    res.json(rows);
  } catch (err) {
    console.error('❌ Error reading channels:', err.message);
    res.status(500).json({ error: 'DB error' });
  }
});

// ----- NEW: SaaS-style pageview tracking (multi-client via public_key) -----
// Yaha sirf gating ho rahi hai public_key se.
// Insert same hai jo /pre-lead use karta hai → DB error nahi aayega.
app.post('/api/v1/track/pageview', (req, res) => {
  try {
    const {
      public_key,
      channel_id,
      fbc,
      fbp,
      source,
      utm_source,
      utm_medium,
      utm_campaign,
      utm_content,
      utm_term,
    } = req.body || {};

    if (!public_key) {
      return res.status(400).json({ ok: false, error: 'public_key required' });
    }
    if (!channel_id) {
      return res.status(400).json({ ok: false, error: 'channel_id required' });
    }

    // Client lookup (multi-tenant gate)
    const client = db
      .prepare('SELECT * FROM clients WHERE public_key = ?')
      .get(String(public_key));

    if (!client) {
      return res.status(403).json({ ok: false, error: 'invalid public_key' });
    }

    const now = Math.floor(Date.now() / 1000);
    const ip = getClientIp(req);
    const country = getCountryFromHeaders(req);
    const userAgent = req.headers['user-agent'] || null;
    const { deviceType, browser, os } = parseUserAgent(userAgent);

    // Insert exactly like /pre-lead (without client_id)
    insertPreLeadStmt.run(
      String(channel_id),
      fbc || null,
      fbp || null,
      ip || null,
      country || null,
      userAgent || null,
      deviceType || null,
      browser || null,
      os || null,
      source || null,
      utm_source || null,
      utm_medium || null,
      utm_campaign || null,
      utm_content || null,
      utm_term || null,
      now
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Error in /api/v1/track/pageview:', err.message || err);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ----- Old LP endpoint: pre-lead capture (fbc/fbp + tracking store) -----
app.post('/pre-lead', (req, res) => {
  try {
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
    } = req.body || {};

    if (!channel_id) {
      return res
        .status(400)
        .json({ ok: false, error: 'channel_id required' });
    }

    const now = Math.floor(Date.now() / 1000);

    const ip = getClientIp(req);
    const country = getCountryFromHeaders(req);
    const userAgent = req.headers['user-agent'] || null;
    const { deviceType, browser, os } = parseUserAgent(userAgent);

    insertPreLeadStmt.run(
      String(channel_id),
      fbc || null,
      fbp || null,
      ip || null,
      country || null,
      userAgent || null,
      deviceType || null,
      browser || null,
      os || null,
      source || null,
      utm_source || null,
      utm_medium || null,
      utm_campaign || null,
      utm_content || null,
      utm_term || null,
      now
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Error in /pre-lead:', err.message || err);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ----- Telegram webhook -----
app.post('/telegram-webhook', async (req, res) => {
  const update = req.body;
  console.log('Incoming update:', JSON.stringify(update, null, 2));

  try {
    if (update.chat_join_request) {
      const jr = update.chat_join_request;
      const user = jr.from;
      const chat = jr.chat;

      // 1) Try approve join request
      try {
        await approveJoinRequest(chat.id, user.id);
        console.log('✅ Approved join request for user:', user.id);
      } catch (e) {
        console.error('❌ Telegram approveChatJoinRequest error RAW:');
        console.error('MESSAGE:', e.message);
        console.error('IS_AXIOS_ERROR:', e.isAxiosError);
        if (e.response) {
          console.error('STATUS:', e.response.status);
          console.error('DATA:', JSON.stringify(e.response.data, null, 2));
        } else {
          console.error('NO RESPONSE OBJECT, FULL ERROR:', e);
        }
      }

      // 2) Fire Meta CAPI in background (not blocking webhook)
      try {
        sendMetaLeadEvent(user, jr).catch((e) => {
          console.error(
            '❌ Meta CAPI sendMetaLeadEvent error:',
            e.response?.data || e.message || e
          );
        });
      } catch (e) {
        console.error(
          '❌ Meta CAPI (outer try) error:',
          e.response?.data || e.message || e
        );
      }
    }

    // ✅ Always reply 200 to Telegram so woh retry na kare
    res.sendStatus(200);
  } catch (err) {
    console.error(
      '❌ Error in webhook handler (outer):',
      err.response?.data || err.message || err
    );
    // still 200 to avoid Telegram retries spam
    res.sendStatus(200);
  }
});

// ----- Helper: approve join request -----
async function approveJoinRequest(chatId, userId) {
  const url = `${TELEGRAM_API}/approveChatJoinRequest`;
  const payload = {
    chat_id: chatId,
    user_id: userId,
  };

  const res = await axios.post(url, payload);
  console.log('Telegram approve response:', res.data);
}

// ----- Helper: channel config nikaalna ya auto-create karna -----
function getOrCreateChannelConfigFromJoin(joinRequest, nowTs) {
  const chat = joinRequest.chat;
  const telegramChatId = String(chat.id);

  let channel = db
    .prepare('SELECT * FROM channels WHERE telegram_chat_id = ?')
    .get(telegramChatId);

  if (!channel) {
    // Agar channel row nahi hai to naya bana do (default client_id = 1)
    const stmt = db.prepare(`
      INSERT INTO channels (
        client_id,
        telegram_chat_id,
        telegram_title,
        deep_link,
        pixel_id,
        lp_url,
        created_at,
        is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `);

    const info = stmt.run(
      1, // default client
      telegramChatId,
      chat.title || null,
      null, // deep_link abhi null
      DEFAULT_META_PIXEL_ID,
      DEFAULT_PUBLIC_LP_URL,
      nowTs
    );

    channel = {
      id: info.lastInsertRowid,
      client_id: 1,
      telegram_chat_id: telegramChatId,
      telegram_title: chat.title || null,
      deep_link: null,
      pixel_id: DEFAULT_META_PIXEL_ID,
      lp_url: DEFAULT_PUBLIC_LP_URL,
      created_at: nowTs,
      is_active: 1,
    };

    console.log('🆕 Auto-created channel row:', channel);
  } else {
    // Optionally: agar title change ho gaya ho to update
    if (chat.title && chat.title !== channel.telegram_title) {
      db.prepare(
        'UPDATE channels SET telegram_title = ? WHERE id = ?'
      ).run(chat.title, channel.id);
      channel.telegram_title = chat.title;
    }
  }

  return channel;
}

// ----- Helper: Meta CAPI Lead + DB insert -----
async function sendMetaLeadEvent(user, joinRequest) {
  const eventTime = Math.floor(Date.now() / 1000);
  const channelId = String(joinRequest.chat.id);

  // 🔹 Last 30 minutes ke andar iss channel ke liye koi pre_lead mila?
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

  // ⭐ Debug log to see which fbc/fbp were used
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
    utmTermForThisLead,
  });

  // Channel config (pixel, LP, client)
  const channelConfig = getOrCreateChannelConfigFromJoin(
    joinRequest,
    eventTime
  );

  const pixelId = channelConfig.pixel_id || DEFAULT_META_PIXEL_ID;
  const lpUrl = channelConfig.lp_url || DEFAULT_PUBLIC_LP_URL;

  const url = `https://graph.facebook.com/v18.0/${pixelId}/events?access_token=${META_ACCESS_TOKEN}`;

  const externalIdHash = hashSha256(String(user.id));
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
    user_data: userData
  };

  if (Object.keys(customData).length > 0) {
    eventBody.custom_data = customData;
  }

  const payload = {
    data: [eventBody]
  };

  const res = await axios.post(url, payload);
  console.log('Meta CAPI response:', res.data);

  // ✅ Joins table me log karein – ID ko insert nahi kar rahe, SQLite auto increment karega
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
      )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `
  ).run(
    String(user.id),
    user.username || null,
    String(joinRequest.chat.id),
    joinRequest.chat.title || null,
    eventTime,
    eventId,
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
      pixel_id,
      lp_url,
      client_id,
      deep_link,
    } = req.body;

    if (admin_key !== ADMIN_KEY) {
      return res.status(401).json({ ok: false, error: 'Unauthorized' });
    }

    if (!telegram_chat_id) {
      return res
        .status(400)
        .json({ ok: false, error: 'telegram_chat_id required' });
    }

    const channel = db
      .prepare('SELECT * FROM channels WHERE telegram_chat_id = ?')
      .get(String(telegram_chat_id));

    if (!channel) {
      return res
        .status(404)
        .json({ ok: false, error: 'Channel not found' });
    }

    const newPixel = pixel_id || channel.pixel_id;
    const newLp = lp_url || channel.lp_url;
    const newClientId = client_id || channel.client_id;
    const newDeepLink = deep_link || channel.deep_link;

    db.prepare(
      `
      UPDATE channels
      SET pixel_id = ?, lp_url = ?, client_id = ?, deep_link = ?
      WHERE telegram_chat_id = ?
    `
    ).run(
      newPixel,
      newLp,
      newClientId,
      newDeepLink,
      String(telegram_chat_id)
    );

    return res.json({
      ok: true,
      message: 'Channel updated',
      data: {
        telegram_chat_id,
        pixel_id: newPixel,
        lp_url: newLp,
        client_id: newClientId,
        deep_link: newDeepLink,
      },
    });
  } catch (err) {
    console.error('❌ Error in /admin/update-channel:', err);
    res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

// ----- JSON Stats API: /api/stats -----
app.get('/api/stats', (req, res) => {
  try {
    // Total joins
    const totalRow = db.prepare('SELECT COUNT(*) AS cnt FROM joins').get();
    const totalJoins = totalRow.cnt || 0;

    // Today joins
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfDayTs = Math.floor(startOfDay.getTime() / 1000);

    const todayRow = db
      .prepare(
        'SELECT COUNT(*) AS cnt FROM joins WHERE joined_at >= ? AND joined_at <= ?'
      )
      .get(startOfDayTs, now);
    const todayJoins = todayRow.cnt || 0;

    // Last 7 days breakdown
    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;
    const rows7 = db
      .prepare(
        'SELECT joined_at FROM joins WHERE joined_at >= ? ORDER BY joined_at ASC'
      )
      .all(sevenDaysAgoTs);

    const byDateMap = {};
    for (const r of rows7) {
      const dateKey = formatDateYYYYMMDD(r.joined_at);
      byDateMap[dateKey] = (byDateMap[dateKey] || 0) + 1;
    }

    const last7Days = Object.keys(byDateMap)
      .sort()
      .map((date) => ({ date, count: byDateMap[date] }));

    // By channel
    const channels = db
      .prepare(
        `
        SELECT 
          channel_id,
          channel_title,
          COUNT(*) AS total
        FROM joins
        GROUP BY channel_id, channel_title
        ORDER BY total DESC
      `
      )
      .all();

    // Recent joins with tracking (for UI)
    const recentJoins = db
      .prepare(
        `
        SELECT
          telegram_username,
          channel_title,
          channel_id,
          joined_at,
          ip,
          country,
          device_type,
          browser,
          os,
          source,
          utm_source,
          utm_medium,
          utm_campaign,
          utm_content,
          utm_term
        FROM joins
        ORDER BY joined_at DESC
        LIMIT 50
      `
      )
      .all();

    res.json({
      ok: true,
      total_joins: totalJoins,
      today_joins: todayJoins,
      last_7_days: last7Days,
      by_channel: channels,
      recent_joins: recentJoins,
    });
  } catch (err) {
    console.error('❌ Error in /api/stats:', err);
    res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

// ----- HTML Dashboard: /dashboard -----
app.get('/dashboard', (req, res) => {
  try {
    const totalRow = db.prepare('SELECT COUNT(*) AS cnt FROM joins').get();
    const totalJoins = totalRow.cnt || 0;

    const now = Math.floor(Date.now() / 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfDayTs = Math.floor(startOfDay.getTime() / 1000);

    const todayRow = db
      .prepare(
        'SELECT COUNT(*) AS cnt FROM joins WHERE joined_at >= ? AND joined_at <= ?'
      )
      .get(startOfDayTs, now);
    const todayJoins = todayRow.cnt || 0;

    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;
    const rows7 = db
      .prepare(
        'SELECT joined_at FROM joins WHERE joined_at >= ? ORDER BY joined_at ASC'
      )
      .all(sevenDaysAgoTs);

    const byDateMap = {};
    for (const r of rows7) {
      const dateKey = formatDateYYYYMMDD(r.joined_at);
      byDateMap[dateKey] = (byDateMap[dateKey] || 0) + 1;
    }

    const last7Days = Object.keys(byDateMap)
      .sort()
      .map((date) => ({ date, count: byDateMap[date] }));

    const channels = db
      .prepare(
        `
        SELECT 
          channel_id,
          channel_title,
          COUNT(*) AS total
        FROM joins
        GROUP BY channel_id, channel_title
        ORDER BY total DESC
      `
      )
      .all();

    const recentJoins = db
      .prepare(
        `
        SELECT
          telegram_username,
          channel_title,
          channel_id,
          joined_at,
          ip,
          country,
          device_type,
          browser,
          os,
          source,
          utm_source,
          utm_medium,
          utm_campaign,
          utm_content,
          utm_term
        FROM joins
        ORDER BY joined_at DESC
        LIMIT 50
      `
      )
      .all();

    // Simple HTML UI
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Telegram Funnel Stats</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
          body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #0f172a;
            color: #e5e7eb;
            padding: 24px;
          }
          .container {
            max-width: 1100px;
            margin: 0 auto;
          }
          h1 {
            font-size: 24px;
            margin-bottom: 16px;
          }
          .cards {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 24px;
          }
          .card {
            background: #111827;
            border-radius: 12px;
            padding: 16px 18px;
            flex: 1 1 180px;
            min-width: 180px;
          }
          .card h2 {
            font-size: 14px;
            color: #9ca3af;
            margin-bottom: 8px;
          }
          .card .value {
            font-size: 22px;
            font-weight: 600;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
          }
          th, td {
            padding: 8px 10px;
            border-bottom: 1px solid #1f2937;
            font-size: 12px;
          }
          th {
            text-align: left;
            color: #9ca3af;
            white-space: nowrap;
          }
          td {
            white-space: nowrap;
          }
          tr:hover {
            background: #111827;
          }
          .section-title {
            font-size: 16px;
            margin: 16px 0 8px;
          }
          .muted {
            color: #6b7280;
            font-size: 12px;
          }
          .nowrap {
            white-space: nowrap;
          }
          @media (max-width: 900px) {
            table {
              display: block;
              overflow-x: auto;
            }
          }
          @media (max-width: 600px) {
            .cards {
              flex-direction: column;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Telegram Funnel Stats 📊</h1>

          <div class="cards">
            <div class="card">
              <h2>Total Joins</h2>
              <div class="value">${totalJoins}</div>
            </div>
            <div class="card">
              <h2>Today Joins</h2>
              <div class="value">${todayJoins}</div>
            </div>
          </div>

          <div>
            <div class="section-title">Last 7 Days</div>
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Joins</th>
                </tr>
              </thead>
              <tbody>
                ${
                  last7Days.length === 0
                    ? `<tr><td colspan="2" class="muted">No data yet</td></tr>`
                    : last7Days
                        .map(
                          (d) => `
                  <tr>
                    <td>${d.date}</td>
                    <td>${d.count}</td>
                  </tr>`
                        )
                        .join('')
                }
              </tbody>
            </table>
          </div>

          <div>
            <div class="section-title">By Channel</div>
            <table>
              <thead>
                <tr>
                  <th>Channel Title</th>
                  <th>Channel ID</th>
                  <th>Total Joins</th>
                </tr>
              </thead>
              <tbody>
                ${
                  channels.length === 0
                    ? `<tr><td colspan="3" class="muted">No data yet</td></tr>`
                    : channels
                        .map(
                          (c) => `
                  <tr>
                    <td>${c.channel_title || '(no title)'}</td>
                    <td>${c.channel_id}</td>
                    <td>${c.total}</td>
                  </tr>`
                        )
                        .join('')
                }
              </tbody>
            </table>
          </div>

          <div>
            <div class="section-title">Recent Joins (Tracking Details)</div>
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
                  <th>UTM Source</th>
                  <th>UTM Medium</th>
                  <th>UTM Campaign</th>
                  <th>UTM Content</th>
                  <th>UTM Term</th>
                </tr>
              </thead>
              <tbody>
                ${
                  recentJoins.length === 0
                    ? `<tr><td colspan="14" class="muted">No joins yet</td></tr>`
                    : recentJoins
                        .map((j) => {
                          const dt = new Date(j.joined_at * 1000).toISOString().replace('T',' ').substring(0,19);
                          return `
                  <tr>
                    <td class="nowrap">${dt}</td>
                    <td>${j.telegram_username || '(no username)'}</td>
                    <td>${j.channel_title || ''}</td>
                    <td>${j.ip || ''}</td>
                    <td>${j.country || ''}</td>
                    <td>${j.device_type || ''}</td>
                    <td>${j.browser || ''}</td>
                    <td>${j.os || ''}</td>
                    <td>${j.source || ''}</td>
                    <td>${j.utm_source || ''}</td>
                    <td>${j.utm_medium || ''}</td>
                    <td>${j.utm_campaign || ''}</td>
                    <td>${j.utm_content || ''}</td>
                    <td>${j.utm_term || ''}</td>
                  </tr>`;
                        })
                        .join('')
                }
              </tbody>
            </table>
          </div>

          <div class="muted">
            Simple v2 dashboard – tracking with IP, device, browser, OS, source & UTM.
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('❌ Error in /dashboard:', err);
    res.status(500).send('Internal error');
  }
});

// ----- DEV: Seed admin + client + keys (one-time helper) -----
app.get('/dev/seed-admin', async (req, res) => {
  try {
    const key = req.query.admin_key;
    if (key !== ADMIN_KEY) {
      return res.status(401).json({ ok: false, error: 'Invalid admin_key' });
    }

    // 1) Check if any admin user already exists
    const existingAdmin = db.prepare(
      'SELECT * FROM users WHERE role = ? LIMIT 1'
    ).get('admin');

    if (existingAdmin) {
      return res.json({
        ok: true,
        message: 'Admin already exists, nothing to do.',
        admin_email: existingAdmin.email
      });
    }

    const now = Math.floor(Date.now() / 1000);

    const email = 'admin@uts.local';   // dev ke liye, baad me change kar dena
    const password = 'Admin@123';      // dev ke liye, UI banne ke baad reset karna

    const password_hash = await bcrypt.hash(password, 10);

    // 2) Insert admin user
    const insertUser = db.prepare(`
      INSERT INTO users (email, password_hash, role, created_at)
      VALUES (?, ?, ?, ?)
    `);

    const userResult = insertUser.run(email, password_hash, 'admin', now);
    const userId = userResult.lastInsertRowid;

    // 3) Random public/secret keys
    const publicKey = 'PUB_' + Math.random().toString(36).slice(2, 10);
    const secretKey = 'SEC_' + Math.random().toString(36).slice(2, 10);

    // 4) Insert client row for this admin
    const insertClient = db.prepare(`
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
    `);

    insertClient.run(
      'Rahul Main Workspace',
      'rahul-main',
      userId,
      publicKey,
      secretKey,
      process.env.META_PIXEL_ID || null,
      process.env.META_ACCESS_TOKEN || null,
      'starter',
      3,
      1,
      now
    );

    return res.json({
      ok: true,
      message: 'Admin + client + keys created ✅ (one-time)',
      admin_login: {
        email,
        password
      },
      tracking_keys: {
        public_key: publicKey,
        secret_key: secretKey
      }
    });
  } catch (err) {
    console.error('❌ Error in /dev/seed-admin:', err);
    res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

// ----- Start server -----
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
