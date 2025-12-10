// Load environment variables from .env (Render / local dono ke liye)
require('dotenv').config();

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const db = require('./db'); // SQLite (better-sqlite3) DB connection
const geoip = require('geoip-lite');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve static frontend for Phase 1 React UI
app.use('/frontend', express.static(path.join(__dirname, 'frontend')));

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


// ----- Auth helpers (simple HMAC token in cookie) -----
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_me_please';

// Token format: "userId.signature"
function signAuthToken(userId) {
  const payload = String(userId);
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('hex');
  return `${payload}.${sig}`;
}

function verifyAuthToken(token) {
  if (!token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('hex');
  if (sig !== expected) return null;

  const id = parseInt(payload, 10);
  if (!id || Number.isNaN(id)) return null;
  return id;
}

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.auth;
  const userId = verifyAuthToken(token);

  if (!userId) {
    return res.redirect('/login');
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) {
    res.clearCookie('auth');
    return res.redirect('/login');
  }

  req.user = user;
  next();
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
function slugifyForUrl(input) {
  return String(input || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .substr(0, 60) || 'lp';
}

function generateLpSlug(baseName) {
  const core = slugifyForUrl(baseName);
  const rand = crypto.randomBytes(3).toString('hex'); // 6 hex chars
  return core + '-' + rand;
}

function generateEventId() {
  return crypto.randomBytes(16).toString('hex');
}

function generateKey(prefix) {
  const rand = crypto.randomBytes(6).toString('hex'); // 12 hex chars
  return `${prefix}_${rand}`;
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


// ----- New LP endpoint: lightweight pre-lead tracking (auto LP button click) -----
// ----- LP Event tracking (per-landing-page views / clicks / pre-leads) -----
app.post('/api/v1/lp-event', (req, res) => {
  try {
    const { public_key, channel_id, lp_id, event_type, source } = req.body || {};

    if (!public_key || !channel_id || !lp_id || !event_type) {
      return res.status(400).json({ ok: false, error: 'missing_fields' });
    }

    const client = db
      .prepare('SELECT * FROM clients WHERE public_key = ?')
      .get(String(public_key));

    if (!client) {
      return res.status(403).json({ ok: false, error: 'invalid_public_key' });
    }

    const lpRow = db
      .prepare('SELECT * FROM landing_pages WHERE id = ? AND client_id = ? AND channel_id = ? LIMIT 1')
      .get(parseInt(lp_id, 10), client.id, parseInt(channel_id, 10));

    if (!lpRow) {
      return res.status(404).json({ ok: false, error: 'lp_not_found' });
    }

    const now = Math.floor(Date.now() / 1000);
    const ip = getClientIp(req);
    const country = getCountryFromHeaders(req);
    const userAgent = req.headers['user-agent'] || null;
    const { deviceType, browser, os } = parseUserAgent(userAgent);

    db.prepare(`
      INSERT INTO lp_events (
        client_id,
        channel_id,
        lp_id,
        event_type,
        ip,
        country,
        user_agent,
        device_type,
        browser,
        os,
        source,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      client.id,
      parseInt(channel_id, 10),
      parseInt(lp_id, 10),
      String(event_type),
      ip || null,
      country || null,
      userAgent || null,
      deviceType || null,
      browser || null,
      os || null,
      source || null,
      now
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Error in /api/v1/lp-event:', err.message || err);
    return res.status(500).json({ ok: false, error: 'internal_error' });
  }
});


app.post('/api/v1/track/pre-lead', (req, res) => {
  try {
    const {
      public_key,
      channel_id,
      source,
      url
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

    // Minimal insert – no fbc/fbp/utms here yet, but compatible with schema
    insertPreLeadStmt.run(
      String(channel_id),
      null, // fbc
      null, // fbp
      ip || null,
      country || null,
      userAgent || null,
      deviceType || null,
      browser || null,
      os || null,
      source || 'lp_click',
      null, // utm_source
      null, // utm_medium
      null, // utm_campaign
      url || null, // store LP URL in utm_content for now
      null, // utm_term
      now
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error('❌ Error in /api/v1/track/pre-lead:', err.message || err);
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
        lp_event_mode,
        lp_anti_crawler,
        created_at,
        is_active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `);

    const info = stmt.run(
      1, // default client
      telegramChatId,
      chat.title || null,
      null, // deep_link abhi null
      DEFAULT_META_PIXEL_ID,
      null,
      'lead',
      0,
      nowTs
    );

    channel = {
      id: info.lastInsertRowid,
      client_id: 1,
      telegram_chat_id: telegramChatId,
      telegram_title: chat.title || null,
      deep_link: null,
      pixel_id: DEFAULT_META_PIXEL_ID,
      lp_url: null,
      lp_event_mode: 'lead',
      lp_anti_crawler: 0,
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

  const lpUrl = channelConfig.lp_url || null;
  const lpModeRaw = (channelConfig.lp_event_mode || '').toLowerCase();
  const serverEventName = lpModeRaw === 'subscribe' ? 'Subscribe' : 'Lead';

  // Pixel & Meta access token strictly from channel config.
  // No default pixel or token should be applied if user didn't provide them.
  const pixelId =
    (channelConfig.pixel_id && String(channelConfig.pixel_id).trim()) || null;
  const tokenToUse =
    (channelConfig.meta_token && String(channelConfig.meta_token).trim()) || null;

  const hasPixel = !!pixelId;
  const hasToken = !!tokenToUse;

  let shouldSendCapi = false;

  if (hasPixel && hasToken) {
    // Pixel + token both present: send CAPI + store in DB
    shouldSendCapi = true;
  } else if (hasPixel && !hasToken) {
    // Pixel hai, lekin Meta access token nahi → sirf DB me store, CAPI skip
    console.log(
      'ℹ️ Pixel ID is set but Meta access token is missing. Skipping CAPI send, only storing join in DB.'
    );
  } else if (!hasPixel && hasToken) {
    // Meta token hai, lekin pixel nahi → pixel ke bina CAPI request valid nahi hoti
    console.log(
      'ℹ️ Meta access token is set but Pixel ID is missing. Cannot send CAPI without pixel. Only storing join in DB.'
    );
  } else {
    // Dono missing → sirf DB
    console.log(
      'ℹ️ No Pixel ID or Meta access token configured for this channel. Only storing join in DB.'
    );
  }

  const url =
    shouldSendCapi && pixelId && tokenToUse
      ? `https://graph.facebook.com/v18.0/${pixelId}/events?access_token=${tokenToUse}`
      : null;

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
    event_name: serverEventName,
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


app.get('/dashboard', requireAuth, (req, res) => {
  // Owner / super analytics dashboard
  try {
    const user = req.user;
    if (!user) {
      return res.redirect('/login');
    }
    if (user.role === 'client') {
      // Clients should not see global analytics, send them back to their panel
      return res.redirect('/panel');
    }

    // Small helpers to avoid hard crashes if DB schema is older
    function safeGet(sql, params = [], fallback = {}) {
      try {
        const stmt = db.prepare(sql);
        const row = Array.isArray(params) ? stmt.get(...params) : stmt.get(params);
        return row || fallback;
      } catch (e) {
        console.error('DB safeGet error:', sql, e.message);
        return fallback;
      }
    }

    function safeAll(sql, params = [], fallback = []) {
      try {
        const stmt = db.prepare(sql);
        const rows = Array.isArray(params) ? stmt.all(...params) : stmt.all(params);
        return rows || fallback;
      } catch (e) {
        console.error('DB safeAll error:', sql, e.message);
        return fallback;
      }
    }

    const now = Math.floor(Date.now() / 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfDayTs = Math.floor(startOfDay.getTime() / 1000);
    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;

    // --- Joins metrics ---
    const totalRow = safeGet('SELECT COUNT(*) AS cnt FROM joins', [], { cnt: 0 });
    const totalJoins = totalRow.cnt || 0;

    const todayRow = safeGet(
      'SELECT COUNT(*) AS cnt FROM joins WHERE joined_at >= ? AND joined_at <= ?',
      [startOfDayTs, now],
      { cnt: 0 }
    );
    const todayJoins = todayRow.cnt || 0;

    const rows7 = safeAll(
      'SELECT joined_at FROM joins WHERE joined_at >= ? ORDER BY joined_at ASC',
      [sevenDaysAgoTs],
      []
    );

    const byDateMap = {};
    for (const r of rows7) {
      if (!r.joined_at) continue;
      const dateKey = formatDateYYYYMMDD(r.joined_at);
      byDateMap[dateKey] = (byDateMap[dateKey] || 0) + 1;
    }
    const last7Days = Object.keys(byDateMap)
      .sort()
      .map((date) => ({ date, count: byDateMap[date] }));
    const last7Total = last7Days.reduce((sum, d) => sum + (d.count || 0), 0);

    // --- Clients / channels metrics ---
    const totalClientsRow = safeGet('SELECT COUNT(*) AS cnt FROM clients', [], { cnt: 0 });
    const totalClients = totalClientsRow.cnt || 0;

    const activeClientsRow = safeGet(
      'SELECT COUNT(*) AS cnt FROM clients WHERE is_active = 1',
      [],
      { cnt: 0 }
    );
    const activeClients = activeClientsRow.cnt || 0;

    const pendingClientsRow = safeGet(
      'SELECT COUNT(*) AS cnt FROM clients WHERE is_active = 0',
      [],
      { cnt: 0 }
    );
    const pendingClients = pendingClientsRow.cnt || 0;

    const inactiveClients = Math.max(totalClients - activeClients, 0);

    const totalChannelsRow = safeGet('SELECT COUNT(*) AS cnt FROM channels', [], { cnt: 0 });
    const totalChannels = totalChannelsRow.cnt || 0;

    const activeChannelsRow = safeGet(
      'SELECT COUNT(*) AS cnt FROM channels WHERE is_active = 1',
      [],
      { cnt: 0 }
    );
    const activeChannels = activeChannelsRow.cnt || 0;

    const planRows = safeAll(
      `
        SELECT
          LOWER(COALESCE(plan, 'unknown')) AS plan,
          COUNT(*) AS cnt
        FROM clients
        GROUP BY LOWER(COALESCE(plan, 'unknown'))
      `,
      [],
      []
    );

    const planCounts = { single: 0, starter: 0, pro: 0, agency: 0, other: 0 };
    for (const row of planRows) {
      const p = row.plan || 'unknown';
      const cnt = row.cnt || 0;
      if (p === 'single') planCounts.single += cnt;
      else if (p === 'starter') planCounts.starter += cnt;
      else if (p === 'pro') planCounts.pro += cnt;
      else if (p === 'agency') planCounts.agency += cnt;
      else planCounts.other += cnt;
    }


    const pendingList = safeAll(
      `
        SELECT
          id,
          name,
          slug,
          plan,
          max_channels,
          is_active,
          created_at
        FROM clients
        WHERE is_active = 0
        ORDER BY created_at DESC
        LIMIT 50
      `,
      [],
      []
    );

    const channels = safeAll(
      `
        SELECT 
          channel_id,
          channel_title,
          COUNT(*) AS total
        FROM joins
        GROUP BY channel_id, channel_title
        ORDER BY total DESC
        LIMIT 20
      `,
      [],
      []
    );

    const topClients7 = safeAll(
      `
        SELECT
          c.id AS client_id,
          c.name AS client_name,
          c.slug AS slug,
          c.plan AS plan,
          COUNT(j.id) AS joins_7d
        FROM clients c
        LEFT JOIN channels ch ON ch.client_id = c.id
        LEFT JOIN joins j
          ON j.channel_id = ch.telegram_chat_id
          AND j.joined_at >= ?
          AND j.joined_at <= ?
        GROUP BY c.id, c.name, c.slug, c.plan
        ORDER BY joins_7d DESC
        LIMIT 10
      `,
      [sevenDaysAgoTs, now],
      []
    );

    const recentJoins = safeAll(
      `
        SELECT
          *
        FROM joins
        ORDER BY joined_at DESC
        LIMIT 50
      `,
      [],
      []
    );

    // Owner super dashboard HTML
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>UTS Owner Super Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
          body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #020617;
            color: #e5e7eb;
            padding: 24px;
            margin: 0;
          }
          .container {
            max-width: 1200px;
            margin: 0 auto;
          }
          h1 {
            font-size: 22px;
            margin-bottom: 4px;
          }
          .sub {
            font-size: 12px;
            color: #9ca3af;
            margin-bottom: 18px;
          }
          .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
          }
          .topbar a {
            color: #38bdf8;
            font-size: 12px;
            text-decoration: none;
            margin-left: 12px;
          }
          .cards {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 24px;
          }
          .card {
            background: #0f172a;
            border-radius: 12px;
            padding: 14px 16px;
            flex: 1 1 180px;
            min-width: 180px;
            border: 1px solid #1f2937;
          }
          .card h2 {
            font-size: 13px;
            color: #9ca3af;
            margin-bottom: 4px;
          }
          .card .value {
            font-size: 22px;
            font-weight: 600;
          }
          .card .hint {
            font-size: 11px;
            color: #6b7280;
            margin-top: 4px;
          }
          .grid-2 {
            display: grid;
            grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr);
            gap: 18px;
            margin-bottom: 24px;
          }
          .section {
            background: #020617;
            border-radius: 14px;
            padding: 18px 18px;
            border: 1px solid #1f2937;
            box-shadow: 0 18px 40px rgba(0,0,0,0.6);
          }
          .section-title {
            font-size: 15px;
            margin-bottom: 8px;
          }
          .section-sub {
            font-size: 12px;
            color: #6b7280;
            margin-bottom: 10px;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 8px;
          }
          th, td {
            padding: 6px 8px;
            border-bottom: 1px solid #1f2937;
            font-size: 12px;
            white-space: nowrap;
          }
          th {
            text-align: left;
            color: #9ca3af;
          }
          tr:hover {
            background: #020617;
          }
          .muted {
            color: #6b7280;
            font-size: 12px;
          }
          code {
            background: #020617;
            padding: 2px 4px;
            border-radius: 4px;
            font-size: 11px;
          }
          @media (max-width: 900px) {
            .grid-2 {
              grid-template-columns: minmax(0, 1fr);
            }
            table {
              display: block;
              overflow-x: auto;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="topbar">
            <div>
              <h1>Owner Super Dashboard</h1>
              <div class="sub">Global view across all clients, channels and joins.</div>
            </div>
            <div>
              <span class="sub">Logged in as ${user.email}</span>
              <a href="/panel">Workspace</a>
              <a href="/logout">Logout</a>
            </div>
          </div>

          <div class="cards">
            <div class="card">
              <h2>Total joins (all time)</h2>
              <div class="value">${totalJoins}</div>
            </div>
            <div class="card">
              <h2>Today joins</h2>
              <div class="value">${todayJoins}</div>
            </div>
            <div class="card">
              <h2>Last 7 days joins</h2>
              <div class="value">${last7Total}</div>
            </div>
            <div class="card">
              <h2>Clients</h2>
              <div class="value">${totalClients}</div>
              <div class="hint">Active: ${activeClients} · Inactive: ${inactiveClients} · Pending: ${pendingClients}</div>
            </div>
            <div class="card">
              <h2>Channels</h2>
              <div class="value">${activeChannels}/${totalChannels}</div>
              <div class="hint">Active / total</div>
            </div>
          </div>

          <div class="grid-2">
            <div class="section">
              <div class="section-title">Last 7 days – timeline</div>
              <div class="section-sub">Daily joins across all clients.</div>
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

            <div class="section">
              <div class="section-title">Clients by plan</div>
              <div class="section-sub">How many workspaces are on each tier.</div>
              <table>
                <thead>
                  <tr>
                    <th>Plan</th>
                    <th>Clients</th>
                  </tr>
                </thead>
                <tbody>
                  <tr><td>Single</td><td>${planCounts.single}</td></tr>
                  <tr><td>Starter</td><td>${planCounts.starter}</td></tr>
                  <tr><td>Pro</td><td>${planCounts.pro}</td></tr>
                  <tr><td>Agency</td><td>${planCounts.agency}</td></tr>
                  <tr><td>Other / unset</td><td>${planCounts.other}</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="grid-2">
            <div class="section">
              <div class="section-title">Top clients (last 7 days)</div>
              <div class="section-sub">Workspaces generating the most joins in the last 7 days.</div>
              <table>
                <thead>
                  <tr>
                    <th>Client</th>
                    <th>Plan</th>
                    <th>Slug</th>
                    <th>Joins (7d)</th>
                  </tr>
                </thead>
                <tbody>
                  ${
                    topClients7.length === 0
                      ? `<tr><td colspan="4" class="muted">No data yet</td></tr>`
                      : topClients7
                          .map(
                            (c) => `
                      <tr>
                        <td>${c.client_name || '(no name)'}</td>
                        <td>${c.plan || ''}</td>
                        <td><code>${c.slug || ''}</code></td>
                        <td>${c.joins_7d || 0}</td>
                      </tr>`
                          )
                          .join('')
                  }
                </tbody>
              </table>
            </div>

            <div class="section">
              <div class="section-title">Top channels (all time)</div>
              <div class="section-sub">Best-performing channels by total joins.</div>
              <table>
                <thead>
                  <tr>
                    <th>Channel</th>
                    <th>Channel ID</th>
                    <th>Total joins</th>
                  </tr>
                </thead>
                <tbody>
                  ${
                    channels.length === 0
                      ? `<tr><td colspan="3" class="muted">No data yet</td></tr>`
                      : channels
                          .map(
                            (ch) => `
                      <tr>
                        <td>${ch.channel_title || ''}</td>
                        <td>${ch.channel_id || ''}</td>
                        <td>${ch.total || 0}</td>
                      </tr>`
                          )
                          .join('')
                  }
                </tbody>
              </table>
            </div>
          </div>

          
          <div class="section">
            <div class="section-title">Pending client approvals</div>
            <div class="section-sub">Approve or reject new client workspaces from one place.</div>
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Name</th>
                  <th>Slug</th>
                  <th>Plan</th>
                  <th>Max channels</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${
                  pendingList.length === 0
                    ? `<tr><td colspan="7" class="muted">No pending clients.</td></tr>`
                    : pendingList
                        .map((c) => {
                          const created = c.created_at
                            ? new Date(c.created_at * 1000)
                                .toISOString()
                                .replace('T', ' ')
                                .substring(0, 19)
                            : '';
                          return `
                    <tr>
                      <td>${c.id}</td>
                      <td>${c.name || ''}</td>
                      <td><code>${c.slug || ''}</code></td>
                      <td>${c.plan || ''}</td>
                      <td>${c.max_channels || ''}</td>
                      <td>${created}</td>
                      <td>
                        <form method="POST" action="/dashboard/clients/${c.id}/approve" style="display:inline;">
                          <button type="submit" style="font-size:11px;padding:4px 10px;border-radius:999px;border:none;background:#22c55e;color:#020617;cursor:pointer;">
                            Approve
                          </button>
                        </form>
                        <form method="POST" action="/dashboard/clients/${c.id}/reject" style="display:inline;margin-left:6px;">
                          <button type="submit" style="font-size:11px;padding:4px 10px;border-radius:999px;border:1px solid #4b5563;background:transparent;color:#fca5a5;cursor:pointer;">
                            Reject
                          </button>
                        </form>
                      </td>
                    </tr>`;
                        })
                        .join('')
                }
              </tbody>
            </table>
          </div>

<div class="section">
            <div class="section-title">Recent joins (tracking details)</div>
            <div class="section-sub">Last 50 approved joins with device, geo & UTM information.</div>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Username</th>
                  <th>Channel</th>
                  <th>Channel ID</th>
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
                    ? `<tr><td colspan="15" class="muted">No joins yet</td></tr>`
                    : recentJoins
                        .map((j) => {
                          const ts = j.joined_at || 0;
                          const dt = ts
                            ? new Date(ts * 1000).toISOString().replace('T', ' ').substring(0, 19)
                            : '';
                          return `
                    <tr>
                      <td>${dt}</td>
                      <td>${j.telegram_username || ''}</td>
                      <td>${j.channel_title || ''}</td>
                      <td>${j.channel_id || ''}</td>
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
            <div class="muted">
              Super dashboard · designed to feel like a full analytics tool for your Telegram funnels.
            </div>
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
// ---------- LOGIN + LOGOUT + PANEL (SaaS UI) ----------

// GET /login
app.get('/login', (req, res) => {
  const token = req.cookies && req.cookies.auth;
  const userId = verifyAuthToken(token);
  if (userId) {
    return res.redirect('/panel');
  }

  const error = req.query.error ? 'Invalid email or password' : '';

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>UTS Login</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <style>
        body {
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #020617;
          color: #e5e7eb;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          margin: 0;
        }
        .card {
          background: #020617;
          border-radius: 16px;
          padding: 24px 22px;
          width: 100%;
          max-width: 360px;
          border: 1px solid #1f2937;
          box-shadow: 0 18px 40px rgba(0,0,0,0.6);
        }
        h1 {
          font-size: 20px;
          margin-bottom: 4px;
        }
        .sub {
          font-size: 12px;
          color: #9ca3af;
          margin-bottom: 18px;
        }
        label {
          font-size: 13px;
          display: block;
          margin-bottom: 4px;
        }
        input[type="email"],
        input[type="password"] {
          width: 100%;
          padding: 8px 10px;
          border-radius: 8px;
          border: 1px solid #374151;
          background: #020617;
          color: #e5e7eb;
          font-size: 13px;
          margin-bottom: 10px;
        }
        button {
          width: 100%;
          margin-top: 6px;
          padding: 10px 12px;
          border-radius: 999px;
          border: none;
          background: linear-gradient(135deg, #22c55e, #16a34a);
          color: #022c22;
          font-weight: 600;
          cursor: pointer;
          font-size: 14px;
        }
        .error {
          color: #f97373;
          font-size: 12px;
          margin-bottom: 8px;
        }
        .hint {
          margin-top: 12px;
          font-size: 11px;
          color: #9ca3af;
        }
        .hint code {
          background: #111827;
          padding: 2px 4px;
          border-radius: 4px;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Universal Tracking Login</h1>
        <div class="sub">Admin / Agency workspace access</div>

        ${error ? `<div class="error">${error}</div>` : ''}

        <form method="POST" action="/login">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" required />

          <label for="password">Password</label>
          <input id="password" name="password" type="password" required />

          <button type="submit">Log in</button>
        </form>

        <div class="hint">
          First-time dev login (after <code>/dev/seed-admin</code>):<br/>
          Email: <code>admin@uts.local</code><br/>
          Pass: <code>Admin@123</code>
        </div>
      </div>
    </body>
    </html>
  `);
});

// POST /login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.redirect('/login?error=1');
    }

    const user = db
      .prepare('SELECT * FROM users WHERE email = ?')
      .get(String(email).toLowerCase());

    if (!user) {
      return res.redirect('/login?error=1');
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.redirect('/login?error=1');
    }

    const token = signAuthToken(user.id);
    res.cookie('auth', token, {
      httpOnly: true,
      sameSite: 'lax'
      // secure: true // HTTPS only
    });

    // Role-based redirect:
    // - admin/owner: go to /dashboard (owner super view)
    // - client: go directly to its own workspace
    if (user.role === 'admin' || user.role === 'owner') {
      return res.redirect('/dashboard');
    }

    if (user.role === 'client') {
      const clientRow = db
        .prepare('SELECT id FROM clients WHERE login_user_id = ?')
        .get(user.id);

      if (clientRow && clientRow.id) {
        return res.redirect('/panel/client/' + clientRow.id);
      }

      // Fallback if mapping missing
      return res.redirect('/panel');
    }

    // Default fallback
    return res.redirect('/panel');
  } catch (err) {
    console.error('❌ Error in POST /login:', err);
    return res.redirect('/login?error=1');
  }
});

// GET /logout
app.get('/logout', (req, res) => {
  res.clearCookie('auth');
  res.redirect('/login');
});

// GET /panel - multi-client panel + "Add client" UI
app.get('/panel', requireAuth, (req, res) => {
  try {
    const user = req.user;
    // If this is a direct client login, redirect them to their own workspace
    if (user.role === 'client') {
      const clientRow = db
        .prepare('SELECT id FROM clients WHERE login_user_id = ?')
        .get(user.id);

      if (clientRow && clientRow.id) {
        return res.redirect('/panel/client/' + clientRow.id);
      }

      return res.status(403).send('Client not assigned to any workspace');
    }


    const errorCode = req.query.error || '';
    let errorHtml = '';
    if (errorCode === 'noname') {
      errorHtml = '<div class="error">Client name is required.</div>';
    } else if (errorCode === 'generic') {
      errorHtml = '<div class="error">Could not create client. Please try again.</div>';
    }

    let clients;
    if (user.role === 'admin') {
      clients = db
        .prepare(`
          SELECT
            id,
            name,
            slug,
            public_key,
            secret_key,
            plan,
            max_channels,
            is_active,
            created_at
          FROM clients
          ORDER BY id ASC
        `)
        .all();
    } else {
      clients = db
        .prepare(`
          SELECT
            id,
            name,
            slug,
            public_key,
            secret_key,
            plan,
            max_channels,
            is_active,
            created_at
          FROM clients
          WHERE owner_user_id = ?
          ORDER BY id ASC
        `)
        .all(user.id);
    }

    const clientStats = clients.map((c) => {
      const row = db
        .prepare(`
          SELECT COUNT(*) AS cnt
          FROM joins j
          JOIN channels ch ON ch.telegram_chat_id = j.channel_id
          WHERE ch.client_id = ?
        `)
        .get(c.id);
      return {
        client_id: c.id,
        total_joins: row.cnt || 0
      };
    });

    const statsByClientId = {};
    clientStats.forEach((s) => {
      statsByClientId[s.client_id] = s.total_joins;
    });

    const rowsHtml =
      clients.length > 0
        ? clients
            .map((c) => {
              const totalJoins = statsByClientId[c.id] || 0;
              const status = c.is_active ? 'Active' : 'Inactive';
              const created = c.created_at
                ? new Date(c.created_at * 1000).toISOString().substring(0, 10)
                : '';

              return `
          <tr>
            <td>${c.name || '(no name)'}</td>
            <td>${c.slug || ''}</td>
            <td><code>${c.public_key || ''}</code></td>
            <td><code>${c.secret_key || ''}</code></td>
            <td>${c.plan || ''}</td>
            <td>${c.max_channels || ''}</td>
            <td>${status}</td>
            <td>${totalJoins}</td>
            <td>${created}</td>
            <td>
              <a href="/panel/client/${c.id}" style="color:#38bdf8;font-size:12px;text-decoration:none;">
                View
              </a>
            </td>
          </tr>
        `;
            })
            .join('')
        : `
        <tr><td colspan="9" class="muted">No clients yet for this user.</td></tr>
      `;

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>UTS Workspace Panel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
          body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #020617;
            color: #e5e7eb;
            padding: 20px;
            margin: 0;
          }
          .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 18px;
          }
          .topbar h1 {
            font-size: 20px;
            margin: 0;
          }
          .topbar .user {
            font-size: 13px;
            color: #9ca3af;
          }
          .topbar a {
            color: #f97316;
            font-size: 12px;
            text-decoration: none;
            margin-left: 12px;
          }
          .card {
            background: #020617;
            border-radius: 14px;
            padding: 16px 18px;
            border: 1px solid #1f2937;
            box-shadow: 0 18px 40px rgba(0,0,0,0.6);
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
          }
          th, td {
            padding: 8px 10px;
            border-bottom: 1px solid #1f2937;
            font-size: 12px;
            white-space: nowrap;
          }
          th {
            text-align: left;
            color: #9ca3af;
          }
          code {
            background: #111827;
            padding: 2px 4px;
            border-radius: 4px;
            font-size: 11px;
          }
          .muted {
            color: #6b7280;
            font-size: 12px;
          }
          .error {
            margin-top: 8px;
            margin-bottom: 4px;
            font-size: 12px;
            color: #f97373;
          }
          .new-client {
            margin-top: 12px;
            margin-bottom: 10px;
          }
          .new-client-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: flex-end;
          }
          .field {
            display: flex;
            flex-direction: column;
            font-size: 12px;
          }
          .field label {
            margin-bottom: 4px;
            color: #9ca3af;
          }
          .field input,
          .field select {
            padding: 6px 8px;
            border-radius: 8px;
            border: 1px solid #1f2937;
            background: #020617;
            color: #e5e7eb;
            font-size: 12px;
            min-width: 120px;
          }
          .field.small input {
            max-width: 90px;
          }
          .new-client button {
            padding: 8px 14px;
            border-radius: 999px;
            border: none;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: #022c22;
            font-weight: 600;
            cursor: pointer;
            font-size: 12px;
          }
          @media (max-width: 900px) {
            table {
              display: block;
              overflow-x: auto;
            }
            .new-client-row {
              flex-direction: column;
              align-items: stretch;
            }
          }
        </style>
      </head>
      <body>
        <div class="topbar">
          <div>
            <h1>Universal Tracking Workspace</h1>
            <div class="user">
              Logged in as: <strong>${user.email}</strong>
            </div>
          </div>
          <div>
            <a href="/dashboard" target="_blank">Global dashboard</a>
            <a href="/logout">Logout</a>
          </div>
        </div>

        <div class="card">
          <h2 style="font-size: 15px; margin: 0 0 6px 0;">Your clients</h2>
          <div class="muted">Use these keys in landing pages / bots for each client.</div>
          ${errorHtml}

          <form method="POST" action="/panel/new-client" class="new-client">
            <div class="new-client-row">
              <div class="field">
                <label for="name">Client name</label>
                <input id="name" name="name" type="text" required placeholder="e.g. VeerBhai Agency" />
              </div>
              <div class="field">
                <label for="slug">Slug (optional)</label>
                <input id="slug" name="slug" type="text" placeholder="veerbhai-agency" />
              </div>
              <div class="field">
                <label for="plan">Plan</label>
                <select id="plan" name="plan">
                  <option value="starter" selected>starter</option>
                  <option value="pro">pro</option>
                  <option value="agency">agency</option>
                </select>
              </div>
              <div class="field small">
                <label for="max_channels">Max channels</label>
                <input id="max_channels" name="max_channels" type="number" min="1" value="3" />
              </div>
              <div class="field">
                <label>&nbsp;</label>
                <button type="submit">+ Add client</button>
              </div>
            </div>
          </form>

          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Slug</th>
                <th>Public key</th>
                <th>Secret key</th>
                <th>Plan</th>
                <th>Max channels</th>
                <th>Status</th>
                <th>Total joins</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${rowsHtml}
            </tbody>
          </table>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('❌ Error in GET /panel:', err);
    res.status(500).send('Internal error');
  }
});

// POST /panel/new-client - create a new client for logged-in user
app.post('/panel/new-client', requireAuth, (req, res) => {
  try {
    const user = req.user;
    let { name, slug, plan, max_channels } = req.body || {};

    name = (name || '').trim();
    slug = (slug || '').trim().toLowerCase();
    plan = (plan || '').trim().toLowerCase() || 'starter';

    let maxChannels = parseInt(max_channels, 10);
    if (!maxChannels || maxChannels < 1) {
      maxChannels = 3;
    }

    if (!name) {
      return res.redirect('/panel?error=noname');
    }

    // Auto-generate slug if empty
    if (!slug) {
      slug = name
        .toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^a-z0-9-]/g, '')
        .slice(0, 32);
      if (!slug) {
        slug = `client-${Date.now()}`;
      }
    }

    // Ensure (owner_user_id, slug) roughly unique
    const existing = db
      .prepare('SELECT id FROM clients WHERE owner_user_id = ? AND slug = ?')
      .get(user.id, slug);

    if (existing) {
      slug = `${slug}-${Math.random().toString(36).slice(2, 5)}`;
    }

    const now = Math.floor(Date.now() / 1000);

    const publicKey = generateKey('PUB');
    const secretKey = generateKey('SEC');

    db.prepare(`
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
    `).run(
      name,
      slug,
      user.id,
      publicKey,
      secretKey,
      process.env.META_PIXEL_ID || null,
      process.env.META_ACCESS_TOKEN || null,
      plan,
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


// GET /panel/client/:id - per-client mini dashboard + channels UI
app.get('/panel/client/:id', requireAuth, (req, res) => {
  try {
    const user = req.user;
    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.status(400).send('Invalid client id');
    }

    // Ensure client belongs to this user:
    // - admin: can see any client
    // - owner: owner_user_id match
    // - client: login_user_id match
    let client = null;
    if (user.role === 'admin') {
      client = db
        .prepare('SELECT * FROM clients WHERE id = ?')
        .get(clientId);
    } else if (user.role === 'owner') {
      client = db
        .prepare('SELECT * FROM clients WHERE id = ? AND owner_user_id = ?')
        .get(clientId, user.id);
    } else if (user.role === 'client') {
      client = db
        .prepare('SELECT * FROM clients WHERE id = ? AND login_user_id = ?')
        .get(clientId, user.id);
    } else {
      return res.status(403).send('Forbidden');
    }

    if (!client) {
      return res.status(404).send('Client not found');
    }

    const now = Math.floor(Date.now() / 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfDayTs = Math.floor(startOfDay.getTime() / 1000);

    // Total joins for this client (via channels mapping)
    const totalRow = db
      .prepare(`
        SELECT COUNT(*) AS cnt
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
      \`)
      .get(clientId);
    const totalJoins = totalRow.cnt || 0;

    // Today joins for this client
    const todayRow = db
      .prepare(
        \`
        SELECT COUNT(*) AS cnt
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
          AND j.joined_at >= ?
          AND j.joined_at <= ?
      \`
      )
      .get(clientId, startOfDayTs, now);
    const todayJoins = todayRow.cnt || 0;

    // Last 7 days breakdown
    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;
    const rows7 = db
      .prepare(
        \`
        SELECT j.joined_at
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
          AND j.joined_at >= ?
      \`
      )
      .all(clientId, sevenDaysAgoTs);

    const last7DaysMap = {};
    for (const r of rows7) {
      const dStr = new Date(r.joined_at * 1000).toISOString().substring(0, 10);
      last7DaysMap[dStr] = (last7DaysMap[dStr] || 0) + 1;
    }
    const last7Days = Object.keys(last7DaysMap)
      .sort()
      .map((d) => ({ date: d, count: last7DaysMap[d] }));

    // Plan + usage info
    const plan = client.plan || 'single';
    const maxChannels = client.max_channels || 1;

    const channelConfigs = db
      .prepare(
        \`
        SELECT *
        FROM channels
        WHERE client_id = ?
        ORDER BY created_at DESC, id DESC
      \`
      )
      .all(clientId);

    const channelCount = channelConfigs.length;
    const canAddMoreChannels = channelCount < maxChannels;

    let errorHtml = '';
    if (!canAddMoreChannels) {
      errorHtml =
        '<div style="margin-top:8px;color:#f97373;font-size:12px;">This client has reached the max channels for its plan. Please remove an existing channel or upgrade the plan.</div>';
    }

    // By channel stats (from joins)
    const byChannelStats = db
      .prepare(
        \`
        SELECT
          ch.telegram_chat_id AS channel_id,
          ch.telegram_title AS channel_title,
          COUNT(*) AS total
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
        GROUP BY ch.telegram_chat_id, ch.telegram_title
        ORDER BY total DESC
      \`
      )
      .all(clientId);

    const trackingBase = process.env.PUBLIC_TRACKING_BASE_URL || process.env.PUBLIC_BACKEND_URL || '';

    const channelTotalsMap = {};
    for (const row of byChannelStats) {
      channelTotalsMap[String(row.channel_id)] = row.total;
    }

    // Per-channel today joins
    const todayByChannel = db
      .prepare(
        \`
        SELECT
          ch.telegram_chat_id AS channel_id,
          COUNT(*) AS total
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
          AND j.joined_at >= ?
          AND j.joined_at <= ?
        GROUP BY ch.telegram_chat_id
      \`
      )
      .all(clientId, startOfDayTs, now);

    const channelTodayMap = {};
    for (const row of todayByChannel) {
      channelTodayMap[String(row.channel_id)] = row.total;
    }

    // Per-channel last 7 days joins
    const sevenByChannel = db
      .prepare(
        \`
        SELECT
          ch.telegram_chat_id AS channel_id,
          COUNT(*) AS total
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
          AND j.joined_at >= ?
        GROUP BY ch.telegram_chat_id
      \`
      )
      .all(clientId, sevenDaysAgoTs);

    const channel7dMap = {};
    for (const row of sevenByChannel) {
      channel7dMap[String(row.channel_id)] = row.total;
    }

    const recentJoins = db
      .prepare(
        \`
        SELECT
          j.joined_at,
          j.telegram_user_id,
          j.telegram_first_name,
          j.telegram_last_name,
          j.telegram_username,
          j.channel_id,
          j.ip,
          j.country,
          j.device_type,
          j.browser,
          j.os,
          j.source,
          j.utm_source,
          j.utm_medium,
          j.utm_campaign,
          ch.telegram_title AS channel_title
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
        ORDER BY j.joined_at DESC
        LIMIT 50
      \`
      )
      .all(clientId);

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
          .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 18px;
          }
          .topbar h1 {
            font-size: 18px;
            margin: 0;
          }
          .muted {
            color: #6b7280;
            font-size: 12px;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
          }
          th, td {
            border-bottom: 1px solid #111827;
            padding: 6px 8px;
            text-align: left;
            font-size: 12px;
          }
          th {
            background: #020617;
            position: sticky;
            top: 0;
            z-index: 1;
          }
          tr:nth-child(even) {
            background: #020617;
          }
          .pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 11px;
            border: 1px solid #1f2937;
          }
          .pill-green {
            background: #022c22;
            color: #6ee7b7;
            border-color: #047857;
          }
          .pill-red {
            background: #450a0a;
            color: #fecaca;
            border-color: #b91c1c;
          }
          .section-title {
            margin-top: 24px;
            margin-bottom: 6px;
            font-size: 14px;
          }
          .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
            margin-top: 12px;
          }
          .card {
            border-radius: 12px;
            border: 1px solid #111827;
            padding: 12px;
            background: radial-gradient(circle at top left, #0f172a, #020617);
          }
          .field {
            margin-bottom: 8px;
          }
          .field label {
            display: block;
            font-size: 12px;
            margin-bottom: 2px;
          }
          .field input {
            padding: 6px 8px;
            border-radius: 8px;
            border: 1px solid #1f2937;
            background: #020617;
            color: #e5e7eb;
            font-size: 12px;
            min-width: 120px;
          }
          .btn {
            padding: 8px 14px;
            border-radius: 999px;
            border: none;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: #022c22;
            font-weight: 600;
            cursor: pointer;
            font-size: 12px;
          }
          .btn-xs {
            padding: 3px 8px;
            border-radius: 999px;
            border: none;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: #022c22;
            font-weight: 600;
            cursor: pointer;
            font-size: 11px;
          }
          .btn-danger {
            background: linear-gradient(135deg, #ef4444, #b91c1c);
            color: #fef2f2;
          }
          .pill-plan {
            background: #020617;
            border-color: #1f2937;
            color: #e5e7eb;
          }
        </style>
      </head>
      <body>
        <div class="topbar">
          <div>
            <h1>${client.name || 'Client workspace'}</h1>
            <div class="muted">
              Client ID ${client.id} · Plan: ${plan} · Max channels: ${maxChannels} · Total joins: ${totalJoins}
            </div>
          </div>
          <div>
            <a href="/panel">← Back to panel</a>
          </div>
        </div>

        <div class="grid">
          <div class="card">
            <div class="muted">Today joins</div>
            <div style="font-size:24px;font-weight:700;">${todayJoins}</div>
          </div>
          <div class="card">
            <div class="muted">Total joins</div>
            <div style="font-size:24px;font-weight:700;">${totalJoins}</div>
          </div>
          <div class="card">
            <div class="muted">Channels used</div>
            <div style="font-size:24px;font-weight:700;">${channelCount} / ${maxChannels}</div>
            ${errorHtml}
          </div>
        </div>

        <h2 class="section-title">Last 7 days</h2>
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
                      (d) => \`
              <tr>
                <td>\${d.date}</td>
                <td>\${d.count}</td>
              </tr>\`
                    )
                    .join('')
            }
          </tbody>
        </table>

        <h2 class="section-title">By channel</h2>
        <table>
          <thead>
            <tr>
              <th>Title</th>
              <th>Channel ID</th>
              <th>Deep link</th>
              <th>Pixel</th>
              <th>Joins (all time)</th>
              <th>Today</th>
              <th>Last 7 days</th>
              <th>LP</th>
            </tr>
          </thead>
          <tbody>
            ${
              channelConfigs.length === 0
                ? '<tr><td colspan="8" class="muted">No channel config yet</td></tr>'
                : channelConfigs
                    .map((ch) => {
                      const created = ch.created_at
                        ? new Date(ch.created_at * 1000).toISOString().substring(0, 10)
                        : '';
                      const status = ch.is_active ? 'Active' : 'Inactive';
                      const tot = channelTotalsMap[String(ch.telegram_chat_id)] || 0;
                      const todayCount = channelTodayMap[String(ch.telegram_chat_id)] || 0;
                      const last7Count = channel7dMap[String(ch.telegram_chat_id)] || 0;
                      const autoLpUrl = `/lp/${ch.id}`;
                      const customLp = ch.lp_url || '';
                      const customDisplay = customLp
                        ? `<a href="\${customLp}" target="_blank">\${customLp}</a>`
                        : 'Not set';
                      const lpModeRaw = (ch.lp_event_mode || '').toLowerCase();
                      const lpModeLabel =
                        lpModeRaw === 'subscribe' ? 'InitiateSubscribe → Subscribe' : 'InitiateLead → Lead';
                      const antiCrawlerLabel = ch.lp_anti_crawler ? 'On' : 'Off';
                      return \`
              <tr>
                <td>\${ch.telegram_title || '(no title)'}</td>
                <td>\${ch.telegram_chat_id}</td>
                <td>\${ch.deep_link || ''}</td>
                <td>\${ch.pixel_id || ''}</td>
                <td>\${tot}</td>
                <td>\${todayCount}</td>
                <td>\${last7Count}</td>
                <td>
                  <div style="display:flex;flex-direction:column;gap:4px;">
                    <span class="muted">Auto: <a href="\${autoLpUrl}" target="_blank">\${autoLpUrl}</a></span>
                    <span class="muted">Custom: \${customDisplay}</span>
                    <span class="muted">Event: \${lpModeLabel}, Anti-crawler: \${antiCrawlerLabel}</span>
                  </div>
                </td>
              </tr>\`;
                    })
                    .join('')
            }
          </tbody>
        </table>

        <h2 class="section-title">Add / update channel</h2>
        <div class="card">
          <form method="POST" action="/panel/client/${client.id}/channels">
            <div class="field">
              <label for="telegram_title">Channel title</label>
              <input id="telegram_title" name="telegram_title" type="text" required />
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
              <input id="pixel_id" name="pixel_id" type="text" placeholder="Leave empty if not used" />
            </div>
            <div class="field">
              <label for="meta_token">Meta Access Token (optional)</label>
              <input id="meta_token" name="meta_token" type="text" placeholder="Leave empty if not used" />
            </div>
            <div class="field">
              <label for="lp_url">Custom LP URL (optional)</label>
              <input id="lp_url" name="lp_url" type="text" placeholder="https://your-landing-page.com" />
            </div>
            <div class="field">
              <label>LP click event mapping</label>
              <div style="font-size:11px;color:#9ca3af;margin-bottom:4px;">
                Use the <strong>same event type</strong> across all LPs &amp; channels on a single pixel for clean optimization.
              </div>
              <div style="display:flex;flex-direction:column;gap:4px;font-size:12px;">
                <label style="display:flex;align-items:center;gap:6px;">
                  <input type="radio" name="lp_event_mode" value="lead" checked />
                  <span>InitiateLead → Lead (recommended)</span>
                </label>
                <label style="display:flex;align-items:center;gap:6px;">
                  <input type="radio" name="lp_event_mode" value="subscribe" />
                  <span>InitiateSubscribe → Subscribe</span>
                </label>
              </div>
            </div>
            <div class="field">
              <label>
                <input type="checkbox" name="lp_anti_crawler" value="1" />
                Enable anti-crawler for this channel
              </label>
            </div>
            <button class="btn" type="submit">Save channel</button>
          </form>
        </div>

        <h2 class="section-title">Recent joins (last 50)</h2>
        <table>
          <thead>
            <tr>
              <th>Joined at</th>
              <th>User ID</th>
              <th>First name</th>
              <th>Last name</th>
              <th>Username</th>
              <th>Channel</th>
              <th>IP</th>
              <th>Country</th>
              <th>Device</th>
              <th>Browser</th>
              <th>OS</th>
              <th>Source</th>
              <th>UTM source</th>
              <th>UTM medium</th>
              <th>UTM campaign</th>
            </tr>
          </thead>
          <tbody>
            ${
              recentJoins.length === 0
                ? '<tr><td colspan="15" class="muted">No joins yet</td></tr>'
                : recentJoins
                    .map((j) => {
                      const dt = new Date(j.joined_at * 1000)
                        .toISOString()
                        .replace('T', ' ')
                        .substring(0, 19);
                      return \`
              <tr>
                <td>\${dt}</td>
                <td>\${j.telegram_user_id}</td>
                <td>\${j.telegram_first_name || ''}</td>
                <td>\${j.telegram_last_name || ''}</td>
                <td>\${j.telegram_username || '(no username)'}</td>
                <td>\${j.channel_title || ''}</td>
                <td>\${j.ip || ''}</td>
                <td>\${j.country || ''}</td>
                <td>\${j.device_type || ''}</td>
                <td>\${j.browser || ''}</td>
                <td>\${j.os || ''}</td>
                <td>\${j.source || ''}</td>
                <td>\${j.utm_source || ''}</td>
                <td>\${j.utm_medium || ''}</td>
                <td>\${j.utm_campaign || ''}</td>
              </tr>\`;
                    })
                    .join('')
            }
          </tbody>
        </table>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('❌ Error in GET /panel/client/:id:', err);
    res.status(500).send('Internal error');
  }
});



// POST /panel/client/:id/channels/new - create or update channel for this client
app.post('/panel/client/:id/channels/new', requireAuth, (req, res) => {
  try {
    const user = req.user;
    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.status(400).send('Invalid client id');
    }

    // Ensure client belongs to this user:
    // - admin/owner: owner_user_id match
    // - client: login_user_id match
    let client = null;
    if (user.role === 'admin' || user.role === 'owner') {
      client = db
        .prepare('SELECT * FROM clients WHERE id = ? AND owner_user_id = ?')
        .get(clientId, user.id);
    } else if (user.role === 'client') {
      client = db
        .prepare('SELECT * FROM clients WHERE id = ? AND login_user_id = ?')
        .get(clientId, user.id);
    } else {
      return res.status(403).send('Forbidden');
    }

    if (!client) {
      return res.status(404).send('Client not found');
    }

    let { telegram_chat_id, telegram_title, deep_link, pixel_id, meta_token, lp_url, lp_event_mode, lp_anti_crawler } = req.body || {};
    telegram_chat_id = (telegram_chat_id || '').trim();
    telegram_title = (telegram_title || '').trim();
    deep_link = (deep_link || '').trim();
    pixel_id = (pixel_id || '').trim();
    meta_token = (meta_token || '').trim();
    lp_url = (lp_url || '').trim();
    lp_event_mode = (lp_event_mode || '').toLowerCase() === 'subscribe' ? 'subscribe' : 'lead';
    const lpAntiCrawlerFlag = lp_anti_crawler ? 1 : 0;

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
        SET telegram_title = ?, deep_link = ?, pixel_id = ?, meta_token = ?, lp_url = ?, lp_event_mode = ?, lp_anti_crawler = ?, client_id = ?, is_active = 1
        WHERE id = ?
      `
      ).run(
        telegram_title || existing.telegram_title,
        deep_link || existing.deep_link,
        pixel_id || existing.pixel_id,
        meta_token || existing.meta_token,
        lp_url || existing.lp_url,
        lp_event_mode || existing.lp_event_mode || 'lead',
        typeof lpAntiCrawlerFlag === 'number' ? lpAntiCrawlerFlag : existing.lp_anti_crawler || 0,
        clientId,
        existing.id
      );
    } else {
      // Enforce plan-based channel limit for this client (only when inserting new channel)
      let maxChannels = client.max_channels;
      if (!maxChannels || Number.isNaN(Number(maxChannels))) {
        const plan = (client.plan || '').toLowerCase();
        if (plan === 'single') maxChannels = 1;
        else if (plan === 'starter') maxChannels = 3;
        else if (plan === 'pro') maxChannels = 5;
        else if (plan === 'agency') maxChannels = 10;
      }

      if (maxChannels && Number(maxChannels) > 0) {
        const rowCount = db
          .prepare('SELECT COUNT(*) AS cnt FROM channels WHERE client_id = ? AND is_active = 1')
          .get(clientId);
        const currentActive = rowCount && rowCount.cnt ? rowCount.cnt : 0;
        if (currentActive >= Number(maxChannels)) {
          return res.redirect('/panel/client/' + clientId + '?error=chlimit');
        }
      }

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
          lp_event_mode,
          lp_anti_crawler,
          created_at,
          is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
      `
      ).run(
        clientId,
        String(telegram_chat_id),
        telegram_title || null,
        deep_link || null,
        pixel_id || null,
        meta_token || null,
        lp_url || null,
        lp_event_mode || 'lead',
        lpAntiCrawlerFlag,
        nowTs
      );
    }

    return res.redirect('/panel/client/' + clientId);
  } catch (err) {
    console.error('❌ Error in POST /panel/client/:id/channels/new:', err);
    return res.status(500).send('Internal error');
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

// ----- Auto-generated landing page for a channel -----
// Simple LP generator: /lp/:channelId (channelId = channels.id)
// ----- LP Generator v1: slug-based hosted landing pages -----
app.get('/lp2/:slug', (req, res) => {
  try {
    const slug = (req.params.slug || '').trim();
    if (!slug) {
      return res.status(400).send('Missing slug');
    }

    const row = db
      .prepare(
        `
        SELECT
          lp.id,
          lp.client_id,
          lp.channel_id,
          lp.name,
          lp.slug,
          lp.template_key,
          lp.status,
          lp.html_config,
          lp.lp_event_mode,
          lp.anti_crawler,
          lp.auto_host_url,
          lp.custom_domain_url,
          lp.created_at,
          lp.updated_at,
          ch.telegram_chat_id,
          ch.telegram_title,
          ch.deep_link,
          ch.pixel_id,
          ch.meta_token,
          c.public_key,
          c.name AS client_name
        FROM landing_pages lp
        JOIN channels ch ON ch.id = lp.channel_id
        JOIN clients c ON c.id = lp.client_id
        WHERE lp.slug = ? AND lp.status = 'published'
        LIMIT 1
        `
      )
      .get(slug);

    if (!row) {
      return res.status(404).send('Landing page not found or not published');
    }

    const pixelId = row.pixel_id;
    const telegramTitle = row.telegram_title || row.name || 'Our Premium Channel';
    const clientName = row.client_name || 'Our Team';
    const publicKey = row.public_key || '';
    const telegramChatId = String(row.telegram_chat_id || '');
    const telegramDeepLink = row.deep_link || ('https://t.me/' + telegramChatId.replace(/^@/, ''));
    const lpId = row.id;
    const channelInternalId = row.channel_id;
    const lpModeRaw = (row.lp_event_mode || '').toLowerCase();
    const lpMode = lpModeRaw === 'subscribe' ? 'subscribe' : 'lead';
    const fbInitiateEvent = lpMode === 'subscribe' ? 'InitiateSubscribe' : 'InitiateLead';
    const antiCrawlerEnabled = row.anti_crawler ? true : false;

    let htmlConfig = {};
    try {
      htmlConfig = row.html_config ? JSON.parse(row.html_config) : {};
    } catch (e) {
      htmlConfig = {};
    }

    const headline = htmlConfig.headline || telegramTitle;
    const subheadline =
      htmlConfig.subheadline ||
      htmlConfig.subtitle ||
      'Join our private Telegram channel for daily high-quality signals and updates.';
    const bulletList = Array.isArray(htmlConfig.bullets) && htmlConfig.bullets.length
      ? htmlConfig.bullets
      : [
          'Daily premium updates',
          'High quality signals',
          'Private Telegram community',
          'Easy-to-follow entries & exits'
        ];
    const ctaText = htmlConfig.cta_text || 'Join Telegram Channel';

    const antiCrawlerBlock = antiCrawlerEnabled
      ? `
    <script>
      (function() {
        try {
          var ua = (navigator.userAgent || '').toLowerCase();
          var badKeywords = ['bot','crawler','spider','preview','facebookexternalhit','facebot'];
          for (var i = 0; i < badKeywords.length; i++) {
            if (ua.indexOf(badKeywords[i]) !== -1) {
              document.documentElement.innerHTML = '<head><meta name="robots" content="noindex"><title>Not available</title></head><body></body>';
              return;
            }
          }
        } catch (e) {}
      })();
    </script>
    `
      : '';

    const pixelBlock = pixelId
      ? `
    <!-- Meta Pixel Code -->
    <script>
      !function(f,b,e,v,n,t,s)
      {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
      n.callMethod.apply(n,arguments):n.queue.push(arguments)};
      if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
      n.queue=[];t=b.createElement(e);t.async=!0;
      t.src=v;s=b.getElementsByTagName(e)[0];
      s.parentNode.insertBefore(t,s)}(window, document,'script',
      'https://connect.facebook.net/en_US/fbevents.js');
      fbq('init', '${pixelId}');
      fbq('track', 'PageView');
    </script>
    <noscript>
      <img height="1" width="1" style="display:none"
           src="https://www.facebook.com/tr?id=${pixelId}&ev=PageView&noscript=1"/>
    </noscript>
    <!-- End Meta Pixel Code -->
    `
      : '';

    const pageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${headline}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, #0f172a, #020617);
      color: #e5e7eb;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }
    .card {
      background: rgba(15, 23, 42, 0.96);
      border-radius: 18px;
      padding: 22px 20px;
      max-width: 460px;
      width: 100%;
      border: 1px solid rgba(148, 163, 184, 0.25);
      box-shadow: 0 22px 45px rgba(15, 23, 42, 0.85);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 4px 10px;
      background: rgba(22, 163, 74, 0.12);
      border: 1px solid rgba(34, 197, 94, 0.35);
      font-size: 11px;
      color: #bbf7d0;
      margin-bottom: 10px;
    }
    h1 {
      font-size: 22px;
      line-height: 1.2;
      margin-bottom: 8px;
      color: #f9fafb;
    }
    .sub {
      font-size: 13px;
      color: #9ca3af;
      margin-bottom: 14px;
    }
    ul {
      list-style: none;
      margin-bottom: 16px;
    }
    li {
      font-size: 13px;
      margin-bottom: 6px;
      display: flex;
      align-items: flex-start;
      gap: 6px;
    }
    li span.bullet-dot {
      display: inline-block;
      width: 5px;
      height: 5px;
      border-radius: 999px;
      margin-top: 6px;
      background: #22c55e;
      flex-shrink: 0;
    }
    .cta-btn {
      width: 100%;
      border: none;
      outline: none;
      border-radius: 999px;
      padding: 10px 16px;
      margin-top: 6px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      background: linear-gradient(135deg, #22c55e, #16a34a);
      color: #022c22;
      box-shadow: 0 12px 30px rgba(34,197,94,0.35);
    }
    .cta-btn:hover {
      filter: brightness(1.05);
      transform: translateY(-1px);
    }
    .footer-note {
      margin-top: 10px;
      font-size: 11px;
      color: #6b7280;
    }
  </style>
  ${pixelBlock}
  ${antiCrawlerBlock}
</head>
<body>
  <div class="card">
    <div class="badge">🔒 Private Telegram • by ${clientName}</div>
    <h1>${headline}</h1>
    <div class="sub">${subheadline}</div>
    <ul>
      ${bulletList
        .map(function (b) {
          return '<li><span class="bullet-dot"></span><span>' + String(b) + '</span></li>';
        })
        .join('')}
    </ul>
    <button class="cta-btn" onclick="window.__UTS_LP_CLICK && window.__UTS_LP_CLICK(); return false;">
      ${ctaText}
    </button>
    <div class="footer-note">
      You will be redirected to the official Telegram channel on tap.
    </div>
  </div>
  <script>
    (function() {
      var CONFIG = {
        publicKey: ${JSON.stringify(publicKey)},
        channelId: ${JSON.stringify(String(channelInternalId))},
        lpId: ${JSON.stringify(lpId)},
        fbInitiateEvent: ${JSON.stringify(fbInitiateEvent)},
        telegramDeepLink: ${JSON.stringify(telegramDeepLink)}
      };

      function sendLpEvent(type, source) {
        try {
          fetch('/api/v1/lp-event', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              public_key: CONFIG.publicKey,
              channel_id: CONFIG.channelId,
              lp_id: CONFIG.lpId,
              event_type: type,
              source: source || null
            })
          }).catch(function(){});
        } catch (e) {}
      }

      // Pageview on load
      sendLpEvent('pageview', 'lp2_pageview');

      window.__UTS_LP_CLICK = function() {
        try {
          if (window.fbq && CONFIG.fbInitiateEvent) {
            fbq('track', CONFIG.fbInitiateEvent);
          }
        } catch (e) {}

        sendLpEvent('click', 'lp2_button_click');
        sendLpEvent('pre_lead', 'lp2_button_click');

        try {
          fetch('/api/v1/track/pre-lead', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              public_key: CONFIG.publicKey,
              channel_id: CONFIG.channelId,
              source: 'lp2_button_click',
              url: window.location.href
            })
          }).catch(function(){});
        } catch (e) {}

        window.location.href = CONFIG.telegramDeepLink;
      };
    })();
  </script>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(pageHtml);
  } catch (err) {
    console.error('❌ Error in GET /lp2/:slug:', err);
    return res.status(500).send('Internal error');
  }
});


app.get('/lp/:channelId', async (req, res) => {
  try {
    const channelId = parseInt(req.params.channelId, 10);
    if (!channelId || Number.isNaN(channelId)) {
      return res.status(400).send('Invalid channel id');
    }

    const row = db
      .prepare(
        `
        SELECT
          ch.id,
          ch.telegram_chat_id,
          ch.telegram_title,
          ch.deep_link,
          ch.pixel_id,
          ch.lp_event_mode,
          ch.lp_anti_crawler,
          c.public_key,
          c.name AS client_name
        FROM channels ch
        JOIN clients c ON c.id = ch.client_id
        WHERE ch.id = ?
      `
      )
      .get(channelId);

    if (!row) {
      return res.status(404).send('Channel not found');
    }

    const pixelId = row.pixel_id || '';
    const deepLink = row.deep_link || `https://t.me/${row.telegram_chat_id}`;
    const channelTitle = row.telegram_title || 'My Telegram Channel';
    const clientName = row.client_name || 'Our Team';
    const publicKey = row.public_key || '';
    const telegramChatId = String(row.telegram_chat_id || '');
    const lpModeRaw = (row.lp_event_mode || '').toLowerCase();
    const lpMode = lpModeRaw === 'subscribe' ? 'subscribe' : 'lead';
    const fbInitiateEvent = lpMode === 'subscribe' ? 'InitiateSubscribe' : 'InitiateLead';
    const antiCrawlerEnabled = row.lp_anti_crawler ? true : false;

    const antiCrawlerBlock = antiCrawlerEnabled
      ? `
    <script>
      (function() {
        try {
          var ua = (navigator.userAgent || '').toLowerCase();
          var badKeywords = ['bot', 'crawler', 'spider', 'preview', 'facebookexternalhit', 'facebot'];
          for (var i = 0; i < badKeywords.length; i++) {
            if (ua.indexOf(badKeywords[i]) !== -1) {
              document.documentElement.innerHTML = '<head><meta name="robots" content="noindex"><title>Not available</title></head><body></body>';
              return;
            }
          }
        } catch (e) {}
      })();
    </script>
    `
      : '';

    const pixelBlock = pixelId
      ? `
    <!-- Meta Pixel Code -->
    <script>
      !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?
      n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;
      n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
      t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}
      (window, document,'script','https://connect.facebook.net/en_US/fbevents.js');
      fbq('init', '${pixelId}');
      fbq('track', 'PageView');
    </script>
    <noscript>
      <img height="1" width="1" style="display:none"
           src="https://www.facebook.com/tr?id=${pixelId}&ev=PageView&noscript=1"/>
    </noscript>
    <!-- End Meta Pixel Code -->
    `
      : '';

    const html = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>${channelTitle} | Telegram Channel</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }
      body {
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: radial-gradient(circle at top left, #0f172a, #020617);
        color: #e5e7eb;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 16px;
      }
      .card {
        background: rgba(15, 23, 42, 0.96);
        border-radius: 18px;
        padding: 22px 20px;
        max-width: 430px;
        width: 100%;
        box-shadow: 0 18px 45px rgba(0, 0, 0, 0.6);
        border: 1px solid rgba(148, 163, 184, 0.15);
      }
      .badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        padding: 4px 8px;
        border-radius: 999px;
        background: rgba(22, 163, 74, 0.12);
        color: #bbf7d0;
        margin-bottom: 10px;
      }
      .badge-dot {
        width: 7px;
        height: 7px;
        border-radius: 999px;
        background: #22c55e;
      }
      h1 {
        font-size: 22px;
        line-height: 1.25;
        margin-bottom: 6px;
      }
      .subtitle {
        font-size: 13px;
        color: #9ca3af;
        margin-bottom: 14px;
      }
      .pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        padding: 4px 9px;
        border-radius: 999px;
        border: 1px solid rgba(148, 163, 184, 0.3);
        margin-right: 6px;
        margin-bottom: 6px;
      }
      .pill-emoji {
        font-size: 13px;
      }
      ul {
        list-style: none;
        margin: 12px 0 16px 0;
      }
      li {
        display: flex;
        align-items: flex-start;
        gap: 8px;
        font-size: 13px;
        margin-bottom: 6px;
      }
      li span.bullet {
        font-size: 14px;
        margin-top: 1px;
      }
      .cta-box {
        margin-top: 16px;
        padding: 10px 12px;
        border-radius: 12px;
        background: rgba(15, 23, 42, 0.9);
        border: 1px dashed rgba(148, 163, 184, 0.3);
        font-size: 11px;
        color: #9ca3af;
      }
      .cta-btn {
        margin-top: 14px;
        width: 100%;
        border: none;
        outline: none;
        cursor: pointer;
        border-radius: 999px;
        padding: 11px 16px;
        font-size: 14px;
        font-weight: 600;
        background: linear-gradient(90deg, #22c55e, #16a34a);
        color: #022c22;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        box-shadow: 0 12px 30px rgba(34, 197, 94, 0.35);
        transition: transform 0.12s ease, box-shadow 0.12s ease, filter 0.12s ease;
      }
      .cta-btn:hover {
        transform: translateY(-1px);
        box-shadow: 0 18px 40px rgba(34, 197, 94, 0.45);
        filter: brightness(1.03);
      }
      .cta-btn:active {
        transform: translateY(0);
        box-shadow: 0 8px 20px rgba(34, 197, 94, 0.35);
      }
      .cta-btn-icon {
        font-size: 16px;
      }
      .footer {
        margin-top: 10px;
        font-size: 10px;
        color: #6b7280;
        text-align: center;
      }
    </style>
    ${antiCrawlerBlock}
    ${pixelBlock}
  </head>
  <body>
    <div class="card">
      <div class="badge">
        <span class="badge-dot"></span>
        <span>Official Telegram Channel</span>
      </div>
      <h1>${channelTitle}</h1>
      <div class="subtitle">
        Curated updates & insights by <strong>${clientName}</strong>. Join the channel to get instant alerts directly on Telegram.
      </div>

      <div>
        <div class="pill">
          <span class="pill-emoji">⚡</span>
          <span>Instant Telegram alerts</span>
        </div>
        <div class="pill">
          <span class="pill-emoji">🔔</span>
          <span>No spam, only signals</span>
        </div>
        <div class="pill">
          <span class="pill-emoji">🎯</span>
          <span>Hand-picked insights</span>
        </div>
      </div>

      <ul>
        <li>
          <span class="bullet">✅</span>
          <span>Get real-time updates before everyone else.</span>
        </li>
        <li>
          <span class="bullet">📊</span>
          <span>Short, actionable messages — no long reading.</span>
        </li>
        <li>
          <span class="bullet">🧠</span>
          <span>Learn the thought process behind every update.</span>
        </li>
      </ul>

      <div class="cta-box">
        Tap the button below and send a join request on Telegram. Our system will auto-approve you within a few seconds.
      </div>

      <button class="cta-btn" onclick="handleJoinClick(event)">
        <span class="cta-btn-icon">📲</span>
        <span>Join Telegram Channel</span>
      </button>

      <div class="footer">
        Powered by your private tracking workspace. Channel ID: ${telegramChatId}
      </div>
    </div>

    <script>
      const UTS_PUBLIC_KEY = "${publicKey}";
      const UTS_CHANNEL_ID = "${telegramChatId}";

      async function handleJoinClick(e) {
        if (e && e.preventDefault) e.preventDefault();

        try {
          await fetch("/api/v1/track/pre-lead", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              public_key: UTS_PUBLIC_KEY,
              channel_id: UTS_CHANNEL_ID,
              url: window.location.href,
              user_agent: navigator.userAgent,
              source: "lp_auto"
            })
          });
        } catch (err) {
          console.error("pre-lead tracking failed", err);
        }

        try {
          if (window.fbq && fbInitiateEvent) {
            fbq('track', fbInitiateEvent);
          }
        } catch (err) {
          console.error('fbq error', err);
        }

        window.location.href = "${deepLink}";
      }
    </script>
  </body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    console.error('❌ Error in GET /lp/:channelId:', err);
    res.status(500).send('Internal error');
  }
});


// ===== Phase 1: JSON Auth + Client Self-Signup + Owner Approval APIs =====

// Helper: plan -> max channels
function getMaxChannelsForPlan(plan) {
  switch ((plan || '').toLowerCase()) {
    case 'single':
      return 1;
    case 'starter':
      return 3;
    case 'pro':
      return 5;
    case 'agency':
      return 10;
    default:
      return 1;
  }
}

// Helper: basic email normalize
function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

// API: Client self-signup with plan
app.post('/api/auth/signup', async (req, res) => {
  try {
    let { name, email, password, plan } = req.body || {};
    name = (name || '').trim();
    email = normalizeEmail(email);
    plan = (plan || '').trim().toLowerCase();

    if (!name || !email || !password || !plan) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    const allowedPlans = ['single', 'starter', 'pro', 'agency'];
    if (!allowedPlans.includes(plan)) {
      return res.status(400).json({ success: false, error: 'Invalid plan selected' });
    }

    // Email already used?
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Email already registered' });
    }

    const now = Math.floor(Date.now() / 1000);
    const password_hash = await bcrypt.hash(password, 10);

    // Insert user as "client"
    const insertUser = db.prepare(`
      INSERT INTO users (email, password_hash, role, is_active, created_at)
      VALUES (?, ?, 'client', 1, ?)
    `);
    const userResult = insertUser.run(email, password_hash, now);
    const userId = userResult.lastInsertRowid;

    // Generate slug from name
    let slug = name
      .toLowerCase()
      .replace(/\s+/g, '-')
      .replace(/[^a-z0-9-]/g, '')
      .slice(0, 32);
    if (!slug) {
      slug = 'client-' + Date.now();
    }

    // Try to attach an owner/admin if available (first admin/owner)
    let ownerUserId = null;
    const ownerRow = db
      .prepare('SELECT id FROM users WHERE role IN (?, ?) ORDER BY id LIMIT 1')
      .get('admin', 'owner');
    if (ownerRow && ownerRow.id) {
      ownerUserId = ownerRow.id;
    }

    // Ensure slug roughly unique (by owner)
    if (ownerUserId) {
      const existingSlug = db
        .prepare('SELECT id FROM clients WHERE owner_user_id = ? AND slug = ?')
        .get(ownerUserId, slug);
      if (existingSlug) {
        slug = slug + '-' + Math.random().toString(36).slice(2, 5);
      }
    }

    const publicKey = generateKey('PUB');
    const secretKey = generateKey('SEC');
    const maxChannels = getMaxChannelsForPlan(plan);

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
        created_at,
        login_user_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const clientResult = insertClient.run(
      name,
      slug,
      ownerUserId,
      publicKey,
      secretKey,
      process.env.META_PIXEL_ID || null,
      process.env.META_ACCESS_TOKEN || null,
      plan,
      maxChannels,
      0, // pending until owner approves
      now,
      userId
    );

    return res.json({
      success: true,
      message: 'Account created. Please wait for owner approval.',
      client: {
        id: clientResult.lastInsertRowid,
        name,
        email,
        plan,
        max_channels: maxChannels,
        is_active: 0,
        slug,
        public_key: publicKey,
        secret_key: secretKey
      }
    });
  } catch (err) {
    console.error('❌ Error in /api/auth/signup:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// API: Client login (JSON) - sets same cookie as HTML /login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const normEmail = normalizeEmail(email);

    if (!normEmail || !password) {
      return res.status(400).json({ success: false, error: 'Missing email or password' });
    }

    const user = db
      .prepare('SELECT * FROM users WHERE email = ? LIMIT 1')
      .get(normEmail);

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    // Client login only for this endpoint
    if (user.role !== 'client') {
      return res.status(403).json({ success: false, error: 'Not a client account' });
    }

    const clientRow = db
      .prepare('SELECT * FROM clients WHERE login_user_id = ? LIMIT 1')
      .get(user.id);

    if (!clientRow) {
      return res.status(403).json({ success: false, error: 'Client workspace not found for this user' });
    }

    if (clientRow.is_active === 0) {
      return res.json({
        success: false,
        status: 'pending',
        message: 'Your account is pending approval by the owner.'
      });
    }

    if (clientRow.is_active === -1) {
      return res.json({
        success: false,
        status: 'rejected',
        message: 'Your account was rejected. Contact support.'
      });
    }

    // Same token format & cookie as existing /login flow (HMAC-based)
    const token = signAuthToken(user.id);
    res.cookie('auth', token, {
      httpOnly: true,
      sameSite: 'lax'
      // secure: true // enable if behind HTTPS
    });

    return res.json({
      success: true,
      user: {
        type: 'client',
        user_id: user.id,
        client_id: clientRow.id,
        email: user.email,
        plan: clientRow.plan,
        max_channels: clientRow.max_channels,
        is_active: clientRow.is_active,
        name: clientRow.name,
        slug: clientRow.slug
      }
    });
  } catch (err) {
    console.error('❌ Error in /api/auth/login:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// API: Who am I? (client/admin/owner) using cookie auth
app.get('/api/auth/me', requireAuth, (req, res) => {
  try {
    const user = req.user;

    if (user.role === 'client') {
      const clientRow = db
        .prepare('SELECT * FROM clients WHERE login_user_id = ? LIMIT 1')
        .get(user.id);

      if (!clientRow) {
        return res.status(404).json({ success: false, error: 'Client workspace not found' });
      }

      return res.json({
        success: true,
        user: {
          type: 'client',
          user_id: user.id,
          client_id: clientRow.id,
          email: user.email,
          plan: clientRow.plan,
          max_channels: clientRow.max_channels,
          is_active: clientRow.is_active,
          name: clientRow.name,
          slug: clientRow.slug
        }
      });
    }

    // Admin / owner
    if (user.role === 'admin' || user.role === 'owner') {
      return res.json({
        success: true,
        user: {
          type: 'owner',
          user_id: user.id,
          email: user.email,
          role: user.role
        }
      });
    }

    return res.status(403).json({ success: false, error: 'Unsupported role' });
  } catch (err) {
    console.error('❌ Error in /api/auth/me:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// API: Owner/admin login (JSON) - optional helper for React owner panel
// API: Client LP list

// API: Client channels list for LP Generator dropdown
app.get('/api/client/channels', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (!user || user.role !== 'client') {
      return res.status(403).json({ success: false, error: 'Not a client user' });
    }

    const clientRow = db
      .prepare('SELECT * FROM clients WHERE login_user_id = ? LIMIT 1')
      .get(user.id);

    if (!clientRow) {
      return res.status(404).json({ success: false, error: 'Client workspace not found' });
    }

    const clientId = clientRow.id;

    const channels = db
  .prepare(`
    SELECT
      id,
      telegram_chat_id,
      telegram_title,
      deep_link,
      pixel_id,
      lp_event_mode,
      lp_anti_crawler
    FROM channels
    WHERE client_id = ?
    ORDER BY id DESC
  `)
  .all(clientId);


    return res.json({ success: true, channels });
  } catch (err) {
    console.error('❌ Error in GET /api/client/channels:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

app.get('/api/client/landing-pages', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (!user || user.role !== 'client') {
      return res.status(403).json({ success: false, error: 'Not a client user' });
    }

    const clientRow = db
      .prepare('SELECT * FROM clients WHERE login_user_id = ? LIMIT 1')
      .get(user.id);

    if (!clientRow) {
      return res.status(404).json({ success: false, error: 'Client workspace not found' });
    }

    const clientId = clientRow.id;
    const channelFilter = req.query.channel_id ? parseInt(req.query.channel_id, 10) : null;
    const statusFilter = (req.query.status || '').trim().toLowerCase();

    let sql = `
      SELECT
        lp.id,
        lp.name,
        lp.slug,
        lp.template_key,
        lp.status,
        lp.channel_id,
        lp.created_at,
        lp.updated_at,
        ch.telegram_title,
        ch.telegram_chat_id,
        COALESCE(stats.views, 0) AS views,
        COALESCE(stats.clicks, 0) AS clicks,
        COALESCE(stats.pre_leads, 0) AS pre_leads
      FROM landing_pages lp
      JOIN channels ch ON ch.id = lp.channel_id
      LEFT JOIN (
        SELECT
          lp_id,
          SUM(CASE WHEN event_type = 'pageview' THEN 1 ELSE 0 END) AS views,
          SUM(CASE WHEN event_type = 'click' THEN 1 ELSE 0 END) AS clicks,
          SUM(CASE WHEN event_type = 'pre_lead' THEN 1 ELSE 0 END) AS pre_leads
        FROM lp_events
        WHERE client_id = ?
        GROUP BY lp_id
      ) AS stats ON stats.lp_id = lp.id
      WHERE lp.client_id = ?
    `;

    const params = [clientId, clientId];

    if (channelFilter) {
      sql += ' AND lp.channel_id = ?';
      params.push(channelFilter);
    }

    if (statusFilter) {
      sql += ' AND LOWER(lp.status) = ?';
      params.push(statusFilter);
    }

    sql += ' ORDER BY lp.id DESC';

    const rows = db.prepare(sql).all(...params);

    return res.json({ success: true, landing_pages: rows });
  } catch (err) {
    console.error('❌ Error in GET /api/client/landing-pages:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// API: Client LP create
app.post('/api/client/landing-pages', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (!user || user.role !== 'client') {
      return res.status(403).json({ success: false, error: 'Not a client user' });
    }

    const clientRow = db
      .prepare('SELECT * FROM clients WHERE login_user_id = ? LIMIT 1')
      .get(user.id);

    if (!clientRow) {
      return res.status(404).json({ success: false, error: 'Client workspace not found' });
    }

    const clientId = clientRow.id;
    let { name, channel_id, template_key, slug, lp_event_mode, anti_crawler, status, html_config, custom_domain_url } =
      req.body || {};

    name = String(name || '').trim();
    template_key = String(template_key || '').trim().toLowerCase();
    slug = String(slug || '').trim();
    lp_event_mode = String(lp_event_mode || '').trim().toLowerCase();
    status = String(status || '').trim().toLowerCase() || 'draft';
    anti_crawler = anti_crawler ? 1 : 0;

    channel_id = parseInt(channel_id, 10);
    if (!name || !channel_id || !template_key) {
      return res.status(400).json({ success: false, error: 'Missing name, channel_id or template_key' });
    }

    const channelRow = db
      .prepare('SELECT * FROM channels WHERE id = ? AND client_id = ? LIMIT 1')
      .get(channel_id, clientId);

    if (!channelRow) {
      return res.status(404).json({ success: false, error: 'Channel not found for this client' });
    }

    if (!lp_event_mode) {
      lp_event_mode = (channelRow.lp_event_mode || 'lead').toLowerCase();
    }
    if (lp_event_mode !== 'subscribe') {
      lp_event_mode = 'lead';
    }

    if (status !== 'draft' && status !== 'published' && status !== 'archived') {
      status = 'draft';
    }

    if (!slug) {
      slug = generateLpSlug(name);
    } else {
      slug = slugifyForUrl(slug);
      if (!slug) {
        slug = generateLpSlug(name);
      }
    }

    // enforce unique slug (simple retry loop)
    let finalSlug = slug;
    for (let i = 0; i < 3; i++) {
      const existing = db
        .prepare('SELECT id FROM landing_pages WHERE slug = ? LIMIT 1')
        .get(finalSlug);
      if (!existing) break;
      finalSlug = generateLpSlug(name);
    }
    slug = finalSlug;

    if (status === 'published') {
      const cntRow = db
        .prepare('SELECT COUNT(*) AS cnt FROM landing_pages WHERE channel_id = ? AND status = 'published'')
        .get(channel_id);
      const publishedCount = (cntRow && cntRow.cnt) || 0;
      if (publishedCount >= 10) {
        return res.status(400).json({
          success: false,
          error: 'MAX_PUBLISHED_PER_CHANNEL',
          message: 'You can publish max 10 LPs per channel. Archive or unpublish one to create new.'
        });
      }
    }

    let htmlConfigStr = '{}';
    try {
      if (typeof html_config === 'string') {
        JSON.parse(html_config);
        htmlConfigStr = html_config;
      } else if (html_config && typeof html_config === 'object') {
        htmlConfigStr = JSON.stringify(html_config);
      }
    } catch (e) {
      htmlConfigStr = '{}';
    }

    const now = Math.floor(Date.now() / 1000);
    const autoHostUrl = '/lp2/' + slug;

    const stmt = db.prepare(`
      INSERT INTO landing_pages (
        client_id,
        channel_id,
        name,
        slug,
        template_key,
        status,
        html_config,
        lp_event_mode,
        anti_crawler,
        auto_host_url,
        custom_domain_url,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const info = stmt.run(
      clientId,
      channel_id,
      name,
      slug,
      template_key,
      status,
      htmlConfigStr,
      lp_event_mode,
      anti_crawler,
      autoHostUrl,
      custom_domain_url || null,
      now,
      now
    );

    return res.json({
      success: true,
      landing_page: {
        id: info.lastInsertRowid,
        client_id: clientId,
        channel_id,
        name,
        slug,
        template_key,
        status,
        auto_host_url: autoHostUrl,
        custom_domain_url: custom_domain_url || null
      }
    });
  } catch (err) {
    console.error('❌ Error in POST /api/client/landing-pages:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// API: Client LP update
app.post('/api/client/landing-pages/:id', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (!user || user.role !== 'client') {
      return res.status(403).json({ success: false, error: 'Not a client user' });
    }

    const cntRow = db
  prepare("SELECT COUNT(*) AS cnt FROM landing_pages WHERE channel_id = ? AND status = 'published'")
  get(channel_id);


    if (!clientRow) {
      return res.status(404).json({ success: false, error: 'Client workspace not found' });
    }

    const clientId = clientRow.id;
    const lpId = parseInt(req.params.id, 10);
    if (!lpId) {
      return res.status(400).json({ success: false, error: 'Invalid LP id' });
    }

    const existing = db
      .prepare('SELECT * FROM landing_pages WHERE id = ? AND client_id = ? LIMIT 1')
      .get(lpId, clientId);

    if (!existing) {
      return res.status(404).json({ success: false, error: 'Landing page not found' });
    }

    let { name, channel_id, template_key, slug, lp_event_mode, anti_crawler, status, html_config, custom_domain_url } =
      req.body || {};

    name = name !== undefined ? String(name || '').trim() : existing.name;
    template_key = template_key !== undefined ? String(template_key || '').trim().toLowerCase() : existing.template_key;
    slug = slug !== undefined ? String(slug || '').trim() : existing.slug;
    lp_event_mode =
      lp_event_mode !== undefined ? String(lp_event_mode || '').trim().toLowerCase() : existing.lp_event_mode;
    status = status !== undefined ? String(status || '').trim().toLowerCase() : existing.status;
    anti_crawler = anti_crawler !== undefined ? (anti_crawler ? 1 : 0) : existing.anti_crawler;
    custom_domain_url =
      custom_domain_url !== undefined ? (custom_domain_url || null) : existing.custom_domain_url;

    channel_id = channel_id !== undefined ? parseInt(channel_id, 10) : existing.channel_id;
    if (!channel_id) {
      return res.status(400).json({ success: false, error: 'channel_id invalid' });
    }

    const channelRow = db
      .prepare('SELECT * FROM channels WHERE id = ? AND client_id = ? LIMIT 1')
      .get(channel_id, clientId);

    if (!channelRow) {
      return res.status(404).json({ success: false, error: 'Channel not found for this client' });
    }

    if (!lp_event_mode) {
      lp_event_mode = (channelRow.lp_event_mode || 'lead').toLowerCase();
    }
    if (lp_event_mode !== 'subscribe') {
      lp_event_mode = 'lead';
    }

    if (status !== 'draft' && status !== 'published' && status !== 'archived') {
      status = existing.status || 'draft';
    }

    if (!slug) {
      slug = generateLpSlug(name);
    } else {
      slug = slugifyForUrl(slug);
      if (!slug) {
        slug = existing.slug;
      }
    }

    if (status === 'published' && existing.status !== 'published') {
      const cntRow = db
        .prepare('SELECT COUNT(*) AS cnt FROM landing_pages WHERE channel_id = ? AND status = 'published' AND id != ?')
        .get(channel_id, lpId);
      const publishedCount = (cntRow && cntRow.cnt) || 0;
      if (publishedCount >= 10) {
        return res.status(400).json({
          success: false,
          error: 'MAX_PUBLISHED_PER_CHANNEL',
          message: 'You can publish max 10 LPs per channel. Archive or unpublish one to create new.'
        });
      }
    }

    let htmlConfigStr = existing.html_config || '{}';
    try {
      if (html_config !== undefined) {
        if (typeof html_config === 'string') {
          JSON.parse(html_config);
          htmlConfigStr = html_config;
        } else if (html_config && typeof html_config === 'object') {
          htmlConfigStr = JSON.stringify(html_config);
        }
      }
    } catch (e) {
      htmlConfigStr = existing.html_config || '{}';
    }

    const now = Math.floor(Date.now() / 1000);
    const autoHostUrl = '/lp2/' + slug;

    const stmt = db.prepare(`
      UPDATE landing_pages
      SET
        channel_id = ?,
        name = ?,
        slug = ?,
        template_key = ?,
        status = ?,
        html_config = ?,
        lp_event_mode = ?,
        anti_crawler = ?,
        auto_host_url = ?,
        custom_domain_url = ?,
        updated_at = ?
      WHERE id = ? AND client_id = ?
    `);

    stmt.run(
      channel_id,
      name,
      slug,
      template_key,
      status,
      htmlConfigStr,
      lp_event_mode,
      anti_crawler,
      autoHostUrl,
      custom_domain_url,
      now,
      lpId,
      clientId
    );

    return res.json({
      success: true,
      landing_page: {
        id: lpId,
        client_id: clientId,
        channel_id,
        name,
        slug,
        template_key,
        status,
        auto_host_url: autoHostUrl,
        custom_domain_url
      }
    });
  } catch (err) {
    console.error('❌ Error in POST /api/client/landing-pages/:id:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});


app.post('/api/owner/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const normEmail = normalizeEmail(email);
    if (!normEmail || !password) {
      return res.status(400).json({ success: false, error: 'Missing email or password' });
    }

    const cntRow = db
  prepare("SELECT COUNT(*) AS cnt FROM landing_pages WHERE channel_id = ? AND status = 'published' AND id != ?")
  get(channel_id, lpId);


    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({ success: false, error: 'Not an owner/admin account' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const token = signAuthToken(user.id);
    res.cookie('auth', token, {
      httpOnly: true,
      sameSite: 'lax'
      // secure: true // HTTPS only
    });

    return res.json({
      success: true,
      user: {
        type: 'owner',
        user_id: user.id,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error('❌ Error in /api/owner/login:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// API: Owner/admin – list pending clients
app.get('/api/owner/clients/pending', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const rows = db
      .prepare(`
        SELECT
          id,
          name,
          slug,
          plan,
          max_channels,
          is_active,
          created_at
        FROM clients
        WHERE is_active = 0
        ORDER BY created_at DESC
      `)
      .all();

    return res.json({
      success: true,
      clients: rows
    });
  } catch (err) {
    console.error('❌ Error in GET /api/owner/clients/pending:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});


// HTML form endpoints for owner dashboard approvals
app.post('/dashboard/clients/:id/approve', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (!user || (user.role !== 'admin' && user.role !== 'owner')) {
      return res.redirect('/login');
    }
    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.redirect('/dashboard');
    }
    const update = db.prepare(`
      UPDATE clients
      SET is_active = 1
      WHERE id = ?
    `);
    update.run(clientId);
    return res.redirect('/dashboard');
  } catch (err) {
    console.error('❌ Error in POST /dashboard/clients/:id/approve:', err);
    return res.redirect('/dashboard');
  }
});

app.post('/dashboard/clients/:id/reject', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (!user || (user.role !== 'admin' && user.role !== 'owner')) {
      return res.redirect('/login');
    }
    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.redirect('/dashboard');
    }
    const update = db.prepare(`
      UPDATE clients
      SET is_active = -1
      WHERE id = ?
    `);
    update.run(clientId);
    return res.redirect('/dashboard');
  } catch (err) {
    console.error('❌ Error in POST /dashboard/clients/:id/reject:', err);
    return res.redirect('/dashboard');
  }
});

// API: Owner/admin – approve client
app.post('/api/owner/clients/:id/approve', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.status(400).json({ success: false, error: 'Invalid client id' });
    }

    const update = db.prepare(`
      UPDATE clients
      SET is_active = 1
      WHERE id = ?
    `);
    update.run(clientId);

    const client = db
      .prepare('SELECT id, name, plan, max_channels, is_active FROM clients WHERE id = ?')
      .get(clientId);

    return res.json({ success: true, client });
  } catch (err) {
    console.error('❌ Error in POST /api/owner/clients/:id/approve:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// API: Owner/admin – reject client
app.post('/api/owner/clients/:id/reject', requireAuth, (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'admin' && user.role !== 'owner') {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const clientId = parseInt(req.params.id, 10);
    if (!clientId || Number.isNaN(clientId)) {
      return res.status(400).json({ success: false, error: 'Invalid client id' });
    }

    const update = db.prepare(`
      UPDATE clients
      SET is_active = -1
      WHERE id = ?
    `);
    update.run(clientId);

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ Error in POST /api/owner/clients/:id/reject:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});


// ----- Start server -----
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});