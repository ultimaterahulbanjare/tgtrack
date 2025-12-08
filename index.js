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
// Serve frontend React panel
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

function requireAuthApi(req, res, next) {
  const token = req.cookies && req.cookies.auth;
  const userId = verifyAuthToken(token);

  if (!userId) {
    return res.status(401).json({ success: false, error: 'Not authenticated' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) {
    res.clearCookie('auth');
    return res.status(401).json({ success: false, error: 'Invalid session' });
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
      null,
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
  const clientIdForJoin = channelConfig.client_id || null;

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
        utm_term,
        client_id
      )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    utmTermForThisLead || null,
    clientIdForJoin
  );

  console.log('✅ Join stored in DB for user:', user.id);


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
      `)
      .get(clientId);
    const totalJoins = totalRow.cnt || 0;

    // Today joins for this client
    const todayRow = db
      .prepare(
        `
        SELECT COUNT(*) AS cnt
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
          AND j.joined_at >= ?
          AND j.joined_at <= ?
      `
      )
      .get(clientId, startOfDayTs, now);
    const todayJoins = todayRow.cnt || 0;

    // Last 7 days breakdown
    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;
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
      .all(clientId, sevenDaysAgoTs);

    const byDateMap = {};
    for (const r of rows7) {
      const dateKey = formatDateYYYYMMDD(r.joined_at);
      byDateMap[dateKey] = (byDateMap[dateKey] || 0) + 1;
    }
    const last7Days = Object.keys(byDateMap)
      .sort()
      .map((date) => ({ date, count: byDateMap[date] }));

    // By channel stats (from joins)
    const byChannelStats = db
      .prepare(
        `
        SELECT
          ch.telegram_chat_id AS channel_id,
          ch.telegram_title AS channel_title,
          COUNT(*) AS total
        FROM joins j
        JOIN channels ch ON ch.telegram_chat_id = j.channel_id
        WHERE ch.client_id = ?
        GROUP BY ch.telegram_chat_id, ch.telegram_title
        ORDER BY total DESC
      `
      )
      .all(clientId);

    const trackingBase = process.env.PUBLIC_TRACKING_BASE_URL || process.env.PUBLIC_BACKEND_URL || '';


    const channelTotalsMap = {};
    for (const row of byChannelStats) {
      channelTotalsMap[String(row.channel_id)] = row.total;
    }


    // Per-channel today joins
    const channelTodayRows = db
      .prepare(
        `
        SELECT
          ch.telegram_chat_id AS channel_id,
          COUNT(j.id) AS cnt
        FROM channels ch
        LEFT JOIN joins j
          ON j.channel_id = ch.telegram_chat_id
          AND j.joined_at >= ?
          AND j.joined_at <= ?
        WHERE ch.client_id = ?
        GROUP BY ch.telegram_chat_id
      `
      )
      .all(startOfDayTs, now, clientId);

    const channelTodayMap = {};
    for (const r of channelTodayRows) {
      channelTodayMap[String(r.channel_id)] = r.cnt || 0;
    }

    // Per-channel last 7 days joins
    const channel7dRows = db
      .prepare(
        `
        SELECT
          ch.telegram_chat_id AS channel_id,
          COUNT(j.id) AS cnt
        FROM channels ch
        LEFT JOIN joins j
          ON j.channel_id = ch.telegram_chat_id
          AND j.joined_at >= ?
        WHERE ch.client_id = ?
        GROUP BY ch.telegram_chat_id
      `
      )
      .all(sevenDaysAgoTs, clientId);

    const channel7dMap = {};
    for (const r of channel7dRows) {
      channel7dMap[String(r.channel_id)] = r.cnt || 0;
    }

    // Channel configs for this client
    const channelConfigs = db
      .prepare(
        `
        SELECT
          id,
          telegram_chat_id,
          telegram_title,
          deep_link,
          pixel_id,
          lp_url,
          is_active,
          created_at
        FROM channels
        WHERE client_id = ?
        ORDER BY created_at DESC, id DESC
      `
      )
      .all(clientId);

    // Recent joins
    const recentJoins = db
      .prepare(
        `
        SELECT
          j.telegram_username,
          j.channel_title,
          j.channel_id,
          j.joined_at,
          j.ip,
          j.country,
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
          .cards {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 20px;
          }
          .card {
            background: #020617;
            border-radius: 14px;
            padding: 12px 14px;
            border: 1px solid #1f2937;
            min-width: 150px;
          }
          .card h2 {
            font-size: 13px;
            color: #9ca3af;
            margin: 0 0 4px 0;
          }
          .card .value {
            font-size: 20px;
            font-weight: 600;
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
          .section-title {
            font-size: 15px;
            margin: 16px 0 4px 0;
          }
          .channels-form-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: flex-end;
            margin-bottom: 10px;
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
          @media (max-width: 900px) {
            table {
              display: block;
              overflow-x: auto;
            }
            .channels-form-row {
              flex-direction: column;
              align-items: stretch;
            }
          }
        </style>
      </head>
      <body>
        <div class="topbar">
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
          <pre style="margin-top:8px;background:#020617;border-radius:10px;border:1px solid #1f2937;padding:10px;font-size:11px;overflow-x:auto;">
<code>&lt;script&gt;
  const UTS_PUBLIC_KEY = "${client.public_key || ''}";
  const UTS_API_BASE   = "${trackingBase}";
  const UTS_CHANNEL_ID = "CHANNEL_ID_HERE";
  // Example: call pageview
  fetch(UTS_API_BASE + "/api/v1/track/pageview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      public_key: UTS_PUBLIC_KEY,
      channel_id: UTS_CHANNEL_ID,
      url: window.location.href,
      user_agent: navigator.userAgent
    })
  });
&lt;/script&gt;</code>
          </pre>
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

        <h2 class="section-title">By channel</h2>
        <table>
          <thead>
            <tr>
              <th>Channel title</th>
              <th>Channel ID</th>
              <th>Total joins</th>
            </tr>
          </thead>
          <tbody>
            ${
              byChannelStats.length === 0
                ? `<tr><td colspan="3" class="muted">No channels yet</td></tr>`
                : byChannelStats
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

        <h2 class="section-title">Manage channels</h2>
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
              <th>LP</th>
              <th>Status</th>
              <th>Total joins</th>
              <th>Today</th>
              <th>Last 7 days</th>
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
                      const todayCount = channelTodayMap[String(ch.telegram_chat_id)] || 0;
                      const last7Count = channel7dMap[String(ch.telegram_chat_id)] || 0;
                      const autoLpUrl = `/lp/${ch.id}`;
                      const customLp = ch.lp_url || '';
                      const customDisplay = customLp
                        ? `<a href="${customLp}" target="_blank">${customLp}</a>`
                        : 'Not set';
                      return `
              <tr>
                <td>${ch.telegram_title || '(no title)'}</td>
                <td>${ch.telegram_chat_id}</td>
                <td>${ch.deep_link || ''}</td>
                <td>${ch.pixel_id || ''}</td>
                <td>
                  <div style="display:flex;flex-direction:column;gap:4px;">
                    <div>
                      <span style="font-size:11px;color:#9ca3af;margin-right:6px;">Auto LP</span>
                      <a href="${autoLpUrl}" target="_blank" class="btn btn-xs">Open</a>
                    </div>
                    <div style="font-size:11px;color:#9ca3af;">
                      Custom: ${customDisplay}
                    </div>
                  </div>
                </td>
                <td>${status}</td>
                <td>${tot}</td>
                <td>${todayCount}</td>
                <td>${last7Count}</td>
                <td>${created}</td>
              </tr>`;
                    })
                    .join('')
            }
          </tbody>
        </table>

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
              <th>UTM Source</th>
              <th>UTM Medium</th>
              <th>UTM Campaign</th>
            </tr>
          </thead>
          <tbody>
            ${
              recentJoins.length === 0
                ? `<tr><td colspan="12" class="muted">No joins yet</td></tr>`
                : recentJoins
                    .map((j) => {
                      const dt = new Date(j.joined_at * 1000)
                        .toISOString()
                        .replace('T', ' ')
                        .substring(0, 19);
                      return `
              <tr>
                <td>${dt}</td>
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
              </tr>`;
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
        pixel_id || null,
        meta_token || null,
        lp_url || null,
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
          if (window.fbq) {
            fbq('track', 'Lead');
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


// ===== API: Auth (Phase 1 – client signup/login) =====

// Helper: map plan -> max_channels
function getMaxChannelsForPlan(plan) {
  if (!plan) return 1;
  const key = String(plan).toLowerCase();
  if (key === 'single') return 1;
  if (key === 'starter') return 3;
  if (key === 'pro') return 5;
  if (key === 'agency') return 10;
  return 1;
}

// Client signup – creates user + client row (pending approval)
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, plan } = req.body || {};

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ success: false, error: 'Name, email, password required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const existingUser = db
      .prepare('SELECT * FROM users WHERE email = ? LIMIT 1')
      .get(normalizedEmail);
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, error: 'Email already registered' });
    }

    const hash = await bcrypt.hash(password, 10);
    const max_channels = getMaxChannelsForPlan(plan);
    const now = Math.floor(Date.now() / 1000);

    const insertUser = db.prepare(
      'INSERT INTO users (email, password_hash, role, is_active, created_at) VALUES (?, ?, ?, ?, ?)'
    );
    const infoUser = insertUser.run(
      normalizedEmail,
      hash,
      'client',
      1,
      now
    );

    const insertClient = db.prepare(
      `INSERT INTO clients (
        name,
        plan,
        max_channels,
        is_active,
        created_at,
        login_user_id
      ) VALUES (?, ?, ?, ?, ?, ?)`
    );
    insertClient.run(
      name,
      plan || 'starter',
      max_channels,
      0,
      now,
      infoUser.lastInsertRowid
    );

    return res.json({
      success: true,
      message:
        'Account created. Owner will review and approve your workspace.',
    });
  } catch (err) {
    console.error('❌ Error in /api/auth/signup:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// Client / owner login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, error: 'Email and password required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const user = db
      .prepare('SELECT * FROM users WHERE email = ? LIMIT 1')
      .get(normalizedEmail);
    if (!user) {
      return res
        .status(401)
        .json({ success: false, error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res
        .status(401)
        .json({ success: false, error: 'Invalid credentials' });
    }

    // For client accounts, check their client workspace status
    if (user.role === 'client') {
      const client = db
        .prepare('SELECT * FROM clients WHERE login_user_id = ? LIMIT 1')
        .get(user.id);

      if (!client) {
        return res.status(403).json({
          success: false,
          status: 'no_client',
          message: 'No client workspace is attached to this user yet.',
        });
      }

      if (client.is_active === 0) {
        return res.status(403).json({
          success: false,
          status: 'pending',
          message: 'Your account is pending approval by the owner.',
        });
      }

      if (client.is_active === -1) {
        return res.status(403).json({
          success: false,
          status: 'rejected',
          message: 'Your account was rejected. Contact support.',
        });
      }
    }

    const token = signAuthToken(user.id);
    res.cookie('auth', token, {
      httpOnly: true,
      sameSite: 'lax',
    });

    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('❌ Error in /api/auth/login:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// Check current session
app.get('/api/auth/me', (req, res) => {
  try {
    const token = req.cookies && req.cookies.auth;
    const userId = verifyAuthToken(token);
    if (!userId) {
      return res.json({ success: false, user: null });
    }

    const user = db
      .prepare('SELECT * FROM users WHERE id = ? LIMIT 1')
      .get(userId);
    if (!user) {
      res.clearCookie('auth');
      return res.json({ success: false, user: null });
    }

    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('❌ Error in /api/auth/me:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// ===== API: Owner – approve/reject clients (simple JSON layer) =====

// Owner login (email/password) – must be role=admin
app.post('/api/owner/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, error: 'Email and password required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = db
      .prepare(
        'SELECT * FROM users WHERE email = ? AND role = ? LIMIT 1'
      )
      .get(normalizedEmail, 'admin');

    if (!user) {
      return res
        .status(401)
        .json({ success: false, error: 'Invalid owner credentials' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res
        .status(401)
        .json({ success: false, error: 'Invalid owner credentials' });
    }

    const token = signAuthToken(user.id);
    res.cookie('auth', token, {
      httpOnly: true,
      sameSite: 'lax',
    });

    return res.json({ success: true, role: 'admin' });
  } catch (err) {
    console.error('❌ Error in /api/owner/login:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// Owner: list pending clients
app.get('/api/owner/clients/pending', requireAuthApi, (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'admin') {
      return res
        .status(403)
        .json({ success: false, error: 'Not an owner/admin' });
    }

    const rows = db
      .prepare('SELECT * FROM clients WHERE is_active = 0 ORDER BY created_at DESC')
      .all();

    return res.json({ success: true, clients: rows });
  } catch (err) {
    console.error('❌ Error in /api/owner/clients/pending:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// Owner: approve / reject client
app.post('/api/owner/clients/:id/status', requireAuthApi, (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'admin') {
      return res
        .status(403)
        .json({ success: false, error: 'Not an owner/admin' });
    }

    const clientId = parseInt(req.params.id, 10);
    const { status } = req.body || {}; // "approved", "rejected"

    if (!clientId || Number.isNaN(clientId)) {
      return res
        .status(400)
        .json({ success: false, error: 'Invalid client id' });
    }

    let newStatus = 0;
    if (status === 'approved') newStatus = 1;
    else if (status === 'rejected') newStatus = -1;
    else {
      return res.status(400).json({
        success: false,
        error: 'status must be "approved" or "rejected"',
      });
    }

    db.prepare('UPDATE clients SET is_active = ? WHERE id = ?').run(
      newStatus,
      clientId
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('❌ Error in /api/owner/clients/:id/status:', err);
    return res.status(500).json({ success: false, error: 'Internal error' });
  }
});

// ===== Phase 2: Client Dashboard (summary + channels) =====

function formatDateYYYYMMDD(ts) {
  const d = new Date(ts * 1000);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function getClientForUser(userId) {
  return db
    .prepare('SELECT * FROM clients WHERE login_user_id = ? LIMIT 1')
    .get(userId);
}

// Client summary: plan, usage, basic stats
app.get('/api/client/dashboard/summary', requireAuthApi, (req, res) => {
  try {
    const user = req.user;

    if (user.role !== 'client') {
      return res
        .status(403)
        .json({ success: false, error: 'Not a client account' });
    }

    const client = getClientForUser(user.id);
    if (!client) {
      return res
        .status(404)
        .json({ success: false, error: 'Client workspace not found' });
    }

    if (client.is_active === 0) {
      return res.json({
        success: false,
        status: 'pending',
        message: 'Your account is pending approval by the owner.',
      });
    }

    if (client.is_active === -1) {
      return res.json({
        success: false,
        status: 'rejected',
        message: 'Your account was rejected. Contact support.',
      });
    }

    const now = Math.floor(Date.now() / 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfDayTs = Math.floor(startOfDay.getTime() / 1000);
    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;

    const totalRow = db
      .prepare('SELECT COUNT(*) AS cnt FROM joins WHERE client_id = ?')
      .get(client.id);
    const totalJoins = totalRow.cnt || 0;

    const todayRow = db
      .prepare(
        'SELECT COUNT(*) AS cnt FROM joins WHERE client_id = ? AND joined_at >= ? AND joined_at <= ?'
      )
      .get(client.id, startOfDayTs, now);
    const todayJoins = todayRow.cnt || 0;

    const rows7 = db
      .prepare(
        'SELECT joined_at FROM joins WHERE client_id = ? AND joined_at >= ? ORDER BY joined_at ASC'
      )
      .all(client.id, sevenDaysAgoTs);

    const byDateMap = {};
    for (const r of rows7) {
      const dateKey = formatDateYYYYMMDD(r.joined_at);
      byDateMap[dateKey] = (byDateMap[dateKey] || 0) + 1;
    }

    const last7Days = Object.keys(byDateMap)
      .sort()
      .map((d) => ({ date: d, count: byDateMap[d] }));

    const usedChannelsRow = db
      .prepare(
        'SELECT COUNT(*) AS cnt FROM channels WHERE client_id = ? AND is_active = 1'
      )
      .get(client.id);
    const usedChannels = usedChannelsRow.cnt || 0;

    return res.json({
      success: true,
      client: {
        id: client.id,
        name: client.name,
        plan: client.plan,
        max_channels: client.max_channels,
        used_channels: usedChannels,
        remaining_channels: Math.max(
          0,
          (client.max_channels || 0) - usedChannels
        ),
      },
      stats: {
        total_joins: totalJoins,
        today_joins: todayJoins,
        last_7_days: last7Days,
      },
    });
  } catch (err) {
    console.error('❌ Error in /api/client/dashboard/summary:', err);
    return res
      .status(500)
      .json({ success: false, error: 'Internal error' });
  }
});

// List channels for this client + per-channel stats
app.get('/api/client/channels', requireAuthApi, (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'client') {
      return res
        .status(403)
        .json({ success: false, error: 'Not a client account' });
    }

    const client = getClientForUser(user.id);
    if (!client) {
      return res
        .status(404)
        .json({ success: false, error: 'Client workspace not found' });
    }

    const now = Math.floor(Date.now() / 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfDayTs = Math.floor(startOfDay.getTime() / 1000);
    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;

    const channels = db
      .prepare(
        \`
        SELECT
          id,
          telegram_chat_id,
          telegram_title,
          deep_link,
          pixel_id,
          meta_token,
          lp_url,
          is_active
        FROM channels
        WHERE client_id = ?
        ORDER BY id DESC
      \`
      )
      .all(client.id);

    const joins = db
      .prepare(
        \`
        SELECT
          channel_id,
          COUNT(*) AS total,
          SUM(CASE WHEN joined_at >= ? AND joined_at <= ? THEN 1 ELSE 0 END) AS today,
          SUM(CASE WHEN joined_at >= ? THEN 1 ELSE 0 END) AS last7
        FROM joins
        WHERE client_id = ?
        GROUP BY channel_id
      \`
      )
      .all(startOfDayTs, now, sevenDaysAgoTs, client.id);

    const statsByChannelId = {};
    for (const row of joins) {
      statsByChannelId[row.channel_id] = {
        total: row.total || 0,
        today: row.today || 0,
        last7: row.last7 || 0,
      };
    }

    const result = channels.map((ch) => {
      const key = ch.telegram_chat_id;
      const s = statsByChannelId[key] || {
        total: 0,
        today: 0,
        last7: 0,
      };
      return {
        ...ch,
        stats: s,
      };
    });

    return res.json({ success: true, channels: result });
  } catch (err) {
    console.error('❌ Error in /api/client/channels (GET):', err);
    return res
      .status(500)
      .json({ success: false, error: 'Internal error' });
  }
});

// Create / update channel for a client
app.post('/api/client/channels', requireAuthApi, (req, res) => {
  try {
    const user = req.user;
    if (user.role !== 'client') {
      return res
        .status(403)
        .json({ success: false, error: 'Not a client account' });
    }

    const client = getClientForUser(user.id);
    if (!client) {
      return res
        .status(404)
        .json({ success: false, error: 'Client workspace not found' });
    }

    const {
      id,
      telegram_chat_id,
      telegram_title,
      deep_link,
      pixel_id,
      meta_token,
      lp_url,
      is_active,
    } = req.body || {};

    if (!telegram_chat_id) {
      return res
        .status(400)
        .json({ success: false, error: 'telegram_chat_id required' });
    }

    const now = Math.floor(Date.now() / 1000);

    if (id) {
      const existing = db
        .prepare(
          'SELECT * FROM channels WHERE id = ? AND client_id = ? LIMIT 1'
        )
        .get(id, client.id);

      if (!existing) {
        return res.status(404).json({
          success: false,
          error: 'Channel not found for this client',
        });
      }

      const updatedPixel = pixel_id ?? existing.pixel_id;
      const updatedMetaToken = meta_token ?? existing.meta_token;
      const updatedLp = lp_url ?? existing.lp_url;
      const updatedTitle = telegram_title ?? existing.telegram_title;
      const updatedDeepLink = deep_link ?? existing.deep_link;
      const updatedIsActive =
        typeof is_active === 'number'
          ? is_active
          : typeof is_active === 'string'
          ? parseInt(is_active, 10)
          : existing.is_active;

      db.prepare(
        \`
        UPDATE channels
        SET telegram_title = ?,
            deep_link = ?,
            pixel_id = ?,
            meta_token = ?,
            lp_url = ?,
            is_active = ?
        WHERE id = ? AND client_id = ?
      \`
      ).run(
        updatedTitle,
        updatedDeepLink,
        updatedPixel,
        updatedMetaToken,
        updatedLp,
        updatedIsActive,
        id,
        client.id
      );

      const fresh = db
        .prepare(
          'SELECT * FROM channels WHERE id = ? AND client_id = ? LIMIT 1'
        )
        .get(id, client.id);

      return res.json({ success: true, channel: fresh, mode: 'updated' });
    }

    const usedChannelsRow = db
      .prepare(
        'SELECT COUNT(*) AS cnt FROM channels WHERE client_id = ? AND is_active = 1'
      )
      .get(client.id);
    const usedChannels = usedChannelsRow.cnt || 0;

    if (usedChannels >= (client.max_channels || 0)) {
      return res.status(403).json({
        success: false,
        error: 'Channel limit reached for your plan',
      });
    }

    const existingByChat = db
      .prepare('SELECT * FROM channels WHERE telegram_chat_id = ?')
      .get(String(telegram_chat_id));

    if (existingByChat && existingByChat.client_id !== client.id) {
      return res.status(400).json({
        success: false,
        error:
          'This Telegram chat ID is already attached to another client workspace.',
      });
    }

    const insert = db.prepare(
      \`
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
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    \`
    );

    const info = insert.run(
      client.id,
      String(telegram_chat_id),
      telegram_title || null,
      deep_link || null,
      pixel_id || client.default_pixel_id || null,
      meta_token || client.default_meta_token || null,
      lp_url || null,
      now,
      typeof is_active === 'number' ? is_active : 1
    );

    const created = db
      .prepare(
        'SELECT * FROM channels WHERE id = ? AND client_id = ? LIMIT 1'
      )
      .get(info.lastInsertRowid, client.id);

    return res.json({ success: true, channel: created, mode: 'created' });
  } catch (err) {
    console.error('❌ Error in /api/client/channels (POST):', err);
    return res
      .status(500)
      .json({ success: false, error: 'Internal error' });
  }
});

// ----- Start server -----
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
