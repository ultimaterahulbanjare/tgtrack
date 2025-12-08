// Load environment variables from .env (Render / local dono ke liye)
require('dotenv').config();

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const db = require('./db'); // SQLite (better-sqlite3) DB connection
const geoip = require('geoip-lite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

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
    // - admin/owner: go to /panel (multi-client view)
    // - client: go directly to its own workspace
    if (user.role === 'admin' || user.role === 'owner') {
      return res.redirect('/panel');
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

    const clients = db
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

    // Same token format & cookie as existing /login flow
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
app.post('/api/owner/login', async (req, res) => {
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