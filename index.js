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
  res.header('Access-Control-Allow-Origin', '*'); // chahe to yaha Netlify domain daal sakte ho
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
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

// ----- Basic health route -----
app.get('/', (req, res) => {
  res.send('Telegram Funnel Bot running ✅');
});

// ----- Debug: last joins -----
app.get('/debug-joins', (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM joins ORDER BY id DESC LIMIT 20').all();
    res.json(rows);
  } catch (err) {
    console.error('❌ Error reading joins:', err.message);
    res.status(500).json({ error: 'DB error' });
  }
});

// ----- Debug: channels table -----
app.get('/debug-channels', (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM channels ORDER BY id DESC LIMIT 20').all();
    res.json(rows);
  } catch (err) {
    console.error('❌ Error reading channels:', err.message);
    res.status(500).json({ error: 'DB error' });
  }
});

// ----- SaaS-style pageview tracking (multi-client via public_key) -----
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

    // Insert same as /pre-lead
    const info = insertPreLeadStmt.run(
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

    // Attach client_id to this pageview pre_lead
    try {
      db.prepare('UPDATE pre_leads SET client_id = ? WHERE id = ?').run(
        client.id,
        info.lastInsertRowid
      );
    } catch (e) {
      console.error(
        '⚠️ Failed to attach client_id to pageview pre_lead:',
        e.message || e
      );
    }

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

    const info = insertPreLeadStmt.run(
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

    // Attach correct client_id using channels table (fallback client_id = 1)
    try {
      const channelRow = db
        .prepare('SELECT client_id FROM channels WHERE telegram_chat_id = ?')
        .get(String(channel_id));

      const clientIdForPreLead =
        channelRow && channelRow.client_id ? channelRow.client_id : 1;

      db.prepare('UPDATE pre_leads SET client_id = ? WHERE id = ?').run(
        clientIdForPreLead,
        info.lastInsertRowid
      );
    } catch (e) {
      console.error(
        '⚠️ Failed to attach client_id to CTR pre_lead:',
        e.message || e
      );
    }

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
  const channelConfig = getOrCreateChannelConfigFromJoin(joinRequest, eventTime);

  const pixelId = channelConfig.pixel_id || DEFAULT_META_PIXEL_ID;
  const lpUrl = channelConfig.lp_url || DEFAULT_PUBLIC_LP_URL;

  const url = `https://graph.facebook.com/v18.0/${pixelId}/events?access_token=${META_ACCESS_TOKEN}`;

  const externalIdHash = hashSha256(String(user.id));
  const eventId = generateEventId();

  const userData = {
    external_id: externalIdHash,
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
  };

  if (Object.keys(customData).length > 0) {
    eventBody.custom_data = customData;
  }

  const payload = {
    data: [eventBody],
  };

  const res = await axios.post(url, payload);
  console.log('Meta CAPI response:', res.data);

  // ✅ Joins table me log karein – client_id bhi store karein
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
    channelConfig.client_id || 1
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

// ----- CLIENT-SPECIFIC JSON Stats API: /api/v1/client/stats -----
// Body example:
// { "public_key": "PUB_xxx" }  OR  { "secret_key": "SEC_xxx" }
app.post('/api/v1/client/stats', (req, res) => {
  try {
    const { public_key, secret_key } = req.body || {};

    if (!public_key && !secret_key) {
      return res.status(400).json({
        ok: false,
        error: 'public_key or secret_key required',
      });
    }

    let client = null;
    if (public_key) {
      client = db
        .prepare('SELECT * FROM clients WHERE public_key = ?')
        .get(String(public_key));
    } else if (secret_key) {
      client = db
        .prepare('SELECT * FROM clients WHERE secret_key = ?')
        .get(String(secret_key));
    }

    if (!client) {
      return res.status(404).json({
        ok: false,
        error: 'client_not_found',
      });
    }

    const clientId = client.id;

    // Total joins for this client
    const totalRow = db
      .prepare('SELECT COUNT(*) AS cnt FROM joins WHERE client_id = ?')
      .get(clientId);
    const totalJoins = totalRow.cnt || 0;

    // Today joins
    const now = Math.floor(Date.now() / 1000);
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const startOfDayTs = Math.floor(startOfDay.getTime() / 1000);

    const todayRow = db
      .prepare(
        'SELECT COUNT(*) AS cnt FROM joins WHERE joined_at >= ? AND joined_at <= ? AND client_id = ?'
      )
      .get(startOfDayTs, now, clientId);
    const todayJoins = todayRow.cnt || 0;

    // Last 7 days breakdown
    const sevenDaysAgoTs = now - 7 * 24 * 60 * 60;
    const rows7 = db
      .prepare(
        'SELECT joined_at FROM joins WHERE joined_at >= ? AND client_id = ? ORDER BY joined_at ASC'
      )
      .all(sevenDaysAgoTs, clientId);

    const byDateMap = {};
    for (const r of rows7) {
      const dateKey = formatDateYYYYMMDD(r.joined_at);
      byDateMap[dateKey] = (byDateMap[dateKey] || 0) + 1;
    }

    const last7Days = Object.keys(byDateMap)
      .sort()
      .map((date) => ({ date, count: byDateMap[date] }));

    // By channel for this client
    const channels = db
      .prepare(
        `
        SELECT 
          channel_id,
          channel_title,
          COUNT(*) AS total
        FROM joins
        WHERE client_id = ?
        GROUP BY channel_id, channel_title
        ORDER BY total DESC
      `
      )
      .all(clientId);

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
        WHERE client_id = ?
        ORDER BY joined_at DESC
        LIMIT 50
      `
      )
      .all(clientId);

    res.json({
      ok: true,
      client_id: clientId,
      total_joins: totalJoins,
      today_joins: todayJoins,
      last_7_days: last7Days,
      by_channel: channels,
      recent_joins: recentJoins,
    });
  } catch (err) {
    console.error('❌ Error in /api/v1/client/stats:', err);
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
                          const dt = new Date(j.joined_at * 1000)
                            .toISOString()
                            .replace('T', ' ')
                            .substring(0, 19);
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
      sameSite: 'lax',
      // secure: true // HTTPS pe on karna
    });

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

// GET /panel - multi-client panel
app.get('/panel', requireAuth, (req, res) => {
  try {
    const user = req.user;

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
        .prepare('SELECT COUNT(*) AS cnt FROM joins WHERE client_id = ?')
        .get(c.id);
      return {
        client_id: c.id,
        total_joins: row.cnt || 0,
      };
    });

    const statsByClientId = {};
    clientStats.forEach((s) => {
      statsByClientId[s.client_id] = s.total_joins;
    });

    const rowsHtml =
      clients
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
          </tr>
        `;
        })
        .join('') ||
      `
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
          @media (max-width: 900px) {
            table {
              display: block;
              overflow-x: auto;
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

// ----- DEV: Seed admin + client + keys (one-time helper) -----
app.get('/dev/seed-admin', async (req, res) => {
  try {
    const key = req.query.admin_key;
    if (key !== ADMIN_KEY) {
      return res.status(401).json({ ok: false, error: 'Invalid admin_key' });
    }

    // 1) Check if any admin user already exists
    const existingAdmin = db
      .prepare('SELECT * FROM users WHERE role = ? LIMIT 1')
      .get('admin');

    if (existingAdmin) {
      return res.json({
        ok: true,
        message: 'Admin already exists, nothing to do.',
        admin_email: existingAdmin.email,
      });
    }

    const now = Math.floor(Date.now() / 1000);

    const email = 'admin@uts.local'; // dev ke liye, baad me change kar dena
    const password = 'Admin@123'; // dev ke liye, UI banne ke baad reset karna

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
        password,
      },
      tracking_keys: {
        public_key: publicKey,
        secret_key: secretKey,
      },
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
