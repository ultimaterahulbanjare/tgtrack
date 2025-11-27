
// Load environment variables from .env (Render / local dono ke liye)
require('dotenv').config();

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const db = require('./db'); // SQLite (better-sqlite3) DB connection
const geoip = require('geoip-lite');

const app = express();
app.use(express.json());

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

// Default Pixel & LP (fallback)
const DEFAULT_META_PIXEL_ID = '1340877837162888';
const DEFAULT_PUBLIC_LP_URL = 'https://tourmaline-flan-4abc0c.netlify.app/';

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

// ----- LP se pre-lead capture (fbc/fbp + tracking store) -----
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
    external_id: externalIdHash,
    ...(fbcForThisLead ? { fbc: fbcForThisLead } : {}),
    ...(fbpForThisLead ? { fbp: fbpForThisLead } : {}),
    ...(ipForThisLead ? { client_ip_address: ipForThisLead } : {}),
    ...(uaForThisLead ? { client_user_agent: uaForThisLead } : {}),
  };

  const customData = {
    ...(sourceForThisLead ? { source: sourceForThisLead } : {}),
    ...(utmSourceForThisLead ? { utm_source: utmSourceForThisLead } : {}),
    ...(utmMediumForThisLead ? { utm_medium: utmMediumForThisLead } : {}),
    ...(utmCampaignForThisLead ? { utm_campaign: utmCampaignForThisLead } : {}),
    ...(utmContentForThisLead ? { utm_content: utmContentForThisLead } : {}),
    ...(utmTermForThisLead ? { utm_term: utmTermForThisLead } : {}),
  };

  const payload = {
    data: [
      {
        event_name: 'Lead',
        event_time: eventTime,
        event_id: eventId,
        event_source_url: lpUrl,
        action_source: 'website',
        user_data: userData,
        ...(Object.keys(customData).length ? { custom_data: customData } : {}),
      },
    ],
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

// ----- Start server -----
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
