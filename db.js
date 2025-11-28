const Database = require('better-sqlite3');

// DB file ka naam (ye hi file me sab data store hoga)
const db = new Database('telegram_funnel.db');

// --- Table: clients (future SaaS users / agencies) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    api_key TEXT,
    created_at INTEGER
  );
`);

// --- Table: channels (har Telegram channel ki config) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER,
    telegram_chat_id TEXT UNIQUE,
    telegram_title TEXT,
    deep_link TEXT,
    pixel_id TEXT,
    lp_url TEXT,
    created_at INTEGER,
    is_active INTEGER DEFAULT 1
  );
`);

// --- Table: joins log ---
// NOTE: purane DB me ye columns na bhi ho sakte hain, neeche migration se add ho jayenge
db.exec(`
  CREATE TABLE IF NOT EXISTS joins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_user_id TEXT,
    telegram_username TEXT,
    channel_id TEXT,
    channel_title TEXT,
    joined_at INTEGER,
    meta_event_id TEXT,
    ip TEXT,
    country TEXT,
    user_agent TEXT,
    device_type TEXT,
    browser TEXT,
    os TEXT,
    source TEXT,
    utm_source TEXT,
    utm_medium TEXT,
    utm_campaign TEXT,
    utm_content TEXT,
    utm_term TEXT
  );
`);

// --- Table: pre_leads (LP JOIN click + tracking data) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS pre_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id TEXT NOT NULL,
    fbc TEXT,
    fbp TEXT,
    ip TEXT,
    country TEXT,
    user_agent TEXT,
    device_type TEXT,
    browser TEXT,
    os TEXT,
    source TEXT,
    utm_source TEXT,
    utm_medium TEXT,
    utm_campaign TEXT,
    utm_content TEXT,
    utm_term TEXT,
    created_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
`);

// 🔹 Safe migration helpers
function ensureColumns(tableName, columns) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${tableName})`).all();
    const existing = new Set(cols.map(c => c.name));

    for (const col of columns) {
      if (!existing.has(col.name)) {
        const sql = `ALTER TABLE ${tableName} ADD COLUMN ${col.name} ${col.type};`;
        db.exec(sql);
        console.log(`✅ Added column ${col.name} to ${tableName}`);
      }
    }
  } catch (e) {
    console.log(`ℹ️ ${tableName} migration check error:`, e.message);
  }
}

// 🔹 pre_leads ke liye ensure karo ke sab nayi tracking columns ho
ensureColumns('pre_leads', [
  { name: 'fbp', type: 'TEXT' },        // agar purane version me missing ho
  { name: 'ip', type: 'TEXT' },
  { name: 'country', type: 'TEXT' },
  { name: 'user_agent', type: 'TEXT' },
  { name: 'device_type', type: 'TEXT' },
  { name: 'browser', type: 'TEXT' },
  { name: 'os', type: 'TEXT' },
  { name: 'source', type: 'TEXT' },
  { name: 'utm_source', type: 'TEXT' },
  { name: 'utm_medium', type: 'TEXT' },
  { name: 'utm_campaign', type: 'TEXT' },
  { name: 'utm_content', type: 'TEXT' },
  { name: 'utm_term', type: 'TEXT' }
]);

// 🔹 joins ke liye bhi ensure karo ke sab nayi tracking columns ho
ensureColumns('joins', [
  { name: 'ip', type: 'TEXT' },
  { name: 'country', type: 'TEXT' },
  { name: 'user_agent', type: 'TEXT' },
  { name: 'device_type', type: 'TEXT' },
  { name: 'browser', type: 'TEXT' },
  { name: 'os', type: 'TEXT' },
  { name: 'source', type: 'TEXT' },
  { name: 'utm_source', type: 'TEXT' },
  { name: 'utm_medium', type: 'TEXT' },
  { name: 'utm_campaign', type: 'TEXT' },
  { name: 'utm_content', type: 'TEXT' },
  { name: 'utm_term', type: 'TEXT' }
]);

// --- Ensure ek default client row ho always (id=1) ---
const defaultClient = db.prepare(`SELECT id FROM clients WHERE id = 1`).get();
if (!defaultClient) {
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    INSERT INTO clients (id, name, email, api_key, created_at)
    VALUES (1, 'Default Client', 'default@example.com', 'DEFAULT_KEY', ?)
  `).run(now);

  console.log("✅ Default client created (id=1)");
}

module.exports = db;
