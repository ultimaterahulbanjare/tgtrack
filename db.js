const Database = require('better-sqlite3');

// DB file ka naam (ye hi file me sab data store hoga)
const db = new Database('telegram_funnel.db');

/**
 * NEW: Users table (login / roles)
 */
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'client'
  );
`);

/**
 * Clients (tumhara SaaS clients = agencies / businesses)
 */
db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    slug TEXT,
    email TEXT,
    api_key TEXT,
    owner_user_id INTEGER,
    public_key TEXT,
    secret_key TEXT,
    default_pixel_id TEXT,
    default_meta_token TEXT,
    plan TEXT,
    max_channels INTEGER,
    is_active INTEGER DEFAULT 1,
    created_at INTEGER
  );
`);

/**
 * Channels (har Telegram channel ki config)
 */
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

/**
 * Joins log
 */
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
    utm_term TEXT,
    client_id INTEGER
  );
`);

/**
 * pre_leads (LP click + tracking)
 */
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
    client_id INTEGER,
    created_at INTEGER
  );
`);

// ---------- Auto-migration helper ----------
function ensureColumns(tableName, columns) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${tableName})`).all();
    const existing = new Set(cols.map((c) => c.name));

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

/**
 * SaaS upgrade: clients table extra columns
 */
ensureColumns('clients', [
  { name: 'slug', type: 'TEXT' },
  { name: 'owner_user_id', type: 'INTEGER' },
  { name: 'public_key', type: 'TEXT' },
  { name: 'secret_key', type: 'TEXT' },
  { name: 'default_pixel_id', type: 'TEXT' },
  { name: 'default_meta_token', type: 'TEXT' },
  { name: 'plan', type: 'TEXT' },
  { name: 'max_channels', type: 'INTEGER' },
  { name: 'is_active', type: 'INTEGER' }
]);

// NEW: per-channel CAPI token column
ensureColumns('channels', [
  { name: 'meta_token', type: 'TEXT' }
]);

// pre_leads upgrade
ensureColumns('pre_leads', [
  { name: 'fbp', type: 'TEXT' },
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
  { name: 'utm_term', type: 'TEXT' },
  { name: 'client_id', type: 'INTEGER' }
]);

// joins upgrade
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
  { name: 'utm_term', type: 'TEXT' },
  { name: 'client_id', type: 'INTEGER' }
]);

// Default client ensure
const defaultClient = db
  .prepare(`SELECT id FROM clients WHERE id = 1`)
  .get();
if (!defaultClient) {
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    INSERT INTO clients (id, name, email, api_key, created_at)
    VALUES (1, 'Default Client', 'default@example.com', 'DEFAULT_KEY', ?)
  `).run(now);

  console.log('✅ Default client created (id=1)');
}

module.exports = db;
