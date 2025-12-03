const Database = require('better-sqlite3');

// DB file ka naam
const db = new Database('telegram_funnel.db');

// --- USERS TABLE ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'client'
  );
`);

// --- CLIENTS ---
db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    slug TEXT,
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

// --- CHANNELS ---
db.exec(`
  CREATE TABLE IF NOT EXISTS channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER,
    telegram_chat_id TEXT UNIQUE,
    telegram_title TEXT,
    deep_link TEXT,
    pixel_id TEXT,
    meta_token TEXT,
    lp_url TEXT,
    created_at INTEGER,
    is_active INTEGER DEFAULT 1
  );
`);

// --- JOINS ---
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

// --- PRE LEADS ---
db.exec(`
  CREATE TABLE IF NOT EXISTS pre_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id TEXT,
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

// 🔧 AUTO-MIGRATION
function ensureColumns(table, columns) {
  const existing = new Set(
    db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name)
  );

  for (const col of columns) {
    if (!existing.has(col.name)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${col.name} ${col.type};`);
      console.log(`Added column ${col.name} to ${table}`);
    }
  }
}


// Users me role + is_active + created_at ensure karo
ensureColumns("users", [
  { name: "role", type: "TEXT" },
  { name: "is_active", type: "INTEGER" },
  { name: "created_at", type: "INTEGER" }
]);

// Clients me login_user_id ensure karo
ensureColumns("clients", [
  { name: "login_user_id", type: "INTEGER" }
]);

// Channels me meta_token ensure karo
ensureColumns("channels", [
  { name: "meta_token", type: "TEXT" }
]);

// pre_leads me created_at ensure karo (agar purana DB hai jisme ts tha)
ensureColumns("pre_leads", [
  { name: "created_at", type: "INTEGER" }
]);

// joins me client_id ensure karo (safety)
ensureColumns("joins", [
  { name: "client_id", type: "INTEGER" }
]);

module.exports = db;
