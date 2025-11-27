const bcrypt = require('bcryptjs');
const db = require('./db');

async function main() {
  const email = 'admin@example.com';      // baad me change kar sakte ho
  const password = 'Admin@123';          // sirf dev ke liye
  const now = Math.floor(Date.now() / 1000);

  // Check: user already hai kya?
  const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (existing) {
    console.log('User already exists:', existing.email);
    return;
  }

  const password_hash = await bcrypt.hash(password, 10);

  const insertUser = db.prepare(`
    INSERT INTO users (email, password_hash, role, created_at)
    VALUES (?, ?, ?, ?)
  `);

  const userResult = insertUser.run(email, password_hash, 'admin', now);
  const userId = userResult.lastInsertRowid;

  // Random keys (simple version)
  const publicKey = 'PUB_' + Math.random().toString(36).slice(2, 10);
  const secretKey = 'SEC_' + Math.random().toString(36).slice(2, 10);

  const insertClient = db.prepare(`
    INSERT INTO clients (
      name, slug, owner_user_id,
      public_key, secret_key,
      default_pixel_id, default_meta_token,
      plan, max_channels, is_active, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertClient.run(
    'Rahul Main Account',
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

  console.log('Seed complete ✅');
  console.log('Login email:', email);
  console.log('Login pass :', password);
  console.log('Public key :', publicKey);
  console.log('Secret key :', secretKey);
}

main().catch(console.error);
