const db = require('../db');

function resolvePublicClient(req, res, next) {
  const publicKey = req.body.public_key || req.headers['x-public-key'];

  if (!publicKey) {
    return res.status(401).json({ error: 'public_key required' });
  }

  const client = db.prepare('SELECT * FROM clients WHERE public_key = ?').get(publicKey);

  if (!client) {
    return res.status(403).json({ error: 'invalid public_key' });
  }

  req.client = client; // yaha se baaki route ko client mil jayega
  next();
}

module.exports = resolvePublicClient;
