const db = require('../db');

function resolveSecretClient(req, res, next) {
  const secretKey = req.body.secret_key;

  if (!secretKey) {
    return res.status(401).json({ error: 'secret_key required' });
  }

  const client = db.prepare('SELECT * FROM clients WHERE secret_key = ?').get(secretKey);

  if (!client) {
    return res.status(403).json({ error: 'invalid secret_key' });
  }

  req.client = client;
  next();
}

module.exports = resolveSecretClient;
