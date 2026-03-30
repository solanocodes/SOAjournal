const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'soa-trading-journal-secret-key-2026';

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, is_mentor: user.is_mentor },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function mentorOnly(req, res, next) {
  if (!req.user.is_mentor) {
    return res.status(403).json({ error: 'Mentor access required' });
  }
  next();
}

module.exports = { generateToken, authMiddleware, mentorOnly, JWT_SECRET };
