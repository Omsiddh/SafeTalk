import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = { id: payload.userId, role: payload.role };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

export async function ensureActive(req, res, next) {
  try {
    const user = await User.findById(req.user.id).select('disabled');
    if (!user || user.disabled) return res.status(403).json({ error: 'Account disabled' });
    next();
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
}