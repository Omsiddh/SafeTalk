import express from 'express';
import User from '../models/User.js';
import { authMiddleware } from '../middleware/auth.js';
import { requireRole } from '../middleware/role.js';

const router = express.Router();

router.get('/users', authMiddleware, requireRole('admin'), async (req, res) => {
  const users = await User.find().select('_id username email role disabled createdAt');
  res.json(users);
});

router.patch('/users/:id/disable', authMiddleware, requireRole('admin'), async (req, res) => {
  const { disabled } = req.body || {};
  const user = await User.findByIdAndUpdate(req.params.id, { disabled: !!disabled }, { new: true }).select('_id username disabled');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ message: 'Updated', user });
});

export default router;