import express from 'express';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';
import Message from '../models/Message.js';
import { authMiddleware, ensureActive } from '../middleware/auth.js';

const router = express.Router();

const messageSchema = z.object({
  receiverId: z.string(),
  ciphertext: z.string().min(1),
  encryptedKey: z.string().min(1),
  iv: z.string().min(1),
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60, // 60 messages per minute per IP (demo)
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/send', authMiddleware, ensureActive, messageLimiter, async (req, res) => {
  try {
    const parsed = messageSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

    const { receiverId, ciphertext, encryptedKey, iv } = parsed.data;
    const msg = await Message.create({ sender: req.user.id, receiver: receiverId, ciphertext, encryptedKey, iv });

    // Emit over socket.io if available
    const io = req.app.get('io');
    if (io) {
      io.to(receiverId).emit('message:receive', {
        _id: msg._id,
        from: req.user.id,
        to: receiverId,
        ciphertext,
        encryptedKey,
        iv,
        timestamp: msg.createdAt,
      });
    }

    return res.status(201).json({ message: 'Sent', id: msg._id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/receive', authMiddleware, ensureActive, async (req, res) => {
  try {
    const { with: withUser } = req.query;
    const filter = withUser
      ? { $or: [ { sender: req.user.id, receiver: withUser }, { sender: withUser, receiver: req.user.id } ] }
      : { receiver: req.user.id };
    const messages = await Message.find(filter).sort({ createdAt: 1 }).limit(200);
    return res.json(messages.map(m => ({
      _id: m._id,
      from: m.sender,
      to: m.receiver,
      ciphertext: m.ciphertext,
      encryptedKey: m.encryptedKey,
      iv: m.iv,
      timestamp: m.createdAt,
    })));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;