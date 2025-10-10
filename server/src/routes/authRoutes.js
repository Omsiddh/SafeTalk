import express from 'express';
import { z } from 'zod';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { isValidPublicKey } from '../utils/encryption.js';
import { authMiddleware } from '../middleware/auth.js';
import { generateTOTPSecret, qrCodeDataURL, verifyTOTP } from '../utils/totp.js';
import rateLimit from 'express-rate-limit';

const router = express.Router();

const registerSchema = z.object({
  username: z.string().min(3),
  email: z.string().email(),
  password: z.string().min(8),
  publicKey: z.string(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const verify2faSchema = z.object({
  tempToken: z.string(),
  otp: z.string().min(6).max(6),
});

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

function signAccessToken(user) {
  return jwt.sign({ userId: user._id.toString(), role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
}

function signRefreshToken(user) {
  return jwt.sign({ userId: user._id.toString() }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
}

function signTemp2FAToken(user) {
  return jwt.sign({ userId: user._id.toString(), twofa: true }, process.env.JWT_SECRET, { expiresIn: '5m' });
}

router.post('/register', async (req, res) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
    const { username, email, password, publicKey } = parsed.data;

    if (!isValidPublicKey(publicKey)) return res.status(400).json({ error: 'Invalid public key' });
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(409).json({ error: 'User already exists' });

    const passwordHash = await argon2.hash(password);
    const user = await User.create({ username, email, passwordHash, publicKey });
    return res.status(201).json({ message: 'Registered', userId: user._id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/login', loginLimiter, async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

    const { email, password } = parsed.data;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.disabled) return res.status(403).json({ error: 'Account disabled' });

    const ok = await argon2.verify(user.passwordHash, password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.twoFactorEnabled) {
      const tempToken = signTemp2FAToken(user);
      return res.json({ requires2FA: true, tempToken });
    }

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    return res.json({ accessToken, refreshToken, user: { id: user._id, username: user.username, role: user.role } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/verify-2fa', async (req, res) => {
  try {
    const parsed = verify2faSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

    const { tempToken, otp } = parsed.data;
    let payload;
    try {
      payload = jwt.verify(tempToken, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    if (!payload.twofa) return res.status(400).json({ error: 'Not a 2FA token' });

    const user = await User.findById(payload.userId);
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) return res.status(400).json({ error: '2FA not enabled' });

    const valid = verifyTOTP({ secret: user.twoFactorSecret, token: otp });
    if (!valid) return res.status(401).json({ error: 'Invalid OTP' });

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    return res.json({ accessToken, refreshToken, user: { id: user._id, username: user.username, role: user.role } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/enable-2fa', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { base32, otpauth_url } = generateTOTPSecret(user.email);
    user.twoFactorSecret = base32;
    // Do not enable yet until verified
    await user.save();

    const qr = await qrCodeDataURL(otpauth_url);
    return res.json({ otpauthUrl: otpauth_url, qrCodeDataUrl: qr });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/disable-2fa', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save();
    return res.json({ message: '2FA disabled' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/verify-setup-2fa', authMiddleware, async (req, res) => {
  try {
    const { otp } = req.body || {};
    if (!otp) return res.status(400).json({ error: 'OTP required' });
    const user = await User.findById(req.user.id);
    if (!user || !user.twoFactorSecret) return res.status(400).json({ error: 'No pending 2FA setup' });
    const ok = verifyTOTP({ secret: user.twoFactorSecret, token: otp });
    if (!ok) return res.status(401).json({ error: 'Invalid OTP' });
    user.twoFactorEnabled = true;
    await user.save();
    return res.json({ message: '2FA enabled' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Lookup user public key by username for chatting
router.get('/users/:username', authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username }).select('_id username publicKey');
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ id: user._id, username: user.username, publicKey: user.publicKey });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;