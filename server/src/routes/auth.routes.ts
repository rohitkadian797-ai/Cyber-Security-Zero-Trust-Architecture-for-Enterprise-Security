import { Router, Response } from 'express';
import { AuthService } from '../services/auth.service.js';
import { authenticate, AuthenticatedRequest } from '../middleware/auth.middleware.js';
import db from '../db/database.js';
import { User } from '../types/index.js';

export const authRouter = Router();

// POST /api/auth/register
authRouter.post('/register', async (req, res) => {
  try {
    const { username, email, password, role, department } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    const newUser = await AuthService.register(username, email, password, role, department);
    return res.status(201).json({ message: 'User registered successfully', user: newUser });
  } catch (err: any) {
    return res.status(400).json({ error: err.message });
  }
});

// POST /api/auth/login
authRouter.post('/login', async (req, res) => {
  try {
    const { username, password, deviceTrust, ipAddress } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const clientIp = ipAddress || req.ip || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'WebBrowser';

    const loginResult = await AuthService.login(username, password, deviceTrust, clientIp, userAgent);
    return res.json(loginResult);
  } catch (err: any) {
    return res.status(401).json({ error: err.message });
  }
});

// POST /api/auth/mfa/setup
authRouter.post('/mfa/setup', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const userId = req.user!.userId;
    const mfaData = await AuthService.generateMfaSecret(userId);
    return res.json(mfaData);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/mfa/verify
authRouter.post('/mfa/verify', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Verification OTP token is required' });
    }

    const { userId, sessionId } = req.user!;
    const verification = AuthService.verifyMfa(userId, token, sessionId);
    return res.json(verification);
  } catch (err: any) {
    return res.status(400).json({ error: err.message });
  }
});

// GET /api/auth/me
authRouter.get('/me', authenticate, (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.userId) as User | undefined;
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json({
      user: AuthService.sanitizeUser(user),
      session: {
        sessionId: req.user!.sessionId,
        role: req.user!.role,
        mfaVerified: req.user!.mfaVerified
      }
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/logout
authRouter.post('/logout', authenticate, (req: AuthenticatedRequest, res: Response) => {
  try {
    AuthService.logout(req.user!.sessionId);
    return res.json({ message: 'Logged out successfully' });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/users (for demo user switcher in dashboard)
authRouter.get('/users', (_req, res) => {
  try {
    const users = db.prepare('SELECT id, username, email, role, mfa_enabled, is_active, department FROM users').all();
    return res.json(users);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
