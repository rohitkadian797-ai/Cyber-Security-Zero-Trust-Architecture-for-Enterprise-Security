import jwt from 'jsonwebtoken';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import db from '../db/database.js';
import { User, UserSanitized, AuthTokenPayload, Session } from '../types/index.js';
import { comparePassword, hashPassword } from '../utils/crypto.js';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-jwt-secret-key-12345';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '8h';

export class AuthService {
  public static sanitizeUser(user: User): UserSanitized {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      mfa_enabled: user.mfa_enabled === 1,
      is_active: user.is_active === 1,
      department: user.department,
      created_at: user.created_at,
      updated_at: user.updated_at
    };
  }

  public static async register(
    username: string,
    email: string,
    password: string,
    role: 'admin' | 'security_analyst' | 'employee' | 'guest' = 'employee',
    department: string = 'General'
  ): Promise<UserSanitized> {
    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existing) {
      throw new Error('Username or email already registered');
    }

    const id = crypto.randomUUID();
    const password_hash = await hashPassword(password);
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, role, mfa_enabled, is_active, department, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, ?)
    `).run(id, username, email, password_hash, role, department, now, now);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as unknown as User;
    return this.sanitizeUser(user);
  }

  public static async login(
    username: string,
    password: string,
    deviceTrust: 'trusted' | 'managed' | 'untrusted' | 'compromised' = 'trusted',
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'WebBrowser'
  ): Promise<{ token: string; user: UserSanitized; requiresMfa: boolean; sessionId: string }> {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as unknown as User | undefined;
    if (!user) {
      throw new Error('Invalid credentials');
    }

    if (user.is_active !== 1) {
      throw new Error('User account is locked or deactivated by Security Administrator');
    }

    const passwordMatch = await comparePassword(password, user.password_hash || '');
    if (!passwordMatch) {
      // Log failed login event
      this.logAuthEvent('LOGIN_FAILED', user.username, user.role, 'DENY', 'Bad password provided', 40, ipAddress, deviceTrust);
      throw new Error('Invalid credentials');
    }

    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
    const now = new Date().toISOString();

    const mfaRequired = user.mfa_enabled === 1;

    // Issue initial token (mfaVerified is false until step-up OTP confirmed if MFA enabled)
    const tokenPayload: AuthTokenPayload = {
      userId: user.id,
      username: user.username,
      role: user.role,
      mfaVerified: !mfaRequired,
      sessionId
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN as any });

    // Store active session
    db.prepare(`
      INSERT INTO sessions (id, user_id, token, ip_address, user_agent, device_trust, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(sessionId, user.id, token, ipAddress, userAgent, deviceTrust, expiresAt, now);

    this.logAuthEvent('LOGIN_SUCCESS', user.username, user.role, 'ALLOW', 'User credentials authenticated', 10, ipAddress, deviceTrust);

    return {
      token,
      user: this.sanitizeUser(user),
      requiresMfa: mfaRequired,
      sessionId
    };
  }

  public static async generateMfaSecret(userId: string): Promise<{ secret: string; qrCodeUrl: string }> {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as unknown as User | undefined;
    if (!user) throw new Error('User not found');

    const secret = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(user.email, 'ZeroTrustSecOps', secret);
    const qrCodeUrl = await QRCode.toDataURL(otpAuthUrl);

    // Save temporary secret to user record
    db.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?').run(secret, userId);

    return { secret, qrCodeUrl };
  }

  public static verifyMfa(userId: string, token: string, sessionId: string): { success: boolean; updatedToken: string } {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as unknown as User | undefined;
    if (!user || !user.mfa_secret) {
      throw new Error('MFA setup is not initialized for this account');
    }

    const isValid = authenticator.check(token, user.mfa_secret);
    if (!isValid) {
      this.logAuthEvent('MFA_FAILED', user.username, user.role, 'DENY', 'Invalid TOTP verification code', 50, '127.0.0.1', 'trusted');
      throw new Error('Invalid authentication code');
    }

    // Enable MFA permanently
    db.prepare('UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?').run(new Date().toISOString(), userId);

    // Issue updated token with mfaVerified = true
    const updatedPayload: AuthTokenPayload = {
      userId: user.id,
      username: user.username,
      role: user.role,
      mfaVerified: true,
      sessionId
    };

    const updatedToken = jwt.sign(updatedPayload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN as any });

    // Update active session token
    db.prepare('UPDATE sessions SET token = ? WHERE id = ?').run(updatedToken, sessionId);

    this.logAuthEvent('MFA_VERIFIED', user.username, user.role, 'ALLOW', 'Step-up TOTP verification succeeded', 0, '127.0.0.1', 'trusted');

    return { success: true, updatedToken };
  }

  public static verifyJwt(token: string): AuthTokenPayload {
    return jwt.verify(token, JWT_SECRET) as AuthTokenPayload;
  }

  public static logout(sessionId: string): void {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
  }

  private static logAuthEvent(
    eventType: string,
    username: string,
    role: string,
    decision: 'ALLOW' | 'DENY',
    reason: string,
    riskScore: number,
    ipAddress: string,
    deviceTrust: string
  ) {
    try {
      db.prepare(`
        INSERT INTO security_events (
          id, event_type, username, user_role, resource, action, decision, 
          reason, risk_score, device_trust, ip_address, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        crypto.randomUUID(),
        eventType,
        username,
        role,
        'AUTH_GATEWAY',
        'AUTHENTICATE',
        decision,
        reason,
        riskScore,
        deviceTrust,
        ipAddress,
        new Date().toISOString()
      );
    } catch (e) {
      console.error('Error logging auth event:', e);
    }
  }
}
