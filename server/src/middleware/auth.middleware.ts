import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service.js';
import { AuthTokenPayload, UserRole } from '../types/index.js';

export interface AuthenticatedRequest extends Request {
  user?: AuthTokenPayload;
}

export function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Missing Bearer token.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = AuthService.verifyJwt(token);
    req.user = payload;
    next();
  } catch (err: any) {
    return res.status(401).json({ error: 'Invalid or expired authentication token', details: err.message });
  }
}

export function optionalAuthenticate(req: AuthenticatedRequest, _res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      req.user = AuthService.verifyJwt(token);
    } catch {
      // Ignored for optional
    }
  }
  next();
}

export function authorizeRole(...allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized: User not authenticated' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden: Insufficient privileges for this operation',
        requiredRoles: allowedRoles,
        userRole: req.user.role
      });
    }

    next();
  };
}

export function requireMfa(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized: User not authenticated' });
  }

  if (!req.user.mfaVerified) {
    return res.status(403).json({
      error: 'MFA Verification Required: Step-up authentication needed to proceed',
      mfaRequired: true
    });
  }

  next();
}
