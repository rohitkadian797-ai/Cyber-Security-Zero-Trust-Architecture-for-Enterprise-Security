import { Router, Response } from 'express';
import { PolicyEngine } from '../services/policyEngine.js';
import { optionalAuthenticate, AuthenticatedRequest } from '../middleware/auth.middleware.js';
import db from '../db/database.js';
import { decryptData } from '../utils/crypto.js';
import { Resource } from '../types/index.js';

export const resourceRouter = Router();

// GET /api/resources - List all protected resources
resourceRouter.get('/', (_req, res) => {
  try {
    const resources = db.prepare(`
      SELECT r.id, r.name, r.segment_id, r.sensitivity, r.required_role, r.requires_mfa, r.description,
             s.name as segment_name, s.color as segment_color, s.isolation_level
      FROM resources r
      JOIN network_segments s ON r.segment_id = s.id
    `).all();
    return res.json(resources);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/resources/:id - Get resource details
resourceRouter.get('/:id', (req, res) => {
  try {
    const resource = db.prepare(`
      SELECT r.id, r.name, r.segment_id, r.sensitivity, r.required_role, r.requires_mfa, r.description,
             s.name as segment_name, s.color as segment_color, s.isolation_level
      FROM resources r
      JOIN network_segments s ON r.segment_id = s.id
      WHERE r.id = ?
    `).get(req.params.id) as unknown as (Resource & { segment_name: string; segment_color: string; isolation_level: string }) | undefined;

    if (!resource) return res.status(404).json({ error: 'Resource not found' });
    return res.json(resource);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/resources/:id/access - Access protected resource (evaluates Zero Trust dynamically)
resourceRouter.post('/:id/access', optionalAuthenticate, (req: AuthenticatedRequest, res: Response) => {
  try {
    const resourceId = req.params.id;
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(resourceId) as unknown as Resource | undefined;
    if (!resource) return res.status(404).json({ error: 'Resource not found' });

    const evaluationReq = {
      userId: req.body.userId || req.user?.userId,
      role: req.body.role || req.user?.role || 'guest',
      resourceId,
      action: req.body.action || 'READ',
      deviceTrust: req.body.deviceTrust || 'trusted',
      mfaVerified: req.body.mfaVerified !== undefined ? Boolean(req.body.mfaVerified) : Boolean(req.user?.mfaVerified),
      simulatedRiskScore: Number(req.body.simulatedRiskScore) || 10,
      ipAddress: req.body.ipAddress || req.ip || '127.0.0.1',
      sourceSegmentId: req.body.sourceSegmentId,
    };

    const evaluation = PolicyEngine.evaluateAccess(evaluationReq);

    if (evaluation.decision === 'DENY') {
      return res.status(403).json({
        accessGranted: false,
        error: evaluation.reason,
        evaluation
      });
    }

    // Access granted: Decrypt sensitive payload
    let decryptedPayload: any = resource.data_payload;
    try {
      const rawDecrypted = decryptData(resource.data_payload);
      decryptedPayload = JSON.parse(rawDecrypted);
    } catch {
      decryptedPayload = decryptData(resource.data_payload);
    }

    return res.json({
      accessGranted: true,
      resource: {
        id: resource.id,
        name: resource.name,
        sensitivity: resource.sensitivity,
        segmentId: resource.segment_id
      },
      data: decryptedPayload,
      evaluation
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
