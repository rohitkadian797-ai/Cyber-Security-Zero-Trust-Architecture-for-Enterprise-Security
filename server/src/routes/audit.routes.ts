import { Router } from 'express';
import crypto from 'crypto';
import db from '../db/database.js';

export const auditRouter = Router();

// GET /api/audit/events - Fetch security audit logs
auditRouter.get('/events', (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
    const decision = req.query.decision as string;

    let query = 'SELECT * FROM security_events';
    const params: any[] = [];

    if (decision && (decision === 'ALLOW' || decision === 'DENY')) {
      query += ' WHERE decision = ?';
      params.push(decision);
    }

    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const events = db.prepare(query).all(...params);
    return res.json(events);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/audit/stats - SOC Dashboard Analytics
auditRouter.get('/stats', (_req, res) => {
  try {
    const totalEvents = db.prepare('SELECT COUNT(*) as count FROM security_events').get() as { count: number };
    const deniedEvents = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE decision = 'DENY'").get() as { count: number };
    const allowedEvents = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE decision = 'ALLOW'").get() as { count: number };
    const avgRisk = db.prepare('SELECT AVG(risk_score) as avg FROM security_events').get() as { avg: number };
    const criticalThreats = db.prepare('SELECT COUNT(*) as count FROM security_events WHERE risk_score >= 70').get() as { count: number };

    // Recent decision distribution
    const recentActivity = db.prepare(`
      SELECT strftime('%H:%M', created_at) as time_bucket, decision, COUNT(*) as count
      FROM security_events
      GROUP BY time_bucket, decision
      ORDER BY time_bucket DESC
      LIMIT 12
    `).all();

    return res.json({
      totalRequests: totalEvents.count,
      blockedRequests: deniedEvents.count,
      allowedRequests: allowedEvents.count,
      blockRatePercentage: totalEvents.count > 0 ? Math.round((deniedEvents.count / totalEvents.count) * 100) : 0,
      averageRiskScore: Math.round(avgRisk.avg || 0),
      criticalThreatAlerts: criticalThreats.count,
      recentActivity
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/audit/simulate-attack - Trigger live simulated anomaly event for SOC demonstration
auditRouter.post('/simulate-attack', (req, res) => {
  try {
    const attackTypes = [
      {
        type: 'LATERAL_MOVEMENT_BLOCKED',
        resource: 'Data Fortress / Production Vault',
        user: 'compromised.user',
        role: 'employee',
        risk: 88,
        device: 'compromised',
        reason: 'Micro-segmentation firewall blocked illegal cross-segment route (seg-corp -> seg-prod-vault)'
      },
      {
        type: 'CREDENTIAL_STUFFING_BLOCKED',
        resource: 'AUTH_GATEWAY',
        user: 'unknown_bot',
        role: 'guest',
        risk: 94,
        device: 'untrusted',
        reason: 'Anomalous velocity: 40 failed authentication attempts from IP 198.51.100.12'
      },
      {
        type: 'PRIVILEGE_ABUSE_DETECTED',
        resource: 'SecOps Threat Intelligence Feed',
        user: 'vendor.contractor',
        role: 'guest',
        risk: 75,
        device: 'untrusted',
        reason: 'Zero Trust Principle "Least Privilege": Guest attempted confidential access without active MFA'
      }
    ];

    const pick = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO security_events (id, event_type, username, user_role, resource, action, decision, reason, risk_score, device_trust, ip_address, details, created_at)
      VALUES (?, ?, ?, ?, ?, 'SIMULATED_ATTACK', 'DENY', ?, ?, ?, '198.51.100.22', ?, ?)
    `).run(
      id,
      pick.type,
      pick.user,
      pick.role,
      pick.resource,
      pick.reason,
      pick.risk,
      pick.device,
      JSON.stringify({ simulated: true, mitreAttackVector: 'Simulated Red Team Threat Injection' }),
      now
    );

    return res.status(201).json({ message: 'Simulated threat vector injected into audit log', threat: pick });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
