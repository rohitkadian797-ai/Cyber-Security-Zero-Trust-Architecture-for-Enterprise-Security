import { Router, Response } from 'express';
import { PolicyEngine } from '../services/policyEngine.js';
import { optionalAuthenticate, AuthenticatedRequest } from '../middleware/auth.middleware.js';
import db from '../db/database.js';
import { PolicyEvaluationRequest, ThreatScenario } from '../types/index.js';

export const policyRouter = Router();

// POST /api/policy/evaluate
policyRouter.post('/evaluate', optionalAuthenticate, (req: AuthenticatedRequest, res: Response) => {
  try {
    const body: PolicyEvaluationRequest = {
      userId: req.body.userId || req.user?.userId,
      role: req.body.role || req.user?.role,
      resourceId: req.body.resourceId,
      action: req.body.action || 'READ',
      deviceTrust: req.body.deviceTrust || 'trusted',
      mfaVerified: req.body.mfaVerified !== undefined ? Boolean(req.body.mfaVerified) : Boolean(req.user?.mfaVerified),
      simulatedRiskScore: Number(req.body.simulatedRiskScore) || 10,
      ipAddress: req.body.ipAddress || req.ip || '127.0.0.1',
      sourceSegmentId: req.body.sourceSegmentId,
    };

    if (!body.resourceId) {
      return res.status(400).json({ error: 'resourceId is required' });
    }

    const evaluation = PolicyEngine.evaluateAccess(body);
    return res.json(evaluation);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/policy/policies
policyRouter.get('/policies', (_req, res) => {
  try {
    const policies = db.prepare('SELECT * FROM access_policies ORDER BY priority ASC').all();
    return res.json(policies);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/policy/policies/:id/toggle
policyRouter.post('/policies/:id/toggle', (req, res) => {
  try {
    const { id } = req.params;
    const policy = db.prepare('SELECT enabled FROM access_policies WHERE id = ?').get(id) as { enabled: number } | undefined;
    if (!policy) return res.status(404).json({ error: 'Policy not found' });

    const newEnabled = policy.enabled === 1 ? 0 : 1;
    db.prepare('UPDATE access_policies SET enabled = ?, updated_at = ? WHERE id = ?')
      .run(newEnabled, new Date().toISOString(), id);

    return res.json({ id, enabled: newEnabled });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/policy/scenarios - Interactive Threat Simulator Scenarios
policyRouter.get('/scenarios', (_req, res) => {
  const scenarios: ThreatScenario[] = [
    {
      id: 'scen-lateral-movement',
      title: 'Workstation to Production Vault Lateral Movement Attack',
      description: 'An attacker breaches an employee laptop in CORP_LAN and attempts direct access to the sensitive customer database in PROD_VAULT.',
      threatType: 'external_unauthorized',
      severity: 'critical',
      expectedDecision: 'DENY',
      requestParams: {
        userId: 'usr-emp-01',
        role: 'employee',
        resourceId: 'res-cust-pii',
        action: 'READ',
        deviceTrust: 'managed',
        mfaVerified: false,
        simulatedRiskScore: 78,
        sourceSegmentId: 'seg-corp',
        ipAddress: '192.168.1.189'
      },
      explanation: 'Blocked by Micro-segmentation barrier (CORP_LAN -> PROD_VAULT disallowed) and strict role privilege check.'
    },
    {
      id: 'scen-compromised-endpoint',
      title: 'Compromised Admin Endpoint (Active Malware / EDR Alert)',
      description: 'An administrator attempts access, but their host device reports compromised integrity (rootkit/malware detected).',
      threatType: 'untrusted_device',
      severity: 'critical',
      expectedDecision: 'DENY',
      requestParams: {
        userId: 'usr-admin-01',
        role: 'admin',
        resourceId: 'res-k8s-cluster',
        action: 'EXECUTE',
        deviceTrust: 'compromised',
        mfaVerified: true,
        simulatedRiskScore: 92,
        sourceSegmentId: 'seg-secure-core',
        ipAddress: '10.0.12.99'
      },
      explanation: 'Zero Trust Principle "Never Trust, Always Verify": Even with valid admin credentials and MFA, a compromised endpoint is instantly quarantined.'
    },
    {
      id: 'scen-privilege-escalation',
      title: 'Contractor Privilege Escalation to Threat Telemetry',
      description: 'An external guest vendor account attempts to query confidential SIEM SecOps intelligence.',
      threatType: 'privilege_escalation',
      severity: 'high',
      expectedDecision: 'DENY',
      requestParams: {
        userId: 'usr-guest-01',
        role: 'guest',
        resourceId: 'res-secops-telemetry',
        action: 'READ',
        deviceTrust: 'untrusted',
        mfaVerified: false,
        simulatedRiskScore: 65,
        sourceSegmentId: 'seg-dmz',
        ipAddress: '203.0.113.44'
      },
      explanation: 'Zero Trust Principle "Least Privilege": Guests cannot access internal SecOps assets, and untrusted devices are barred from confidential tiers.'
    },
    {
      id: 'scen-missing-mfa',
      title: 'Admin Session without Step-Up MFA Challenge',
      description: 'Admin logs in with password only, attempting to view sensitive Customer PII without 2-factor OTP verification.',
      threatType: 'missing_mfa',
      severity: 'high',
      expectedDecision: 'DENY',
      requestParams: {
        userId: 'usr-admin-01',
        role: 'admin',
        resourceId: 'res-cust-pii',
        action: 'READ',
        deviceTrust: 'trusted',
        mfaVerified: false,
        simulatedRiskScore: 25,
        sourceSegmentId: 'seg-secure-core',
        ipAddress: '10.0.12.44'
      },
      explanation: 'Step-up MFA check fails. Zero Trust mandates multi-factor authentication for all critical data vaults.'
    },
    {
      id: 'scen-verified-admin',
      title: 'Legitimate Authorized Admin Operation',
      description: 'Verified Administrator on a corporate trusted laptop with valid MFA accessing application core.',
      threatType: 'external_unauthorized',
      severity: 'low',
      expectedDecision: 'ALLOW',
      requestParams: {
        userId: 'usr-admin-01',
        role: 'admin',
        resourceId: 'res-k8s-cluster',
        action: 'ADMINISTER',
        deviceTrust: 'trusted',
        mfaVerified: true,
        simulatedRiskScore: 10,
        sourceSegmentId: 'seg-secure-core',
        ipAddress: '10.0.12.1'
      },
      explanation: 'Continuous verification succeeded across all 6 context checkpoints.'
    }
  ];

  return res.json(scenarios);
});
