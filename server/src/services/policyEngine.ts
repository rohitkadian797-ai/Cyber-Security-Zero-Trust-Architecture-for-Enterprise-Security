import crypto from 'crypto';
import db from '../db/database.js';
import { 
  PolicyEvaluationRequest, 
  PolicyEvaluationResult, 
  Resource, 
  AccessPolicy, 
  User, 
  SegmentRule,
  UserRole 
} from '../types/index.js';

export class PolicyEngine {
  /**
   * Evaluates an access request against the Zero Trust security matrix:
   * 1. Identity Verification
   * 2. Device Posture & Integrity
   * 3. Role & Least Privilege
   * 4. Multi-Factor Authentication Requirements
   * 5. Contextual Risk Scoring & Anomaly Detection
   * 6. Network Micro-Segmentation Rules
   */
  public static evaluateAccess(req: PolicyEvaluationRequest): PolicyEvaluationResult {
    const timestamp = new Date().toISOString();
    
    // Fetch requested resource
    const resource = db.prepare('SELECT * FROM resources WHERE id = ?').get(req.resourceId) as unknown as Resource | undefined;
    if (!resource) {
      const result: PolicyEvaluationResult = {
        decision: 'DENY',
        reason: 'Target resource does not exist or has been de-provisioned',
        riskScore: Math.min(100, req.simulatedRiskScore + 40),
        checks: {
          identityVerified: { passed: false, details: 'Target resource invalid' },
          roleAuthorization: { passed: false, details: 'N/A' },
          mfaRequirement: { passed: false, details: 'N/A' },
          deviceTrustPosture: { passed: false, details: 'N/A' },
          riskTolerance: { passed: false, details: 'N/A' },
          segmentIsolation: { passed: false, details: 'N/A' }
        },
        timestamp
      };
      this.logSecurityEvent(req, result, 'RESOURCE_NOT_FOUND');
      return result;
    }

    // Fetch user details if userId provided
    let user: User | undefined;
    if (req.userId) {
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId) as unknown as User | undefined;
    }

    const effectiveRole: UserRole = req.role || user?.role || 'guest';
    const isUserActive = user ? user.is_active === 1 : true;

    // 1. Identity Check
    const identityPassed = !!(req.userId ? user && isUserActive : effectiveRole !== 'guest');
    const identityDetails = !identityPassed 
      ? (user && !isUserActive ? 'User account is locked or deactivated' : 'Unauthenticated anonymous request')
      : `Authenticated as ${user ? user.username : 'service_principal'} (${effectiveRole})`;

    // 2. Device Trust Posture Check
    let devicePassed = true;
    let deviceDetails = `Device status: ${req.deviceTrust}`;
    if (req.deviceTrust === 'compromised') {
      devicePassed = false;
      deviceDetails = 'CRITICAL: Host endpoint reports active malware, compromised kernel, or EDR alert';
    } else if (req.deviceTrust === 'untrusted' && (resource.sensitivity === 'critical' || resource.sensitivity === 'confidential')) {
      devicePassed = false;
      deviceDetails = 'Untrusted device forbidden from accessing confidential or critical resources';
    }

    // 3. Role Authorization (RBAC)
    const roleHierarchy: Record<UserRole, number> = {
      admin: 100,
      security_analyst: 70,
      employee: 40,
      guest: 10
    };
    const requiredLevel = roleHierarchy[resource.required_role] || 10;
    const userLevel = roleHierarchy[effectiveRole] || 10;
    const rolePassed = userLevel >= requiredLevel;
    const roleDetails = rolePassed 
      ? `Role '${effectiveRole}' satisfies minimum role requirement '${resource.required_role}'`
      : `Insufficient privileges: Role '${effectiveRole}' cannot access '${resource.required_role}' resource`;

    // 4. Step-up MFA Requirement
    let mfaPassed = true;
    let mfaDetails = 'MFA requirement satisfied or not required';
    if (resource.requires_mfa === 1 && !req.mfaVerified) {
      mfaPassed = false;
      mfaDetails = 'Step-up Multi-Factor Authentication required for this sensitive resource';
    }

    // 5. Contextual Risk Score Calculation
    let calculatedRisk = Number(req.simulatedRiskScore) || 10;
    if (req.deviceTrust === 'untrusted') calculatedRisk += 25;
    if (req.deviceTrust === 'compromised') calculatedRisk += 60;
    if (resource.sensitivity === 'critical') calculatedRisk += 15;
    if (!req.mfaVerified && resource.sensitivity !== 'public') calculatedRisk += 10;
    calculatedRisk = Math.min(100, Math.max(0, calculatedRisk));

    // Evaluate matching access policies
    const policies = db.prepare(
      'SELECT * FROM access_policies WHERE enabled = 1 ORDER BY priority ASC'
    ).all() as unknown as AccessPolicy[];

    let matchedPolicy: AccessPolicy | undefined;
    for (const policy of policies) {
      const allowedRoles: UserRole[] = JSON.parse(policy.allowed_roles || '[]');
      const matchesPattern = policy.resource_pattern === '*' || 
        resource.name.toLowerCase().includes(policy.resource_pattern.toLowerCase()) ||
        resource.id === policy.resource_pattern;

      if (matchesPattern && (allowedRoles.length === 0 || allowedRoles.includes(effectiveRole))) {
        matchedPolicy = policy;
        break;
      }
    }

    const policyMaxRisk = matchedPolicy ? matchedPolicy.max_risk_score : 50;
    const riskPassed = calculatedRisk <= policyMaxRisk;
    const riskDetails = riskPassed 
      ? `Risk score (${calculatedRisk}) within acceptable policy threshold (${policyMaxRisk})`
      : `Risk score (${calculatedRisk}) exceeds allowable threshold (${policyMaxRisk})`;

    if (matchedPolicy && matchedPolicy.require_trusted_device === 1 && req.deviceTrust !== 'trusted') {
      devicePassed = false;
      deviceDetails = 'Policy strictly mandates fully corporate-trusted device posture';
    }

    if (matchedPolicy && matchedPolicy.require_mfa === 1 && !req.mfaVerified) {
      mfaPassed = false;
      mfaDetails = 'Matched policy strictly mandates active MFA session';
    }

    // 6. Network Micro-Segmentation Verification
    let segmentPassed = true;
    let segmentDetails = 'Micro-segmentation barrier cleared or intra-segment traffic';
    if (req.sourceSegmentId && req.sourceSegmentId !== resource.segment_id) {
      const rule = db.prepare(
        'SELECT * FROM segment_rules WHERE source_segment_id = ? AND target_segment_id = ? AND enabled = 1'
      ).get(req.sourceSegmentId, resource.segment_id) as unknown as SegmentRule | undefined;

      if (!rule || rule.allowed !== 1) {
        segmentPassed = false;
        segmentDetails = `Micro-segmentation firewall blocked cross-segment route (${req.sourceSegmentId} -> ${resource.segment_id})`;
      } else {
        segmentDetails = `Micro-segmentation policy permitted route on ${rule.port_or_protocol}`;
      }
    }

    // Final Zero Trust Decision synthesis
    const allPassed = identityPassed && devicePassed && rolePassed && mfaPassed && riskPassed && segmentPassed;
    const decision: 'ALLOW' | 'DENY' = allPassed ? 'ALLOW' : 'DENY';

    let reason = 'Zero Trust Continuous Verification Succeeded: All context checkpoints validated.';
    if (!allPassed) {
      const failedChecks: string[] = [];
      if (!identityPassed) failedChecks.push('Identity/Auth');
      if (!devicePassed) failedChecks.push('Device Trust');
      if (!rolePassed) failedChecks.push('Role Privilege');
      if (!mfaPassed) failedChecks.push('MFA Verification');
      if (!riskPassed) failedChecks.push('Risk Score Threshold');
      if (!segmentPassed) failedChecks.push('Micro-segmentation Barrier');
      reason = `Zero Trust Access Denied: Failed verification on [${failedChecks.join(', ')}]`;
    }

    const result: PolicyEvaluationResult = {
      decision,
      reason,
      matchedPolicyId: matchedPolicy?.id,
      matchedPolicyName: matchedPolicy?.name,
      riskScore: calculatedRisk,
      checks: {
        identityVerified: { passed: identityPassed, details: identityDetails },
        roleAuthorization: { passed: rolePassed, details: roleDetails },
        mfaRequirement: { passed: mfaPassed, details: mfaDetails },
        deviceTrustPosture: { passed: devicePassed, details: deviceDetails },
        riskTolerance: { passed: riskPassed, details: riskDetails },
        segmentIsolation: { passed: segmentPassed, details: segmentDetails }
      },
      resourceDetails: {
        id: resource.id,
        name: resource.name,
        sensitivity: resource.sensitivity,
        segmentId: resource.segment_id
      },
      timestamp
    };

    // Log the immutable audit event
    this.logSecurityEvent(req, result, decision === 'ALLOW' ? 'ACCESS_GRANTED' : 'ACCESS_BLOCKED');

    return result;
  }

  private static logSecurityEvent(
    req: PolicyEvaluationRequest,
    result: PolicyEvaluationResult,
    eventType: string
  ) {
    try {
      const eventId = crypto.randomUUID();
      const decision = result.decision === 'ALLOW' ? 'ALLOW' : 'DENY';
      
      db.prepare(`
        INSERT INTO security_events (
          id, event_type, user_id, username, user_role, resource, action, 
          decision, reason, risk_score, device_trust, ip_address, details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        eventId,
        eventType,
        req.userId || null,
        req.userId || 'anonymous',
        req.role || 'guest',
        result.resourceDetails?.name || req.resourceId,
        req.action || 'READ',
        decision,
        result.reason,
        result.riskScore,
        req.deviceTrust,
        req.ipAddress || '127.0.0.1',
        JSON.stringify({ checks: result.checks, matchedPolicy: result.matchedPolicyName }),
        result.timestamp
      );
    } catch (err) {
      console.error('Failed to write security event log:', err);
    }
  }
}
