export type UserRole = 'admin' | 'security_analyst' | 'employee' | 'guest';

export interface User {
  id: string;
  username: string;
  email: string;
  password_hash?: string;
  role: UserRole;
  mfa_enabled: number; // 0 or 1
  mfa_secret?: string | null;
  is_active: number; // 0 or 1
  department: string;
  created_at: string;
  updated_at: string;
}

export interface UserSanitized {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  mfa_enabled: boolean;
  is_active: boolean;
  department: string;
  created_at: string;
  updated_at: string;
}

export interface Session {
  id: string;
  user_id: string;
  token: string;
  ip_address: string;
  user_agent: string;
  device_trust: 'trusted' | 'managed' | 'untrusted' | 'compromised';
  expires_at: string;
  created_at: string;
}

export interface Resource {
  id: string;
  name: string;
  segment_id: string;
  sensitivity: 'public' | 'internal' | 'confidential' | 'critical';
  required_role: UserRole;
  requires_mfa: number; // 0 or 1
  description: string;
  data_payload: string;
}

export interface NetworkSegment {
  id: string;
  name: string;
  code: string;
  description: string;
  color: string;
  icon: string;
  isolation_level: 'standard' | 'strict' | 'isolated';
}

export interface SegmentRule {
  id: string;
  source_segment_id: string;
  target_segment_id: string;
  allowed: number; // 0 or 1
  port_or_protocol: string;
  description: string;
  enabled: number; // 0 or 1
  created_at: string;
  updated_at: string;
}

export interface AccessPolicy {
  id: string;
  name: string;
  description: string;
  resource_pattern: string;
  allowed_roles: string; // JSON string of UserRole[]
  require_mfa: number; // 0 or 1
  require_trusted_device: number; // 0 or 1
  max_risk_score: number;
  action: 'ALLOW' | 'DENY';
  priority: number;
  enabled: number; // 0 or 1
  created_at: string;
  updated_at: string;
}

export interface SecurityEvent {
  id: string;
  event_type: string;
  user_id?: string | null;
  username?: string | null;
  user_role?: string | null;
  resource?: string | null;
  action?: string | null;
  decision: 'ALLOW' | 'DENY' | 'ALERT' | 'INFO';
  reason: string;
  risk_score: number;
  device_trust?: string | null;
  ip_address?: string | null;
  details?: string | null; // JSON string
  created_at: string;
}

export interface PolicyEvaluationRequest {
  userId?: string;
  role?: UserRole;
  resourceId: string;
  action: string;
  deviceTrust: 'trusted' | 'managed' | 'untrusted' | 'compromised';
  mfaVerified: boolean;
  simulatedRiskScore: number;
  ipAddress?: string;
  sourceSegmentId?: string;
}

export interface PolicyEvaluationResult {
  decision: 'ALLOW' | 'DENY';
  reason: string;
  matchedPolicyId?: string;
  matchedPolicyName?: string;
  riskScore: number;
  checks: {
    identityVerified: { passed: boolean; details: string };
    roleAuthorization: { passed: boolean; details: string };
    mfaRequirement: { passed: boolean; details: string };
    deviceTrustPosture: { passed: boolean; details: string };
    riskTolerance: { passed: boolean; details: string };
    segmentIsolation: { passed: boolean; details: string };
  };
  resourceDetails?: {
    id: string;
    name: string;
    sensitivity: string;
    segmentId: string;
  };
  timestamp: string;
}

export interface ThreatScenario {
  id: string;
  title: string;
  description: string;
  threatType: 'external_unauthorized' | 'privilege_escalation' | 'missing_mfa' | 'untrusted_device' | 'anomaly_risk' | 'insider_threat';
  severity: 'low' | 'medium' | 'high' | 'critical';
  expectedDecision: 'DENY' | 'ALLOW';
  requestParams: PolicyEvaluationRequest;
  explanation: string;
}

export interface AuthTokenPayload {
  userId: string;
  username: string;
  role: UserRole;
  mfaVerified: boolean;
  sessionId: string;
}
