import crypto from 'crypto';
import db, { initDatabase } from './database.js';
import { hashPassword, encryptData } from '../utils/crypto.js';

export async function seed() {
  console.log('🔄 Initializing database schema...');
  initDatabase();

  console.log('🧹 Cleaning existing records...');
  db.exec(`
    DELETE FROM security_events;
    DELETE FROM access_policies;
    DELETE FROM resources;
    DELETE FROM segment_rules;
    DELETE FROM network_segments;
    DELETE FROM sessions;
    DELETE FROM users;
  `);

  console.log('👤 Seeding default users...');
  const now = new Date().toISOString();
  const defaultPassword = 'Password123!';
  const hashedPassword = await hashPassword(defaultPassword);

  const users = [
    {
      id: 'usr-admin-01',
      username: 'admin',
      email: 'admin@zerotrust.corp',
      password_hash: hashedPassword,
      role: 'admin',
      mfa_enabled: 1,
      mfa_secret: 'JBSWY3DPEHPK3PXP', // Base32 test secret for quick TOTP demo
      is_active: 1,
      department: 'Global Security Operations',
    },
    {
      id: 'usr-sec-01',
      username: 'analyst',
      email: 'analyst.sarah@zerotrust.corp',
      password_hash: hashedPassword,
      role: 'security_analyst',
      mfa_enabled: 1,
      mfa_secret: 'JBSWY3DPEHPK3PXP',
      is_active: 1,
      department: 'SOC Tier-3',
    },
    {
      id: 'usr-emp-01',
      username: 'john.doe',
      email: 'johndoe@zerotrust.corp',
      password_hash: hashedPassword,
      role: 'employee',
      mfa_enabled: 0,
      mfa_secret: null,
      is_active: 1,
      department: 'Engineering',
    },
    {
      id: 'usr-guest-01',
      username: 'vendor.contractor',
      email: 'contractor@external-partner.com',
      password_hash: hashedPassword,
      role: 'guest',
      mfa_enabled: 0,
      mfa_secret: null,
      is_active: 1,
      department: 'External Vendors',
    },
    {
      id: 'usr-locked-01',
      username: 'compromised.user',
      email: 'compromised@zerotrust.corp',
      password_hash: hashedPassword,
      role: 'employee',
      mfa_enabled: 0,
      mfa_secret: null,
      is_active: 0, // Disabled
      department: 'Sales',
    },
  ];

  const insertUser = db.prepare(`
    INSERT INTO users (id, username, email, password_hash, role, mfa_enabled, mfa_secret, is_active, department, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const u of users) {
    insertUser.run(u.id, u.username, u.email, u.password_hash, u.role, u.mfa_enabled, u.mfa_secret, u.is_active, u.department, now, now);
  }

  console.log('🌐 Seeding Network Micro-Segments...');
  const segments = [
    {
      id: 'seg-dmz',
      name: 'Public Edge / DMZ',
      code: 'DMZ',
      description: 'Public facing API gateway and load balancers',
      color: '#3b82f6',
      icon: 'Globe',
      isolation_level: 'standard',
    },
    {
      id: 'seg-corp',
      name: 'Corporate LAN / Workstations',
      code: 'CORP_LAN',
      description: 'Employee managed laptops and office network',
      color: '#10b981',
      icon: 'Laptop',
      isolation_level: 'standard',
    },
    {
      id: 'seg-secure-core',
      name: 'Application VPC / Core Services',
      code: 'APP_CORE',
      description: 'Internal microservices and business logic tier',
      color: '#8b5cf6',
      icon: 'Server',
      isolation_level: 'strict',
    },
    {
      id: 'seg-prod-vault',
      name: 'Data Fortress / Production Vault',
      code: 'PROD_VAULT',
      description: 'Critical database clusters, HSM keys, and customer PII',
      color: '#ef4444',
      icon: 'ShieldAlert',
      isolation_level: 'isolated',
    },
  ];

  const insertSegment = db.prepare(`
    INSERT INTO network_segments (id, name, code, description, color, icon, isolation_level)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const s of segments) {
    insertSegment.run(s.id, s.name, s.code, s.description, s.color, s.icon, s.isolation_level);
  }

  console.log('🔒 Seeding Micro-segmentation Firewall Rules...');
  const segmentRules = [
    // DMZ -> APP_CORE (Allowed HTTPS 443)
    {
      id: 'rule-01',
      source_segment_id: 'seg-dmz',
      target_segment_id: 'seg-secure-core',
      allowed: 1,
      port_or_protocol: 'HTTPS / 443 (mTLS)',
      description: 'Reverse proxy ingress to application microservices',
    },
    // CORP_LAN -> APP_CORE (Allowed HTTPS 443)
    {
      id: 'rule-02',
      source_segment_id: 'seg-corp',
      target_segment_id: 'seg-secure-core',
      allowed: 1,
      port_or_protocol: 'HTTPS / 443 (Zero Trust Tunnel)',
      description: 'Employee internal enterprise dashboard access',
    },
    // APP_CORE -> PROD_VAULT (Allowed PostgreSQL 5432)
    {
      id: 'rule-03',
      source_segment_id: 'seg-secure-core',
      target_segment_id: 'seg-prod-vault',
      allowed: 1,
      port_or_protocol: 'TCP / 5432 (Encrypted DB Link)',
      description: 'Application tier to production database queries',
    },
    // CORP_LAN -> PROD_VAULT (BLOCKED directly - Lateral movement prevention)
    {
      id: 'rule-04',
      source_segment_id: 'seg-corp',
      target_segment_id: 'seg-prod-vault',
      allowed: 0,
      port_or_protocol: 'ALL / DENY',
      description: 'STRICT ZERO TRUST: No direct lateral access from workstations to database',
    },
    // DMZ -> PROD_VAULT (BLOCKED directly)
    {
      id: 'rule-05',
      source_segment_id: 'seg-dmz',
      target_segment_id: 'seg-prod-vault',
      allowed: 0,
      port_or_protocol: 'ALL / DENY',
      description: 'Direct DMZ to Vault is strictly prohibited',
    },
  ];

  const insertRule = db.prepare(`
    INSERT INTO segment_rules (id, source_segment_id, target_segment_id, allowed, port_or_protocol, description, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
  `);

  for (const r of segmentRules) {
    insertRule.run(r.id, r.source_segment_id, r.target_segment_id, r.allowed, r.port_or_protocol, r.description, now, now);
  }

  console.log('📦 Seeding Protected Enterprise Resources...');
  const resources = [
    {
      id: 'res-cust-pii',
      name: 'Customer PII & Credit Card Vault',
      segment_id: 'seg-prod-vault',
      sensitivity: 'critical',
      required_role: 'admin',
      requires_mfa: 1,
      description: 'Restricted high-compliance database containing encrypted user biometric and financial records.',
      data_payload: encryptData(JSON.stringify({
        database: 'vault_db_cluster_01',
        records: 482190,
        complianceTier: 'PCI-DSS v4.0 / HIPAA',
        secretAccessKey: 'sec_vault_live_992a7fb3c11e403d9876a',
        encryptionStandard: 'AES-256-GCM Hardware Security Module'
      })),
    },
    {
      id: 'res-k8s-cluster',
      name: 'Production Kubernetes Cluster API',
      segment_id: 'seg-secure-core',
      sensitivity: 'critical',
      required_role: 'admin',
      requires_mfa: 1,
      description: 'Control plane for container orchestration, secrets deployment, and network ingress.',
      data_payload: encryptData(JSON.stringify({
        clusterName: 'k8s-prod-us-east-1',
        nodeCount: 36,
        apiEndpoint: 'https://k8s-api.internal.zerotrust.corp:6443',
        status: 'HEALTHY',
        activePods: 240
      })),
    },
    {
      id: 'res-secops-telemetry',
      name: 'SecOps Threat Intelligence Feed',
      segment_id: 'seg-secure-core',
      sensitivity: 'confidential',
      required_role: 'security_analyst',
      requires_mfa: 1,
      description: 'Aggregated SIEM telemetry, anomaly signatures, and automated quarantine webhooks.',
      data_payload: encryptData(JSON.stringify({
        siemEngine: 'Splunk / OpenSearch Core',
        activeAlerts: 3,
        mitreTechniquesDetected: ['T1078.003 - Cloud Accounts', 'T1021.002 - SMB/Windows Admin Shares'],
        autoQuarantine: 'ENABLED'
      })),
    },
    {
      id: 'res-internal-wiki',
      name: 'Internal Engineering Confluence & Docs',
      segment_id: 'seg-corp',
      sensitivity: 'internal',
      required_role: 'employee',
      requires_mfa: 0,
      description: 'Team documentation, architectural blueprints, onboarding guides, and sprint roadmaps.',
      data_payload: encryptData(JSON.stringify({
        portal: 'Confluence Cloud Private',
        totalPages: 1240,
        accessType: 'Read / Write for verified employees',
        lastUpdated: now
      })),
    },
    {
      id: 'res-public-status',
      name: 'Public System Status API',
      segment_id: 'seg-dmz',
      sensitivity: 'public',
      required_role: 'guest',
      requires_mfa: 0,
      description: 'Public health status and service uptime statistics for enterprise clients.',
      data_payload: encryptData(JSON.stringify({
        status: 'ALL_SYSTEMS_OPERATIONAL',
        uptimePercentage: '99.99%',
        incidentHistory: []
      })),
    },
  ];

  const insertResource = db.prepare(`
    INSERT INTO resources (id, name, segment_id, sensitivity, required_role, requires_mfa, description, data_payload)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const res of resources) {
    insertResource.run(res.id, res.name, res.segment_id, res.sensitivity, res.required_role, res.requires_mfa, res.description, res.data_payload);
  }

  console.log('📜 Seeding Zero Trust Dynamic Access Policies...');
  const policies = [
    {
      id: 'pol-01',
      name: 'Zero Trust Master Isolation: Default Deny Compromised Endpoints',
      description: 'Any device reporting compromised integrity or active malware signature is immediately denied access to all resources.',
      resource_pattern: '*',
      allowed_roles: JSON.stringify(['admin', 'security_analyst', 'employee', 'guest']),
      require_mfa: 0,
      require_trusted_device: 1,
      max_risk_score: 40,
      action: 'ALLOW',
      priority: 10,
    },
    {
      id: 'pol-02',
      name: 'Critical Infrastructure Strict MFA & Admin Privilege',
      description: 'Access to customer PII and Kubernetes clusters strictly requires Admin role, verified MFA, and corporate-managed device posture.',
      resource_pattern: 'res-cust-pii',
      allowed_roles: JSON.stringify(['admin']),
      require_mfa: 1,
      require_trusted_device: 1,
      max_risk_score: 30,
      action: 'ALLOW',
      priority: 20,
    },
    {
      id: 'pol-03',
      name: 'SecOps Telemetry & Threat Intelligence Access',
      description: 'Only Security Analysts and Admins can query security telemetry with MFA active and risk score under 45.',
      resource_pattern: 'res-secops-telemetry',
      allowed_roles: JSON.stringify(['admin', 'security_analyst']),
      require_mfa: 1,
      require_trusted_device: 1,
      max_risk_score: 45,
      action: 'ALLOW',
      priority: 30,
    },
    {
      id: 'pol-04',
      name: 'Standard Employee Corporate Resources',
      description: 'Authenticated corporate staff can access internal wikis and tools under moderate risk thresholds.',
      resource_pattern: 'res-internal-wiki',
      allowed_roles: JSON.stringify(['admin', 'security_analyst', 'employee']),
      require_mfa: 0,
      require_trusted_device: 0,
      max_risk_score: 65,
      action: 'ALLOW',
      priority: 50,
    },
    {
      id: 'pol-05',
      name: 'Public Health Check Access',
      description: 'Permits unauthenticated and guest status queries for public services.',
      resource_pattern: 'res-public-status',
      allowed_roles: JSON.stringify(['admin', 'security_analyst', 'employee', 'guest']),
      require_mfa: 0,
      require_trusted_device: 0,
      max_risk_score: 95,
      action: 'ALLOW',
      priority: 90,
    },
  ];

  const insertPolicy = db.prepare(`
    INSERT INTO access_policies (id, name, description, resource_pattern, allowed_roles, require_mfa, require_trusted_device, max_risk_score, action, priority, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
  `);

  for (const p of policies) {
    insertPolicy.run(p.id, p.name, p.description, p.resource_pattern, p.allowed_roles, p.require_mfa, p.require_trusted_device, p.max_risk_score, p.action, p.priority, now, now);
  }

  console.log('🚨 Seeding Security Event Audit Logs...');
  const sampleEvents = [
    {
      id: crypto.randomUUID(),
      event_type: 'ACCESS_GRANTED',
      username: 'admin',
      user_role: 'admin',
      resource: 'Customer PII & Credit Card Vault',
      action: 'READ',
      decision: 'ALLOW',
      reason: 'Zero Trust Continuous Verification Succeeded: All context checkpoints validated.',
      risk_score: 12,
      device_trust: 'trusted',
      ip_address: '10.0.12.44',
      details: JSON.stringify({ mfaVerified: true, segment: 'seg-prod-vault' }),
      created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    },
    {
      id: crypto.randomUUID(),
      event_type: 'ACCESS_BLOCKED',
      username: 'john.doe',
      user_role: 'employee',
      resource: 'Customer PII & Credit Card Vault',
      action: 'READ',
      decision: 'DENY',
      reason: 'Zero Trust Access Denied: Failed verification on [Role Privilege, MFA Verification]',
      risk_score: 55,
      device_trust: 'managed',
      ip_address: '192.168.1.105',
      details: JSON.stringify({ mfaVerified: false, requiredRole: 'admin' }),
      created_at: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    },
    {
      id: crypto.randomUUID(),
      event_type: 'LATERAL_MOVEMENT_PREVENTED',
      username: 'compromised.user',
      user_role: 'employee',
      resource: 'Data Fortress / Production Vault',
      action: 'DIRECT_TCP_CONNECT',
      decision: 'DENY',
      reason: 'Micro-segmentation firewall blocked cross-segment route (seg-corp -> seg-prod-vault)',
      risk_score: 85,
      device_trust: 'compromised',
      ip_address: '192.168.1.189',
      details: JSON.stringify({ threatVector: 'Lateral Movement attempt detected' }),
      created_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    },
    {
      id: crypto.randomUUID(),
      event_type: 'MFA_CHALLENGE_FAILED',
      username: 'vendor.contractor',
      user_role: 'guest',
      resource: 'SecOps Threat Intelligence Feed',
      action: 'QUERY',
      decision: 'DENY',
      reason: 'Zero Trust Access Denied: Failed verification on [Role Privilege, MFA Verification]',
      risk_score: 60,
      device_trust: 'untrusted',
      ip_address: '203.0.113.88',
      details: JSON.stringify({ reason: 'External untrusted IP attempting privileged read' }),
      created_at: new Date(Date.now() - 1000 * 60 * 75).toISOString(),
    },
  ];

  const insertEvent = db.prepare(`
    INSERT INTO security_events (id, event_type, username, user_role, resource, action, decision, reason, risk_score, device_trust, ip_address, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const ev of sampleEvents) {
    insertEvent.run(ev.id, ev.event_type, ev.username, ev.user_role, ev.resource, ev.action, ev.decision, ev.reason, ev.risk_score, ev.device_trust, ev.ip_address, ev.details, ev.created_at);
  }

  console.log('✅ Database seeded successfully with Zero Trust baseline configuration!');
}

// Run if executed directly
if (process.argv[1]?.endsWith('seed.ts') || process.argv[1]?.endsWith('seed.js')) {
  seed()
    .then(() => {
      console.log('🚀 Seeding finished.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('❌ Seeding failed:', err);
      process.exit(1);
    });
}
