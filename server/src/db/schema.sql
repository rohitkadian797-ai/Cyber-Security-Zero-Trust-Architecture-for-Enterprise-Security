-- Zero Trust Enterprise Security - Database Schema
-- Optimized for SQLite with foreign keys and performance indexes

PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin', 'security_analyst', 'employee', 'guest')),
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  department TEXT NOT NULL DEFAULT 'General',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  ip_address TEXT DEFAULT '127.0.0.1',
  user_agent TEXT,
  device_trust TEXT NOT NULL DEFAULT 'trusted' CHECK(device_trust IN ('trusted', 'managed', 'untrusted', 'compromised')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Network segments
CREATE TABLE IF NOT EXISTS network_segments (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  code TEXT UNIQUE NOT NULL,
  description TEXT,
  color TEXT NOT NULL DEFAULT '#3b82f6',
  icon TEXT NOT NULL DEFAULT 'Network',
  isolation_level TEXT NOT NULL DEFAULT 'strict' CHECK(isolation_level IN ('standard', 'strict', 'isolated'))
);

-- Micro-segmentation access rules
CREATE TABLE IF NOT EXISTS segment_rules (
  id TEXT PRIMARY KEY,
  source_segment_id TEXT NOT NULL,
  target_segment_id TEXT NOT NULL,
  allowed INTEGER NOT NULL DEFAULT 0,
  port_or_protocol TEXT NOT NULL DEFAULT 'ALL',
  description TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (source_segment_id) REFERENCES network_segments(id) ON DELETE CASCADE,
  FOREIGN KEY (target_segment_id) REFERENCES network_segments(id) ON DELETE CASCADE
);

-- Protected Enterprise Resources
CREATE TABLE IF NOT EXISTS resources (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  segment_id TEXT NOT NULL,
  sensitivity TEXT NOT NULL CHECK(sensitivity IN ('public', 'internal', 'confidential', 'critical')),
  required_role TEXT NOT NULL CHECK(required_role IN ('admin', 'security_analyst', 'employee', 'guest')),
  requires_mfa INTEGER NOT NULL DEFAULT 0,
  description TEXT,
  data_payload TEXT,
  FOREIGN KEY (segment_id) REFERENCES network_segments(id) ON DELETE RESTRICT
);

-- Zero Trust Access Policies
CREATE TABLE IF NOT EXISTS access_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  resource_pattern TEXT NOT NULL,
  allowed_roles TEXT NOT NULL, -- JSON array string e.g. ["admin", "security_analyst"]
  require_mfa INTEGER NOT NULL DEFAULT 0,
  require_trusted_device INTEGER NOT NULL DEFAULT 0,
  max_risk_score INTEGER NOT NULL DEFAULT 50,
  action TEXT NOT NULL CHECK(action IN ('ALLOW', 'DENY')),
  priority INTEGER NOT NULL DEFAULT 100,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Append-Only Security Event & Audit Log
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  user_id TEXT,
  username TEXT,
  user_role TEXT,
  resource TEXT,
  action TEXT,
  decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY', 'ALERT', 'INFO')),
  reason TEXT NOT NULL,
  risk_score INTEGER NOT NULL DEFAULT 0,
  device_trust TEXT,
  ip_address TEXT,
  details TEXT, -- JSON string
  created_at TEXT NOT NULL
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_resources_segment_id ON resources(segment_id);
CREATE INDEX IF NOT EXISTS idx_segment_rules_source_target ON segment_rules(source_segment_id, target_segment_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_priority ON access_policies(priority ASC);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_decision ON security_events(decision);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
