const API_BASE = 'http://localhost:5000/api';

// State management
const state = {
  activeTab: 'simulator',
  users: [],
  currentUser: null,
  authToken: null,
  mfaVerified: true,
  resources: [],
  segments: [],
  rules: [],
  scenarios: [],
  stats: null
};

// DOM Elements
const activeUserSelect = document.getElementById('active-user-select');
const mfaStatusText = document.getElementById('mfa-status-text');
const mfaStatusDot = document.getElementById('mfa-status-dot');
const simForm = document.getElementById('simulator-form');
const simResource = document.getElementById('sim-resource');
const simRole = document.getElementById('sim-role');
const simAction = document.getElementById('sim-action');
const simDevice = document.getElementById('sim-device');
const simSegment = document.getElementById('sim-segment');
const simRisk = document.getElementById('sim-risk');
const simMfa = document.getElementById('sim-mfa');
const riskScoreDisplay = document.getElementById('risk-score-display');
const btnResetSim = document.getElementById('btn-reset-sim');

// Result elements
const evalEmptyState = document.getElementById('eval-empty-state');
const evalContent = document.getElementById('eval-content');
const evalBanner = document.getElementById('eval-banner');
const bannerIcon = document.getElementById('banner-icon');
const bannerTitle = document.getElementById('banner-title');
const bannerReason = document.getElementById('banner-reason');
const bannerRisk = document.getElementById('banner-risk');
const evalPolicyName = document.getElementById('eval-policy-name');
const evalTimestamp = document.getElementById('eval-timestamp');

// Checkpoints
const chks = {
  identity: { card: document.getElementById('chk-identity'), txt: document.getElementById('chk-identity-txt') },
  device: { card: document.getElementById('chk-device'), txt: document.getElementById('chk-device-txt') },
  role: { card: document.getElementById('chk-role'), txt: document.getElementById('chk-role-txt') },
  mfa: { card: document.getElementById('chk-mfa'), txt: document.getElementById('chk-mfa-txt') },
  risk: { card: document.getElementById('chk-risk'), txt: document.getElementById('chk-risk-txt') },
  segment: { card: document.getElementById('chk-segment'), txt: document.getElementById('chk-segment-txt') }
};

// Modal
const resourceModal = document.getElementById('resource-modal');
const modalTitle = document.getElementById('modal-title');
const modalSensitivity = document.getElementById('modal-sensitivity');
const modalSegment = document.getElementById('modal-segment');
const modalPayloadCode = document.getElementById('modal-payload-code');
const modalClose = document.getElementById('modal-close');

// Initialize App
async function initApp() {
  setupTabs();
  setupEventListeners();
  await checkGatewayHealth();
  await loadUsers();
  await loadMetadata();
  await loadStats();
  await loadScenarios();
  await loadResources();
  await loadTopology();
  await loadAuditEvents();

  // Poll metrics every 10 seconds
  setInterval(loadStats, 10000);
}

// Gateway Health Ping
async function checkGatewayHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    const data = await res.json();
    if (data.status === 'ONLINE') {
      document.getElementById('gateway-status-text').textContent = 'GATEWAY ONLINE (NIST 800-207)';
    }
  } catch (err) {
    document.getElementById('gateway-status-text').textContent = 'GATEWAY DISCONNECTED';
    document.getElementById('gateway-status-text').parentElement.style.background = 'rgba(244, 63, 94, 0.1)';
    document.getElementById('gateway-status-text').parentElement.style.color = '#f43f5e';
    showToast('Cannot connect to Zero Trust Gateway on port 5000', 'danger');
  }
}

// Navigation Tabs
function setupTabs() {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const tabId = tab.dataset.tab;
      document.getElementById(`tab-${tabId}`).classList.add('active');
      state.activeTab = tabId;

      if (tabId === 'audit') loadAuditEvents();
      if (tabId === 'topology') loadTopology();
      if (tabId === 'resources') loadResources();
    });
  });
}

// Event Listeners
function setupEventListeners() {
  // Slider listener
  simRisk.addEventListener('input', (e) => {
    const val = Number(e.target.value);
    riskScoreDisplay.textContent = `${val} (${val < 35 ? 'Low Risk' : val < 70 ? 'Moderate Risk' : 'High Threat Anomaly'})`;
    riskScoreDisplay.className = `risk-pill ${val < 35 ? 'low' : val < 70 ? 'med' : 'high'}`;
  });

  // User identity switcher
  activeUserSelect.addEventListener('change', (e) => {
    const userId = e.target.value;
    const user = state.users.find(u => u.id === userId);
    if (user) {
      state.currentUser = user;
      simRole.value = user.role;
      state.mfaVerified = user.mfa_enabled === 1;
      simMfa.checked = state.mfaVerified;

      mfaStatusText.textContent = state.mfaVerified ? 'MFA: ACTIVE' : 'MFA: NONE';
      mfaStatusDot.style.background = state.mfaVerified ? '#00f0ff' : '#f59e0b';
      showToast(`Switched active subject to ${user.username} (${user.role})`, 'info');
    }
  });

  // Simulator Form
  simForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await evaluateAccess();
  });

  // Reset Simulator
  btnResetSim.addEventListener('click', () => {
    simRisk.value = 15;
    simRisk.dispatchEvent(new Event('input'));
    simDevice.value = 'trusted';
    simAction.value = 'READ';
    if (state.currentUser) {
      simRole.value = state.currentUser.role;
      simMfa.checked = state.currentUser.mfa_enabled === 1;
    }
    showToast('Simulation context reset', 'info');
  });

  // Inject Threat Button
  document.getElementById('btn-inject-threat')?.addEventListener('click', injectSimulatedThreat);

  // Modal Close
  modalClose.addEventListener('click', () => resourceModal.classList.add('hidden'));
  resourceModal.addEventListener('click', (e) => {
    if (e.target === resourceModal) resourceModal.classList.add('hidden');
  });

  // Audit filter & refresh
  document.getElementById('audit-filter-decision')?.addEventListener('change', loadAuditEvents);
  document.getElementById('btn-refresh-audit')?.addEventListener('click', loadAuditEvents);
}

// Load metadata (users, segments, resources)
async function loadUsers() {
  try {
    const res = await fetch(`${API_BASE}/auth/users`);
    const users = await res.json();
    state.users = users;
    state.currentUser = users[0];
  } catch (err) {
    console.error('Failed to load users:', err);
  }
}

async function loadMetadata() {
  try {
    const [resResp, segResp] = await Promise.all([
      fetch(`${API_BASE}/resources`),
      fetch(`${API_BASE}/network/segments`)
    ]);

    state.resources = await resResp.json();
    state.segments = await segResp.json();

    // Populate simulator selects
    simResource.innerHTML = state.resources.map(r => 
      `<option value="${r.id}">${r.name} [${r.sensitivity.toUpperCase()} / Req: ${r.required_role}]</option>`
    ).join('');

    simSegment.innerHTML = state.segments.map(s => 
      `<option value="${s.id}">${s.name} (${s.code})</option>`
    ).join('');
    
    // Default to Corp LAN as origin
    const corpSeg = state.segments.find(s => s.code === 'CORP_LAN');
    if (corpSeg) simSegment.value = corpSeg.id;
  } catch (err) {
    console.error('Failed to load metadata:', err);
  }
}

// Load Stats
async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/audit/stats`);
    const stats = await res.json();
    state.stats = stats;

    document.getElementById('stat-total-requests').textContent = stats.totalRequests;
    document.getElementById('stat-blocked-requests').textContent = stats.blockedRequests;
    document.getElementById('stat-block-rate').textContent = `${stats.blockRatePercentage}% Block Rate`;
    document.getElementById('stat-threat-alerts').textContent = stats.criticalThreatAlerts;
    document.getElementById('stat-avg-risk').textContent = `${stats.averageRiskScore}/100`;
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

// Evaluate Access
async function evaluateAccess() {
  const payload = {
    userId: state.currentUser?.id,
    role: simRole.value,
    resourceId: simResource.value,
    action: simAction.value,
    deviceTrust: simDevice.value,
    mfaVerified: simMfa.checked,
    simulatedRiskScore: Number(simRisk.value),
    sourceSegmentId: simSegment.value
  };

  const btn = document.getElementById('btn-evaluate');
  btn.disabled = true;
  btn.textContent = 'Verifying Continuous Checkpoints...';

  try {
    const res = await fetch(`${API_BASE}/policy/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const result = await res.json();
    renderEvaluationResult(result);
    await loadStats();
  } catch (err) {
    showToast('Failed to evaluate policy: ' + err.message, 'danger');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Evaluate Zero Trust Policy
    `;
  }
}

// Render Evaluation Result UI
function renderEvaluationResult(result) {
  evalEmptyState.classList.add('hidden');
  evalContent.classList.remove('hidden');

  const isAllow = result.decision === 'ALLOW';
  evalBanner.className = `eval-banner ${isAllow ? 'allow' : 'deny'}`;
  bannerIcon.textContent = isAllow ? '✓' : '✕';
  bannerTitle.textContent = isAllow ? 'ACCESS GRANTED' : 'ACCESS DENIED';
  bannerReason.textContent = result.reason;
  bannerRisk.textContent = `${result.riskScore}/100`;
  evalPolicyName.textContent = result.matchedPolicyName || 'Default Deny Matrix';
  evalTimestamp.textContent = new Date(result.timestamp).toLocaleTimeString();

  // Update 6 Checkpoints
  updateCheckpoint(chks.identity, result.checks.identityVerified);
  updateCheckpoint(chks.device, result.checks.deviceTrustPosture);
  updateCheckpoint(chks.role, result.checks.roleAuthorization);
  updateCheckpoint(chks.mfa, result.checks.mfaRequirement);
  updateCheckpoint(chks.risk, result.checks.riskTolerance);
  updateCheckpoint(chks.segment, result.checks.segmentIsolation);
}

function updateCheckpoint(chk, data) {
  chk.card.className = `checkpoint-card ${data.passed ? 'passed' : 'failed'}`;
  chk.card.querySelector('.chk-status').textContent = data.passed ? '✓' : '✕';
  chk.txt.textContent = data.details;
}

// Load Threat Scenarios
async function loadScenarios() {
  try {
    const res = await fetch(`${API_BASE}/policy/scenarios`);
    const scenarios = await res.json();
    state.scenarios = scenarios;

    const container = document.getElementById('scenarios-container');
    container.innerHTML = scenarios.map(sc => `
      <div class="scenario-card">
        <div class="scenario-top">
          <span class="severity-pill severity-${sc.severity}">${sc.severity} threat</span>
          <span class="badge-deny">Expects ${sc.expectedDecision}</span>
        </div>
        <div class="scenario-title">${sc.title}</div>
        <div class="scenario-desc">${sc.description}</div>
        <div class="scenario-explanation">${sc.explanation}</div>
        <button class="btn btn-secondary btn-sm" onclick="window.runScenario('${sc.id}')">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Run Attack Scenario
        </button>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load scenarios:', err);
  }
}

// Run Scenario from card
window.runScenario = (scenarioId) => {
  const sc = state.scenarios.find(s => s.id === scenarioId);
  if (!sc) return;

  // Populate simulator form
  const p = sc.requestParams;
  if (p.resourceId) simResource.value = p.resourceId;
  if (p.role) simRole.value = p.role;
  if (p.deviceTrust) simDevice.value = p.deviceTrust;
  if (p.sourceSegmentId) simSegment.value = p.sourceSegmentId;
  simMfa.checked = Boolean(p.mfaVerified);
  simRisk.value = p.simulatedRiskScore;
  simRisk.dispatchEvent(new Event('input'));

  // Switch to simulator tab & evaluate
  document.querySelector('[data-tab="simulator"]').click();
  evaluateAccess();
  showToast(`Initiating threat vector: ${sc.title}`, 'warning');
};

// Load Resources Vault
async function loadResources() {
  try {
    const res = await fetch(`${API_BASE}/resources`);
    const resources = await res.json();
    state.resources = resources;

    const container = document.getElementById('resources-container');
    container.innerHTML = resources.map(r => `
      <div class="resource-card">
        <div class="resource-card-header">
          <span class="tag-sensitivity" style="background: ${r.sensitivity === 'critical' ? 'rgba(244,63,94,0.2)' : 'rgba(59,130,246,0.2)'}">${r.sensitivity.toUpperCase()}</span>
          <span class="tag-segment" style="color: ${r.segment_color}">${r.segment_name}</span>
        </div>
        <div class="resource-name">${r.name}</div>
        <div class="resource-desc">${r.description}</div>
        <div class="resource-meta">
          <span class="meta-tag">Role: <strong>${r.required_role}</strong></span>
          <span class="meta-tag">${r.requires_mfa ? '🔒 MFA Required' : '🔓 Password Only'}</span>
          <span class="meta-tag">Isolation: ${r.isolation_level}</span>
        </div>
        <button class="btn btn-primary btn-sm" onclick="window.requestResourceAccess('${r.id}')">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Request & Decrypt Data
        </button>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load resources:', err);
  }
}

// Request and decrypt resource
window.requestResourceAccess = async (resourceId) => {
  try {
    const res = await fetch(`${API_BASE}/resources/${resourceId}/access`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role: state.currentUser?.role || simRole.value,
        deviceTrust: simDevice.value,
        mfaVerified: state.mfaVerified,
        simulatedRiskScore: Number(simRisk.value),
        sourceSegmentId: simSegment.value
      })
    });

    const data = await res.json();
    if (res.ok && data.accessGranted) {
      modalTitle.textContent = data.resource.name;
      modalSensitivity.textContent = data.resource.sensitivity.toUpperCase();
      modalSegment.textContent = data.resource.segmentId;
      modalPayloadCode.textContent = JSON.stringify(data.data, null, 2);
      resourceModal.classList.remove('hidden');
      showToast('Zero Trust verification PASSED. Cryptographic payload unlocked.', 'success');
    } else {
      showToast(data.error || 'Access Denied by Zero Trust Policy Engine', 'danger');
    }
    await loadStats();
  } catch (err) {
    showToast('Access request error: ' + err.message, 'danger');
  }
};

// Load Micro-Segmentation Topology & Rules
async function loadTopology() {
  try {
    const [segRes, ruleRes] = await Promise.all([
      fetch(`${API_BASE}/network/segments`),
      fetch(`${API_BASE}/network/rules`)
    ]);

    const segments = await segRes.json();
    const rules = await ruleRes.json();
    state.segments = segments;
    state.rules = rules;

    // Render segment cards
    const segContainer = document.getElementById('segments-container');
    segContainer.innerHTML = segments.map(s => `
      <div class="segment-card" style="border-top-color: ${s.color}">
        <div class="segment-code">${s.code}</div>
        <div class="segment-name">${s.name}</div>
        <div class="segment-desc">${s.description}</div>
        <div style="margin-top: 0.85rem">
          <span class="meta-tag">Isolation: <strong>${s.isolation_level}</strong></span>
        </div>
      </div>
    `).join('');

    // Render rules table
    const rulesTbody = document.getElementById('rules-tbody');
    rulesTbody.innerHTML = rules.map(r => `
      <tr>
        <td><strong style="color: ${r.source_segment_color}">${r.source_segment_name}</strong></td>
        <td><strong style="color: ${r.target_segment_color}">${r.target_segment_name}</strong></td>
        <td><code>${r.port_or_protocol}</code></td>
        <td>
          <span class="${r.allowed ? 'badge-allow' : 'badge-deny'}">
            ${r.allowed ? 'ALLOWED (Zero Trust Tunnel)' : 'BLOCKED (Default Deny)'}
          </span>
        </td>
        <td>${r.description}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="window.toggleSegmentRule('${r.id}')">
            ${r.allowed ? 'Disable' : 'Enable'}
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load topology:', err);
  }
}

// Toggle firewall rule
window.toggleSegmentRule = async (ruleId) => {
  try {
    const res = await fetch(`${API_BASE}/network/rules/${ruleId}/toggle`, { method: 'POST' });
    if (res.ok) {
      showToast('Micro-segmentation firewall rule toggled', 'info');
      await loadTopology();
    }
  } catch (err) {
    showToast('Failed to toggle rule: ' + err.message, 'danger');
  }
};

// Load Audit Events
async function loadAuditEvents() {
  try {
    const filter = document.getElementById('audit-filter-decision')?.value || '';
    const url = filter ? `${API_BASE}/audit/events?decision=${filter}` : `${API_BASE}/audit/events`;
    const res = await fetch(url);
    const events = await res.json();

    const tbody = document.getElementById('audit-tbody');
    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center">No security events recorded.</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(ev => `
      <tr>
        <td><code>${new Date(ev.created_at).toLocaleTimeString()}</code></td>
        <td><span class="${ev.decision === 'ALLOW' ? 'badge-allow' : 'badge-deny'}">${ev.decision}</span></td>
        <td><strong>${ev.event_type}</strong></td>
        <td>${ev.username || 'unknown'} <span style="color:var(--text-dim)">(${ev.user_role || 'guest'})</span></td>
        <td>${ev.resource || 'N/A'}</td>
        <td><span class="risk-pill ${ev.risk_score < 35 ? 'low' : ev.risk_score < 70 ? 'med' : 'high'}">${ev.risk_score}</span></td>
        <td><code>${ev.device_trust || 'trusted'}</code></td>
        <td style="max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${ev.reason}">${ev.reason}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load audit events:', err);
  }
}

// Inject Simulated Threat Vector
async function injectSimulatedThreat() {
  try {
    const res = await fetch(`${API_BASE}/audit/simulate-attack`, { method: 'POST' });
    const data = await res.json();
    showToast(`Red Team Attack Simulated: ${data.threat.type}`, 'danger');
    await loadStats();
    if (state.activeTab === 'audit') await loadAuditEvents();
  } catch (err) {
    showToast('Failed to inject threat: ' + err.message, 'danger');
  }
}

// Toast notification helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Boot
window.addEventListener('DOMContentLoaded', initApp);
