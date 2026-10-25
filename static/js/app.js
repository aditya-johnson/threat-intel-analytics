// ====================================================================
// Main Application Controller (Cyber Threat Intelligence Dashboard)
// ====================================================================

let globalData = null;
let leafletMap = null;
let mapMarkers = [];
let activeSevFilter = 'ALL';
let activeStatusFilter = 'ALL';

document.addEventListener('DOMContentLoaded', () => {
  initIcons();
  initMap();
  initCharts();
  bindEvents();
  fetchDashboardData();
  loadPresetScenarios();

  // Check URL parameters for automated modal inspection & screenshots
  const params = new URLSearchParams(window.location.search);
  const openParam = params.get('open');
  if (openParam === 'investigate') {
    setTimeout(() => {
      const firstAlert = globalData?.alerts?.[0];
      if (firstAlert) openInvestigationModal(firstAlert.alert_id);
    }, 600);
  } else if (openParam === 'scenarios') {
    setTimeout(() => {
      document.getElementById('datasetsModal')?.classList.add('active');
    }, 400);
  } else if (openParam === 'lookup') {
    setTimeout(() => {
      openIpLookupDirect('194.26.29.112');
    }, 400);
  }

});

function initIcons() {
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

// 1. Initialize Leaflet Map
function initMap() {
  const mapElement = document.getElementById('threatMap');
  if (!mapElement) return;

  leafletMap = L.map('threatMap', {
    center: [25.0, 10.0],
    zoom: 2,
    minZoom: 1,
    maxZoom: 16,
    zoomControl: true
  });

  // Free, high-fidelity Cyber Dark Canvas (Esri World Dark Gray - No API Key Required)
  const darkBase = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
    attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
    maxZoom: 16
  });

  const darkLabels = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
    attribution: '',
    maxZoom: 16
  });

  // Standard OpenStreetMap Fallback
  const osmBase = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors',
    maxZoom: 19,
    className: 'osm-dark-filter'
  });

  // Add default dark layers
  darkBase.addTo(leafletMap);
  darkLabels.addTo(leafletMap);

  // Layer control switcher for the analyst
  const baseMaps = {
    "Cyber Dark Canvas": darkBase,
    "OpenStreetMap (Filtered)": osmBase
  };
  const overlayMaps = {
    "Geographic Labels": darkLabels
  };
  L.control.layers(baseMaps, overlayMaps, { position: 'topright' }).addTo(leafletMap);

  // Resize listener
  window.addEventListener('resize', () => {
    if (leafletMap) leafletMap.invalidateSize();
  });

  setTimeout(() => {
    if (leafletMap) leafletMap.invalidateSize();
  }, 300);
}

// 2. Fetch and render dashboard
async function fetchDashboardData() {
  try {
    const res = await fetch('/api/results');
    if (!res.ok) throw new Error('Failed to fetch dashboard data');
    const data = await res.json();
    globalData = data;
    renderAll(data);
  } catch (err) {
    console.error('Error fetching dashboard data:', err);
  }
}

function renderAll(data) {
  // Update Header
  document.getElementById('activeDatasetLabel').innerText = `Dataset: ${data.dataset_name || 'Active'}`;

  // Update KPIs
  const k = data.kpis || {};
  document.getElementById('kpiTotalLogs').innerText = (k.total_logs || 0).toLocaleString();
  document.getElementById('kpiLogSub').innerText = `${data.stats?.valid_records || 0} valid, ${data.stats?.dropped_records || 0} dropped`;
  document.getElementById('kpiCriticalCount').innerText = k.critical_count || 0;
  document.getElementById('kpiHighMedCount').innerText = `${k.high_count || 0} / ${k.medium_count || 0}`;
  document.getElementById('kpiMaliciousIps').innerText = k.malicious_ips || 0;
  document.getElementById('kpiMaxRisk').innerHTML = `${k.max_risk || 0}<span style="font-size: 14px; color: var(--text-muted);">/100</span>`;
  document.getElementById('kpiAvgRisk').innerText = `Avg priority score: ${k.avg_risk || 0}`;

  document.getElementById('alertCountBadge').innerText = data.alerts?.length || 0;
  document.getElementById('logCountBadge').innerText = data.stats?.valid_records || data.raw_logs_sample?.length || 0;

  // Render Map Markers
  renderMapMarkers(data.geo_threats || []);

  // Render Top IPs Leaderboard
  renderTopIps(data.top_ips || []);

  // Update Visual Charts
  updateAttackTypesChart(data.attack_breakdown || []);
  updateTimelineChart(data.timeline || {});

  // Render MITRE Matrix
  renderMitreMatrix(data.mitre_matrix || []);

  // Render Tables
  renderAlertsTable(data.alerts || []);
  renderLogsTable(data.raw_logs_sample || []);

  initIcons();
}

// 3. Map Marker Rendering
function renderMapMarkers(threats) {
  if (!leafletMap) return;

  // Clear existing markers
  mapMarkers.forEach(m => leafletMap.removeLayer(m));
  mapMarkers = [];

  document.getElementById('threatMapCount').innerText = `${threats.length} External Threat Nodes`;

  threats.forEach(t => {
    if (t.latitude && t.longitude && t.latitude !== 0) {
      const isCrit = t.risk_level === 'CRITICAL' || t.abuse_score >= 80;
      const markerColor = isCrit ? '#EF4444' : '#F97316';

      const circle = L.circleMarker([t.latitude, t.longitude], {
        radius: isCrit ? 8 : 6,
        fillColor: markerColor,
        color: '#fff',
        weight: 1.5,
        opacity: 0.9,
        fillOpacity: 0.8
      });

      const popupHtml = `
        <div style="font-size: 12px; line-height: 1.5;">
          <div style="font-weight: 700; color: #fff; display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <span>${t.ip}</span>
            <span style="font-family: monospace; font-size: 11px; color: ${markerColor};">${t.risk_score || t.abuse_score}/100</span>
          </div>
          <div style="color: #94A3B8; font-size: 11px; margin-top: 3px;">
            <b>Role:</b> ${t.role} (${t.country}, ${t.city})
          </div>
          <div style="color: #38BDF8; font-size: 11px; margin-top: 2px;">
            <b>Classification:</b> ${t.classification}
          </div>
          ${t.threat_actor ? `<div style="color: #F87171; font-size: 10px; font-weight: 600; margin-top: 2px;">Actor: ${t.threat_actor}</div>` : ''}
          <div style="color: #64748B; font-size: 10px; margin-top: 2px;">
            <b>ISP:</b> ${t.isp}
          </div>
        </div>
      `;

      circle.bindPopup(popupHtml);
      circle.addTo(leafletMap);
      mapMarkers.push(circle);
    }
  });

  if (mapMarkers.length > 0) {
    const group = new L.featureGroup(mapMarkers);
    leafletMap.fitBounds(group.getBounds().pad(0.3), { maxZoom: 5 });
  }
}

// 4. Render Top IPs Leaderboard
function renderTopIps(topIps) {
  const container = document.getElementById('topIpsContainer');
  if (!container) return;

  if (!topIps || topIps.length === 0) {
    container.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; padding: 20px; text-align: center;">No suspicious external IPs identified.</div>';
    return;
  }

  container.innerHTML = topIps.map(ipData => {
    const score = ipData.abuse_score || ipData.max_risk_score || 0;
    const actorHtml = ipData.threat_actor ? `<span style="color: #F87171; font-size: 10px; font-weight: 600;">[${ipData.threat_actor}]</span>` : '';
    return `
      <div class="ip-item" onclick="openIpLookupDirect('${ipData.ip}')" title="Click to inspect IP threat dossier">
        <div class="ip-meta">
          <div class="ip-address">
            <span>${ipData.ip}</span>
            ${actorHtml}
          </div>
          <div class="ip-country">${ipData.country} &bull; ${ipData.classification.substring(0, 32)}</div>
        </div>
        <div class="ip-badge-wrap">
          <span style="font-family: var(--font-mono); font-size: 11px; font-weight: 700; color: ${score >= 80 ? '#EF4444' : '#F59E0B'};">
            ${score}% Abuse
          </span>
          <div class="abuse-bar-container">
            <div class="abuse-bar-fill" style="width: ${Math.min(100, score)}%;"></div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

// 5. Render MITRE ATT&CK Matrix
function renderMitreMatrix(matrix) {
  const container = document.getElementById('mitreContainer');
  if (!container) return;

  document.getElementById('mitreTacticCount').innerText = `${matrix.length} Active Tactics`;

  if (!matrix || matrix.length === 0) {
    container.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; padding: 10px;">No MITRE techniques mapped yet.</div>';
    return;
  }

  container.innerHTML = matrix.map(m => `
    <div class="mitre-item">
      <div>
        <div class="mitre-tactic">${m.tactic}</div>
        <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">
          ${m.techniques.join(', ')}
        </div>
      </div>
      <span class="mitre-badge">${m.count} alerts</span>
    </div>
  `).join('');
}

// 6. Render Alerts Table with Filters
function renderAlertsTable(alerts) {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;

  const searchVal = (document.getElementById('alertSearchInput')?.value || '').toLowerCase().trim();

  const filtered = alerts.filter(a => {
    // Severity filter
    if (activeSevFilter !== 'ALL' && a.risk_level !== activeSevFilter) return false;
    // Status filter
    if (activeStatusFilter !== 'ALL' && a.triage_status !== activeStatusFilter) return false;
    // Search query
    if (searchVal) {
      const matchIp = (a.source_ip || '').toLowerCase().includes(searchVal);
      const matchDst = (a.dest_ip || '').toLowerCase().includes(searchVal);
      const matchTitle = (a.title || '').toLowerCase().includes(searchVal);
      const matchUser = (a.target_user || '').toLowerCase().includes(searchVal);
      const matchMitre = (a.mitre_attack?.technique_name || '').toLowerCase().includes(searchVal);
      if (!matchIp && !matchDst && !matchTitle && !matchUser && !matchMitre) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No alerts match current filter criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(a => {
    const sev = a.risk_level || 'MEDIUM';
    const scoreClass = sev === 'CRITICAL' ? 'score-crit' : (sev === 'HIGH' ? 'score-high' : (sev === 'MEDIUM' ? 'score-med' : 'score-low'));
    const mitre = a.mitre_attack || {};
    const ti = a.threat_intel || {};

    return `
      <tr>
        <td>
          <div class="risk-score-pill ${scoreClass}">
            ${a.risk_score}
          </div>
        </td>
        <td>
          <div style="font-weight: 700; color: #fff; margin-bottom: 3px;">${a.title}</div>
          <div style="font-size: 10px; color: var(--accent-cyan); font-family: var(--font-mono);">
            ${mitre.tactic || 'Security'} &bull; ${mitre.technique_id || 'T0000'} ${mitre.technique_name || ''}
          </div>
        </td>
        <td>
          <div style="font-family: var(--font-mono); font-weight: 600; color: #fff;">${a.source_ip}</div>
          <div style="font-size: 10px; color: var(--text-muted);">${ti.country_name || 'External'} (${ti.abuse_confidence_score || 0}% abuse)</div>
        </td>
        <td>
          <div style="font-family: var(--font-mono); font-size: 11px;">${a.dest_ip}</div>
          <div style="font-size: 10px; color: #C4B5FD;">User: <i>${a.target_user}</i></div>
        </td>
        <td>
          <span class="badge badge-low">${a.evidence_count} logs</span>
        </td>
        <td>
          <span style="font-size: 11px; color: #E2E8F0;">${(ti.threat_classification || 'Unclassified').substring(0, 26)}</span>
        </td>
        <td>
          <select class="badge-status" onchange="updateAlertStatusDirect('${a.alert_id}', this.value)">
            <option value="OPEN" ${a.triage_status === 'OPEN' ? 'selected' : ''}>OPEN</option>
            <option value="INVESTIGATING" ${a.triage_status === 'INVESTIGATING' ? 'selected' : ''}>INVESTIGATING</option>
            <option value="RESOLVED" ${a.triage_status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
            <option value="FALSE_POSITIVE" ${a.triage_status === 'FALSE_POSITIVE' ? 'selected' : ''}>FALSE POSITIVE</option>
          </select>
        </td>
        <td>
          <button class="btn btn-outline" style="padding: 5px 9px; font-size: 11px;" onclick="openInvestigationModal('${a.alert_id}')">
            Investigate
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

// 7. Render Logs Explorer Table
function renderLogsTable(logs) {
  const tbody = document.getElementById('logsTableBody');
  if (!tbody) return;

  const searchVal = (document.getElementById('logSearchInput')?.value || '').toLowerCase().trim();

  const filtered = logs.filter(l => {
    if (!searchVal) return true;
    return (
      (l.src_ip || '').toLowerCase().includes(searchVal) ||
      (l.dest_ip || '').toLowerCase().includes(searchVal) ||
      (l.event_type || '').toLowerCase().includes(searchVal) ||
      (l.user || '').toLowerCase().includes(searchVal) ||
      (l.message || '').toLowerCase().includes(searchVal)
    );
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No logs found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.slice(0, 100).map(l => {
    const isFail = l.status === 'FAILURE' || l.event_type === 'AUTH_FAILURE';
    const statusColor = isFail ? '#EF4444' : '#10B981';

    return `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">${l.log_id}</td>
        <td style="font-family: var(--font-mono); font-size: 10px; color: #CBD5E1;">${l.timestamp.replace('T', ' ').substring(0, 19)}</td>
        <td><span class="badge ${isFail ? 'badge-critical' : 'badge-low'}">${l.event_type}</span></td>
        <td style="font-family: var(--font-mono);">${l.src_ip}:${l.src_port}</td>
        <td style="font-family: var(--font-mono);">${l.dest_ip}:${l.dest_port}</td>
        <td style="color: #C4B5FD;">${l.user}</td>
        <td style="font-weight: 700; color: ${statusColor}; font-size: 10px;">${l.status}</td>
        <td style="font-size: 11px; color: var(--text-secondary); max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${l.message}">
          ${l.message}
        </td>
      </tr>
    `;
  }).join('');
}

// 8. Alert Investigation Deep Dive Modal
let currentModalAlertId = null;

function openInvestigationModal(alertId) {
  const alert = (globalData?.alerts || []).find(a => a.alert_id === alertId);
  if (!alert) return;

  currentModalAlertId = alertId;
  const ti = alert.threat_intel || {};
  const mitre = alert.mitre_attack || {};

  document.getElementById('invModalTitle').innerText = alert.title;
  document.getElementById('invModalSubtitle').innerText = `Alert ID: ${alert.alert_id} | Rule: ${alert.rule_id}`;
  
  const sevColor = alert.risk_level === 'CRITICAL' ? '#EF4444' : (alert.risk_level === 'HIGH' ? '#F97316' : '#F59E0B');
  document.getElementById('invRiskScoreDisplay').style.color = sevColor;
  document.getElementById('invRiskScoreDisplay').innerText = `${alert.risk_score}/100 (${alert.risk_level})`;
  document.getElementById('invActionDisplay').innerText = alert.recommended_action || 'Review incident';

  // Risk Factors Breakdown
  const breakdownList = document.getElementById('invRiskBreakdownList');
  breakdownList.innerHTML = (alert.risk_factors || []).map(rf => `
    <div class="breakdown-row">
      <span><b>[+${rf.points} pts]</b> ${rf.explanation}</span>
      <span class="tag">${rf.category}</span>
    </div>
  `).join('');

  // Threat Intel Dossier
  const dossier = document.getElementById('invThreatIntelDossier');
  dossier.innerHTML = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
      <div><b>Source IP:</b> <span style="font-family: var(--font-mono); color: #fff;">${alert.source_ip}</span></div>
      <div><b>Country & City:</b> ${ti.country_name || 'Unknown'} (${ti.city || 'N/A'})</div>
      <div><b>Threat Classification:</b> <span style="color: #38BDF8;">${ti.threat_classification || 'N/A'}</span></div>
      <div><b>Abuse Confidence Score:</b> <span style="color: ${ti.abuse_confidence_score > 60 ? '#EF4444' : '#10B981'}; font-weight: 700;">${ti.abuse_confidence_score || 0}%</span></div>
      <div><b>Adversary Attribution:</b> <span style="color: #F87171;">${ti.threat_actor || 'None / Unattributed'}</span></div>
      <div><b>ISP / Autonomous System:</b> ${ti.isp || 'N/A'} (${ti.asn || ''})</div>
      <div style="grid-column: span 2;"><b>Threat Blacklists:</b> ${(ti.blacklists || []).join(', ') || 'No public blocklist match'}</div>
    </div>
  `;

  // MITRE display
  const mitreBox = document.getElementById('invMitreDisplay');
  mitreBox.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <div style="font-weight: 700; color: #fff;">${mitre.tactic} &rarr; ${mitre.technique_name}</div>
        <div style="color: var(--text-muted); font-size: 11px; font-family: var(--font-mono); margin-top: 2px;">
          Technique ID: ${mitre.technique_id} | Tactic ID: ${mitre.tactic_id || 'TA0000'}
        </div>
      </div>
      <span class="badge badge-high">${mitre.tactic}</span>
    </div>
  `;

  // Evidence JSON
  const matchingLogs = (globalData?.raw_logs_sample || []).filter(l => (alert.log_ids || []).includes(l.log_id));
  document.getElementById('invEvidenceCount').innerText = alert.evidence_count || matchingLogs.length;
  document.getElementById('invEvidenceJson').innerText = JSON.stringify(matchingLogs.length > 0 ? matchingLogs : alert.indicators, null, 2);

  // Status & Notes
  document.getElementById('invStatusSelect').value = alert.triage_status || 'OPEN';
  document.getElementById('invNotesInput').value = alert.analyst_notes || '';

  document.getElementById('investigationModal').classList.add('active');
  initIcons();
}

// 9. Update Alert Status API Call
async function updateAlertStatusDirect(alertId, newStatus) {
  try {
    const res = await fetch(`/api/alerts/${alertId}/triage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    if (res.ok) {
      const a = (globalData?.alerts || []).find(item => item.alert_id === alertId);
      if (a) a.triage_status = newStatus;
      renderAlertsTable(globalData.alerts);
    }
  } catch (err) {
    console.error('Failed to update alert status:', err);
  }
}

// 10. Load Presets List
async function loadPresetScenarios() {
  try {
    const res = await fetch('/api/samples');
    if (!res.ok) return;
    const presets = await res.json();
    const container = document.getElementById('presetGridContainer');
    if (!container) return;

    container.innerHTML = presets.map(p => `
      <div class="preset-card" onclick="loadScenario('${p.id}')">
        <h4>${p.name}</h4>
        <p>${p.description}</p>
        <div class="tag-list">
          ${p.tags.map(t => `<span class="tag">${t}</span>`).join('')}
        </div>
      </div>
    `).join('');
  } catch (e) {
    console.error(e);
  }
}

async function loadScenario(scenarioId) {
  const modal = document.getElementById('datasetsModal');
  try {
    modal.classList.remove('active');
    document.getElementById('pipelineStatusText').innerText = 'ANALYZING SCENARIO...';
    const res = await fetch(`/api/sample/${scenarioId}`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to load preset scenario');
    const data = await res.json();
    globalData = data;
    renderAll(data);
    document.getElementById('pipelineStatusText').innerText = 'PIPELINE ACTIVE';
  } catch (err) {
    alert('Error loading scenario: ' + err.message);
    document.getElementById('pipelineStatusText').innerText = 'PIPELINE ACTIVE';
  }
}

// 11. On-Demand IP Lookup
async function openIpLookupDirect(ipAddress) {
  document.getElementById('lookupIpInput').value = ipAddress;
  document.getElementById('lookupModal').classList.add('active');
  await runIpLookup();
}

async function runIpLookup() {
  const ip = document.getElementById('lookupIpInput').value.trim();
  if (!ip) return;

  const resultBox = document.getElementById('lookupResultBox');
  resultBox.style.display = 'block';
  resultBox.innerHTML = '<div style="color: var(--accent-cyan); font-size: 12px;">Querying threat feeds and GeoIP services...</div>';

  try {
    const res = await fetch(`/api/enrich-ip/${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error('Query failed');
    const ti = await res.json();

    const scoreColor = ti.abuse_confidence_score > 60 ? '#EF4444' : (ti.abuse_confidence_score > 20 ? '#F59E0B' : '#10B981');

    resultBox.innerHTML = `
      <div style="background: rgba(13, 20, 36, 0.8); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 10px;">
          <div>
            <h4 style="font-size: 16px; font-family: var(--font-mono); color: #fff;">${ti.ip}</h4>
            <span style="font-size: 11px; color: var(--text-muted);">${ti.country_name} (${ti.city}) &bull; ${ti.domain_ptr}</span>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 18px; font-weight: 700; color: ${scoreColor}; font-family: var(--font-mono);">${ti.abuse_confidence_score}%</div>
            <div style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Abuse Confidence</div>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 12px;">
          <div><b>Classification:</b> <span style="color: #38BDF8;">${ti.threat_classification}</span></div>
          <div><b>Adversary Attribution:</b> <span style="color: #F87171;">${ti.threat_actor || 'None reported'}</span></div>
          <div><b>ISP / Provider:</b> ${ti.isp}</div>
          <div><b>ASN:</b> ${ti.asn}</div>
          <div><b>Total Abuse Reports:</b> ${ti.total_reports || 0}</div>
          <div><b>Coordinates:</b> ${ti.latitude}, ${ti.longitude}</div>
          <div style="grid-column: span 2;"><b>Blacklists:</b> ${(ti.blacklists || []).join(', ') || 'Clean on known threat lists'}</div>
        </div>
      </div>
    `;
  } catch (err) {
    resultBox.innerHTML = `<div style="color: #EF4444; font-size: 12px;">Failed to lookup IP: ${err.message}</div>`;
  }
}

// 12. Bind UI Events
function bindEvents() {
  // Tabs Navigation
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const tabId = btn.getAttribute('data-tab');
      document.getElementById(tabId)?.classList.add('active');
      initIcons();
    });
  });

  // Severity Filters
  document.querySelectorAll('#severityFilters .pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#severityFilters .pill-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeSevFilter = btn.getAttribute('data-sev');
      renderAlertsTable(globalData?.alerts || []);
    });
  });

  // Status Filters
  document.querySelectorAll('#statusFilters .pill-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#statusFilters .pill-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeStatusFilter = btn.getAttribute('data-status');
      renderAlertsTable(globalData?.alerts || []);
    });
  });

  // Alert Search Input
  document.getElementById('alertSearchInput')?.addEventListener('input', () => {
    renderAlertsTable(globalData?.alerts || []);
  });

  // Log Search Input
  document.getElementById('logSearchInput')?.addEventListener('input', () => {
    renderLogsTable(globalData?.raw_logs_sample || []);
  });

  // Modal Closers
  document.getElementById('btnCloseInvModal')?.addEventListener('click', () => {
    document.getElementById('investigationModal').classList.remove('active');
  });
  document.getElementById('btnCloseDatasetsModal')?.addEventListener('click', () => {
    document.getElementById('datasetsModal').classList.remove('active');
  });
  document.getElementById('btnCloseUploadModal')?.addEventListener('click', () => {
    document.getElementById('uploadModal').classList.remove('active');
  });
  document.getElementById('btnCloseLookupModal')?.addEventListener('click', () => {
    document.getElementById('lookupModal').classList.remove('active');
  });

  // Modal Openers
  document.getElementById('btnOpenDatasets')?.addEventListener('click', () => {
    document.getElementById('datasetsModal').classList.add('active');
  });
  document.getElementById('btnOpenUpload')?.addEventListener('click', () => {
    document.getElementById('uploadModal').classList.add('active');
  });
  document.getElementById('btnOpenLookup')?.addEventListener('click', () => {
    document.getElementById('lookupModal').classList.add('active');
  });

  // Save Triage in Modal
  document.getElementById('btnSaveTriage')?.addEventListener('click', async () => {
    if (!currentModalAlertId) return;
    const status = document.getElementById('invStatusSelect').value;
    const notes = document.getElementById('invNotesInput').value;

    try {
      const res = await fetch(`/api/alerts/${currentModalAlertId}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes })
      });
      if (res.ok) {
        const a = (globalData?.alerts || []).find(item => item.alert_id === currentModalAlertId);
        if (a) {
          a.triage_status = status;
          a.analyst_notes = notes;
        }
        renderAlertsTable(globalData.alerts);
        document.getElementById('investigationModal').classList.remove('active');
      }
    } catch (e) {
      alert('Error saving triage: ' + e.message);
    }
  });

  // Export Buttons
  document.getElementById('btnExportCsv')?.addEventListener('click', () => {
    window.location.href = '/api/export/csv';
  });
  document.getElementById('btnExportPdf')?.addEventListener('click', () => {
    window.location.href = '/api/export/pdf';
  });

  // Dropzone File Upload
  const dropzone = document.getElementById('dropzoneArea');
  const fileInput = document.getElementById('fileInput');

  dropzone?.addEventListener('click', () => fileInput.click());
  dropzone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'var(--accent-cyan)';
  });
  dropzone?.addEventListener('dragleave', () => {
    dropzone.style.borderColor = 'rgba(56, 189, 248, 0.4)';
  });
  dropzone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'rgba(56, 189, 248, 0.4)';
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput?.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileUpload(e.target.files[0]);
    }
  });

  // IP Lookup Button
  document.getElementById('btnRunLookup')?.addEventListener('click', runIpLookup);

  // API Key Form
  document.getElementById('apiKeysForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const abuseKey = document.getElementById('abuseKeyInput').value.trim();
    const vtKey = document.getElementById('vtKeyInput').value.trim();
    try {
      const res = await fetch('/api/config/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ abuseipdb_key: abuseKey, virustotal_key: vtKey })
      });
      if (res.ok) {
        alert('API keys updated successfully!');
      }
    } catch (err) {
      alert('Error updating API keys: ' + err.message);
    }
  });
}

async function handleFileUpload(file) {
  const statusEl = document.getElementById('uploadStatusMessage');
  statusEl.style.display = 'block';
  statusEl.innerText = `Parsing and validating ${file.name}...`;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/upload', {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || 'Upload failed');
    }
    const data = await res.json();
    globalData = data;
    renderAll(data);
    statusEl.innerText = `Analysis complete! Found ${data.alerts?.length || 0} alerts across ${data.stats?.valid_records || 0} valid logs.`;
    setTimeout(() => {
      document.getElementById('uploadModal').classList.remove('active');
      statusEl.style.display = 'none';
    }, 1500);
  } catch (err) {
    statusEl.style.color = '#EF4444';
    statusEl.innerText = `Error: ${err.message}`;
  }
}
