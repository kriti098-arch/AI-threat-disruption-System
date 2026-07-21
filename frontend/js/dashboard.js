// js/dashboard.js
let incidentChart, severityChart, attackChart;

async function loadDashboard() {
  const [stats, incidents, risk, threats, attackDist, fatigue, hpStats, evasionStats] = await Promise.all([
    fetchStats(), fetchIncidents(), fetchSystemRisk(),
    fetchTopThreats(), fetchAttackDist(), fetchAlertFatigue(),
    fetchJSON('/network-events/honeypot/stats'),   // ← NEW FEATURE 4
    fetchJSON('/network-events/evasion/suspects'),  // ← NEW FEATURE 3
  ]);

  // Stats
  if (stats) {
    document.getElementById('totalEvents').textContent =
      (stats.total_network_events || 0).toLocaleString();
    const af = stats.alert_stream_stats || {};
    document.getElementById('suppressedAlerts').textContent =
      (af.total_suppressed || 0).toLocaleString();
  }

  if (incidents) {
    document.getElementById('totalIncidents').textContent = incidents.length;
    const active = incidents.filter(i =>
      ['HIGH','CRITICAL'].includes(i.severity) && i.mitigation_status !== 'CONTAINED'
    ).length;
    document.getElementById('activeAnomalies').textContent = active;
  }

  // Risk banner
  if (risk) {
    const level = (risk.system_risk || 'NORMAL').toUpperCase();
    const banner = document.getElementById('riskBanner');
    const sidebar = document.getElementById('sidebarRisk');
    banner.textContent = `● SYSTEM STATUS: ${level}`;
    banner.className = `risk-banner ${level.toLowerCase()}`;
    sidebar.textContent = `STATUS: ${level}`;
  }

  // Incidents over time chart
  if (incidents) buildIncidentChart(incidents);
  if (incidents) buildSeverityChart(incidents);

  // Attack distribution  
  if (attackDist) buildAttackChart(attackDist);

  // Leaderboard
  if (threats) buildLeaderboard(threats);

  // Alert fatigue
  if (fatigue) buildFatigueDisplay(fatigue);

  // Sidebar fatigue stats
if (fatigue) {
    document.getElementById('suppressionRate').textContent =
      (fatigue.suppression_rate_pct || 0) + '%';
    document.getElementById('streamHealth').textContent =
      fatigue.stream_health || '—';
}

  // ← NEW FEATURE 4: Honeypot stats card
  if (hpStats) {
    document.getElementById('honeypotHits').textContent =
      (hpStats.total_confirmed_attacks || 0).toLocaleString();
  }

  // ← NEW FEATURE 3: Evasion suspects card
  if (evasionStats) {
    document.getElementById('evasionSuspects').textContent =
      (evasionStats.total_suspects || 0).toLocaleString();
  }
}

function buildIncidentChart(incidents) {
  const hourMap = {};  
  incidents.forEach(inc => {
    const h = new Date(inc.timestamp).getHours();
    hourMap[h] = (hourMap[h] || 0) + 1;
  });
  const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
  const data = labels.map((_, i) => hourMap[i] || 0);

  const ctx = document.getElementById('incidentChart').getContext('2d');
  if (incidentChart) incidentChart.destroy();
  incidentChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data,
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 4
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#5a7a9a', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2535' } },
        y: { ticks: { color: '#5a7a9a', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2535' } }
      }
    }
  });
}

function buildSeverityChart(incidents) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  incidents.forEach(i => { if (counts[i.severity] !== undefined) counts[i.severity]++; });

  const ctx = document.getElementById('severityChart').getContext('2d');
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: Object.keys(counts),
      datasets: [{
        data: Object.values(counts),
        backgroundColor: ['#ff335544','#ff660044','#ffcc0044','#00ff8844'],
        borderColor:     ['#ff3355','#ff6600','#ffcc00','#00ff88'],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: { color: '#c8d8e8', font: { family: 'Share Tech Mono', size: 11 } }
        }
      }
    }
  });
}

function buildAttackChart(dist) {
  const labels = Object.keys(dist);
  const data = Object.values(dist);
  const ctx = document.getElementById('attackChart').getContext('2d');
  if (attackChart) attackChart.destroy();
  attackChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: 'rgba(0,212,255,0.2)',
        borderColor: '#00d4ff',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#5a7a9a', font: { family: 'Share Tech Mono', size: 9 }, maxRotation: 30 }, grid: { color: '#1a2535' } },
        y: { ticks: { color: '#5a7a9a', font: { family: 'Share Tech Mono', size: 10 } }, grid: { color: '#1a2535' } }
      }
    }
  });
}

function buildLeaderboard(threats) {
  const el = document.getElementById('threatLeaderboard');
  if (!threats || !threats.length) {
    el.innerHTML = '<div class="empty-state">No repeat offenders detected yet.</div>';
    return;
  }
  el.innerHTML = threats.slice(0, 5).map(([ip, score], i) => `
    <div class="threat-row">
      <div>
        <span style="color:var(--text-dim);font-size:10px;">#${i+1} </span>
        <span class="threat-ip">${ip}</span>
      </div>
      <span class="threat-score">${score.toFixed(1)}</span>
    </div>
  `).join('');
}

function buildFatigueDisplay(fatigue) {
  const el = document.getElementById('alertFatigueDisplay');
  const health = fatigue.stream_health || '—';
  const healthColor = health === 'HEALTHY' ? 'var(--green)' :
                      health === 'STRESSED' ? 'var(--yellow)' : 'var(--red)';
  el.innerHTML = `
    <div class="fatigue-metric">
      <div class="fatigue-metric-val">${fatigue.total_alerts_processed || 0}</div>
      <div class="fatigue-metric-label">TOTAL PROCESSED</div>
    </div>
    <div class="fatigue-metric">
      <div class="fatigue-metric-val">${fatigue.total_suppressed || 0}</div>
      <div class="fatigue-metric-label">SUPPRESSED</div>
    </div>
    <div class="fatigue-metric">
      <div class="fatigue-metric-val">${fatigue.suppression_rate_pct || 0}%</div>
      <div class="fatigue-metric-label">SUPPRESSION RATE</div>
    </div>
    <div class="fatigue-metric">
      <div class="fatigue-metric-val" style="color:${healthColor}">${health}</div>
      <div class="fatigue-metric-label">STREAM HEALTH</div>
    </div>
  `;
}

async function loadPersonas() {
  const personas = await fetchAllPersonas();
  const el = document.getElementById('personaGrid');
  if (!personas || !Object.keys(personas).length) {
    el.innerHTML = '<div class="empty-state">No persona clusters detected yet.<br>Send traffic from multiple IPs to trigger DBSCAN clustering.</div>';
    return;
  }
  el.innerHTML = Object.values(personas).map(p => `
    <div class="persona-card">
      <div class="persona-id">${p.persona_id}</div>
      <div class="persona-stat">
        <span class="persona-stat-label">MEMBER IPs</span>
        <span class="persona-stat-val">${p.ip_count}</span>
      </div>
      <div class="persona-stat">
        <span class="persona-stat-label">DOMINANT ATTACK</span>
        <span class="persona-stat-val" style="color:var(--red);font-size:11px;">${p.dominant_attack_type}</span>
      </div>
      <div class="persona-stat">
        <span class="persona-stat-label">AVG RISK SCORE</span>
        <span class="persona-stat-val">${p.avg_risk_score}</span>
      </div>
      <div class="persona-stat">
        <span class="persona-stat-label">THREAT LEVEL</span>
        <span class="persona-stat-val" style="color:${p.threat_level==='HIGH'?'var(--red)':'var(--yellow)'}">${p.threat_level}</span>
      </div>
      <div class="persona-stat" style="border:none;">
        <span class="persona-stat-label">IPs</span>
        <span class="persona-stat-val" style="font-size:10px;color:var(--text-dim);">${(p.member_ips||[]).join(', ')}</span>
      </div>
    </div>
  `).join('');
}

async function loadEvaluation() {
  const summary = await fetchEvalSummary();
  const el = document.getElementById('evalContent');
  if (!summary || summary.status === 'no_results') {
    el.innerHTML = '<div class="empty-state">No evaluation results found.<br>Run: <code style="color:var(--cyan)">python scripts/train_and_evaluate.py</code></div>';
    return;
  }

  const models = [
    { key: 'isolation_forest', name: 'ISOLATION FOREST', subtitle: 'Unsupervised · Our Model' },
    { key: 'random_forest',    name: 'RANDOM FOREST',    subtitle: 'Supervised · Baseline' }
  ];

  const metricColor = (key, val) => {
    if (['fpr', 'fnr'].includes(key)) return val < 0.1 ? 'val-good' : val < 0.3 ? 'val-warn' : 'val-bad';
    return val >= 0.9 ? 'val-good' : val >= 0.5 ? 'val-warn' : 'val-bad';
  };

  el.innerHTML = models.map(m => {
    const r = summary[m.key];
    if (!r) return '';
    const metrics = [
      ['PRECISION', 'precision'], ['RECALL', 'recall'], ['F1 SCORE', 'f1'],
      ['ACCURACY', 'accuracy'],  ['ROC-AUC', 'roc_auc'], ['FPR', 'fpr'], ['FNR', 'fnr']
    ];
    return `
      <div class="eval-card">
        <div class="eval-model-name">${m.name}<br><span style="font-size:11px;color:var(--text-dim);font-weight:400;">${m.subtitle}</span></div>
        ${metrics.map(([label, key]) => {
          const val = r[key];
          const display = val != null ? (val * 1).toFixed(4) : 'N/A';
          const cls = val != null ? metricColor(key, val) : '';
          return `
            <div class="eval-metric">
              <span class="eval-metric-name">${label}</span>
              <span class="eval-metric-val ${cls}">${display}</span>
            </div>`;
        }).join('')}
      </div>`;
  }).join('') + (summary.isolation_forest_cv ? `
    <div class="eval-card">
      <div class="eval-model-name">IF CROSS-VALIDATION<br><span style="font-size:11px;color:var(--text-dim);font-weight:400;">5-Fold · Robustness Check</span></div>
      <div class="eval-metric"><span class="eval-metric-name">F1 MEAN</span><span class="eval-metric-val val-warn">${summary.isolation_forest_cv.f1_mean}</span></div>
      <div class="eval-metric"><span class="eval-metric-name">F1 STD</span><span class="eval-metric-val">${summary.isolation_forest_cv.f1_std}</span></div>
      <div class="eval-metric"><span class="eval-metric-name">FOLDS</span><span class="eval-metric-val">${summary.isolation_forest_cv.n_folds}</span></div>
      <div style="margin-top:16px;padding:12px;background:var(--bg3);border-left:3px solid var(--cyan);font-size:12px;color:var(--text);line-height:1.8;">
        Low IF F1 confirms unsupervised models need multi-signal augmentation —
        the basis of our dual-detector + AI reasoning architecture.
      </div>
    </div>` : '');

  // ← NEW FEATURE 2: Load SHAP importance after main eval renders
  loadEvaluationWithSHAP();
}

// Auto-refresh dashboard every 15s
loadDashboard();
setInterval(loadDashboard, 15000);

// ─── helpers ───────────────────────────────────────────────────────────────
async function fetchJSON(url) {
  try { const r = await fetch(`http://127.0.0.1:8000${url}`); return await r.json(); }
  catch { return null; }
}

// ─── SHAP global importance (added to evaluation section) ← NEW FEATURE 2 ──
async function loadEvaluationWithSHAP() {
  await loadEvaluation(); // your existing function
  const data = await fetchJSON('/network-events/shap/importance');
  const el = document.getElementById('evalContent');
  if (!data || !data.importance || !data.importance.length) return;

  const shapHtml = `
    <div class="eval-card">
      <div class="eval-model-name">SHAP FEATURE IMPORTANCE<br>
        <span style="font-size:11px;color:var(--text-dim);font-weight:400;">
          XAI · Mean |SHAP| over ${data.sample_size} events
        </span>
      </div>
      ${data.importance.map((f, i) => {
        const colors = ['var(--cyan)', 'var(--yellow)', 'var(--orange)'];
        const color = colors[i % colors.length];
        const maxVal = data.importance[0].mean_abs_shap;
        const pct = maxVal > 0 ? (f.mean_abs_shap / maxVal * 100).toFixed(1) : 0;
        return `
          <div class="eval-metric" style="flex-direction:column;align-items:flex-start;gap:4px;">
            <div style="display:flex;justify-content:space-between;width:100%;">
              <span class="eval-metric-name">#${f.rank} ${f.feature.replace(/_/g,' ')}</span>
              <span class="eval-metric-val" style="color:${color};">${f.mean_abs_shap.toFixed(4)}</span>
            </div>
            <div style="width:100%;background:var(--bg);border-radius:2px;height:6px;">
              <div style="width:${pct}%;height:100%;background:${color};border-radius:2px;transition:width 0.4s;"></div>
            </div>
          </div>`;
      }).join('')}
      <div style="margin-top:16px;padding:10px 12px;background:var(--bg3);border-left:3px solid var(--cyan);font-size:11px;color:var(--text-dim);line-height:1.8;">
        SHAP (SHapley Additive exPlanations) shows which features most influenced
        each detection decision. Higher mean |SHAP| = more important for classification.
        This addresses the XAI gap identified in the 2025 NIDS survey literature.
      </div>
    </div>`;

  el.insertAdjacentHTML('beforeend', shapHtml);
}

// ─── EVASION DETECTION section loader ← NEW FEATURE 3 ──────────────────────
async function loadEvasion() {
  const data = await fetchJSON('/network-events/evasion/suspects');
  if (!data) return;

  document.getElementById('confirmedEvaders').textContent = data.confirmed_evaders || 0;
  document.getElementById('suspectedEvaders').textContent = data.suspected_evaders || 0;
  document.getElementById('totalSuspects').textContent    = data.total_suspects || 0;

  const grid = document.getElementById('evasionGrid');
  if (!data.evaders || !data.evaders.length) {
    grid.innerHTML = '<div class="empty-state">No evasion attempts detected yet.<br>Evasion detection activates after 10+ events per IP.</div>';
    return;
  }

  grid.innerHTML = data.evaders.map(ev => {
    const isConfirmed = ev.status === 'CONFIRMED_EVADER';
    const scoreColor  = ev.evasion_score >= 0.70 ? 'var(--red)' :
                        ev.evasion_score >= 0.40 ? 'var(--yellow)' : 'var(--green)';
    const flagsHtml = (ev.flags || []).map(f => `
      <div style="padding:6px 10px;background:var(--bg3);border-left:2px solid ${
        f.severity === 'HIGH' ? 'var(--red)' : 'var(--yellow)'
      };font-size:10px;margin-bottom:4px;">
        <span style="color:var(--text-bright);font-weight:bold;">${f.type.replace(/_/g,' ')}</span>
        <div style="color:var(--text-dim);margin-top:2px;">${f.detail}</div>
      </div>`).join('');

    return `
      <div class="persona-card" style="border-color:${isConfirmed ? 'var(--red)' : 'var(--yellow)'};">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
          <div style="color:var(--cyan);font-family:var(--display);font-weight:700;font-size:14px;">${ev.ip}</div>
          <span class="sev-badge sev-${isConfirmed ? 'CRITICAL' : 'HIGH'}">${isConfirmed ? 'CONFIRMED' : 'SUSPECTED'}</span>
        </div>
        <div style="margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px;">
            <span style="color:var(--text-dim);">EVASION SCORE</span>
            <span style="color:${scoreColor};font-weight:bold;">${ev.evasion_score_pct}%</span>
          </div>
          <div style="background:var(--bg);border-radius:2px;height:8px;">
            <div style="width:${ev.evasion_score_pct}%;height:100%;background:${scoreColor};border-radius:2px;transition:width 0.4s;"></div>
          </div>
        </div>
        <div class="persona-stat">
          <span class="persona-stat-label">EVENTS TRACKED</span>
          <span class="persona-stat-val">${ev.events_tracked}</span>
        </div>
        <div class="persona-stat">
          <span class="persona-stat-label">FLAGS TRIGGERED</span>
          <span class="persona-stat-val" style="color:var(--red);">${ev.flag_count}</span>
        </div>
        <div style="margin-top:8px;">${flagsHtml}</div>
        <div style="display:flex;gap:6px;margin-top:10px;">
          <button class="analyze-btn" onclick="analyzeEvasionIP('${ev.ip}')">DEEP ANALYZE</button>
          <button class="analyze-btn" style="border-color:var(--text-dim);color:var(--text-dim);"
            onclick="resetEvasionIP('${ev.ip}')">CLEAR</button>
        </div>
      </div>`;
  }).join('');
}

async function analyzeEvasionIP(ip) {
  const data = await fetchJSON(`/network-events/evasion/analyze/${ip}`);
  alert(`Evasion Analysis for ${ip}:\nScore: ${data.evasion_score_pct}%\nFlags: ${data.flag_count}\n${data.recommended_action}`);
}

async function resetEvasionIP(ip) {
  if (!confirm(`Clear evasion profile for ${ip}?`)) return;
  await fetch(`http://127.0.0.1:8000/network-events/evasion/reset/${ip}`, { method: 'POST' });
  loadEvasion();
}

// ─── HONEYPOT section loader ← NEW FEATURE 4 ───────────────────────────────
async function loadHoneypot() {
  const [stats, hitsData] = await Promise.all([
    fetchJSON('/network-events/honeypot/stats'),
    fetchJSON('/network-events/honeypot/hits?limit=10'),
  ]);

  if (stats) {
    document.getElementById('hpTotalHits').textContent   = stats.total_confirmed_attacks || 0;
    document.getElementById('hpActivePorts').textContent = stats.honeypot_ports_active || 0;
    document.getElementById('hpNextRetrain').textContent =
      stats.next_retrain_at > 0 ? `${stats.next_retrain_at} hits` : 'READY';
    document.getElementById('hpModelStatus').textContent =
      stats.model_loaded ? 'LOADED' : 'NOT LOADED';

    // Top targeted ports
    const portsEl = document.getElementById('honeypotPortsList');
    const topPorts = stats.top_targeted_ports || [];
    if (topPorts.length) {
      portsEl.innerHTML = `
        <div style="margin-bottom:10px;font-size:10px;color:var(--text-dim);">TOP TARGETED</div>
        ${topPorts.map(([port, count]) => `
          <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px;">
            <span style="color:var(--cyan);">Port ${port}</span>
            <span style="color:var(--red);">${count} hits</span>
          </div>`).join('')}`;
    } else {
      // Show all decoy ports
      portsEl.innerHTML = `
        <div style="font-size:10px;color:var(--text-dim);margin-bottom:8px;">ACTIVE DECOY PORTS</div>
        ${[2222,3389,1433,3306,5432,6379,27017,9200,4444,31337].map(p => `
          <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:11px;">
            <span style="color:var(--cyan);">:${p}</span>
            <span style="color:var(--text-dim);font-size:10px;">0 hits</span>
          </div>`).join('')}`;
    }
  }

  // Recent hits list
  const hitsEl = document.getElementById('honeypotHitsList');
  if (hitsData && hitsData.hits && hitsData.hits.length) {
    hitsEl.innerHTML = hitsData.hits.map(h => `
      <div style="padding:10px;border-bottom:1px solid var(--border);border-left:3px solid var(--red);">
        <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
          <span style="color:var(--red);font-size:11px;font-weight:bold;">🍯 ${h.attack_type}</span>
          <span class="sev-badge sev-CRITICAL">CONFIRMED</span>
        </div>
        <div style="color:var(--cyan);font-size:12px;">${h.source_ip}</div>
        <div style="font-size:10px;color:var(--text-dim);margin-top:4px;">
          Port ${h.destination_port} · ${h.service_pretended} · ${h.timestamp ? h.timestamp.slice(0,19) : ''}
        </div>
      </div>`).join('');
  } else {
    hitsEl.innerHTML = '<div class="empty-state" style="padding:20px;">No honeypot hits yet.<br>Try sending a packet to port 4444.</div>';
  }
}

async function triggerHoneypotRetrain() {
  const btn = event.target;
  btn.textContent = '⟳ RETRAINING...';
  btn.disabled = true;
  const result = await fetchJSON('/network-events/honeypot/retrain');
  btn.textContent = '⟳ FORCE RETRAIN ISOLATION FOREST';
  btn.disabled = false;
  if (result && result.success) {
    alert(`✓ Retrain complete!\nAttack samples used: ${result.confirmed_attacks_used}\nNew contamination: ${(result.new_contamination * 100).toFixed(1)}%`);
  } else {
    alert(`Retrain: ${(result && result.reason) || 'Failed — need more honeypot hits first'}`);
  }
  loadHoneypot();
}