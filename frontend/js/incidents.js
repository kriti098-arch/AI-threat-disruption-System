// js/incidents.js
async function loadIncidents() {
  const incidents = await fetchIncidents();
  const tbody = document.getElementById('incidentTableBody');
  const countEl = document.getElementById('incidentCount');

  if (!incidents || !incidents.length) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text-dim);padding:30px;">No incidents detected yet.</td></tr>';
    return;
  }

  countEl.textContent = `${incidents.length} incidents`;
  const sorted = [...incidents].sort((a, b) => b.incident_id - a.incident_id);

  tbody.innerHTML = sorted.map(inc => {
    const proof = inc.proof || {};
    const kc    = proof.kill_chain || {};
    const conf  = proof.confidence || {};
    const confPct = conf.confidence_pct || 0;
    const stage   = kc.current_stage || '—';

    return `
      <tr>
        <td style="color:var(--text-dim)">#${inc.incident_id}</td>
        <td style="color:var(--cyan)">${inc.src_ip}</td>
        <td style="font-size:11px;">${inc.incident_type}</td>
        <td><span class="sev-badge sev-${inc.severity}">${inc.severity}</span></td>
        <td>
          <div class="conf-bar">
            <div class="conf-track"><div class="conf-fill" style="width:${confPct}%"></div></div>
            <span style="font-size:10px;color:var(--text-dim)">${confPct}%</span>
          </div>
        </td>
        <td><span class="kc-pill">${stage}</span></td>
        <td style="color:var(--text-dim);font-size:11px;">${formatTime(inc.timestamp)}</td>
        <td>
          <button class="analyze-btn" onclick="openIncident(${inc.incident_id})">ANALYZE</button>
          <a href="http://127.0.0.1:8000/reports/incident/${inc.incident_id}" target="_blank">
            <button class="analyze-btn" style="margin-left:4px;border-color:var(--green);color:var(--green);">PDF</button>
          </a>
        </td>
      </tr>`;
  }).join('');
}

function openIncident(id) {
  fetchIncidents().then(incidents => {
    const inc = incidents.find(i => i.incident_id === id);
    if (!inc) return;
    renderIncidentModal(inc);
    document.getElementById('incidentModal').classList.add('open');
  });
}

function renderIncidentModal(inc) {
  const proof      = inc.proof || {};
  const ai         = proof.ai_analysis || {};
  const kc         = proof.kill_chain || {};
  const conf       = proof.confidence || {};
  const persona    = proof.persona || {};
  const ifResult   = proof.isolation_forest || {};
  const geo        = proof.geolocation || {};
  const intel      = proof.threat_intel || {};
  const shap       = proof.shap_explanation || {};       // ← NEW FEATURE 2
  const evasion    = proof.evasion_analysis || {};       // ← NEW FEATURE 3
  const honeypotP  = proof.honeypot || {};               // ← NEW FEATURE 4

  const signals    = conf.signals_triggered || [];
  const missed     = conf.signals_missed || [];
  const actions    = ai.immediate_actions || [];
  const nextStages = kc.predicted_next_stages || [];

  const abuseScore = (intel.abuseipdb || {}).abuse_confidence_score || 0;
  const otxPulses  = (intel.alienvault || {}).pulse_count || 0;

  // ── Session-aware badge text  ← NEW FEATURE 1
  const sessionCount   = ai.session_event_count || 0;
  const isSessionAware = ai.reasoning_type === 'session_aware';
  const sessionBadge   = isSessionAware
    ? `<span style="background:var(--cyan-dim);color:var(--cyan);border:1px solid var(--cyan);
         font-size:9px;padding:2px 8px;letter-spacing:1px;margin-left:8px;">
         SESSION-AWARE · ${sessionCount} EVENTS</span>`
    : '';

  document.getElementById('incidentDetailsContent').innerHTML = `

    <!-- ── HONEYPOT CONFIRMED BANNER  ← NEW FEATURE 4 ── -->
    ${honeypotP.honeypot_hit ? `
    <div style="padding:14px 16px;background:var(--red-dim);border:2px solid var(--red);
                margin-bottom:16px;display:flex;align-items:center;gap:12px;">
      <span style="font-size:24px;">🍯</span>
      <div>
        <div style="color:var(--red);font-size:13px;font-weight:bold;letter-spacing:2px;">
          HONEYPOT CONFIRMED — 100% ATTACK CERTAINTY
        </div>
        <div style="font-size:11px;color:var(--text-dim);margin-top:4px;">
          Packet targeted decoy service: <strong style="color:var(--text);">${honeypotP.service_targeted || '—'}</strong>
          · No ML needed · Confidence locked at 100%
        </div>
      </div>
    </div>` : ''}

    <!-- ── EVASION WARNING BANNER  ← NEW FEATURE 3 ── -->
    ${evasion.evasion_detected ? `
    <div style="padding:12px 16px;background:var(--yellow-dim);border:1px solid var(--yellow);
                margin-bottom:16px;">
      <div style="color:var(--yellow);font-size:11px;font-weight:bold;letter-spacing:2px;">
        ⚠ THRESHOLD-AWARE EVASION DETECTED
      </div>
      <div style="font-size:11px;color:var(--text-dim);margin-top:4px;">
        Evasion score: <strong style="color:var(--yellow);">${evasion.evasion_score_pct || 0}%</strong>
        · ${evasion.flag_count || 0} evasion flags triggered
        · ${proof.evasion_force_flag ? 'Force-flagged: IP is a confirmed evader' : 'IP escalated via evasion detection'}
      </div>
      ${(evasion.flags || []).map(f => `
        <div style="margin-top:4px;font-size:10px;color:var(--text-dim);padding-left:8px;
                    border-left:2px solid var(--yellow);">
          <strong>${f.type.replace(/_/g,' ')}</strong> — ${f.detail}
        </div>`).join('')}
    </div>` : ''}

    <!-- Header -->
    <div class="modal-section">
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;">
        <div style="padding:12px;background:var(--bg3);border:1px solid var(--border);">
          <div style="font-size:9px;color:var(--text-dim);letter-spacing:2px;">SOURCE IP</div>
          <div style="color:var(--cyan);font-size:16px;font-family:var(--display);font-weight:700;margin-top:4px;">${inc.src_ip}</div>
        </div>
        <div style="padding:12px;background:var(--bg3);border:1px solid var(--border);">
          <div style="font-size:9px;color:var(--text-dim);letter-spacing:2px;">SEVERITY</div>
          <div style="margin-top:4px;"><span class="sev-badge sev-${inc.severity}">${inc.severity}</span></div>
        </div>
        <div style="padding:12px;background:var(--bg3);border:1px solid var(--border);">
          <div style="font-size:9px;color:var(--text-dim);letter-spacing:2px;">CONFIDENCE</div>
          <div style="color:var(--cyan);font-size:20px;font-family:var(--display);font-weight:700;margin-top:4px;">${conf.confidence_pct || 0}%</div>
        </div>
        <div style="padding:12px;background:var(--bg3);border:1px solid var(--border);">
          <div style="font-size:9px;color:var(--text-dim);letter-spacing:2px;">LABEL</div>
          <div style="color:var(--yellow);font-size:13px;font-weight:bold;margin-top:4px;">${conf.confidence_label || '—'}</div>
        </div>
      </div>
      <div style="margin-top:10px;display:flex;gap:8px;">
        <a href="http://127.0.0.1:8000/reports/incident/${inc.incident_id}" target="_blank">
          <button class="analyze-btn" style="border-color:var(--green);color:var(--green);">⬇ DOWNLOAD PDF REPORT</button>
        </a>
        <a href="http://127.0.0.1:8000/reports/incident/${inc.incident_id}/preview" target="_blank">
          <button class="analyze-btn" style="border-color:var(--cyan);color:var(--cyan);">👁 PREVIEW PDF</button>
        </a>
      </div>
    </div>

    <!-- Threat Intel & Geo -->
    ${geo.country || intel.is_known_malicious !== undefined ? `
    <div class="modal-section">
      <div class="modal-section-title">◈ THREAT INTELLIGENCE</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;">
        ${geo.country ? `
        <div style="padding:10px;background:var(--bg3);border:1px solid var(--border);">
          <div style="font-size:9px;color:var(--text-dim);">ORIGIN</div>
          <div style="color:var(--text-bright);font-size:13px;margin-top:4px;">${geo.country || '—'}</div>
          <div style="font-size:10px;color:var(--text-dim);">${geo.city || ''} · ${geo.isp || ''}</div>
        </div>` : ''}
        ${intel.threat_score !== undefined ? `
        <div style="padding:10px;background:var(--bg3);border:1px solid var(--border);">
          <div style="font-size:9px;color:var(--text-dim);">ABUSE SCORE</div>
          <div style="color:${abuseScore > 50 ? 'var(--red)' : abuseScore > 25 ? 'var(--yellow)' : 'var(--green)'};font-size:20px;font-family:var(--display);font-weight:700;margin-top:4px;">${abuseScore}%</div>
        </div>
        <div style="padding:10px;background:var(--bg3);border:1px solid ${intel.is_known_malicious ? 'var(--red)' : 'var(--border)'};">
          <div style="font-size:9px;color:var(--text-dim);">KNOWN MALICIOUS</div>
          <div style="color:${intel.is_known_malicious ? 'var(--red)' : 'var(--green)'};font-size:14px;font-weight:bold;margin-top:4px;">${intel.is_known_malicious ? '⚠ YES' : '✓ NOT LISTED'}</div>
          <div style="font-size:10px;color:var(--text-dim);">OTX Pulses: ${otxPulses}</div>
        </div>` : ''}
      </div>
    </div>` : ''}

    <!-- AI Narrative — session-aware  ← NEW FEATURE 1 -->
    ${ai.threat_narrative || ai.narrative ? `
    <div class="modal-section">
      <div class="modal-section-title">
        ◈ AI THREAT ANALYSIS
        ${isSessionAware ? `<span style="color:var(--cyan);font-size:9px;">● SESSION-AWARE</span>` :
          ai.ai_powered ? `<span style="color:var(--green);font-size:9px;">● AI POWERED</span>` :
          `<span style="color:var(--text-dim);font-size:9px;">● RULE-BASED</span>`}
        ${sessionBadge}
      </div>
      ${isSessionAware && sessionCount > 0 ? `
      <div style="display:flex;gap:12px;margin-bottom:10px;">
        <div style="padding:8px 12px;background:var(--bg3);border:1px solid var(--border);font-size:10px;text-align:center;">
          <div style="color:var(--cyan);font-size:16px;font-weight:bold;">${sessionCount}</div>
          <div style="color:var(--text-dim);">SESSION EVENTS</div>
        </div>
        <div style="padding:8px 12px;background:var(--bg3);border:1px solid var(--border);font-size:10px;text-align:center;">
          <div style="color:var(--cyan);font-size:16px;font-weight:bold;">${ai.past_incident_count || 0}</div>
          <div style="color:var(--text-dim);">PRIOR INCIDENTS</div>
        </div>
        <div style="padding:8px 12px;background:var(--bg3);border:1px solid ${ai.threat_level==='CRITICAL'?'var(--red)':ai.threat_level==='HIGH'?'var(--orange)':'var(--yellow)'};font-size:10px;text-align:center;">
          <div style="color:${ai.threat_level==='CRITICAL'?'var(--red)':ai.threat_level==='HIGH'?'var(--orange)':'var(--yellow)'};font-size:16px;font-weight:bold;">${ai.threat_level || '—'}</div>
          <div style="color:var(--text-dim);">THREAT LEVEL</div>
        </div>
      </div>` : ''}
      <div class="ai-narrative">${ai.threat_narrative || ai.narrative}</div>
      ${ai.analyst_note ? `<div style="margin-top:8px;padding:10px 12px;background:var(--bg3);border-left:3px solid var(--yellow);font-size:12px;color:var(--yellow);">⚠ ${ai.analyst_note}</div>` : ''}
    </div>` : ''}

    <!-- Immediate Actions -->
    ${actions.length ? `
    <div class="modal-section">
      <div class="modal-section-title">◉ IMMEDIATE ACTIONS</div>
      <ul class="action-list">
        ${actions.map(a => `<li>${a}</li>`).join('')}
      </ul>
    </div>` : ''}

    <!-- Kill Chain -->
    <div class="modal-section">
      <div class="modal-section-title">◈ KILL CHAIN PROGRESSION</div>
      <div class="kc-modal-bar">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-dim);margin-bottom:6px;">
          <span>Stage: <span style="color:var(--orange)">${kc.current_stage || '—'}</span></span>
          <span>${kc.kill_chain_progression_pct || 0}% through kill chain</span>
        </div>
        <div class="kc-track"><div class="kc-fill" style="width:${kc.kill_chain_progression_pct || 0}%"></div></div>
      </div>
      <div style="margin-top:8px;">
        <span class="kc-modal-stage">▶ ${kc.current_stage || '—'}</span>
        ${nextStages.map(s => `<span class="predicted-stage">→ ${s}</span>`).join('')}
      </div>
      ${kc.recommendation ? `<div style="margin-top:8px;font-size:12px;color:var(--text-dim);padding:8px 12px;background:var(--bg3);">${kc.recommendation}</div>` : ''}
      ${ai.predicted_next_move ? `<div style="margin-top:8px;padding:8px 12px;background:var(--red-dim);border-left:3px solid var(--red);font-size:12px;color:var(--red);">PREDICTED: ${ai.predicted_next_move}</div>` : ''}
    </div>

    <!-- Confidence Signals -->
    ${signals.length || missed.length ? `
    <div class="modal-section">
      <div class="modal-section-title">◎ EVIDENCE SIGNALS (${signals.length}/${signals.length + missed.length} triggered)</div>
      <div class="signals-grid">
        ${signals.map(s => `<div class="signal-item triggered">✓ ${s.name}</div>`).join('')}
        ${missed.map(s => `<div class="signal-item missed">○ ${s.name}</div>`).join('')}
      </div>
    </div>` : ''}

    <!-- SHAP Explainability  ← NEW FEATURE 2 -->
    ${shap && shap.top_features && shap.top_features.length ? `
    <div class="modal-section">
      <div class="modal-section-title">◈ SHAP — WHY THIS WAS FLAGGED <span style="color:var(--cyan);font-size:9px;">● XAI</span></div>
      <div style="font-size:11px;color:var(--text-dim);margin-bottom:10px;">${shap.explanation_text || ''}</div>
      ${shap.top_features.map(f => {
        const isRisk = f.direction === 'increased_risk';
        const color  = isRisk ? 'var(--red)' : 'var(--green)';
        const maxAbs = Math.max(...shap.top_features.map(x => Math.abs(x.shap_value)));
        const pct    = maxAbs > 0 ? (Math.abs(f.shap_value) / maxAbs * 100).toFixed(1) : 0;
        const sign   = f.shap_value >= 0 ? '+' : '';
        return `
          <div style="margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px;">
              <span style="color:var(--text-bright);font-weight:500;">${f.feature.replace(/_/g,' ')}</span>
              <span style="color:${color};font-weight:bold;">${sign}${f.shap_value.toFixed(4)}</span>
            </div>
            <div style="background:var(--bg);border-radius:2px;height:8px;overflow:hidden;">
              <div style="width:${pct}%;height:100%;background:${color};border-radius:2px;transition:width 0.4s;"></div>
            </div>
            <div style="font-size:10px;color:var(--text-dim);margin-top:2px;">
              actual value: ${f.actual_value}
              &nbsp;·&nbsp;
              <span style="color:${color};">${isRisk ? '▲ increased detection probability' : '▼ decreased detection probability'}</span>
            </div>
          </div>`;
      }).join('')}
      <div style="margin-top:8px;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);display:flex;justify-content:space-between;font-size:11px;color:var(--text-dim);">
        <span>Base probability: <strong>${((shap.base_value || 0) * 100).toFixed(1)}%</strong></span>
        <span>Predicted probability: <strong style="color:var(--cyan);">${((shap.predicted_probability || 0) * 100).toFixed(1)}%</strong></span>
      </div>
    </div>` : ''}

    <!-- Isolation Forest -->
    <div class="modal-section">
      <div class="modal-section-title">◈ ISOLATION FOREST</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;">
        <div style="padding:10px;background:var(--bg3);border:1px solid var(--border);text-align:center;">
          <div style="font-size:9px;color:var(--text-dim);">ANOMALY</div>
          <div style="font-size:20px;font-family:var(--display);font-weight:700;color:${ifResult.anomaly?'var(--red)':'var(--green)'};">${ifResult.anomaly ? 'YES' : 'NO'}</div>
        </div>
        <div style="padding:10px;background:var(--bg3);border:1px solid var(--border);text-align:center;">
          <div style="font-size:9px;color:var(--text-dim);">IF SCORE</div>
          <div style="font-size:20px;font-family:var(--display);font-weight:700;color:var(--cyan);">${ifResult.score || 0}</div>
        </div>
        <div style="padding:10px;background:var(--bg3);border:1px solid var(--border);text-align:center;">
          <div style="font-size:9px;color:var(--text-dim);">CONFIDENCE</div>
          <div style="font-size:20px;font-family:var(--display);font-weight:700;color:var(--cyan);">${ifResult.confidence || 0}%</div>
        </div>
      </div>
    </div>

    <!-- Before/After -->
    <div class="modal-section">
      <div class="modal-section-title">◎ MITIGATION</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div>
          <div style="font-size:9px;color:var(--text-dim);letter-spacing:2px;margin-bottom:6px;">BEFORE</div>
          <pre style="background:var(--bg3);padding:12px;font-size:11px;border:1px solid var(--border);overflow:auto;max-height:120px;color:var(--text);">${JSON.stringify(proof.before||{}, null, 2)}</pre>
        </div>
        <div>
          <div style="font-size:9px;color:var(--green);letter-spacing:2px;margin-bottom:6px;">AFTER</div>
          <pre style="background:var(--green-dim);padding:12px;font-size:11px;border:1px solid var(--green);overflow:auto;max-height:120px;color:var(--green);">${JSON.stringify(proof.after||{}, null, 2)}</pre>
        </div>
      </div>
      <div style="margin-top:8px;padding:8px 12px;background:var(--bg3);font-size:12px;color:var(--text-dim);">
        Status: <span style="color:${inc.mitigation_status==='CONTAINED'?'var(--green)':'var(--yellow)'};font-weight:bold;">${inc.mitigation_status || 'MONITORING'}</span>
      </div>
    </div>
  `;
}

function closeModal() {
  document.getElementById('incidentModal').classList.remove('open');
}

function formatTime(ts) {
  if (!ts) return '—';
  try {
    // Handle multiple formats from DB
    let d = new Date(ts);
    if (isNaN(d.getTime())) {
      // Try adding Z for UTC
      d = new Date(ts + 'Z');
    }
    if (isNaN(d.getTime())) {
      // Try replacing space with T
      d = new Date(ts.replace(' ', 'T') + 'Z');
    }
    if (isNaN(d.getTime())) return ts; // Return raw if all fail
    return d.toLocaleTimeString() + ' ' + d.toLocaleDateString();
  } catch { return ts; }
}

loadIncidents();
setInterval(loadIncidents, 15000);