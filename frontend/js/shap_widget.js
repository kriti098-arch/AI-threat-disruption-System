// ============================================================
// FEATURE 2: SHAP FRONTEND WIDGET
// File: frontend/js/shap_widget.js
//
// Drop this file into your frontend/js/ folder.
// Call renderSHAPChart(containerId, shapData) from inside
// your incident modal after you fetch incident details.
//
// shapData = the incident.proof.shap_explanation object
// ============================================================

/**
 * Renders a horizontal bar chart showing SHAP feature contributions.
 * Green bars = decreased risk, Red bars = increased risk.
 * Bars are proportional to absolute SHAP value.
 */
function renderSHAPChart(containerId, shapData) {
    const container = document.getElementById(containerId);
    if (!container || !shapData || shapData.error) {
        if (container) container.innerHTML = '<p style="color:#888;font-size:12px;">SHAP explanation unavailable</p>';
        return;
    }

    const features = shapData.top_features || [];
    if (features.length === 0) return;

    const maxAbs = Math.max(...features.map(f => Math.abs(f.shap_value)));

    let html = `
    <div style="margin-top:12px;">
        <div style="font-size:13px;font-weight:600;margin-bottom:6px;color:var(--text-primary, #1a1a2e);">
            Why this was flagged (SHAP)
        </div>
        <div style="font-size:11px;color:#888;margin-bottom:10px;">
            ${shapData.explanation_text || ''}
        </div>
    `;

    features.forEach(f => {
        const pct = maxAbs > 0 ? (Math.abs(f.shap_value) / maxAbs) * 100 : 0;
        const isRisk = f.direction === 'increased_risk';
        const barColor = isRisk ? '#ef4444' : '#22c55e';
        const sign = f.shap_value >= 0 ? '+' : '';
        const label = f.feature.replace(/_/g, ' ');

        html += `
        <div style="margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px;">
                <span style="color:#374151;font-weight:500;">${label}</span>
                <span style="color:${barColor};font-weight:600;">${sign}${f.shap_value.toFixed(4)}</span>
            </div>
            <div style="background:#f3f4f6;border-radius:4px;height:10px;overflow:hidden;">
                <div style="width:${pct.toFixed(1)}%;height:100%;background:${barColor};border-radius:4px;
                            transition:width 0.4s ease;"></div>
            </div>
            <div style="font-size:11px;color:#9ca3af;margin-top:2px;">
                actual value: ${f.actual_value}
                &nbsp;|&nbsp;
                <span style="color:${isRisk ? '#ef4444' : '#22c55e'}">
                    ${isRisk ? '▲ increased detection probability' : '▼ decreased detection probability'}
                </span>
            </div>
        </div>
        `;
    });

    // Base value + prediction probability
    html += `
        <div style="margin-top:12px;padding:8px;background:#f9fafb;border-radius:6px;border:1px solid #e5e7eb;">
            <div style="display:flex;justify-content:space-between;font-size:11px;color:#6b7280;">
                <span>Base probability (dataset average): <strong>${(shapData.base_value * 100).toFixed(1)}%</strong></span>
                <span>Final predicted probability: <strong style="color:#1d4ed8;">${(shapData.predicted_probability * 100).toFixed(1)}%</strong></span>
            </div>
        </div>
    </div>
    `;

    container.innerHTML = html;
}


/**
 * Renders a global feature importance chart for the Model Evaluation page.
 * Uses batch SHAP results from /evaluation/shap-importance endpoint.
 */
function renderGlobalSHAPImportance(containerId, importanceData) {
    const container = document.getElementById(containerId);
    if (!container || !importanceData || importanceData.length === 0) return;

    const maxVal = Math.max(...importanceData.map(f => f.mean_abs_shap));

    let html = `
    <div style="margin-top:16px;">
        <div style="font-size:14px;font-weight:600;margin-bottom:4px;">
            Global Feature Importance (Mean |SHAP|)
        </div>
        <div style="font-size:12px;color:#888;margin-bottom:12px;">
            Average contribution of each feature across all detections
        </div>
    `;

    importanceData.forEach((f, idx) => {
        const pct = maxVal > 0 ? (f.mean_abs_shap / maxVal) * 100 : 0;
        const colors = ['#3b82f6', '#8b5cf6', '#f59e0b'];
        const color = colors[idx % colors.length];

        html += `
        <div style="margin-bottom:12px;">
            <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px;">
                <span style="font-weight:500;">#${f.rank} ${f.feature.replace(/_/g, ' ')}</span>
                <span style="color:${color};font-weight:600;">${f.mean_abs_shap.toFixed(4)}</span>
            </div>
            <div style="background:#f3f4f6;border-radius:4px;height:14px;overflow:hidden;">
                <div style="width:${pct.toFixed(1)}%;height:100%;background:${color};border-radius:4px;"></div>
            </div>
        </div>
        `;
    });

    html += `</div>`;
    container.innerHTML = html;
}


// ============================================================
// HOW TO USE IN YOUR INCIDENT MODAL (incidents.js)
// ============================================================
//
// 1. In your modal fetch, extract shap data:
//    const shapData = incident.proof?.shap_explanation;
//
// 2. Add a div to your modal HTML:
//    <div id="shap-chart-container"></div>
//
// 3. Call after modal opens:
//    renderSHAPChart('shap-chart-container', shapData);
//
// For Model Evaluation page:
//    fetch('/evaluation/shap-importance')
//      .then(r => r.json())
//      .then(data => renderGlobalSHAPImportance('global-shap-container', data));
// ============================================================
