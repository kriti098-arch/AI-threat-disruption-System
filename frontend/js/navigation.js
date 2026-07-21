// js/navigation.js
function showSection(name) {
  document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));

  document.getElementById(name)?.classList.add('active');
  event.currentTarget.classList.add('active');

  if (name === 'personas')   loadPersonas();
  if (name === 'evaluation') loadEvaluation();
}

async function lookupKillChain() {
  const ip = document.getElementById('kcIpInput').value.trim();
  if (!ip) return;

  const data = await fetchKillChain(ip);
  const el = document.getElementById('kcResult');

  if (!data || !data.history || !data.history.length) {
    el.innerHTML = `<div style="color:var(--text-dim);">No kill chain history found for <span style="color:var(--cyan)">${ip}</span></div>`;
    el.classList.remove('hidden');
    return;
  }

  const last = data.history[data.history.length - 1];
  el.innerHTML = `
    <div style="margin-bottom:12px;">
      <span style="font-size:9px;color:var(--text-dim);letter-spacing:2px;">IP: </span>
      <span style="color:var(--cyan)">${ip}</span>
      <span style="margin-left:16px;font-size:9px;color:var(--text-dim);">${data.history.length} STAGE EVENTS</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;">
      ${data.history.map(h => `
        <div style="padding:6px 12px;background:var(--bg3);border:1px solid var(--border2);font-size:11px;">
          <span style="color:var(--orange)">${h.stage}</span>
          <span style="color:var(--text-dim);font-size:10px;margin-left:8px;">${new Date(h.timestamp).toLocaleTimeString()}</span>
        </div>
      `).join('')}
    </div>
    <div style="margin-top:12px;padding:10px 12px;background:var(--bg3);border-left:3px solid var(--orange);font-size:12px;color:var(--text-dim);">
      Last recorded stage: <span style="color:var(--orange);font-weight:bold;">${last.stage}</span>
    </div>
  `;
  el.classList.remove('hidden');
}

// Close modal on backdrop click
document.getElementById('incidentModal').addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});