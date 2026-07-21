// js/live.js
function formatTimestamp(ts) {
  if (!ts) return '—';
  // Handle both "2026-03-13T14:11:10" and "2026-03-13 14:11:10" formats
  const normalized = ts.includes('T') ? ts + 'Z' : ts.replace(' ', 'T') + 'Z';
  const d = new Date(normalized);
  return d.toLocaleTimeString() + ' ' + d.toLocaleDateString();
}
async function loadLiveEvents() {
  const events = await fetchLiveEvents();
  const tbody = document.getElementById('liveEventsBody');
  if (!events || !events.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:30px;">No live traffic yet.</td></tr>';
    return;
  }
  tbody.innerHTML = events.map(e => `
    <tr>
      <td style="color:var(--cyan)">${e.src_ip}</td>
      <td>${e.dst_ip}</td>
      <td><span style="color:var(--text-dim);font-size:11px;">${e.protocol}</span></td>
      <td>${e.packet_size?.toLocaleString()} B</td>
      <td style="color:var(--text-dim);font-size:11px;">${formatTimestamp(e.timestamp)}</td>
    </tr>
  `).join('');
}

loadLiveEvents();
setInterval(loadLiveEvents, 5000);