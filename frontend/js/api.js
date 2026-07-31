// js/api.js
const API = window.location.origin;

async function apiFetch(path) {
  try {
    const res = await fetch(API + path);
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

const fetchStats         = () => apiFetch('/network-events/stats');
const fetchIncidents     = () => apiFetch('/incidents/');
const fetchLiveEvents    = () => apiFetch('/network-events/live');
const fetchSystemRisk    = () => apiFetch('/network-events/system-risk');
const fetchTopThreats    = () => apiFetch('/network-events/top-threats');
const fetchAttackDist    = () => apiFetch('/network-events/attack-distribution');
const fetchAlertFatigue  = () => apiFetch('/network-events/alert-fatigue');
const fetchAllPersonas   = () => apiFetch('/network-events/personas');
const fetchKillChain     = (ip) => apiFetch(`/network-events/kill-chain/${encodeURIComponent(ip)}`);
const fetchPersonaForIP  = (ip) => apiFetch(`/network-events/personas/${encodeURIComponent(ip)}`);
const fetchEvalSummary   = () => apiFetch('/evaluation/summary');
const fetchConfMatrix    = (model) => apiFetch(`/evaluation/confusion-matrix/${model}`);