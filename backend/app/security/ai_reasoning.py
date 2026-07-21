# app/security/ai_reasoning.py
# UPGRADED — Phase 3: Session-Aware LLM Reasoning
#
# WHAT CHANGED:
# Added get_session_aware_analysis() which wraps your existing
# get_ai_threat_analysis() but enriches the prompt with the full
# attack session context before calling Claude.
#
# Your original get_ai_threat_analysis() is kept below untouched
# so nothing else in your codebase breaks.

import anthropic
from sqlalchemy.orm import Session
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env")

client = anthropic.Anthropic()


# ─────────────────────────────────────────────────────────────
# SESSION CONTEXT BUILDER
# ─────────────────────────────────────────────────────────────
def _build_session_context(db: Session, src_ip: str) -> dict:
    """
    Fetch the full attack session for this IP from the database.
    Returns the last 10 events + past incident history.
    """
    try:
        from app.database.models import NetworkEvent, Incident

        # Last 10 raw events from this IP
        recent_events = (
            db.query(NetworkEvent)
            .filter(NetworkEvent.src_ip == src_ip)
            .order_by(NetworkEvent.timestamp.desc())
            .limit(10)
            .all()
        )

        # Past incidents from this IP (kill chain history)
        past_incidents = (
            db.query(Incident)
            .filter(Incident.src_ip == src_ip)
            .order_by(Incident.timestamp.desc())
            .limit(5)
            .all()
        )

        # Build timeline string
        timeline_lines = []
        for ev in reversed(recent_events):
            timeline_lines.append(
                f"  [{str(ev.timestamp)[:19]}] "
                f"proto={ev.protocol} "
                f"size={ev.packet_size}b"
            )

        # Build kill chain history string
        kc_lines = []
        seen = set()
        for inc in past_incidents:
            stage = (inc.proof or {}).get("kill_chain", {}).get("current_stage", "Unknown") \
                    if isinstance(inc.proof, dict) else "Unknown"
            if stage not in seen:
                kc_lines.append(f"  - {stage} ({inc.incident_type})")
                seen.add(stage)

        # Session stats
        packet_sizes = [e.packet_size for e in recent_events if e.packet_size]
        avg_size = round(sum(packet_sizes) / len(packet_sizes), 1) if packet_sizes else 0

        return {
            "event_count":       len(recent_events),
            "past_incidents":    len(past_incidents),
            "avg_packet_size":   avg_size,
            "timeline":          "\n".join(timeline_lines) or "  No prior events.",
            "kill_chain_history": "\n".join(kc_lines) or "  No prior kill chain stages.",
        }

    except Exception:
        return {
            "event_count": 0,
            "past_incidents": 0,
            "avg_packet_size": 0,
            "timeline": "  Session data unavailable.",
            "kill_chain_history": "  No history.",
        }


# ─────────────────────────────────────────────────────────────
# NEW: SESSION-AWARE ANALYSIS  (Feature 1)
# Called from network_events.py Step 9
# ─────────────────────────────────────────────────────────────
async def get_session_aware_analysis(
    db: Session,
    src_ip: str,
    attack_type: str,
    severity: str,
    risk_score: float,
    confidence: dict,
    kill_chain: dict,
    persona: dict,
    features: dict,
    is_repeat_offender: bool,
    z_score: float = 0,
    if_score: float = 0,
) -> dict:
    """
    Session-aware Claude analysis.

    Fetches the full attack session from the DB and builds
    a rich prompt so Claude reasons about the ENTIRE attack,
    not just the single current event.

    Returns a dict that slots directly into your proof["ai_analysis"].
    """

    # Fetch session context from DB
    session = _build_session_context(db, src_ip)

    # Determine threat level label
    if severity == "CRITICAL" or confidence.get("confidence_pct", 0) >= 85:
        threat_label = "CRITICAL"
    elif severity == "HIGH":
        threat_label = "HIGH"
    else:
        threat_label = "MEDIUM"

    prompt = f"""You are a senior cybersecurity analyst reviewing a network intrusion alert.
You have been given the FULL attack session — not just one packet.
Analyze the complete picture and provide concise, actionable intelligence.

═══ CURRENT INCIDENT ═══════════════════════════════════════════
Source IP     : {src_ip}
Attack Type   : {attack_type}
Severity      : {severity}
Confidence    : {confidence.get('confidence_pct', 0)}%
Kill Chain    : {kill_chain.get('current_stage', 'Unknown')}
Next Predicted: {', '.join(kill_chain.get('predicted_next_stages', [])) or 'None'}
Z-Score       : {round(z_score, 3)}
IF Score      : {round(if_score, 3)}
Repeat IP     : {'YES — known threat actor' if is_repeat_offender else 'No'}

═══ FULL ATTACK SESSION ({session['event_count']} prior events) ═════════════
Avg Packet Size    : {session['avg_packet_size']} bytes
Past Incidents     : {session['past_incidents']}

Recent event timeline:
{session['timeline']}

Kill chain progression across session:
{session['kill_chain_history']}

═══ ATTACKER PROFILE ═══════════════════════════════════════════
Persona       : {persona.get('persona_id', 'Unknown')} — {persona.get('behavior_summary', '')}
Coordinated   : {'YES' if persona.get('is_coordinated') else 'No'}

═══ YOUR ANALYSIS (max 200 words) ══════════════════════════════
Based on the FULL SESSION above, provide:

1. SESSION NARRATIVE (2-3 sentences): What is this attacker doing
   across their entire session? What is the likely end goal?

2. THREAT LEVEL: {threat_label} — confirm or revise and explain why
   the session as a whole justifies this rating.

3. IMMEDIATE ACTIONS (exactly 3 bullet points):
   • Action 1
   • Action 2
   • Action 3

4. PREDICTED ESCALATION: Most likely next step in next 5-15 minutes.

Keep response under 200 words. Reference actual data from the session above.
"""

    try:
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
        )
        narrative = response.content[0].text

        # Detect threat level from response
        detected_level = threat_label
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if level in narrative.upper():
                detected_level = level
                break

        return {
            "narrative":                narrative,
            "threat_level":             detected_level,
            "session_event_count":      session["event_count"],
            "session_past_incidents":   session["past_incidents"],
            "reasoning_type":           "session_aware",
            "model":                    "claude-opus-4-5",
        }

    except Exception as e:
        # Graceful fallback — never crash the pipeline
        return {
            "narrative":           f"Session-aware analysis unavailable: {e}",
            "threat_level":        threat_label,
            "session_event_count": session["event_count"],
            "reasoning_type":      "session_aware",
            "error":               str(e),
        }


# ─────────────────────────────────────────────────────────────
# ORIGINAL FUNCTION — kept intact, nothing broke
# ─────────────────────────────────────────────────────────────
async def get_ai_threat_analysis(
    src_ip: str,
    attack_type: str,
    severity: str,
    risk_score: float,
    confidence: dict,
    kill_chain: dict,
    persona: dict,
    features: dict,
    is_repeat_offender: bool,
) -> dict:
    """
    Original single-event Claude analysis.
    Kept here so any other code that imports it still works.
    network_events.py now calls get_session_aware_analysis instead.
    """
    prompt = f"""Analyze this cybersecurity threat:
IP: {src_ip} | Attack: {attack_type} | Severity: {severity}
Risk: {risk_score} | Confidence: {confidence.get('confidence_pct', 0)}%
Kill Chain Stage: {kill_chain.get('current_stage', 'Unknown')}
Repeat Offender: {is_repeat_offender}

Provide: 1) Threat assessment 2) Attack explanation 3) Recommended actions.
Keep under 150 words."""

    try:
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return {
            "narrative":      response.content[0].text,
            "reasoning_type": "single_event",
            "model":          "claude-opus-4-5",
        }
    except Exception as e:
        return {
            "narrative":      f"AI analysis unavailable: {e}",
            "reasoning_type": "single_event",
            "error":          str(e),
        }


