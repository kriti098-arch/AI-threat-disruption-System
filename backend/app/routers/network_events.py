# app/routers/network_events.py
# UPGRADED — Phase 3: Session-Aware LLM + SHAP + Evasion Detection + Honeypot
import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app import schemas, crud
from app.detection.risk_scoring import map_risk_level
from app.database.db import get_db
from app.database.models import NetworkEvent, Incident
from app.schemas import NetworkEventCreate, NetworkEventResponse

# ---- Existing modules ----
from app.ml.stream_detector import StreamDetector
from app.security.global_risk import GlobalRiskManager
from app.security.attack_classifier import AttackClassifier
from app.security.threat_memory import ThreatMemory

# ---- Phase 2 modules ----
from app.ml.isolation_forest import IsolationForestDetector
from app.security.kill_chain import KillChainPredictor
from app.security.persona_engine import PersonaEngine
from app.security.confidence_scorer import ConfidenceScorer
from app.security.alert_fatigue import AlertFatigueManager

# ---- Phase 3 NEW modules (4 features) ----
# Feature 1: Session-Aware LLM  — replaces get_ai_threat_analysis
from app.security.ai_reasoning import get_session_aware_analysis

# Feature 2: SHAP Explainability
from app.security.shap_explainer import SHAPExplainer

# Feature 3: Adversarial Evasion Detection
from app.security.evasion_detector import EvasionDetector

# Feature 4: Honeypot Self-Improvement Loop
from app.security.honeypot import HoneypotManager

import numpy as np


# ─────────────────────────────────────────────────────────────
# Serialization helpers  (unchanged from your original)
# ─────────────────────────────────────────────────────────────
def convert_to_serializable(obj):
    if obj is ...:
        return None
    elif isinstance(obj, bool):
        return bool(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(i) for i in obj]
    elif hasattr(obj, '__dict__'):
        return convert_to_serializable(vars(obj))
    return obj


def safe_proof(data: dict) -> dict:
    """Guarantee JSON-safe dict."""
    return json.loads(json.dumps(convert_to_serializable(data), default=str))


# ─────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────
router = APIRouter(prefix="/network-events", tags=["Network Events"])

# ---- Existing singletons (unchanged) ----
detector      = StreamDetector()
global_risk   = GlobalRiskManager()
classifier    = AttackClassifier()
threat_memory = ThreatMemory()

# ---- Phase 2 singletons (unchanged) ----
if_detector    = IsolationForestDetector(min_samples=50)
kill_chain     = KillChainPredictor(history_window_minutes=30)
persona_engine = PersonaEngine(min_events_for_profile=5)
conf_scorer    = ConfidenceScorer()
fatigue_mgr    = AlertFatigueManager(window_minutes=10)

# ---- Phase 3 singletons (NEW) ----
shap_explainer  = SHAPExplainer()          # Feature 2
evasion_detector = EvasionDetector()       # Feature 3
honeypot        = HoneypotManager()        # Feature 4


# ─────────────────────────────────────────────────────────────
# MAIN EVENT HANDLER
# ─────────────────────────────────────────────────────────────
@router.post("/")
async def create_event(event: NetworkEventCreate, db: Session = Depends(get_db)):

    # ══════════════════════════════════════════════════════════
    # STEP 0 [NEW — FEATURE 4]: HONEYPOT CHECK
    # Runs before everything. Any hit = 100% confirmed attack.
    # Skips all ML steps and creates a CRITICAL incident immediately.
    # ══════════════════════════════════════════════════════════
    protocol_id = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(
        (event.protocol or "").upper(), 0
    )

    honeypot_result = honeypot.check_event(
        destination_port=getattr(event, "dst_port", 0) or 0,
        source_ip=event.src_ip,
        packet_length=event.packet_size or 0,
        protocol=event.protocol or "TCP",
    )

    if honeypot_result["honeypot_hit"]:
        # 100% confirmed — no ML needed
        risk_score = 10.0
        risk_level = map_risk_level(risk_score)

        incident_data = schemas.IncidentCreate(
            src_ip=event.src_ip,
            incident_type=honeypot_result["attack_type"],
            description=(
                f"HONEYPOT CONFIRMED: {honeypot_result['attack_type']} | "
                f"Service targeted: {honeypot_result['service_targeted']} | "
                f"Confidence: 100%"
            ),
            severity="CRITICAL",
            risk_score=risk_score,
            risk_level=risk_level,
        )
        hp_incident = crud.create_incident(db, incident_data)
        hp_incident.mitigation_status = "CONTAINED"
        hp_incident.proof = safe_proof({
            "honeypot":          honeypot_result,
            "detection_method":  "honeypot_confirmed",
            "confidence_pct":    100,
            "note":              "No ML needed — honeypot port hit is 100% confirmed attack",
        })
        db.commit()
        db.refresh(hp_incident)

        # Update global risk and store the raw event
        global_risk.update(True)
        db_event = NetworkEvent(
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            protocol=event.protocol,
            packet_size=event.packet_size,
            features={"honeypot_hit": True},
        )
        db.add(db_event)
        db.commit()

        return convert_to_serializable({
            "event_id":             db_event.event_id,
            "src_ip":               db_event.src_ip,
            "honeypot_confirmed":   True,
            "service_targeted":     honeypot_result["service_targeted"],
            "incident_id":          hp_incident.id,
            "retrain_triggered":    honeypot_result.get("retrain_triggered", False),
            "message":              honeypot_result["message"],
        })

    # ══════════════════════════════════════════════════════════
    # STEP 1: Z-score / EMA detection  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    detector.add_event(event.packet_size, event.src_ip)
    ml_result = detector.detect(event.src_ip)

    features         = {}
    db_ml_incident   = None
    anomaly_detected = False
    ai_analysis      = {}

    if ml_result:
        features   = ml_result.get("features", {})
        anomaly    = ml_result.get("anomaly", False)
        escalation = ml_result.get("escalation", False)
        z_score    = ml_result.get("score", 0)
    else:
        anomaly = escalation = False
        z_score = 0

    # ══════════════════════════════════════════════════════════
    # STEP 1.5 [NEW — FEATURE 3]: EVASION DETECTION
    # Record every event (even non-anomalous) for evasion tracking.
    # If this IP is a confirmed evader, force-flag it.
    # ══════════════════════════════════════════════════════════
    evasion_detector.record_event(
        source_ip=event.src_ip,
        z_score=float(z_score),
        packet_length=float(event.packet_size or 0),
    )

    # Force-flag override: confirmed evaders skip the Z-score threshold
    evasion_force_flag = evasion_detector.force_flag_check(event.src_ip)
    if evasion_force_flag:
        anomaly    = True
        escalation = True

    # Run periodic evasion analysis every 10 events for this IP
    ip_profile = evasion_detector.profiles.get(event.src_ip)
    evasion_result = {}
    if ip_profile and ip_profile.total_events % 10 == 0:
        evasion_result = evasion_detector.analyze(event.src_ip)
        # If evasion suspected, treat as anomaly even if Z-score is low
        if evasion_result.get("evasion_detected"):
            anomaly    = True
            escalation = True

    # ══════════════════════════════════════════════════════════
    # STEP 2: Isolation Forest  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    baseline = detector.get_baseline(event.src_ip)
    if_detector.add_sample(event.src_ip, event.packet_size, baseline)
    if_result  = if_detector.detect(event.src_ip, event.packet_size, baseline)
    if_anomaly = if_result.get("anomaly", False)
    if_score   = if_result.get("score", 0.0)

    # ══════════════════════════════════════════════════════════
    # STEP 3: Attack classification  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    attack_type = classifier.classify(features, z_score, escalation, current_size=event.packet_size)
    if attack_type == "Benign":
        attack_type = "Unknown Suspicious Activity"

    # ══════════════════════════════════════════════════════════
    # STEP 3.5 [NEW — FEATURE 2]: SHAP EXPLAINABILITY
    # Generate per-feature attribution for this classification.
    # Stored in proof so the frontend can render the SHAP chart.
    # ══════════════════════════════════════════════════════════
    shap_result = shap_explainer.explain(
        packet_length=float(event.packet_size or 0),
        port=int(getattr(event, "dst_port", 0) or 0),
        protocol_id=protocol_id,
    )

    # ══════════════════════════════════════════════════════════
    # STEP 4: Kill chain prediction  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    kc_result = kill_chain.update(event.src_ip, attack_type)

    # ══════════════════════════════════════════════════════════
    # STEP 5: Persona clustering  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    risk_for_persona = min(z_score * 10, 10.0)
    persona_engine.update_profile(event.src_ip, features, attack_type, risk_for_persona)
    persona_result = persona_engine.get_persona(event.src_ip)

    # ══════════════════════════════════════════════════════════
    # STEP 6: Confidence scoring  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    is_repeat           = threat_memory.is_repeat_offender(event.src_ip)
    persona_known       = persona_result.get("status") == "assigned"
    persona_coordinated = persona_result.get("is_coordinated", False)

    confidence = conf_scorer.score(
        ml_anomaly=anomaly,
        ml_score=z_score / 10,
        isolation_forest_anomaly=if_anomaly,
        isolation_forest_score=if_score,
        escalation_detected=escalation,
        kill_chain_stage=kc_result["current_stage"],
        kill_chain_progression_pct=kc_result["kill_chain_progression_pct"],
        is_repeat_offender=is_repeat,
        persona_is_known=persona_known,
        persona_is_coordinated=persona_coordinated,
        risk_score=risk_for_persona,
    )

    # ══════════════════════════════════════════════════════════
    # STEP 7: Create incident if anomaly detected  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    if anomaly and if_anomaly:
        anomaly_detected = True

        if z_score >= 4 or if_score >= 0.85:
            severity = "CRITICAL"
        elif z_score >= 3 or if_score >= 0.70:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        risk_score = round(max(z_score * 10, if_score * 10), 2)
        risk_level = map_risk_level(risk_score)

        # ══════════════════════════════════════════════════════
        # STEP 8: Alert fatigue  (YOUR ORIGINAL CODE)
        # ══════════════════════════════════════════════════════
        fatigue_result = fatigue_mgr.evaluate(
            event.src_ip, attack_type, severity, confidence["confidence_pct"]
        )

        if fatigue_result["should_show"]:

            incident_data = schemas.IncidentCreate(
                src_ip=event.src_ip,
                incident_type=attack_type,
                description=(
                    f"{attack_type} detected | "
                    f"Kill Chain: {kc_result['current_stage']} | "
                    f"Confidence: {confidence['confidence_pct']}%"
                ),
                severity=severity,
                risk_score=risk_score,
                risk_level=risk_level,
            )

            db_ml_incident = crud.create_incident(db, incident_data)
            threat_memory.update_score(event.src_ip, severity)

            if is_repeat:
                db_ml_incident.mitigation_status = "ISOLATED - Repeat Offender"

            # ══════════════════════════════════════════════════
            # STEP 9 [NEW — FEATURE 1]: SESSION-AWARE LLM REASONING
            # Replaces the old single-event get_ai_threat_analysis call.
            # Now sends the full attack session to Claude:
            #   — last 10 events from this IP
            #   — kill chain progression history
            #   — persona profile
            #   — global risk level
            # ══════════════════════════════════════════════════
            ai_analysis = await get_session_aware_analysis(
                db=db,
                src_ip=event.src_ip,
                attack_type=attack_type,
                severity=severity,
                risk_score=risk_score,
                confidence=confidence,
                kill_chain=kc_result,
                persona=persona_result,
                features=features,
                is_repeat_offender=is_repeat,
                z_score=z_score,
                if_score=if_score,
            )

            # ══════════════════════════════════════════════════
            # STEP 10: Auto-mitigation with enriched proof
            # All 4 new features now stored in proof dict.
            # Frontend reads these to render SHAP chart,
            # evasion badge, honeypot banner, session badge.
            # ══════════════════════════════════════════════════
            proof_core = {
                "kill_chain":        kc_result,
                "persona":           persona_result,
                "confidence":        confidence,
                "ai_analysis":       ai_analysis,           # Feature 1: session-aware
                "isolation_forest":  if_result,
                "alert_fatigue":     fatigue_result,
                "shap_explanation":  shap_result,           # Feature 2: SHAP
                "evasion_analysis":  evasion_result,        # Feature 3: evasion
                "honeypot":          {"hit": False},        # Feature 4: not a honeypot hit
                "detection_method":  "session_aware_ml_llm",
            }

            if evasion_force_flag:
                proof_core["evasion_force_flagged"] = True

            if severity in ["HIGH", "CRITICAL"] or escalation:
                db_ml_incident.mitigation_status = "CONTAINED"
                db_ml_incident.proof = safe_proof({
                    "before": features,
                    "after": {
                        "action_taken":           "Dynamic rate limiting + isolation",
                        "avg_packet_size_reduced": round(
                            features.get("avg_packet_size", 0) * 0.4, 2
                        ),
                        "escalation_blocked":     bool(escalation),
                        "network_state":          "Stabilized",
                    },
                    **proof_core,
                })
            else:
                db_ml_incident.proof = safe_proof({
                    "before": features,
                    **proof_core,
                })

            db.commit()
            db.refresh(db_ml_incident)

    # ══════════════════════════════════════════════════════════
    # STEP 11: Update global risk  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    system_risk = global_risk.update(anomaly_detected)

    # ══════════════════════════════════════════════════════════
    # STEP 12: Store network event  (YOUR ORIGINAL CODE)
    # ══════════════════════════════════════════════════════════
    db_event = NetworkEvent(
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        protocol=event.protocol,
        packet_size=event.packet_size,
        features=features,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    return convert_to_serializable({
        "event_id":              db_event.event_id,
        "src_ip":                db_event.src_ip,
        "dst_ip":                db_event.dst_ip,
        "protocol":              db_event.protocol,
        "packet_size":           db_event.packet_size,
        "features":              db_event.features,
        "timestamp":             str(db_event.timestamp),
        "system_risk":           system_risk,
        "kill_chain_stage":      kc_result["current_stage"],
        "kill_chain_prediction": kc_result["predicted_next_stages"],
        "confidence_pct":        confidence["confidence_pct"],
        "persona_id":            persona_result.get("persona_id"),
        "isolation_forest":      if_result,
        # NEW fields in response
        "evasion_suspected":     evasion_result.get("evasion_detected", False),
        "evasion_score":         evasion_result.get("evasion_score", 0.0),
        "shap_top_feature":      (shap_result or {}).get("top_features", [{}])[0].get("feature"),
        "session_events_used":   (ai_analysis or {}).get("session_event_count", 0)
                                 if anomaly_detected else 0,
    })


# ─────────────────────────────────────────────────────────────
# EXISTING ENDPOINTS  (all unchanged)
# ─────────────────────────────────────────────────────────────

@router.get("/stats")
def network_event_stats(db: Session = Depends(get_db)):
    return {
        "total_network_events": db.query(NetworkEvent).count(),
        "alert_stream_stats":   fatigue_mgr.get_stream_stats(),
    }

@router.get("/live")
def live_network_events(db: Session = Depends(get_db)):
    events = db.query(NetworkEvent).order_by(NetworkEvent.timestamp.desc()).limit(50).all()
    return [
        {
            "event_id":   e.event_id,
            "src_ip":     e.src_ip,
            "dst_ip":     e.dst_ip,
            "protocol":   e.protocol,
            "packet_size": e.packet_size,
            "features":   e.features,
            "timestamp":  e.timestamp,
        }
        for e in events
    ]

@router.get("/attack-distribution")
def attack_distribution(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    distribution = {}
    for inc in incidents:
        distribution[inc.incident_type] = distribution.get(inc.incident_type, 0) + 1
    return distribution

@router.get("/system-risk")
def get_system_risk():
    return {"system_risk": global_risk.get_level()}

@router.get("/top-threats")
def top_threats():
    return sorted(
        threat_memory.ip_scores.items(), key=lambda x: x[1], reverse=True
    )[:5]

@router.get("/personas")
def get_all_personas():
    return persona_engine.get_all_personas()

@router.get("/personas/{src_ip}")
def get_persona_for_ip(src_ip: str):
    return persona_engine.get_persona(src_ip)

@router.get("/kill-chain/{src_ip}")
def get_kill_chain_history(src_ip: str):
    return {"src_ip": src_ip, "history": kill_chain.get_history(src_ip)}

@router.get("/alert-fatigue")
def get_alert_fatigue_stats():
    return fatigue_mgr.get_stream_stats()


# ─────────────────────────────────────────────────────────────
# NEW ENDPOINTS  (Phase 3 features)
# ─────────────────────────────────────────────────────────────

@router.get("/evasion/suspects")
def get_evasion_suspects():
    """All IPs suspected of threshold-aware evasion."""
    return {
        "suspects": evasion_detector.get_all_evaders(),
        "total":    len(evasion_detector.get_all_evaders()),
    }

@router.get("/evasion/analyze/{src_ip}")
def analyze_evasion(src_ip: str):
    """On-demand evasion analysis for a specific IP."""
    result = evasion_detector.analyze(src_ip)
    result["src_ip"] = src_ip
    return result

@router.post("/evasion/reset/{src_ip}")
def reset_evasion(src_ip: str):
    """Clear evasion profile for an IP after manual review."""
    evasion_detector.reset_ip(src_ip)
    return {"message": f"Evasion profile cleared for {src_ip}"}

@router.get("/honeypot/stats")
def honeypot_stats():
    """Honeypot dashboard stats."""
    return honeypot.get_stats()

@router.get("/honeypot/hits")
def honeypot_hits(limit: int = 20):
    """Recent confirmed attacks captured by honeypot."""
    return {
        "hits":  honeypot.get_recent_hits(limit),
        "total": honeypot.get_stats()["total_confirmed_attacks"],
    }

@router.post("/honeypot/retrain")
def honeypot_retrain():
    """Manually trigger IF retraining with confirmed honeypot data."""
    return honeypot._retrain_isolation_forest()

@router.get("/honeypot/ports")
def honeypot_ports():
    """Active honeypot ports and their fake service names."""
    return {
        "ports": [
            {"port": p, "service": s}
            for p, s in honeypot.HONEYPOT_PORTS.items()
        ]
    }

@router.get("/shap/importance")
def shap_global_importance(db: Session = Depends(get_db)):
    """
    Global feature importance from SHAP across recent events.
    Used by the Model Evaluation page.
    """
    events = db.query(NetworkEvent).order_by(
        NetworkEvent.timestamp.desc()
    ).limit(200).all()

    if not events:
        return {"importance": [], "sample_size": 0}

    event_dicts = [
        {
            "packet_length":    e.packet_size or 0,
            "destination_port": (e.features or {}).get("dst_port", 0),
            "protocol_id":      {"TCP": 6, "UDP": 17, "ICMP": 1}.get(
                                    e.protocol or "", 0),
        }
        for e in events
    ]

    importance = shap_explainer.explain_batch(event_dicts)
    return {"importance": importance, "sample_size": len(events)}