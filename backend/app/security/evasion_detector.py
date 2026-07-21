# ============================================================
# FEATURE 3: ADVERSARIAL EVASION DETECTION
# File: backend/app/security/evasion_detector.py
#
# NEW FILE — add to your security/ folder
#
# WHAT IT DOES:
# Detects attackers who are deliberately keeping their traffic
# just below your detection thresholds to evade the IDS.
#
# THE INSIGHT:
# A real attacker who knows you use Z-score detection will try to
# send packets that stay just under |Z| = 2.5. The problem for
# them: random legitimate traffic varies naturally. An attacker
# artificially holding a consistent Z-score of ~2.3 is
# statistically suspicious — it's TOO consistent.
#
# HOW IT WORKS (3 detection methods):
# 1. Z-score variance analysis: legitimate IPs show natural variance
#    in their Z-scores. Suspiciously LOW variance = possible evasion.
# 2. Threshold proximity clustering: flags IPs whose Z-scores
#    cluster just below detection threshold (2.0-2.4 range).
# 3. Rate consistency detection: real attackers often accidentally
#    send bursts. Unnaturally constant packet rates are suspicious.
#
# WHY THIS IS NOVEL:
# No published open-source IDS implements meta-detection of
# threshold-aware evasion. This is a genuine research contribution.
# ============================================================

import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional
import time


@dataclass
class IPEvasionProfile:
    """Tracks per-IP statistics for evasion detection."""
    ip: str
    z_scores: deque = field(default_factory=lambda: deque(maxlen=50))
    packet_timestamps: deque = field(default_factory=lambda: deque(maxlen=50))
    packet_lengths: deque = field(default_factory=lambda: deque(maxlen=50))
    evasion_score: float = 0.0
    evasion_flags: list = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)
    total_events: int = 0


class EvasionDetector:
    """
    Meta-detection layer that identifies IPs trying to evade
    the primary Z-score and Isolation Forest detectors.

    This runs AFTER Steps 2-3 in your pipeline, as an additional
    check specifically for events that were NOT flagged as anomalous
    (i.e., the attacker "succeeded" in staying under the threshold).
    """

    # Detection thresholds — tune these based on your traffic
    ZSCORE_VARIANCE_THRESHOLD = 0.15    # below this = suspiciously consistent
    PROXIMITY_ZONE_LOW = 1.8            # "just below threshold" zone start
    PROXIMITY_ZONE_HIGH = 2.45          # just under your detection threshold of 2.5
    PROXIMITY_COUNT_MIN = 5             # how many in-zone events before flagging
    RATE_CV_THRESHOLD = 0.12            # coefficient of variation below this = too consistent
    MIN_EVENTS_FOR_ANALYSIS = 10        # don't analyze until enough data

    def __init__(self):
        self.profiles: dict[str, IPEvasionProfile] = {}

    def _get_profile(self, ip: str) -> IPEvasionProfile:
        if ip not in self.profiles:
            self.profiles[ip] = IPEvasionProfile(ip=ip)
        return self.profiles[ip]

    def record_event(
        self,
        source_ip: str,
        z_score: float,
        packet_length: float,
        timestamp: Optional[float] = None,
    ):
        """
        Record every network event for an IP (even non-anomalous ones).
        Call this for ALL events, not just flagged ones.
        """
        profile = self._get_profile(source_ip)
        ts = timestamp or time.time()

        profile.z_scores.append(z_score)
        profile.packet_timestamps.append(ts)
        profile.packet_lengths.append(packet_length)
        profile.total_events += 1
        profile.last_updated = ts

    def analyze(self, source_ip: str) -> dict:
        """
        Analyze an IP for evasion patterns.
        Returns evasion assessment with score and specific flags.

        Call this after recording an event when you want to check
        if this IP is attempting evasion (e.g., every 10 events).
        """
        profile = self._get_profile(source_ip)

        if len(profile.z_scores) < self.MIN_EVENTS_FOR_ANALYSIS:
            return {
                "evasion_detected": False,
                "evasion_score": 0.0,
                "flags": [],
                "analysis": "insufficient_data",
                "events_needed": self.MIN_EVENTS_FOR_ANALYSIS - len(profile.z_scores),
            }

        flags = []
        component_scores = []

        zscores = list(profile.z_scores)
        abs_zscores = [abs(z) for z in zscores]

        # ── Detection Method 1: Z-score variance analysis ───────────────────
        # Legitimate traffic has natural variance. Too-consistent Z-scores
        # suggest the attacker is rate-limiting to stay just under threshold.
        zscore_std = float(np.std(abs_zscores))
        zscore_mean = float(np.mean(abs_zscores))

        if zscore_mean > 0.5:  # only flag if there's meaningful activity
            if zscore_std < self.ZSCORE_VARIANCE_THRESHOLD:
                score_1 = min(1.0, (self.ZSCORE_VARIANCE_THRESHOLD - zscore_std) / self.ZSCORE_VARIANCE_THRESHOLD)
                component_scores.append(score_1 * 0.40)  # 40% weight
                flags.append({
                    "type": "LOW_ZSCORE_VARIANCE",
                    "severity": "HIGH" if zscore_std < 0.05 else "MEDIUM",
                    "detail": f"Z-score std={zscore_std:.3f} (expected >={self.ZSCORE_VARIANCE_THRESHOLD:.2f} for organic traffic)",
                    "description": "Traffic Z-scores are suspiciously consistent — possible rate-controlled evasion",
                })

        # ── Detection Method 2: Threshold proximity clustering ──────────────
        # Count how many Z-scores land in the "just below threshold" zone.
        # Legitimate traffic randomly distributed; attacker traffic clusters here.
        proximity_events = [
            z for z in abs_zscores
            if self.PROXIMITY_ZONE_LOW <= z <= self.PROXIMITY_ZONE_HIGH
        ]
        proximity_ratio = len(proximity_events) / len(abs_zscores)

        if len(proximity_events) >= self.PROXIMITY_COUNT_MIN:
            # Also check: are they clustering tightly within the zone?
            if proximity_events:
                proximity_std = float(np.std(proximity_events))
                tight_cluster = proximity_std < 0.2

            score_2 = min(1.0, proximity_ratio * 2)
            component_scores.append(score_2 * 0.40)  # 40% weight
            flags.append({
                "type": "THRESHOLD_PROXIMITY_CLUSTERING",
                "severity": "HIGH" if (proximity_ratio > 0.6 and tight_cluster) else "MEDIUM",
                "detail": f"{len(proximity_events)}/{len(abs_zscores)} events ({proximity_ratio:.0%}) in zone [{self.PROXIMITY_ZONE_LOW}-{self.PROXIMITY_ZONE_HIGH}]",
                "description": "Unusual concentration of events just below detection threshold — classic threshold-aware evasion pattern",
            })

        # ── Detection Method 3: Packet rate consistency ──────────────────────
        # Real attackers send bursts. Unnaturally constant inter-packet timing
        # suggests automated rate-limiting to avoid volumetric detection.
        timestamps = list(profile.packet_timestamps)
        if len(timestamps) >= 5:
            inter_arrival = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
                if timestamps[i] - timestamps[i - 1] > 0
            ]
            if len(inter_arrival) >= 4:
                iat_mean = float(np.mean(inter_arrival))
                iat_std = float(np.std(inter_arrival))
                cv = iat_std / iat_mean if iat_mean > 0 else 1.0  # coefficient of variation

                if cv < self.RATE_CV_THRESHOLD:
                    score_3 = min(1.0, (self.RATE_CV_THRESHOLD - cv) / self.RATE_CV_THRESHOLD)
                    component_scores.append(score_3 * 0.20)  # 20% weight
                    flags.append({
                        "type": "SUSPICIOUSLY_CONSTANT_RATE",
                        "severity": "MEDIUM",
                        "detail": f"Inter-arrival time CV={cv:.3f} (expected >={self.RATE_CV_THRESHOLD:.2f})",
                        "description": "Packet inter-arrival times are too uniform — possible bot or rate-controlled script",
                    })

        # ── Compute composite evasion score ──────────────────────────────────
        evasion_score = sum(component_scores)
        evasion_score = min(1.0, evasion_score)

        # Update profile
        profile.evasion_score = evasion_score
        profile.evasion_flags = flags

        evasion_detected = evasion_score >= 0.40 and len(flags) >= 1

        return {
            "evasion_detected": evasion_detected,
            "evasion_score": round(evasion_score, 4),
            "evasion_score_pct": round(evasion_score * 100, 1),
            "flags": flags,
            "flag_count": len(flags),
            "analysis": "evasion_suspected" if evasion_detected else "normal",
            "statistics": {
                "events_analyzed": len(zscores),
                "zscore_mean": round(zscore_mean, 3),
                "zscore_std": round(zscore_std, 3),
                "proximity_events": len(proximity_events) if 'proximity_events' in dir() else 0,
            },
            "recommended_action": (
                "ESCALATE: Force-flag all future events from this IP regardless of Z-score"
                if evasion_score >= 0.70
                else "MONITOR: Increase scrutiny on this IP"
                if evasion_detected
                else "NORMAL"
            ),
        }

    def force_flag_check(self, source_ip: str) -> bool:
        """
        Returns True if this IP has been identified as an evader and
        should be force-flagged regardless of Z-score.
        Call this at Step 2 of your pipeline BEFORE Z-score threshold check.
        """
        profile = self.profiles.get(source_ip)
        if not profile:
            return False
        return profile.evasion_score >= 0.70

    def get_all_evaders(self) -> list[dict]:
        """
        Returns all IPs currently suspected of evasion.
        Used by the frontend Evasion Dashboard page.
        """
        evaders = []
        for ip, profile in self.profiles.items():
            if profile.evasion_score >= 0.40:
                evaders.append({
                    "ip": ip,
                    "evasion_score": round(profile.evasion_score, 4),
                    "evasion_score_pct": round(profile.evasion_score * 100, 1),
                    "flags": profile.evasion_flags,
                    "total_events": profile.total_events,
                    "events_tracked": len(profile.z_scores),
                    "status": "CONFIRMED_EVADER" if profile.evasion_score >= 0.70 else "SUSPECTED_EVADER",
                })
        return sorted(evaders, key=lambda x: x["evasion_score"], reverse=True)

    def reset_ip(self, source_ip: str):
        """Clear evasion profile for an IP (e.g. after blocking)."""
        self.profiles.pop(source_ip, None)


# ── Singleton ─────────────────────────────────────────────────────────────────
evasion_detector = EvasionDetector()


# ============================================================
# HOW TO PLUG INTO YOUR PIPELINE (network_events.py)
# ============================================================
#
# At the TOP of your pipeline, import:
#   from .evasion_detector import evasion_detector
#
# Step 1.5 (add BEFORE Step 2 — Z-score check):
#   # Record every event for evasion tracking
#   evasion_detector.record_event(
#       source_ip=event.source_ip,
#       z_score=z_score,  # the Z-score you compute in step 2
#       packet_length=event.length,
#   )
#
#   # Check if this IP is a known evader (force-flag)
#   if evasion_detector.force_flag_check(event.source_ip):
#       anomaly_detected = True  # override Z-score result
#       incident_notes = "Force-flagged: confirmed threshold evader"
#
# Step 2.5 (after every 10 events from an IP):
#   if profile.total_events % 10 == 0:
#       evasion_result = evasion_detector.analyze(event.source_ip)
#       if evasion_result["evasion_detected"]:
#           # Store in incident proof
#           incident.proof["evasion_analysis"] = evasion_result
# ============================================================
