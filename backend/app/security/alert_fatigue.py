# app/security/alert_fatigue.py
# ATDS — Adaptive Alert Fatigue Manager

from datetime import datetime, timedelta
from sqlalchemy.orm import Session

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
COOLDOWN_MINUTES     = 5
MIN_CONFIDENCE_PCT   = 30
MAX_LOW_SEV_PER_HOUR = 10
# ──────────────────────────────────────────────────────────────────────────────


class AlertFatigueManager:
    """
    Suppresses duplicate / low-value alerts.

    Methods used by network_events.py:
      - __init__(window_minutes=10)
      - evaluate(src_ip, attack_type, severity, confidence_pct) → dict with "should_show"
      - get_stream_stats() → dict for dashboard
      - get_stats(db)      → dict for DB-backed stats (optional)
    """

    def __init__(self, window_minutes=None, min_confidence=None, max_low_per_hour=None):
        self.cooldown_minutes     = window_minutes    or COOLDOWN_MINUTES
        self.min_confidence_pct   = min_confidence   or MIN_CONFIDENCE_PCT
        self.max_low_sev_per_hour = max_low_per_hour or MAX_LOW_SEV_PER_HOUR

        # In-memory tracking (no DB needed for stream stats)
        self._total_evaluated  = 0
        self._total_suppressed = 0
        self._total_demoted    = 0
        self._recent_ips: dict = {}   # src_ip → last_seen datetime

    # ─────────────────────────────────────────────────────────────────────────
    # PRIMARY METHOD — called as fatigue_mgr.evaluate(...) in network_events.py
    # ─────────────────────────────────────────────────────────────────────────
    def evaluate(
        self,
        src_ip: str,
        attack_type: str,
        severity: str,
        confidence_pct: float,
    ) -> dict:
        """
        Decide whether an incident should be shown or suppressed.

        Returns:
            {
                "should_show":  bool,   # True = surface in dashboard
                "suppress":     bool,   # True = suppressed
                "reason":       str,
                "demoted":      bool,
                "original_sev": str,
            }
        """
        self._total_evaluated += 1
        now = datetime.utcnow()

        result = {
            "should_show":  True,
            "suppress":     False,
            "reason":       "passed",
            "demoted":      False,
            "original_sev": severity,
        }

        # ── Rule 1: Recency cooldown (in-memory) ─────────────────────────
        last_seen = self._recent_ips.get(src_ip)
        if last_seen:
            age_seconds = (now - last_seen).total_seconds()
            if age_seconds < self.cooldown_minutes * 60:
                self._total_suppressed += 1
                result["should_show"] = False
                result["suppress"]    = True
                result["reason"]      = (
                    f"Cooldown: {src_ip} seen {int(age_seconds)}s ago "
                    f"(cooldown={self.cooldown_minutes}min)"
                )
                return result

        # ── Rule 2: Confidence threshold ─────────────────────────────────
        if confidence_pct < self.min_confidence_pct:
            self._total_suppressed += 1
            result["should_show"] = False
            result["suppress"]    = True
            result["reason"]      = (
                f"Low confidence: {confidence_pct:.1f}% < "
                f"minimum {self.min_confidence_pct}%"
            )
            return result

        # ── Rule 3: Low-severity rate limit (in-memory count) ────────────
        if severity == "LOW":
            one_hour_ago   = now - timedelta(hours=1)
            # Count recent LOW events for this IP from in-memory store
            low_count = sum(
                1 for ip, ts in self._recent_ips.items()
                if ip == src_ip and ts >= one_hour_ago
            )
            if low_count >= self.max_low_sev_per_hour:
                self._total_suppressed += 1
                result["should_show"] = False
                result["suppress"]    = True
                result["reason"]      = (
                    f"Rate-limited: {low_count} LOW alerts from "
                    f"{src_ip} in last hour (max {self.max_low_sev_per_hour})"
                )
                return result

        # ── Demotion check ────────────────────────────────────────────────
        if (
            confidence_pct < self.min_confidence_pct + 10
            and severity in ("CRITICAL", "HIGH")
        ):
            self._total_demoted += 1
            result["demoted"] = True
            result["reason"]  = (
                f"Demoted: confidence {confidence_pct:.1f}% is borderline — "
                f"severity downgraded from {severity} to LOW"
            )

        # ── Mark as seen ──────────────────────────────────────────────────
        self._recent_ips[src_ip] = now

        # Prune old entries (keep memory bounded)
        cutoff = now - timedelta(hours=2)
        self._recent_ips = {
            ip: ts for ip, ts in self._recent_ips.items() if ts >= cutoff
        }

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # STREAM STATS — called as fatigue_mgr.get_stream_stats() in network_events.py
    # ─────────────────────────────────────────────────────────────────────────
    def get_stream_stats(self) -> dict:
        """
        In-memory stats for the dashboard /alert-fatigue endpoint
        and the sidebar SUPPRESSION / STREAM counters.
        """
        rate = (
            round(self._total_suppressed / self._total_evaluated * 100, 1)
            if self._total_evaluated > 0
            else 0.0
        )
        return {
            "total_evaluated":    self._total_evaluated,
            "total_suppressed":   self._total_suppressed,
            "total_demoted":      self._total_demoted,
            "suppression_rate":   rate,
            "active_ips_tracked": len(self._recent_ips),
            "cooldown_minutes":   self.cooldown_minutes,
            "min_confidence":     self.min_confidence_pct,
            "max_low_per_hour":   self.max_low_sev_per_hour,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # DB-BACKED STATS — optional, used if anything calls get_stats(db)
    # ─────────────────────────────────────────────────────────────────────────
    def get_stats(self, db: Session) -> dict:
        """DB-backed version of stats (24h window)."""
        from app.database.models import Incident
        import json

        now   = datetime.utcnow()
        since = now - timedelta(hours=24)

        all_recent = (
            db.query(Incident)
            .filter(Incident.timestamp >= since)
            .all()
        )

        total      = len(all_recent)
        suppressed = 0
        demoted    = 0

        for inc in all_recent:
            proof = inc.proof or {}
            if isinstance(proof, str):
                try:
                    proof = json.loads(proof)
                except Exception:
                    proof = {}
            fatigue = proof.get("alert_fatigue", {})
            if isinstance(fatigue, dict):
                if fatigue.get("suppress"):
                    suppressed += 1
                if fatigue.get("demoted"):
                    demoted += 1

        suppression_rate = round((suppressed / total * 100), 1) if total > 0 else 0.0

        return {
            "total_24h":        total,
            "suppressed_24h":   suppressed,
            "demoted_24h":      demoted,
            "suppression_rate": suppression_rate,
            "cooldown_minutes": self.cooldown_minutes,
            "min_confidence":   self.min_confidence_pct,
            "max_low_per_hour": self.max_low_sev_per_hour,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # ALIAS — in case anything calls .check() directly
    # ─────────────────────────────────────────────────────────────────────────
    def check(self, db, src_ip, severity, confidence_pct):
        return self.evaluate(src_ip, "", severity, confidence_pct)


# ── Module-level convenience functions ───────────────────────────────────────
def check_alert_fatigue(db, src_ip, severity, confidence_pct):
    return AlertFatigueManager().evaluate(src_ip, "", severity, confidence_pct)

def get_fatigue_stats(db):
    return AlertFatigueManager().get_stats(db)