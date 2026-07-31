"""
spread_timestamps.py
---------------------
Run this AFTER seed_db.py. Rewrites all Incident timestamps to be spread
across a synthetic 24h window (today), instead of clustered in the few
minutes it took seed_db.py to run.

Preserves relative order: incidents keep the same before/after sequence
they were created in, so kill-chain progression still reads sensibly.
Does NOT touch attack_type, severity, proof, or anything else — timestamp
only.

HOW TO RUN:
    cd backend
    python spread_timestamps.py
"""

from datetime import datetime, timedelta, timezone
import random

from app.database.db import SessionLocal
from app.database.models import Incident

# Spread incidents across this window, ending "now"
WINDOW_HOURS = 24


def main():
    db = SessionLocal()
    try:
        incidents = (
            db.query(Incident)
            .order_by(Incident.timestamp.asc())
            .all()
        )

        if not incidents:
            print("No incidents found — run seed_db.py first.")
            return

        total = len(incidents)
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=WINDOW_HOURS)
        window_seconds = WINDOW_HOURS * 3600

        # Evenly space incidents across the window, then add jitter so
        # it doesn't look mechanically uniform, while keeping order intact.
        slot_size = window_seconds / total

        for i, incident in enumerate(incidents):
            slot_start = i * slot_size
            jitter = random.uniform(0, slot_size * 0.8)
            offset_seconds = slot_start + jitter
            new_timestamp = window_start + timedelta(seconds=offset_seconds)
            incident.timestamp = new_timestamp

        db.commit()
        print(f"Spread {total} incidents across the last {WINDOW_HOURS}h.")
        print(f"Earliest: {incidents[0].timestamp}")
        print(f"Latest:   {incidents[-1].timestamp}")

    finally:
        db.close()


if __name__ == "__main__":
    main()