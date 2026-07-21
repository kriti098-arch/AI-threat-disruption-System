class ThreatMemory:

    def __init__(self):
        self.ip_scores = {}

    def update_score(self, src_ip: str, severity: str):
        weight = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 5
        }.get(severity, 1)

        self.ip_scores[src_ip] = self.ip_scores.get(src_ip, 0) + weight

    def get_score(self, src_ip: str):
        return self.ip_scores.get(src_ip, 0)

    def is_repeat_offender(self, src_ip: str):
        return self.get_score(src_ip) >= 8
