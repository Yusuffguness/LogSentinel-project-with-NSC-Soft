import unittest
from datetime import datetime, timedelta

from logsentinel.models import LogEvent
from logsentinel.engine import DetectionEngine, load_config

BASE = datetime(2026, 1, 1, 0, 0, 0)


def bruteforce_events(ip, n=6, step=5):
    return [LogEvent(timestamp=BASE + timedelta(seconds=i * step), source="ssh",
                     src_ip=ip, action="failed_password", user="root", raw="x") for i in range(n)]


class TestEngine(unittest.TestCase):
    def test_analyze_produces_bruteforce_alert(self):
        engine = DetectionEngine(load_config(None))
        alerts, stats = engine.analyze(bruteforce_events("9.9.9.9"))
        self.assertTrue(any(a.rule_id == "SSH-001" for a in alerts))
        self.assertEqual(stats["event_count"], 6)

    def test_alerts_sorted_by_severity(self):
        engine = DetectionEngine(load_config(None))
        alerts, _ = engine.analyze(bruteforce_events("8.8.8.8", n=20))
        severities = [a.severity for a in alerts]
        self.assertEqual(severities, sorted(severities, reverse=True))

    def test_whitelist_excludes_ip(self):
        config = load_config(None)
        config["whitelist"] = ["1.2.3.4"]
        engine = DetectionEngine(config)
        alerts, stats = engine.analyze(bruteforce_events("1.2.3.4"))
        self.assertEqual(len(alerts), 0)
        self.assertEqual(stats["event_count"], 0)


if __name__ == "__main__":
    unittest.main()
