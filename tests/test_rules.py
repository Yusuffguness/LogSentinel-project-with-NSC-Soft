import unittest
from datetime import datetime, timedelta

from logsentinel.models import LogEvent, Severity
from logsentinel.parsers import normalize_url
from logsentinel.rules import (
    find_bursts, SshBruteForceRule, SqlInjectionRule, SuccessAfterBruteForceRule,
)

BASE = datetime(2026, 1, 1, 0, 0, 0)


def ssh_fail(ip, secs, user="root"):
    return LogEvent(timestamp=BASE + timedelta(seconds=secs), source="ssh",
                    src_ip=ip, action="failed_password", user=user, raw="x")


def ssh_ok(ip, secs, user="root"):
    return LogEvent(timestamp=BASE + timedelta(seconds=secs), source="ssh",
                    src_ip=ip, action="accepted", user=user, raw="x")


def web(ip, path):
    return LogEvent(timestamp=BASE, source="web", src_ip=ip, action="request",
                    method="GET", path=path, norm_path=normalize_url(path), status=200, raw="x")


class TestFindBursts(unittest.TestCase):
    def test_burst_detected(self):
        evs = [ssh_fail("1.1.1.1", i * 10) for i in range(5)]
        self.assertEqual(len(find_bursts(evs, 5, timedelta(seconds=120))), 1)

    def test_no_burst_when_spread_out(self):
        evs = [ssh_fail("1.1.1.1", i * 60) for i in range(5)]
        self.assertEqual(len(find_bursts(evs, 5, timedelta(seconds=120))), 0)


class TestBruteForce(unittest.TestCase):
    def test_bruteforce_alert(self):
        evs = [ssh_fail("2.2.2.2", i * 5) for i in range(6)]
        alerts = SshBruteForceRule(threshold=5, window_seconds=120).evaluate(evs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "SSH-001")
        self.assertEqual(alerts[0].severity, Severity.HIGH)


class TestSqlInjection(unittest.TestCase):
    def test_detects_union_select(self):
        alerts = SqlInjectionRule().evaluate([web("3.3.3.3", "/p?id=1 UNION SELECT user,pass FROM users")])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "WEB-001")

    def test_clean_request_no_alert(self):
        self.assertEqual(len(SqlInjectionRule().evaluate([web("3.3.3.3", "/urunler?kategori=gozluk")])), 0)


class TestCorrelation(unittest.TestCase):
    def test_success_after_bruteforce_is_critical(self):
        evs = [ssh_fail("4.4.4.4", i * 5) for i in range(6)]
        evs.append(ssh_ok("4.4.4.4", 60))
        alerts = SuccessAfterBruteForceRule(min_failures=5, window_seconds=900).evaluate(evs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "COR-001")
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_no_correlation_without_success(self):
        evs = [ssh_fail("5.5.5.5", i * 5) for i in range(6)]
        self.assertEqual(len(SuccessAfterBruteForceRule().evaluate(evs)), 0)


if __name__ == "__main__":
    unittest.main()
