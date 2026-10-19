"""Tespit motoru: olayları kurallardan geçirir, alarmları birleştirir ve
rapor için istatistik üretir."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from .models import Alert, LogEvent, Severity
from .rules import MultiStageAttackRule, build_rules

DEFAULT_CONFIG = {
    "whitelist": [],
    "ssh_bruteforce": {"threshold": 5, "window_seconds": 120},
    "ssh_user_enumeration": {"distinct_users": 4, "window_seconds": 600},
    "success_after_bruteforce": {"min_failures": 5, "window_seconds": 900},
    "web_directory_scan": {"threshold": 15, "window_seconds": 60},
}

"""JSON ayar dosyasını okur; dosyada olmayan ayarlar için varsayılanı kullanır."""
def load_config(path: str | Path | None) -> dict:

    config = json.loads(json.dumps(DEFAULT_CONFIG))  # derin kopya
    if path:
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        for key, value in user.items():
            if key.startswith("_"):          # "_aciklama" gibi yorum alanlarını atla
                continue
            if isinstance(value, dict) and isinstance(config.get(key), dict):
                config[key].update(value)
            else:
                config[key] = value
    return config


class DetectionEngine:
    def __init__(self, config: dict | None = None):
        self.config = config or load_config(None)
        self.whitelist = set(self.config.get("whitelist", []))
        self.rules = build_rules(self.config)
        self.correlator = MultiStageAttackRule()

    """Olayları analiz eder. Dönüş: (önem sırasına göre alarmlar, istatistikler)."""
    def analyze(self, events: list[LogEvent]) -> tuple[list[Alert], dict]:

        trusted = [e for e in events if e.src_ip in self.whitelist]
        events = sorted((e for e in events if e.src_ip not in self.whitelist), key=lambda e: e.timestamp)

        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(rule.evaluate(events))
        alerts.extend(self.correlator.evaluate(alerts))

        # Önce önem derecesi (yüksekten düşüğe), sonra zaman
        alerts.sort(key=lambda a: (-a.severity, a.first_seen))
        return alerts, self.statistics(events, alerts, len(trusted))

    @staticmethod
    def statistics(events: list[LogEvent], alerts: list[Alert], whitelisted: int) -> dict:
        hourly_ssh_fail = [0] * 24
        hourly_web_error = [0] * 24
        hourly_total = [0] * 24
        for e in events:
            hourly_total[e.timestamp.hour] += 1
            if e.source == "ssh" and e.action == "failed_password":
                hourly_ssh_fail[e.timestamp.hour] += 1
            elif e.source == "web" and e.status and e.status >= 400:
                hourly_web_error[e.timestamp.hour] += 1

        by_ip: dict[str, list[Alert]] = defaultdict(list)
        for a in alerts:
            by_ip[a.src_ip].append(a)
        top_ips = sorted(
            by_ip.items(),
            key=lambda kv: (-max(a.severity for a in kv[1]), -len(kv[1]), kv[0]),
        )

        dates = sorted({e.timestamp.date() for e in events})
        return {
            "event_count": len(events),
            "ssh_events": sum(1 for e in events if e.source == "ssh"),
            "web_events": sum(1 for e in events if e.source == "web"),
            "whitelisted": whitelisted,
            "unique_ips": len({e.src_ip for e in events}),
            "severity_counts": {s: sum(1 for a in alerts if a.severity == s) for s in Severity},
            "rule_counts": Counter(a.rule_id for a in alerts),
            "hourly_ssh_fail": hourly_ssh_fail,
            "hourly_web_error": hourly_web_error,
            "hourly_total": hourly_total,
            "top_ips": [
                {
                    "ip": ip,
                    "alerts": len(al),
                    "max_severity": max(a.severity for a in al),
                    "rules": sorted({a.rule_id for a in al}),
                    "events": sum(a.count for a in al if not a.rule_id.startswith("COR-002")),
                }
                for ip, al in top_ips
            ],
            "date_range": (dates[0], dates[-1]) if dates else None,
        }
