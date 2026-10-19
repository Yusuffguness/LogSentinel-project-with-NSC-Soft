"""Tespit kuralları.

Her kural, normalize edilmiş olay listesini (LogEvent) inceler ve bulduğu
şüpheli durumlar için Alert listesi döndürür. Kurallar iki türlüdür:

  * Eşik/zaman penceresi kuralları: "X saniye içinde aynı IP'den N olay"
    (ör. SSH kaba kuvvet, dizin taraması)
  * İmza (desen) kuralları: olayın içeriğinde bilinen bir saldırı deseni
    aranır (ör. SQL injection, XSS)

Her kural MITRE ATT&CK çerçevesindeki ilgili teknikle eşleştirilmiştir.
"""
from __future__ import annotations

import re
from bisect import bisect_left
from collections import Counter, defaultdict
from datetime import timedelta

from .models import Alert, LogEvent, Severity

MAX_EVIDENCE = 5  # Alarm başına gösterilecek en fazla kanıt satırı



# Yardımcı fonksiyonlar

def group_by_ip(events: list[LogEvent]) -> dict[str, list[LogEvent]]:
    """Olayları kaynak IP'ye göre gruplar (zaman sırası korunur)."""
    groups: dict[str, list[LogEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda e: e.timestamp):
        groups[event.src_ip].append(event)
    return groups


def find_bursts(events: list[LogEvent], threshold: int, window: timedelta) -> list[tuple[int, int]]:
    """Kayan zaman penceresi (sliding window) ile "patlamaları" bulur.

    Zaman sırasındaki olaylar üzerinde iki işaretçi (start, end) gezdirilir.
    Pencere [start..end] süresi `window`'u aşınca start ileri kaydırılır.
    Pencerede `threshold` veya daha fazla olay varsa bu bir patlamadır.

    Birbiriyle çakışan pencereler tek bir patlama olarak birleştirilir; böylece
    40 denemelik bir saldırı için 36 ayrı alarm değil, tek bir alarm üretilir.

    Dönüş: [(ilk_indeks, son_indeks), ...]
    """
    bursts: list[tuple[int, int]] = []
    current: list[int] | None = None
    start = 0
    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 >= threshold:
            if current and start <= current[1]:
                current[1] = end              # mevcut patlamayı uzat
            else:
                if current:
                    bursts.append((current[0], current[1]))
                current = [start, end]        # yeni patlama başlat
    if current:
        bursts.append((current[0], current[1]))
    return bursts


def _evidence(events: list[LogEvent]) -> list[str]:
    return [e.raw for e in events[:MAX_EVIDENCE]]


# Temel kural sınıfı

class Rule:
    rule_id = ""
    title = ""
    severity = Severity.LOW
    mitre = ""
    source = ""

    def evaluate(self, events: list[LogEvent]) -> list[Alert]:
        raise NotImplementedError

    def make_alert(self, ip: str, events: list[LogEvent], description: str,
                   evidence: list[str] | None = None, severity: Severity | None = None) -> Alert:
        return Alert(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity or self.severity,
            src_ip=ip,
            first_seen=events[0].timestamp,
            last_seen=events[-1].timestamp,
            count=len(events),
            description=description,
            mitre=self.mitre,
            source=self.source,
            evidence=evidence if evidence is not None else _evidence(events),
        )


# SSH kuralları
class SshBruteForceRule(Rule):
    """SSH-001: Kısa sürede aynı IP'den çok sayıda başarısız giriş."""

    rule_id = "SSH-001"
    title = "SSH kaba kuvvet (brute-force) saldırısı"
    severity = Severity.HIGH
    mitre = "T1110.001 - Brute Force: Password Guessing"
    source = "ssh"

    def __init__(self, threshold: int = 5, window_seconds: int = 120):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        failed = [e for e in events if e.source == "ssh" and e.action == "failed_password"]
        alerts = []
        for ip, ip_events in group_by_ip(failed).items():
            for first, last in find_bursts(ip_events, self.threshold, self.window):
                burst = ip_events[first:last + 1]
                users = Counter(e.user for e in burst)
                targets = ", ".join(f"{u} ({n})" for u, n in users.most_common(3))
                seconds = int((burst[-1].timestamp - burst[0].timestamp).total_seconds()) or 1
                alerts.append(self.make_alert(
                    ip, burst,
                    f"{ip} adresinden {seconds} saniye içinde {len(burst)} başarısız SSH girişi. "
                    f"Hedeflenen kullanıcılar: {targets}.",
                ))
        return alerts


class SshUserEnumerationRule(Rule):
    """SSH-002: Aynı IP'nin kısa sürede çok sayıda FARKLI kullanıcı adı denemesi.

    Yavaş yapılan saldırılar (ör. dakikada 1 deneme) SSH-001'in hız eşiğine
    takılmaz; ancak her denemede farklı kullanıcı adı denenmesi bu kural ile
    yakalanır.
    """

    rule_id = "SSH-002"
    title = "SSH kullanıcı adı taraması / parola püskürtme"
    severity = Severity.MEDIUM
    mitre = "T1110.003 - Brute Force: Password Spraying"
    source = "ssh"

    def __init__(self, distinct_users: int = 4, window_seconds: int = 600):
        self.distinct_users = distinct_users
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        failed = [e for e in events if e.source == "ssh" and e.action == "failed_password"]
        alerts = []
        for ip, evs in group_by_ip(failed).items():
            users_in_window: Counter = Counter()
            bursts: list[list[int]] = []
            start = 0
            for end, ev in enumerate(evs):
                users_in_window[ev.user] += 1
                while ev.timestamp - evs[start].timestamp > self.window:
                    old = evs[start].user
                    users_in_window[old] -= 1
                    if users_in_window[old] == 0:
                        del users_in_window[old]
                    start += 1
                if len(users_in_window) >= self.distinct_users:
                    if bursts and start <= bursts[-1][1]:
                        bursts[-1][1] = end
                    else:
                        bursts.append([start, end])
            for first, last in bursts:
                burst = evs[first:last + 1]
                names = sorted({e.user for e in burst})
                alerts.append(self.make_alert(
                    ip, burst,
                    f"{ip} adresi {len(names)} farklı kullanıcı adı denedi: {', '.join(names)}.",
                ))
        return alerts


class SuccessAfterBruteForceRule(Rule):
    """COR-001: Çok sayıda başarısız denemenin ardından aynı IP'den BAŞARILI giriş.

    Bu bir korelasyon kuralıdır: tek başına "başarılı giriş" normal bir olaydır,
    tek başına "başarısız giriş" de sıradan olabilir. İkisinin aynı IP'den
    art arda gelmesi ise parolanın tahmin edildiğini ve hesabın ele
    geçirildiğini gösterir. Bu nedenle en yüksek önem derecesini alır.
    """

    rule_id = "COR-001"
    title = "Kaba kuvvet sonrası başarılı giriş (hesap ele geçirilmiş olabilir)"
    severity = Severity.CRITICAL
    mitre = "T1110 - Brute Force + T1078 - Valid Accounts"
    source = "korelasyon"

    def __init__(self, min_failures: int = 5, window_seconds: int = 900):
        self.min_failures = min_failures
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        ssh = [e for e in events if e.source == "ssh"]
        failed_by_ip = group_by_ip([e for e in ssh if e.action == "failed_password"])
        alerts = []
        for ok in sorted((e for e in ssh if e.action == "accepted"), key=lambda e: e.timestamp):
            failures = failed_by_ip.get(ok.src_ip, [])
            times = [e.timestamp for e in failures]
            # bisect: sıralı listede pencere başlangıcını ikili arama ile bulur
            lo = bisect_left(times, ok.timestamp - self.window)
            hi = bisect_left(times, ok.timestamp + timedelta(seconds=1))
            recent = failures[lo:hi]
            if len(recent) >= self.min_failures:
                related = recent + [ok]
                alerts.append(self.make_alert(
                    ok.src_ip, related,
                    f"{ok.src_ip} adresinden {len(recent)} başarısız denemenin ardından "
                    f"'{ok.user}' kullanıcısıyla BAŞARILI giriş yapıldı. Parola ele geçirilmiş "
                    f"olabilir; hesap derhal kilitlenmeli ve oturum incelenmelidir.",
                    evidence=[e.raw for e in recent[-3:]] + [ok.raw],
                ))
        return alerts


# Web kuralları
class WebSignatureRule(Rule):
    """İmza tabanlı web kurallarının ortak sınıfı.

    URL'nin çözülmüş hali (norm_path) desen listesindeki düzenli ifadelerle
    (regex) karşılaştırılır. Her IP için tek bir alarm üretilir.
    """

    source = "web"
    patterns: list[tuple[str, str]] = []

    def __init__(self):
        self.compiled = [(name, re.compile(rx)) for name, rx in self.patterns]

    def match(self, event: LogEvent) -> list[str]:
        return [name for name, rx in self.compiled if rx.search(event.norm_path or "")]

    def evaluate(self, events):
        hits: dict[str, list[LogEvent]] = defaultdict(list)
        techniques: dict[str, Counter] = defaultdict(Counter)
        for e in events:
            if e.source != "web":
                continue
            matched = self.match(e)
            if matched:
                hits[e.src_ip].append(e)
                techniques[e.src_ip].update(matched)
        alerts = []
        for ip, evs in hits.items():
            evs.sort(key=lambda e: e.timestamp)
            found = ", ".join(name for name, _ in techniques[ip].most_common())
            ok = sum(1 for e in evs if e.status and e.status < 400)
            alerts.append(self.make_alert(
                ip, evs,
                f"{ip} adresinden {len(evs)} şüpheli istek ({ok} tanesi sunucudan 2xx/3xx yanıt aldı). "
                f"Tespit edilen teknikler: {found}.",
            ))
        return alerts


class SqlInjectionRule(WebSignatureRule):
    rule_id = "WEB-001"
    title = "SQL injection denemesi"
    severity = Severity.HIGH
    mitre = "T1190 - Exploit Public-Facing Application"
    patterns = [
        ("UNION SELECT", r"union(\s|/\*.*?\*/)+(all\s+)?select"),
        ("Her zaman doğru ifade (OR 1=1)", r"'?\s*\bor\b\s+'?\w+'?\s*=\s*'?\w+"),
        ("Yorum ile sorgu kesme ('--)", r"'\s*(--|#|/\*)"),
        ("Zaman tabanlı (SLEEP/BENCHMARK)", r"\b(sleep|benchmark|pg_sleep)\s*\("),
        ("Şema keşfi (information_schema)", r"information_schema"),
        ("Yığılmış sorgu (; DROP/DELETE)", r";\s*(drop|delete|insert|update)\s"),
    ]


class XssRule(WebSignatureRule):
    rule_id = "WEB-002"
    title = "Siteler arası betik çalıştırma (XSS) denemesi"
    severity = Severity.MEDIUM
    mitre = "T1190 - Exploit Public-Facing Application"
    patterns = [
        ("<script> etiketi", r"<\s*script"),
        ("Olay işleyici (onerror/onload)", r"\bon(error|load|mouseover|focus|click)\s*="),
        ("javascript: URI", r"javascript\s*:"),
        ("HTML etiketi enjeksiyonu (svg/img/iframe)", r"<\s*(svg|img|iframe|body)\b"),
        ("Çerez çalma (document.cookie)", r"document\.cookie"),
    ]


class PathTraversalRule(WebSignatureRule):
    rule_id = "WEB-003"
    title = "Dizin atlama (path traversal / LFI) denemesi"
    severity = Severity.HIGH
    mitre = "T1190 - Exploit Public-Facing Application"
    patterns = [
        ("../ ile üst dizine çıkma", r"\.\./|\.\.\\"),
        ("Hassas sistem dosyası", r"/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini"),
        ("PHP sarmalayıcı (php://, file://)", r"\b(php|file|expect)://"),
    ]


class WebDirectoryScanRule(Rule):
    """WEB-004: Kısa sürede çok sayıda 404 (bulunamadı) yanıtı alan IP.

    Saldırganlar gobuster/dirb gibi araçlarla /admin, /.env, /backup.zip gibi
    gizli dosya ve dizinleri tahmin etmeye çalışır; bunların çoğu 404 döner.
    """

    rule_id = "WEB-004"
    title = "Dizin / dosya taraması"
    severity = Severity.MEDIUM
    mitre = "T1595.003 - Active Scanning: Wordlist Scanning"
    source = "web"

    def __init__(self, threshold: int = 15, window_seconds: int = 60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def evaluate(self, events):
        not_found = [e for e in events if e.source == "web" and e.status == 404]
        alerts = []
        for ip, evs in group_by_ip(not_found).items():
            for first, last in find_bursts(evs, self.threshold, self.window):
                burst = evs[first:last + 1]
                sample = ", ".join(e.path for e in burst[:6])
                alerts.append(self.make_alert(
                    ip, burst,
                    f"{ip} adresi kısa sürede {len(burst)} adet var olmayan yol istedi "
                    f"(404). Örnekler: {sample} ...",
                ))
        return alerts


class ScannerUserAgentRule(Rule):
    """WEB-005: İstemci bilgisinde (User-Agent) bilinen bir saldırı aracı adı."""

    rule_id = "WEB-005"
    title = "Bilinen saldırı/tarama aracı kullanımı"
    severity = Severity.LOW
    mitre = "T1595.002 - Active Scanning: Vulnerability Scanning"
    source = "web"
    TOOLS = ["sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "dirb",
             "wpscan", "hydra", "nuclei", "zgrab", "acunetix", "ffuf"]

    def evaluate(self, events):
        hits: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
        for e in events:
            if e.source != "web" or not e.user_agent:
                continue
            ua = e.user_agent.lower()
            for tool in self.TOOLS:
                if tool in ua:
                    hits[(e.src_ip, tool)].append(e)
                    break
        alerts = []
        for (ip, tool), evs in hits.items():
            alerts.append(self.make_alert(
                ip, evs,
                f"{ip} adresinden '{tool}' aracına ait {len(evs)} istek. Not: User-Agent "
                f"bilgisi saldırgan tarafından değiştirilebilir, tek başına kesin kanıt değildir.",
                evidence=_evidence(evs)[:2],
            ))
        return alerts


# Alarm korelasyonu (alarmlar üzerinde çalışan üst kural)

class MultiStageAttackRule:
    """COR-002: Aynı IP'nin hem web uygulamasına hem SSH servisine saldırması.

    Bu kural olaylar üzerinde değil, diğer kuralların ürettiği ALARMLAR üzerinde
    çalışır. Farklı kaynaklardaki alarmları birleştirerek tek başına
    görülemeyecek çok aşamalı bir saldırıyı ortaya çıkarır.
    """

    rule_id = "COR-002"
    title = "Çok aşamalı saldırı (web + SSH)"
    severity = Severity.CRITICAL
    mitre = "TA0001 - Initial Access (birden fazla teknik)"

    def evaluate(self, alerts: list[Alert]) -> list[Alert]:
        by_ip: dict[str, list[Alert]] = defaultdict(list)
        for a in alerts:
            by_ip[a.src_ip].append(a)
        result = []
        for ip, ip_alerts in by_ip.items():
            web = [a for a in ip_alerts if a.source == "web"]
            ssh = [a for a in ip_alerts if a.source in ("ssh", "korelasyon")]
            if not web or not ssh:
                continue
            related = sorted(ip_alerts, key=lambda a: a.first_seen)
            rule_list = ", ".join(sorted({a.rule_id for a in related}))
            result.append(Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                src_ip=ip,
                first_seen=related[0].first_seen,
                last_seen=max(a.last_seen for a in related),
                count=sum(a.count for a in related),
                description=(f"{ip} adresi önce web uygulamasını, ardından SSH servisini hedef aldı. "
                             f"İlişkili alarmlar: {rule_list}. IP güvenlik duvarında engellenmeli "
                             f"ve sistemde iz araştırması yapılmalıdır."),
                mitre=self.mitre,
                source="korelasyon",
                evidence=[f"{a.first_seen:%H:%M:%S}  {a.rule_id}  {a.title} ({a.count} olay)" for a in related],
            ))
        return result


def build_rules(config: dict) -> list[Rule]:
    """Ayar dosyasındaki eşik değerleriyle kural nesnelerini oluşturur."""
    c = config
    return [
        SshBruteForceRule(**c.get("ssh_bruteforce", {})),
        SshUserEnumerationRule(**c.get("ssh_user_enumeration", {})),
        SuccessAfterBruteForceRule(**c.get("success_after_bruteforce", {})),
        SqlInjectionRule(),
        XssRule(),
        PathTraversalRule(),
        WebDirectoryScanRule(**c.get("web_directory_scan", {})),
        ScannerUserAgentRule(),
    ]
