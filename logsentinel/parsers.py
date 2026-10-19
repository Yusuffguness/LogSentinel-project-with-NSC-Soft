"""Ham log satırlarını LogEvent nesnelerine dönüştüren ayrıştırıcılar (parser).

Desteklenen formatlar:
  * OpenSSH (syslog formatı)            -> Linux'ta /var/log/auth.log
  * Apache / Nginx "combined" formatı   -> access.log


"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

from .models import LogEvent


MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

IP = r"\d{1,3}(?:\.\d{1,3}){3}"

# --- SSH (syslog) ----------------------------------------------------------
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[\d+\]: (?P<msg>.*)$"
)

# Sıra önemli: "Failed password for invalid user admin ..." satırı ilk desene uyar.
SSH_MESSAGE_PATTERNS = [
    ("failed_password", re.compile(rf"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>{IP})")),
    ("invalid_user", re.compile(rf"^Invalid user (?P<user>\S*) from (?P<ip>{IP})")),
    ("accepted", re.compile(rf"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>{IP})")),
]

# --- Web erişim logu (combined format) --------------------------------------
ACCESS_RE = re.compile(
    rf'^(?P<ip>{IP}) \S+ \S+ '
    r'\[(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2}) [+-]\d{4}\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)


def _make_datetime(year: int, mon: str, day: str, hms: str) -> datetime:
    hour, minute, second = (int(x) for x in hms.split(":"))
    return datetime(year, MONTHS[mon], int(day), hour, minute, second)


def normalize_url(path: str) -> str:
    """URL'yi kurallarla karşılaştırmaya hazır hale getirir.

    Saldırganlar saldırı kodunu (payload) genelde URL kodlaması ile gizler:
        %27%20OR%20%271%27%3D%271   ->   ' OR '1'='1
    Bazen iki kez kodlarlar (%2527 -> %27 -> '). Bu yüzden URL iki kez
    çözülür ve büyük/küçük harf farkı ortadan kaldırılır.
    """
    decoded = unquote_plus(unquote_plus(path))
    return decoded.lower()


def parse_ssh_line(line: str, year: int, line_no: int = 0) -> LogEvent | None:
    """Tek bir auth.log satırını çözer. İlgisiz satırlar için None döner.

    Syslog formatında yıl bilgisi bulunmaz; bu yüzden yıl dışarıdan verilir.
    """
    m = SYSLOG_RE.match(line)
    if not m or m.group("mon") not in MONTHS:
        return None
    msg = m.group("msg")
    for action, pattern in SSH_MESSAGE_PATTERNS:
        pm = pattern.match(msg)
        if pm:
            return LogEvent(
                timestamp=_make_datetime(year, m.group("mon"), m.group("day"), m.group("time")),
                source="ssh",
                src_ip=pm.group("ip"),
                action=action,
                user=pm.group("user") or "(boş)",
                raw=line.rstrip("\n"),
                line_no=line_no,
            )
    return None  # "Connection closed", "pam_unix" gibi analiz için gereksiz satırlar


def parse_access_line(line: str, line_no: int = 0) -> LogEvent | None:
    """Tek bir access.log satırını çözer. Formata uymayan satır için None döner."""
    m = ACCESS_RE.match(line)
    if not m or m.group("mon") not in MONTHS:
        return None
    path = m.group("path")
    return LogEvent(
        timestamp=_make_datetime(int(m.group("year")), m.group("mon"), m.group("day"), m.group("time")),
        source="web",
        src_ip=m.group("ip"),
        action="request",
        method=m.group("method"),
        path=path,
        norm_path=normalize_url(path),
        status=int(m.group("status")),
        user_agent=m.group("ua"),
        raw=line.rstrip("\n"),
        line_no=line_no,
    )


def read_ssh_log(path: str | Path, year: int, stats: dict | None = None) -> list[LogEvent]:
    """auth.log dosyasını okuyup SSH olaylarının listesini döndürür."""
    events: list[LogEvent] = []
    lines = 0
    # errors="replace": dosyada bozuk karakter olsa bile okuma yarıda kalmaz
    with open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            lines += 1
            event = parse_ssh_line(line, year, line_no)
            if event:
                events.append(event)
    if stats is not None:
        stats["ssh"] = {"dosya": str(path), "satir": lines, "olay": len(events), "atlanan": lines - len(events)}
    return events


def read_access_log(path: str | Path, stats: dict | None = None) -> list[LogEvent]:
    """access.log dosyasını okuyup web isteklerinin listesini döndürür."""
    events: list[LogEvent] = []
    lines = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            lines += 1
            event = parse_access_line(line, line_no)
            if event:
                events.append(event)
    if stats is not None:
        stats["web"] = {"dosya": str(path), "satir": lines, "olay": len(events), "atlanan": lines - len(events)}
    return events
