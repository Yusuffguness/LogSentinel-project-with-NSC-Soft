"""Projede kullanılan temel veri yapıları: log olayı (LogEvent), alarm (Alert)
ve alarm önem derecesi (Severity)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    """Alarm önem derecesi.

    IntEnum kullanıldığı için dereceler sayı gibi karşılaştırılabilir ve
    sıralanabilir (KRİTİK > YÜKSEK > ORTA > DÜŞÜK).
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return SEVERITY_LABELS[self]


SEVERITY_LABELS = {
    Severity.LOW: "DÜŞÜK",
    Severity.MEDIUM: "ORTA",
    Severity.HIGH: "YÜKSEK",
    Severity.CRITICAL: "KRİTİK",
}


@dataclass
class LogEvent:
    """Farklı kaynaklardan gelen log satırlarının ortak (normalize edilmiş) hali.

    SIEM sistemlerinde buna "normalizasyon" denir: SSH logu ile web sunucusu
    logu farklı formatta olsa da ikisi de aynı alanlara (zaman, kaynak IP,
    eylem...) dönüştürülür. Böylece kurallar tek bir veri yapısı üzerinde çalışır.
    """

    timestamp: datetime
    source: str                     # "ssh" veya "web"
    src_ip: str                     # olayı oluşturan istemcinin IP adresi
    action: str                     # ssh: failed_password / invalid_user / accepted, web: request
    user: str | None = None         # SSH kullanıcı adı
    method: str | None = None       # HTTP metodu (GET, POST...)
    path: str | None = None         # İstenen URL (ham hali)
    norm_path: str | None = None    # URL'nin çözülmüş (decode) ve küçük harfe çevrilmiş hali
    status: int | None = None       # HTTP durum kodu (200, 404...)
    user_agent: str | None = None   # İstemcinin tarayıcı / araç bilgisi
    raw: str = ""                   # Orijinal log satırı (alarm kanıtı olarak gösterilir)
    line_no: int = 0                # Dosyadaki satır numarası


@dataclass
class Alert:
    """Bir tespit kuralının ürettiği alarm."""

    rule_id: str
    title: str
    severity: Severity
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int                      # alarma konu olan olay sayısı
    description: str
    mitre: str                      # MITRE ATT&CK teknik eşleştirmesi
    source: str = ""                # "ssh", "web" veya "korelasyon"
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON çıktısı için alarmı sözlüğe çevirir."""
        return {
            "kural": self.rule_id,
            "baslik": self.title,
            "onem": self.severity.label,
            "kaynak": self.source,
            "ip": self.src_ip,
            "ilk_gorulme": self.first_seen.isoformat(sep=" "),
            "son_gorulme": self.last_seen.isoformat(sep=" "),
            "olay_sayisi": self.count,
            "aciklama": self.description,
            "mitre_attack": self.mitre,
            "kanit": self.evidence,
        }
