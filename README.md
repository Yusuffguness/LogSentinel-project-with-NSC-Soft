# LogSentinel — Mini SIEM

SSH ve web sunucusu loglarını analiz ederek yaygın saldırıları tespit eden, Python ile yazılmış hafif bir güvenlik olay yönetimi (SIEM) aracı. Kaba kuvvet, SQL injection, XSS, dizin atlama ve tarama gibi saldırıları yakalar; farklı kaynaklardaki olayları ilişkilendirir (korelasyon) ve bulguları konsol, JSON ve görsel HTML raporu olarak sunar.

> NSC Soft (NSC Bilişim) Siber Güvenlik Departmanı'ndaki staj kapsamında geliştirilmiştir.

## Özellikler

- **İki log biçimi:** OpenSSH `auth.log` (syslog) ve Apache/Nginx `access.log` (combined)
- **8 tespit kuralı + 2 korelasyon kuralı**, MITRE ATT&CK eşleştirmesiyle
- **Önceliklendirme:** Kritik / Yüksek / Orta / Düşük önem dereceleri
- **Üç çıktı biçimi:** renkli konsol, JSON ve grafikli HTML raporu
- **Canlı izleme:** log dosyasını gerçek zamanlı takip edip yeni alarmları anında bildirir
- **Yapılandırılabilir:** kural eşikleri ve güvenilir IP (beyaz liste) `config.json` üzerinden
- **Sıfır bağımlılık:** yalnızca Python standart kütüphanesi

## Dizin Yapısı

```
LogSentinel/
├── main.py              # Komut satırı arayüzü (analiz / izle)
├── config.json          # Kural eşikleri ve beyaz liste
├── logsentinel/
│   ├── models.py        # Veri yapıları: LogEvent, Alert, Severity
│   ├── parsers.py       # SSH ve web log ayrıştırıcıları
│   ├── rules.py         # Tespit ve korelasyon kuralları
│   ├── engine.py        # Tespit motoru ve istatistikler
│   └── report.py        # Konsol / JSON / HTML raporlama
└── sample_logs/
    └── OpenSSH_2k.log   # Test için örnek saldırı logu (Loghub)
```

## Kurulum

Python 3.8 veya üzeri yeterlidir; harici bir paket kurmaya gerek yoktur.

```bash
git clone https://github.com/<kullanıcı-adın>/LogSentinel.git
cd LogSentinel
```

## Kullanım

### Analiz (tek seferlik)

Log dosyasını analiz edip konsol, JSON ve HTML çıktısı üretir:

```bash
python main.py analiz --auth sample_logs/OpenSSH_2k.log --yil 2026 \
    --html rapor.html --json alarmlar.json
```

Web logu da eklenebilir:

```bash
python main.py analiz --auth /var/log/auth.log --web /var/log/nginx/access.log --html rapor.html
```

### Canlı izleme

Log dosyasını gerçek zamanlı izler, yeni alarm oluştukça ekrana yazar:

```bash
python main.py izle --auth /var/log/auth.log
```

### Başlıca parametreler

| Parametre | Açıklama |
|---|---|
| `--auth` | SSH log dosyası (auth.log) |
| `--web` | Web sunucusu erişim logu (access.log) |
| `--html` | HTML raporun kaydedileceği dosya |
| `--json` | Alarmların kaydedileceği JSON dosyası |
| `--yil` | auth.log satırlarının yılı (syslog'da yıl bulunmaz) |
| `--ayar` | Yapılandırma dosyası (varsayılan: `config.json`) |
| `--renksiz` | Konsol çıktısında renk kullanma |

## Tespit Kuralları

| Kural | Ad | Önem | MITRE ATT&CK |
|---|---|---|---|
| SSH-001 | SSH kaba kuvvet (brute-force) | Yüksek | T1110.001 |
| SSH-002 | SSH kullanıcı adı taraması | Orta | T1110.003 |
| COR-001 | Kaba kuvvet sonrası başarılı giriş | Kritik | T1110 + T1078 |
| WEB-001 | SQL injection | Yüksek | T1190 |
| WEB-002 | XSS (betik çalıştırma) | Orta | T1190 |
| WEB-003 | Dizin atlama (traversal / LFI) | Yüksek | T1190 |
| WEB-004 | Dizin ve dosya taraması | Orta | T1595.003 |
| WEB-005 | Bilinen tarama aracı | Düşük | T1595.002 |
| COR-002 | Çok aşamalı saldırı (web + SSH) | Kritik | TA0001 |

## Örnek Çıktı

`sample_logs/OpenSSH_2k.log` (2000 satır) analiz edildiğinde 630 olaydan 15 alarm üretilir
(10 Yüksek kaba kuvvet, 5 Orta kullanıcı adı taraması). Örneğin `183.62.140.253` adresinin
~10 dakikada 286 başarısız `root` denemesi tek bir alarmda toplanır.

## Testler

Birim testleri Python'un yerleşik `unittest` modülüyle yazılmıştır; ekstra kurulum gerektirmez.
Proje kök dizininde:

```bash
python -m unittest discover -s tests -v
```

Testler ayrıştırıcıları, tespit kurallarını (kaba kuvvet, SQL injection), korelasyonu ve
tespit motorunu (beyaz liste dâhil) kapsar.

## Örnek Veri

`sample_logs/OpenSSH_2k.log` dosyası, akademik çalışmalarda yaygın olarak kullanılan
[Loghub](https://github.com/logpai/loghub) OpenSSH veri setinden alınmıştır ve gerçek bir
sunucuya yönelmiş SSH saldırı denemelerini içerir.

## Teknolojiler

Python 3 (re, dataclasses, datetime, collections, json, argparse, bisect) · HTML / CSS / SVG · MITRE ATT&CK
