"""LogSentinel komut satırı arayüzü.

Kullanım örnekleri:
  python main.py analiz --auth sample_logs/auth.log --web sample_logs/access.log --html rapor.html
  python main.py izle   --auth sample_logs/canli_auth.log --web sample_logs/canli_access.log
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from logsentinel.engine import DetectionEngine, load_config
from logsentinel.parsers import parse_access_line, parse_ssh_line, read_access_log, read_ssh_log
from logsentinel.report import enable_console_colors, format_alert_line, print_console, write_html, write_json

DEFAULT_CONFIG = Path(__file__).with_name("config.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="LogSentinel",
        description="SSH ve web sunucusu loglarından saldırı tespiti yapan mini SIEM aracı.",
    )
    sub = parser.add_subparsers(dest="komut", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--auth", help="SSH log dosyası (ör. /var/log/auth.log)")
        p.add_argument("--web", help="Web sunucusu erişim logu (Apache/Nginx combined)")
        p.add_argument("--ayar", default=str(DEFAULT_CONFIG) if DEFAULT_CONFIG.exists() else None,
                       help="Kural eşiklerini ve beyaz listeyi içeren JSON dosyası")
        p.add_argument("--renksiz", action="store_true", help="Konsolda renk kullanma")

    analyze = sub.add_parser("analiz", help="Log dosyalarını bir kez analiz et ve rapor üret")
    common(analyze)
    analyze.add_argument("--html", help="HTML raporun kaydedileceği dosya")
    analyze.add_argument("--json", help="Alarmların kaydedileceği JSON dosyası")
    analyze.add_argument("--yil", type=int,
                         help="auth.log satırlarının yılı (syslog formatında yıl yoktur)")

    watch = sub.add_parser("izle", help="Log dosyalarını canlı izle, yeni alarmları anında göster")
    common(watch)
    watch.add_argument("--pencere", type=int, default=15,
                       help="Bellekte tutulacak olay penceresi, dakika (varsayılan 15)")
    watch.add_argument("--bastan", action="store_true",
                       help="Dosyaları baştan oku (varsayılan: sadece yeni eklenen satırlar)")
    return parser


def run_analyze(args, config) -> int:
    parse_stats: dict = {}
    events = []
    if args.web:
        events += read_access_log(args.web, parse_stats)
    if args.auth:
        # Syslog satırlarında yıl yoktur: önce --yil, yoksa web logunun yılı, o da yoksa bu yıl
        web_years = [e.timestamp.year for e in events]
        year = args.yil or (max(set(web_years), key=web_years.count) if web_years else datetime.now().year)
        events += read_ssh_log(args.auth, year, parse_stats)

    engine = DetectionEngine(config)
    alerts, stats = engine.analyze(events)
    print_console(alerts, stats, parse_stats, color=not args.renksiz)

    if args.json:
        write_json(alerts, args.json)
        print(f"  JSON çıktısı kaydedildi : {args.json}")
    if args.html:
        write_html(alerts, stats, parse_stats, args.html)
        print(f"  HTML rapor kaydedildi   : {args.html}")
    # Kritik alarm varsa çıkış kodu 2 (betiklerde/otomasyonda kullanılabilir)
    return 2 if any(a.severity.name == "CRITICAL" for a in alerts) else 0


def run_watch(args, config) -> int:
    """Dosyaların sonuna eklenen satırları okuyup (tail -f mantığı) analiz eder."""
    sources = []
    if args.auth:
        sources.append(("ssh", args.auth))
    if args.web:
        sources.append(("web", args.web))
    handles = {}
    for kind, path in sources:
        Path(path).touch(exist_ok=True)
        f = open(path, encoding="utf-8", errors="replace")
        if not args.bastan:
            f.seek(0, 2)          # dosyanın sonuna git, sadece yeni satırları oku
        handles[kind] = f

    engine = DetectionEngine(config)
    window = timedelta(minutes=args.pencere)
    buffer: deque = deque()
    seen: set = set()
    color = not args.renksiz
    year = datetime.now().year

    print(f"[{datetime.now():%H:%M:%S}] İzleme başladı: {', '.join(p for _, p in sources)}  (durdurmak için Ctrl+C)")
    try:
        while True:
            new_events = []
            for kind, f in handles.items():
                for line in f.readlines():
                    ev = parse_ssh_line(line, year) if kind == "ssh" else parse_access_line(line)
                    if ev:
                        new_events.append(ev)
            if new_events:
                buffer.extend(sorted(new_events, key=lambda e: e.timestamp))
                newest = max(e.timestamp for e in buffer)
                while buffer and newest - buffer[0].timestamp > window:
                    buffer.popleft()  # pencere dışına çıkan eski olayları bırak
                alerts, _ = engine.analyze(list(buffer))
                for a in sorted(alerts, key=lambda a: a.last_seen):
                    key = (a.rule_id, a.src_ip, a.first_seen)
                    if key not in seen:
                        seen.add(key)
                        print(f"[{datetime.now():%H:%M:%S}] YENİ ALARM  {format_alert_line(a, color)}")
                        print(f"{'':>22}-> {a.description}")
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{datetime.now():%H:%M:%S}] İzleme durduruldu. Toplam {len(seen)} alarm üretildi.")
    finally:
        for f in handles.values():
            f.close()
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.auth and not args.web:
        print("Hata: en az bir log dosyası verilmelidir (--auth ve/veya --web).", file=sys.stderr)
        return 1
    enable_console_colors()
    config = load_config(args.ayar)
    if args.komut == "analiz":
        return run_analyze(args, config)
    return run_watch(args, config)


if __name__ == "__main__":
    sys.exit(main())
