"""Raporlama: konsol çıktısı, JSON dosyası ve HTML raporu."""
from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from .models import Alert, Severity

# --- Konsol ------------------------------------------------------------------
ANSI = {
    Severity.CRITICAL: "\033[1;97;41m",   # kırmızı zemin, beyaz yazı
    Severity.HIGH: "\033[1;91m",          # parlak kırmızı
    Severity.MEDIUM: "\033[1;93m",        # sarı
    Severity.LOW: "\033[1;96m",           # açık mavi
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"


def enable_console_colors() -> bool:
    """Windows komut isteminde ANSI renk kodlarını etkinleştirir."""
    if os.name == "nt":
        os.system("")  # Windows 10+ konsolunda VT100 modunu açan bilinen yöntem
    # Çıktı dosyaya yönlendirildiğinde karakter hatası oluşmasın
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    return sys.stdout.isatty()


def format_alert_line(alert: Alert, color: bool = True) -> str:
    badge = f"[{alert.severity.label}]"
    if color:
        badge = f"{ANSI[alert.severity]}{badge}{RESET}"
    span = f"{alert.first_seen:%H:%M:%S}-{alert.last_seen:%H:%M:%S}"
    return f"{badge:<8} {alert.rule_id:<8} {alert.src_ip:<16} {span:<18} {alert.count:>4} olay  {alert.title}"


def print_console(alerts: list[Alert], stats: dict, parse_stats: dict, color: bool = True) -> None:
    line = "=" * 96
    print(line)
    print(f"{BOLD if color else ''}  LogSentinel - Mini SIEM | Güvenlik Olay Analizi{RESET if color else ''}")
    print(line)
    for key, name in (("ssh", "SSH (auth.log)"), ("web", "Web (access.log)")):
        if key in parse_stats:
            p = parse_stats[key]
            extra = f", {p['atlanan']} satır atlandı" if p["atlanan"] else ""
            print(f"  {name:<18}: {p['satir']:>6} satır okundu, {p['olay']:>6} olay{extra}")
    if stats["whitelisted"]:
        print(f"  Beyaz liste       : {stats['whitelisted']} olay güvenilir IP'den geldiği için analiz dışı bırakıldı")
    sc = stats["severity_counts"]
    print(f"  Analiz edilen     : {stats['event_count']} olay, {stats['unique_ips']} farklı IP")
    print(f"  Üretilen alarm    : {len(alerts)}  "
          f"(KRİTİK {sc[Severity.CRITICAL]} | YÜKSEK {sc[Severity.HIGH]} | "
          f"ORTA {sc[Severity.MEDIUM]} | DÜŞÜK {sc[Severity.LOW]})")
    print(line)
    if not alerts:
        print("  Şüpheli bir etkinlik bulunamadı.")
        return
    header = f"{'ÖNEM':<8} {'KURAL':<8} {'KAYNAK IP':<16} {'ZAMAN ARALIĞI':<18} {'ADET':>9}  BAŞLIK"
    print(header)
    print("-" * 96)
    for a in alerts:
        print(format_alert_line(a, color))
        print(f"{DIM if color else ''}{'':>17}-> {a.description}{RESET if color else ''}")
    print(line)


# --- JSON ----------------------------------------------------------------------
def write_json(alerts: list[Alert], path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([a.to_dict() for a in alerts], f, ensure_ascii=False, indent=2)


# --- HTML ----------------------------------------------------------------------
SEV_CLASS = {
    Severity.CRITICAL: "crit",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
}


def esc(value) -> str:
    """HTML kaçışlama (escape).

    Kanıt satırlarında saldırganın gönderdiği <script> gibi kodlar bulunur.
    Bunlar kaçışlanmadan rapora yazılırsa, raporu açan analistin tarayıcısında
    çalışır. Yani güvenlik raporu kendisi bir XSS açığına dönüşür.
    """
    return html.escape(str(value), quote=True)


def _column_chart(values: list[int], color: str, title: str, unit: str) -> str:
    """24 saatlik sütun grafiği (harici kütüphane olmadan, saf SVG)."""
    width, height = 560, 170
    left, right, top, bottom = 34, 8, 18, 24
    plot_w, plot_h = width - left - right, height - top - bottom
    vmax = max(values) or 1
    step = 10 ** (len(str(vmax)) - 1)
    ymax = ((vmax + step - 1) // step) * step       # üst sınırı yuvarla
    slot = plot_w / 24
    bar_w = min(14, slot - 2)
    peak = values.index(max(values))
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}">']
    for i in range(3):                                # yatay ızgara çizgileri
        val = ymax * i / 2
        y = top + plot_h - plot_h * i / 2
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>')
        parts.append(f'<text x="{left - 6}" y="{y + 4:.1f}" class="tick" text-anchor="end">{int(val)}</text>')
    for h, v in enumerate(values):
        x = left + h * slot + (slot - bar_w) / 2
        bh = plot_h * v / ymax
        y = top + plot_h - bh
        if v:
            r = min(4, bh)
            # Üst köşeleri yuvarlatılmış, tabanı düz sütun
            parts.append(
                f'<path d="M{x:.1f},{top + plot_h:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} '
                f'H{x + bar_w - r:.1f} Q{x + bar_w:.1f},{y:.1f} {x + bar_w:.1f},{y + r:.1f} V{top + plot_h:.1f} Z" '
                f'style="fill:{color}"><title>{h:02d}:00-{h:02d}:59  {v} {esc(unit)}</title></path>'
            )
        if h % 3 == 0:
            parts.append(f'<text x="{x + bar_w / 2:.1f}" y="{height - 6}" class="tick" text-anchor="middle">{h:02d}</text>')
    if values[peak]:
        px = left + peak * slot + slot / 2
        py = top + plot_h - plot_h * values[peak] / ymax - 5
        parts.append(f'<text x="{px:.1f}" y="{py:.1f}" class="peak" text-anchor="middle">{values[peak]}</text>')
    parts.append("</svg>")
    return "".join(parts)


def write_html(alerts: list[Alert], stats: dict, parse_stats: dict, path: str | Path) -> None:
    sc = stats["severity_counts"]
    generated = datetime.now().strftime("%d.%m.%Y %H:%M")
    dr = stats["date_range"]
    period = f"{dr[0]:%d.%m.%Y}" + (f" - {dr[1]:%d.%m.%Y}" if dr and dr[1] != dr[0] else "") if dr else "-"
    files = " · ".join(esc(Path(p["dosya"]).name) for p in parse_stats.values())

    kpis = [
        ("Analiz edilen olay", f"{stats['event_count']:,}".replace(",", "."), ""),
        ("Toplam alarm", str(len(alerts)), ""),
        ("Kritik", str(sc[Severity.CRITICAL]), "crit"),
        ("Yüksek", str(sc[Severity.HIGH]), "high"),
        ("Saldırgan IP", str(len(stats["top_ips"])), ""),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><div class="kpi-label">{esc(label)}</div>'
        f'<div class="kpi-value {cls}">{esc(value)}</div></div>'
        for label, value, cls in kpis
    )

    total = max(len(alerts), 1)
    sev_rows = "".join(
        f'<div class="sev-row"><span class="badge {SEV_CLASS[s]}">{s.label}</span>'
        f'<div class="sev-track"><div class="sev-bar {SEV_CLASS[s]}" style="width:{100 * sc[s] / total:.1f}%"></div></div>'
        f'<span class="sev-num">{sc[s]}</span></div>'
        for s in sorted(Severity, reverse=True)
    )

    ip_rows = "".join(
        f"<tr><td class='mono'>{esc(ip['ip'])}</td><td><span class='badge {SEV_CLASS[ip['max_severity']]}'>"
        f"{ip['max_severity'].label}</span></td><td class='num'>{ip['alerts']}</td>"
        f"<td class='num'>{ip['events']}</td><td class='mono small'>{esc(', '.join(ip['rules']))}</td></tr>"
        for ip in stats["top_ips"]
    )

    alert_cards = []
    for i, a in enumerate(alerts, start=1):
        evidence = "\n".join(esc(line) for line in a.evidence)
        alert_cards.append(f"""
      <article class="alert {SEV_CLASS[a.severity]}">
        <div class="alert-head">
          <span class="badge {SEV_CLASS[a.severity]}">{a.severity.label}</span>
          <span class="rule mono">{esc(a.rule_id)}</span>
          <h3>{esc(a.title)}</h3>
        </div>
        <dl class="meta">
          <div><dt>Kaynak IP</dt><dd class="mono">{esc(a.src_ip)}</dd></div>
          <div><dt>Zaman</dt><dd>{a.first_seen:%d.%m.%Y %H:%M:%S} - {a.last_seen:%H:%M:%S}</dd></div>
          <div><dt>Olay sayısı</dt><dd>{a.count}</dd></div>
          <div><dt>MITRE ATT&amp;CK</dt><dd>{esc(a.mitre)}</dd></div>
        </dl>
        <p class="desc">{esc(a.description)}</p>
        <details{' open' if i <= 2 else ''}><summary>Kanıt ({len(a.evidence)} satır)</summary><pre>{evidence}</pre></details>
      </article>""")

    doc = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogSentinel Analiz Raporu</title>
<style>
  :root {{
    --bg: #f4f5f7; --surface: #ffffff; --ink: #14161a; --ink-2: #4b5260; --ink-3: #7a8190;
    --line: #e3e6eb; --grid: #edf0f3; --accent: #1f3a5f;
    --crit: #d03b3b; --high: #ec835a; --med: #fab219; --low: #7f8ea3;
    --s1: #2a78d6; --s2: #eb6834;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--ink);
         font: 14px/1.5 "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif; }}
  header {{ background: var(--accent); color: #fff; padding: 22px 32px; }}
  header .brand {{ font-size: 12px; letter-spacing: .12em; text-transform: uppercase; opacity: .75; }}
  header h1 {{ margin: 4px 0 6px; font-size: 22px; font-weight: 600; }}
  header .sub {{ font-size: 13px; opacity: .85; }}
  main {{ max-width: 1120px; margin: 0 auto; padding: 24px 32px 40px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }}
  .kpi {{ background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }}
  .kpi-label {{ color: var(--ink-2); font-size: 12px; }}
  .kpi-value {{ font-size: 28px; font-weight: 600; margin-top: 2px; font-variant-numeric: tabular-nums; }}
  .kpi-value.crit {{ color: #b42323; }} .kpi-value.high {{ color: #b9531f; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }}
  .card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; }}
  .card h2 {{ font-size: 14px; margin: 0 0 2px; font-weight: 600; }}
  .card .hint {{ color: var(--ink-3); font-size: 12px; margin: 0 0 8px; }}
  svg {{ width: 100%; height: auto; display: block; }}
  svg .grid {{ stroke: var(--grid); stroke-width: 1; }}
  svg .tick {{ fill: var(--ink-3); font-size: 10px; }}
  svg .peak {{ fill: var(--ink); font-size: 11px; font-weight: 600; }}
  .badge {{ display: inline-block; min-width: 62px; text-align: center; font-size: 11px; font-weight: 700;
           letter-spacing: .04em; padding: 2px 8px; border-radius: 999px; color: #fff; }}
  .badge.crit {{ background: var(--crit); }} .badge.high {{ background: var(--high); color: #2a1408; }}
  .badge.med {{ background: var(--med); color: #2b1d00; }} .badge.low {{ background: var(--low); }}
  .sev-row {{ display: grid; grid-template-columns: 80px 1fr 32px; align-items: center; gap: 10px; margin: 9px 0; }}
  .sev-track {{ background: var(--grid); border-radius: 4px; height: 12px; }}
  .sev-bar {{ height: 12px; border-radius: 0 4px 4px 0; }}
  .sev-bar.crit {{ background: var(--crit); }} .sev-bar.high {{ background: var(--high); }}
  .sev-bar.med {{ background: var(--med); }} .sev-bar.low {{ background: var(--low); }}
  .sev-num {{ text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; font-size: 12px; color: var(--ink-2); font-weight: 600; border-bottom: 1px solid var(--line); padding: 6px 8px; }}
  td {{ border-bottom: 1px solid var(--grid); padding: 7px 8px; vertical-align: middle; }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .mono {{ font-family: Consolas, "Cascadia Mono", "DejaVu Sans Mono", monospace; }}
  .small {{ font-size: 12px; color: var(--ink-2); }}
  h2.section {{ font-size: 16px; margin: 28px 0 10px; }}
  .alert {{ background: var(--surface); border: 1px solid var(--line); border-left: 4px solid var(--low);
           border-radius: 10px; padding: 14px 18px; margin-bottom: 10px; }}
  .alert.crit {{ border-left-color: var(--crit); }} .alert.high {{ border-left-color: var(--high); }}
  .alert.med {{ border-left-color: var(--med); }}
  .alert-head {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .alert-head h3 {{ margin: 0; font-size: 15px; font-weight: 600; }}
  .rule {{ color: var(--ink-2); font-size: 12px; }}
  .meta {{ display: grid; grid-template-columns: 150px 260px 100px 1fr; gap: 8px; margin: 10px 0 6px; }}
  .meta dt {{ font-size: 11px; color: var(--ink-3); }} .meta dd {{ margin: 0; font-size: 13px; }}
  .desc {{ margin: 6px 0; color: var(--ink-2); }}
  details summary {{ cursor: pointer; font-size: 12px; color: var(--accent); font-weight: 600; }}
  pre {{ background: #0f1720; color: #d7dde6; padding: 10px 12px; border-radius: 6px; font-size: 11.5px;
        overflow-x: auto; white-space: pre; margin: 8px 0 0; }}
  footer {{ color: var(--ink-3); font-size: 12px; text-align: center; padding: 10px 0 30px; }}
  @media (max-width: 760px) {{
    main {{ padding: 16px; }} .kpis {{ grid-template-columns: repeat(2, 1fr); }}
    .grid2 {{ grid-template-columns: 1fr; }} .meta {{ grid-template-columns: 1fr 1fr; }}
  }}
</style>
</head>
<body>
<header>
  <div class="brand">LogSentinel · Mini SIEM</div>
  <h1>Güvenlik Olay Analiz Raporu</h1>
  <div class="sub">Analiz dönemi: {esc(period)} &nbsp;|&nbsp; Kaynaklar: {files} &nbsp;|&nbsp; Oluşturulma: {generated}</div>
</header>
<main>
  <section class="kpis">{kpi_html}</section>

  <section class="grid2">
    <div class="card">
      <h2>Saatlik başarısız SSH girişleri</h2>
      <p class="hint">Gece saatlerindeki sıçramalar kaba kuvvet saldırılarına işaret eder.</p>
      {_column_chart(stats["hourly_ssh_fail"], "var(--s1)", "Saatlik başarısız SSH girişleri", "başarısız giriş")}
    </div>
    <div class="card">
      <h2>Saatlik hatalı web yanıtları (4xx/5xx)</h2>
      <p class="hint">Tarama araçları çok sayıda 404 yanıtı üretir.</p>
      {_column_chart(stats["hourly_web_error"], "var(--s2)", "Saatlik hatalı web yanıtları", "hatalı yanıt")}
    </div>
  </section>

  <section class="grid2">
    <div class="card">
      <h2>Alarmların önem derecesine göre dağılımı</h2>
      <p class="hint">Toplam {len(alerts)} alarm</p>
      {sev_rows}
    </div>
    <div class="card">
      <h2>Alarm üreten IP adresleri</h2>
      <p class="hint">En yüksek önem derecesine göre sıralı</p>
      <table>
        <thead><tr><th>IP adresi</th><th>En yüksek önem</th><th class="num">Alarm</th><th class="num">Olay</th><th>Kurallar</th></tr></thead>
        <tbody>{ip_rows}</tbody>
      </table>
    </div>
  </section>

  <h2 class="section">Alarm ayrıntıları</h2>
  {''.join(alert_cards) or '<p>Şüpheli bir etkinlik bulunamadı.</p>'}
</main>
<footer>Bu rapor LogSentinel tarafından otomatik olarak oluşturulmuştur.</footer>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
