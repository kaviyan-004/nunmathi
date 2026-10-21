"""Report rendering: JSON, standalone HTML (ZAP-report style) and PDF."""
from __future__ import annotations

import html
import io
import json
import time

from .assess import RISK_ORDER, _bytes, _dur

RISK_COLOR = {"High": "#e0301e", "Medium": "#f08c00", "Low": "#e6c700", "Informational": "#3b82c4"}


def _e(x) -> str:
    return html.escape(str(x if x is not None else "—"))


def _ts(t) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)) if t else "—"


def slim(result: dict) -> dict:
    """Result without per-window traffic detail (for JSON export)."""
    r = json.loads(json.dumps(result, default=str))
    for t in r.get("tunnels", []):
        if t.get("traffic"):
            t["traffic"].pop("windows", None)
    return r


def render_json(result: dict, meta: dict) -> bytes:
    return json.dumps({"nunmathi_report": 1, "analysis": meta, **slim(result)}, indent=1, default=str).encode()


def render_html(result: dict, meta: dict) -> bytes:
    alerts = result["alerts"]
    counts = {r: sum(a["risk"] == r for a in alerts) for r in RISK_ORDER}
    g = result["grade"]
    rows = "".join(
        f"<tr><td><span class='dot' style='background:{RISK_COLOR[r]}'></span>{r}</td><td>{counts[r]}</td></tr>"
        for r in RISK_ORDER)
    groups = {}
    for a in alerts:
        groups.setdefault((a["id"], a["name"], a["risk"]), []).append(a)
    summary = "".join(
        f"<tr><td><a href='#{_e(k[0])}'>{_e(k[1])}</a></td><td>{_e(k[0])}</td>"
        f"<td style='color:{RISK_COLOR[k[2]]};font-weight:600'>{k[2]}</td><td>{len(v)}</td></tr>"
        for k, v in groups.items())
    details = []
    for (rid, name, risk), items in groups.items():
        inst = "".join(f"<tr><td>Tunnel</td><td>{_e(a['tunnel'] or 'capture')}</td></tr>"
                       f"<tr><td>Evidence</td><td>{_e(a['evidence'])}</td></tr>"
                       f"<tr><td>Confidence</td><td>{_e(a['confidence'])}</td></tr>" for a in items)
        a0 = items[0]
        details.append(f"""<table class='alert' id='{_e(rid)}'>
<tr class='head' style='background:{RISK_COLOR[risk]}'><th>{_e(risk)}</th><th>{_e(name)} ({_e(rid)})</th></tr>
<tr><td>Description</td><td>{_e(a0['description'])}</td></tr>{inst}
<tr><td>Solution</td><td>{_e(a0['solution'])}</td></tr>
<tr><td>Reference</td><td>{_e(', '.join(a0['references']))}</td></tr></table>""")
    tunnels = []
    for t in result["tunnels"]:
        ic = (t.get("ike_crypto") or {}).get("names") or {}
        cls = (t.get("traffic") or {}).get("summary", {}).get("class_windows", {})
        tunnels.append(f"""<table class='kv'><tr class='head'><th colspan=2>{_e(t['id'])}: {_e(t['initiator'])} → {_e(t['responder'])}
 — grade {_e(t['grade']['letter'])} ({t['grade']['score']})</th></tr>
<tr><td>IKE</td><td>IKEv{_e(t['version'])}: {_e(ic.get('encr'))} / {_e(ic.get('prf'))} / {_e(ic.get('group'))}
 {('+ ' + ', '.join(ic.get('addke'))) if ic.get('addke') else ''}</td></tr>
<tr><td>ESP geometry</td><td>{_e('; '.join(sorted({(c['geometry'].get('best') or {}).get('label', '?') for c in t['child_sas']})))}</td></tr>
<tr><td>PFS</td><td>{_e(t['pfs']['status'])} {_e(t['pfs'].get('group') or '')} (confidence {_e(t['pfs']['confidence'])})</td></tr>
<tr><td>Lifetimes</td><td>Child {_e(_dur(t['lifetimes']['child_rekey_interval']) if t['lifetimes']['child_rekey_interval'] else '> ' + _dur(t['lifetimes']['child_lower_bound']))},
 IKE {_e(_dur(t['lifetimes']['ike_rekey_interval']) if t['lifetimes']['ike_rekey_interval'] else '> ' + _dur(t['lifetimes']['ike_lower_bound']))}</td></tr>
<tr><td>Traffic</td><td>{_e(t['esp_packets'])} ESP packets, {_e(_bytes(t['esp_bytes']))};
 classes {_e(', '.join(f'{k}: {v}' for k, v in cls.items() if v))}</td></tr>
</table>""")
    f = result["file"]
    doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>Nunmathi Scanning Report</title>
<style>body{{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#222;background:#fff}}h1{{font-size:22px}}
table{{border-collapse:collapse;width:100%;margin:10px 0 18px}}td,th{{border:1px solid #ccc;padding:5px 8px;font-size:13px;text-align:left;vertical-align:top}}
tr.head th{{color:#fff;background:#666}}.dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}}
table.alert td:first-child,table.kv td:first-child{{width:160px;font-weight:600;background:#f4f4f4}}.muted{{color:#666;font-size:12px}}
.grade{{font-size:42px;font-weight:700}}</style></head><body>
<h1>Nunmathi Scanning Report</h1>
<p class='muted'>Analysis {_e(meta.get('id'))} · {_e(meta.get('name'))} · generated {_ts(time.time())} · engine {_e(result.get('engine'))}</p>
<p>Capture: {_e(f.get('frames'))} frames ({_e(f.get('ike'))} IKE, {_e(f.get('esp'))} ESP), {_ts(f.get('first_ts'))} – {_ts(f.get('last_ts'))}.
Passive analysis only; no traffic was decrypted.</p>
<p>Overall grade: <span class='grade'>{_e(g['letter'])}</span> (score {g['score']}/100)</p>
<h2>Summary of Alerts</h2><table style='width:320px'><tr class='head'><th>Risk Level</th><th>Number of Alerts</th></tr>{rows}</table>
<h2>Alerts</h2><table><tr class='head'><th>Name</th><th>Rule</th><th>Risk Level</th><th>Instances</th></tr>{summary}</table>
<h2>Tunnels</h2>{''.join(tunnels)}
<h2>Alert Detail</h2>{''.join(details)}
<p class='muted'>Traffic classification uses a model trained on synthetic traffic (test accuracy
{_e(result.get('model_card', {}).get('test_accuracy'))} on synthetic data). Treat class labels as indicative.</p>
</body></html>"""
    return doc.encode()


def render_pdf(result: dict, meta: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title="Nunmathi Scanning Report")
    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=8.5, leading=11)
    P = lambda t, s=small: Paragraph(html.escape(str(t)), s)  # noqa: E731
    story = [Paragraph("Nunmathi Scanning Report", ss["Title"]),
             P(f"Analysis {meta.get('id')} · {meta.get('name')} · {_ts(time.time())}"),
             Spacer(1, 6),
             Paragraph(f"Overall grade <b>{result['grade']['letter']}</b> (score {result['grade']['score']}/100)", ss["Heading2"])]
    alerts = result["alerts"]
    data = [["Risk", "Count"]] + [[r, str(sum(a["risk"] == r for a in alerts))] for r in RISK_ORDER]
    t = Table(data, colWidths=[40 * mm, 25 * mm])
    style = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#555555")),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 9)]
    for i, r in enumerate(RISK_ORDER, 1):
        style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(RISK_COLOR[r])))
    t.setStyle(TableStyle(style))
    story += [t, Spacer(1, 8), Paragraph("Tunnels", ss["Heading2"])]
    for tu in result["tunnels"]:
        ic = (tu.get("ike_crypto") or {}).get("names") or {}
        rows = [["Tunnel", f"{tu['id']}  {tu['initiator']} → {tu['responder']}  grade {tu['grade']['letter']}"],
                ["IKE", f"IKEv{tu['version']} {ic.get('encr')} / {ic.get('prf')} / {ic.get('group')} "
                        f"{'+ ' + ', '.join(ic.get('addke')) if ic.get('addke') else ''}"],
                ["ESP", "; ".join(sorted({(c['geometry'].get('best') or {}).get('label', '?') for c in tu['child_sas']}))],
                ["PFS", f"{tu['pfs']['status']} {tu['pfs'].get('group') or ''}"]]
        tt = Table([[P(a), P(b)] for a, b in rows], colWidths=[35 * mm, 140 * mm])
        tt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee"))]))
        story += [tt, Spacer(1, 6)]
    story.append(Paragraph("Alerts", ss["Heading2"]))
    for a in alerts:
        rows = [[P(f"{a['risk']}"), P(f"{a['id']}  {a['name']}")], [P("Evidence"), P(a["evidence"])],
                [P("Solution"), P(a["solution"])], [P("Reference"), P(", ".join(a["references"]) or "—")]]
        tt = Table(rows, colWidths=[35 * mm, 140 * mm])
        tt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(RISK_COLOR[a["risk"]])),
                                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#eeeeee"))]))
        story += [tt, Spacer(1, 5)]
    doc.build(story)
    return buf.getvalue()
