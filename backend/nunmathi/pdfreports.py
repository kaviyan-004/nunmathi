"""Executive (2-3 page) and technical (15-30 page) PDF reports.

Both are built with reportlab platypus and reportlab.graphics only (no system fonts, no browser), so
they render identically on Linux and in the Windows build. Text is restricted to WinAnsi characters
because the standard PDF fonts cannot draw arrows or math symbols.
"""
from __future__ import annotations

import html
import io
import time

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph, Preformatted,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from . import assess, attack, explain
from .assess import RISK_ORDER, _bytes, _dur

RISK_HEX = {"High": "#c62828", "Medium": "#ef6c00", "Low": "#c9a400", "Informational": "#1f6fb2"}
GRADE_HEX = {"A+": "#1b7f3b", "A": "#2e9e4f", "B": "#7cb342", "C": "#f9a825", "D": "#ef6c00", "F": "#c62828"}
INK = colors.HexColor("#1d2530")
MUTED = colors.HexColor("#5d6875")
RULE = colors.HexColor("#c9d1da")
HEAD = colors.HexColor("#27313d")
TINT = colors.HexColor("#f1f4f7")
ACCENT = colors.HexColor("#2b6cb0")
CLASS_HEX = {"voip": "#7b1fa2", "video": "#1565c0", "web": "#2e7d32", "chat": "#ef6c00", "email": "#6d4c41"}
W = A4[0] - 36 * mm      # usable width

_TR = str.maketrans({"→": "->", "←": "<-", "≤": "<=", "≥": ">=", "≠": "!=", "×": "x",
                     "–": "-", "—": "-", "…": "...", "≈": "~", "φ": "phi", "•": "-",
                     "−": "-", "±": "+/-"})


def _a(x) -> str:
    """WinAnsi-safe text."""
    s = str(x if x is not None else "-").translate(_TR)
    return s.encode("cp1252", "replace").decode("cp1252")


def _ts(t) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)) if t else "-"


# ------------------------------------------------------------------ styles
def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("b", parent=ss["BodyText"], fontName="Helvetica", fontSize=9, leading=12.2, textColor=INK)
    st = {
        "body": base,
        "small": ParagraphStyle("s", parent=base, fontSize=7.8, leading=10),
        "tiny": ParagraphStyle("t", parent=base, fontSize=6.8, leading=8.4),
        "muted": ParagraphStyle("m", parent=base, fontSize=8, leading=10.5, textColor=MUTED),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=17, leading=21, spaceBefore=4,
                             spaceAfter=8, textColor=HEAD),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=12.5, leading=16, spaceBefore=10,
                             spaceAfter=5, textColor=HEAD),
        "h3": ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=10, leading=13, spaceBefore=7,
                             spaceAfter=3, textColor=ACCENT),
        "title": ParagraphStyle("ti", parent=base, fontName="Helvetica-Bold", fontSize=26, leading=31, textColor=HEAD),
        "sub": ParagraphStyle("su", parent=base, fontSize=12, leading=16, textColor=MUTED),
        "cell": ParagraphStyle("c", parent=base, fontSize=7.8, leading=9.8),
        "cellb": ParagraphStyle("cb", parent=base, fontName="Helvetica-Bold", fontSize=7.8, leading=9.8),
        "headc": ParagraphStyle("hc", parent=base, fontName="Helvetica-Bold", fontSize=7.8, leading=9.8,
                                textColor=colors.white),
        "code": ParagraphStyle("code", parent=base, fontName="Courier", fontSize=7, leading=8.4),
        "big": ParagraphStyle("big", parent=base, fontName="Helvetica-Bold", fontSize=40, leading=44,
                              alignment=TA_CENTER),
        "center": ParagraphStyle("ce", parent=base, alignment=TA_CENTER, fontSize=8, textColor=MUTED),
    }
    return st


S = _styles()


def P(text, style="body", raw=False) -> Paragraph:
    t = _a(text)
    return Paragraph(t if raw else html.escape(t), S[style])


def table(rows, widths, header=True, zebra=True, style=None, head_bg=HEAD, font="cell"):
    data = []
    for i, r in enumerate(rows):
        data.append([c if not isinstance(c, (str, int, float, type(None))) else
                     P(c if c is not None else "-", "headc" if header and i == 0 else font) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    ts = [("GRID", (0, 0), (-1, -1), 0.35, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("TOPPADDING", (0, 0), (-1, -1), 2.2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
          ("LEFTPADDING", (0, 0), (-1, -1), 3.5), ("RIGHTPADDING", (0, 0), (-1, -1), 3.5)]
    if header:
        ts.append(("BACKGROUND", (0, 0), (-1, 0), head_bg))
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if (i % 2 == 0) == header:
                ts.append(("BACKGROUND", (0, i), (-1, i), TINT))
    t.setStyle(TableStyle(ts + (style or [])))
    return t


def kv(rows, key_w=38 * mm):
    t = table([[P(k, "cellb"), v if not isinstance(v, (str, int, float, type(None))) else P(v, "cell")]
               for k, v in rows], [key_w, W - key_w], header=False, zebra=False,
              style=[("BACKGROUND", (0, 0), (0, -1), TINT)])
    return t


def _page_deco(title: str, meta: dict):
    def deco(canv, doc):
        canv.saveState()
        canv.setFont("Helvetica", 7)
        canv.setFillColor(MUTED)
        canv.drawString(18 * mm, 10 * mm, _a(f"Nunmathi {title} - analysis {meta.get('id', '')} - {meta.get('name', '')}"))
        canv.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canv.setStrokeColor(RULE)
        canv.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canv.drawString(18 * mm, A4[1] - 11 * mm, "PASSIVE ANALYSIS - NO TRAFFIC DECRYPTED - CONFIDENTIAL")
        canv.restoreState()
    return deco


def _doc(buf, title):
    return SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                             bottomMargin=18 * mm, title=title, author="Nunmathi", creator="Nunmathi")


# ------------------------------------------------------------------ drawings
def grade_badge(letter: str, score: int, size: float = 36 * mm) -> Drawing:
    d = Drawing(size, size)
    col = colors.HexColor(GRADE_HEX.get(letter, "#555555"))
    d.add(Rect(0, 0, size, size, rx=6, ry=6, fillColor=col, strokeColor=None))
    d.add(String(size / 2, size * 0.40, letter, fontName="Helvetica-Bold", fontSize=size * 0.42,
                 fillColor=colors.white, textAnchor="middle"))
    d.add(String(size / 2, size * 0.13, f"score {score}/100", fontName="Helvetica", fontSize=8,
                 fillColor=colors.white, textAnchor="middle"))
    return d


def risk_gauge(risk: int, width: float = 80 * mm) -> Drawing:
    h = 26
    d = Drawing(width, h + 16)
    bands = [(0, 20, "#2e9e4f"), (20, 40, "#7cb342"), (40, 60, "#f9a825"), (60, 80, "#ef6c00"), (80, 100, "#c62828")]
    for a, b, c in bands:
        d.add(Rect(width * a / 100, 12, width * (b - a) / 100, 10, fillColor=colors.HexColor(c), strokeColor=None))
    x = width * max(0, min(100, risk)) / 100
    d.add(Polygon([x, 24, x - 5, h + 8, x + 5, h + 8], fillColor=INK, strokeColor=None))
    d.add(String(x, h + 10, str(risk), fontName="Helvetica-Bold", fontSize=9, fillColor=INK, textAnchor="middle"))
    for v in (0, 50, 100):
        d.add(String(width * v / 100, 2, str(v), fontName="Helvetica", fontSize=6.5, fillColor=MUTED,
                     textAnchor="start" if v == 0 else "end" if v == 100 else "middle"))
    return d


def bars(items: list[tuple[str, float, str]], width=W, bar_h=9, label_w=62 * mm, fmt="{:.3f}", signed=False):
    """Horizontal bar chart: (label, value, hex colour)."""
    n = len(items)
    d = Drawing(width, n * (bar_h + 4) + 6)
    vmax = max([abs(v) for _, v, _ in items] + [1e-9])
    plot = width - label_w - 44
    zero = label_w + (plot / 2 if signed else 0)
    scale = (plot / 2 if signed else plot) / vmax
    for i, (lab, v, col) in enumerate(items):
        y = d.height - (i + 1) * (bar_h + 4)
        d.add(String(label_w - 4, y + 1.5, _a(lab)[:44], fontName="Helvetica", fontSize=7, fillColor=INK,
                     textAnchor="end"))
        w = v * scale
        d.add(Rect(zero if w >= 0 else zero + w, y, abs(w), bar_h, fillColor=colors.HexColor(col), strokeColor=None))
        tx = zero + w + (3 if w >= 0 else -3)
        d.add(String(tx, y + 1.5, fmt.format(v), fontName="Helvetica", fontSize=6.5, fillColor=MUTED,
                     textAnchor="start" if w >= 0 else "end"))
    if signed:
        d.add(Line(zero, 0, zero, d.height, strokeColor=RULE, strokeWidth=0.6))
    return d


def length_histogram(hist: dict, width=W, height=70) -> Drawing:
    lens, out, inn = hist.get("lengths", []), hist.get("out", []), hist.get("in", [])
    d = Drawing(width, height + 22)
    if not lens:
        return d
    n = len(lens)
    vmax = max([a + b for a, b in zip(out, inn)] + [1])
    bw = min(16, (width - 30) / n)
    for i, (L, a, b) in enumerate(zip(lens, out, inn)):
        x = 26 + i * bw
        ha, hb = height * a / vmax, height * b / vmax
        d.add(Rect(x, 16, bw * 0.8, ha, fillColor=colors.HexColor("#2b6cb0"), strokeColor=None))
        d.add(Rect(x, 16 + ha, bw * 0.8, hb, fillColor=colors.HexColor("#90b4dc"), strokeColor=None))
        if n <= 24 or i % max(1, n // 20) == 0:
            d.add(String(x + bw * 0.4, 6, str(L), fontName="Helvetica", fontSize=5.5, fillColor=MUTED,
                         textAnchor="middle"))
    d.add(Line(24, 16, width, 16, strokeColor=RULE))
    d.add(String(0, height + 12, f"count (max {vmax})", fontName="Helvetica", fontSize=6, fillColor=MUTED))
    d.add(Rect(width - 120, height + 12, 6, 6, fillColor=colors.HexColor("#2b6cb0"), strokeColor=None))
    d.add(String(width - 111, height + 12, "initiator->responder", fontName="Helvetica", fontSize=6, fillColor=MUTED))
    d.add(Rect(width - 48, height + 12, 6, 6, fillColor=colors.HexColor("#90b4dc"), strokeColor=None))
    d.add(String(width - 39, height + 12, "reverse", fontName="Helvetica", fontSize=6, fillColor=MUTED))
    return d


def rekey_timeline(t: dict, width=W) -> Drawing:
    lt = t["lifetimes"]
    t0, t1 = t["first_ts"], t["last_ts"]
    span = max(1.0, t1 - t0)
    d = Drawing(width, 64)
    x0, x1 = 60, width - 10

    def X(sec):
        return x0 + (x1 - x0) * max(0.0, min(1.0, sec / span))
    rows = [("Child SA rekeys", lt.get("child_rekey_times") or [], "#2b6cb0", 40),
            ("IKE SA rekeys", lt.get("ike_rekey_times") or [], "#c62828", 18)]
    for lab, times, col, y in rows:
        d.add(String(0, y - 3, lab, fontName="Helvetica", fontSize=6.5, fillColor=INK))
        d.add(Line(x0, y, x1, y, strokeColor=RULE, strokeWidth=1))
        for s in times:
            d.add(Rect(X(s) - 1.2, y - 6, 2.4, 12, fillColor=colors.HexColor(col), strokeColor=None))
    for ch in t["child_sas"]:
        a, b = ch["first_ts"] - t0, ch["last_ts"] - t0
        d.add(Rect(X(a), 52, max(1, X(b) - X(a)), 4, fillColor=colors.HexColor("#90b4dc"), strokeColor=None))
    d.add(String(0, 50, "Child SA life", fontName="Helvetica", fontSize=6.5, fillColor=INK))
    for f in (0, 0.25, 0.5, 0.75, 1):
        d.add(String(X(span * f), 2, _dur(int(span * f)) if f else "0 s", fontName="Helvetica", fontSize=6,
                     fillColor=MUTED, textAnchor="middle"))
    return d


def ladder_drawing(t: dict, msgs: list[dict], width=W) -> Drawing:
    row = 15
    h = len(msgs) * row + 30
    d = Drawing(width, h)
    xl, xr = 70, width - 70
    d.add(String(xl, h - 10, _a(f"Initiator {t['initiator']}"), fontName="Helvetica-Bold", fontSize=7.5,
                 textAnchor="middle", fillColor=INK))
    d.add(String(xr, h - 10, _a(f"Responder {t['responder']}"), fontName="Helvetica-Bold", fontSize=7.5,
                 textAnchor="middle", fillColor=INK))
    d.add(Line(xl, h - 16, xl, 4, strokeColor=RULE, strokeWidth=1.2))
    d.add(Line(xr, h - 16, xr, 4, strokeColor=RULE, strokeWidth=1.2))
    for i, m in enumerate(msgs):
        y = h - 28 - i * row
        a, b = (xl, xr) if m["from_initiator"] else (xr, xl)
        col = colors.HexColor("#c62828" if m["exchange"] in ("INFORMATIONAL",) and any(
            "DELETE" in p or p.startswith("D") for p in m.get("payloads", [])) else "#2b6cb0"
            if m["exchange"] in ("IKE_SA_INIT", "IKE_AUTH", "IKE_INTERMEDIATE") else "#5d6875")
        d.add(Line(a, y, b, y, strokeColor=col, strokeWidth=0.9))
        dx = -5 if b < a else 5
        d.add(Polygon([b, y, b - dx, y + 2.5, b - dx, y - 2.5], fillColor=col, strokeColor=None))
        pay = ", ".join(m.get("payloads") or []) or (m.get("inferred") or "")
        lab = f"#{m['packet']} {m['exchange']} {'resp' if m['response'] else 'req'} mid={m['msgid']}"
        d.add(String((xl + xr) / 2, y + 2.5, _a(lab), fontName="Helvetica-Bold", fontSize=6.2,
                     fillColor=INK, textAnchor="middle"))
        d.add(String((xl + xr) / 2, y - 6.2, _a(pay)[:118], fontName="Helvetica", fontSize=5.4,
                     fillColor=MUTED, textAnchor="middle"))
        d.add(String(4, y - 2, f"+{m['t'] - t['first_ts']:.3f}s", fontName="Helvetica", fontSize=5.6, fillColor=MUTED))
    return d


def segments_drawing(t: dict, width=W) -> Drawing:
    segs = (t.get("traffic") or {}).get("segments") or []
    d = Drawing(width, 40)
    if not segs:
        return d
    t0, t1 = t["first_ts"], t["last_ts"]
    span = max(1.0, t1 - t0)
    x0, x1 = 4, width - 4
    for s in segs:
        a = x0 + (x1 - x0) * (float(s["start"]) - t0) / span
        b = x0 + (x1 - x0) * (float(s["end"]) - t0) / span
        col = colors.HexColor("#9e9e9e" if s.get("ood") else CLASS_HEX.get(s["label"], "#607d8b"))
        d.add(Rect(a, 20, max(1.2, b - a), 14, fillColor=col, strokeColor=None))
    x = x0
    for c, hx in CLASS_HEX.items():
        d.add(Rect(x, 4, 7, 7, fillColor=colors.HexColor(hx), strokeColor=None))
        d.add(String(x + 10, 4.5, c, fontName="Helvetica", fontSize=6.5, fillColor=INK))
        x += 50
    d.add(Rect(x, 4, 7, 7, fillColor=colors.HexColor("#9e9e9e"), strokeColor=None))
    d.add(String(x + 10, 4.5, "out-of-distribution", fontName="Helvetica", fontSize=6.5, fillColor=INK))
    return d


# ------------------------------------------------------------------ shared analysis helpers
def _groups(alerts):
    g: dict = {}
    for a in alerts:
        g.setdefault(a["id"], []).append(a)
    order = {r: i for i, r in enumerate(RISK_ORDER)}
    return sorted(g.values(), key=lambda v: (order[v[0]["risk"]], v[0]["id"]))


def _ai_confidence(res: dict) -> dict:
    geo = {"High": 0, "Medium": 0, "Low": 0, "None": 0}
    pfs = {"High": 0, "Medium": 0, "Low": 0, "None": 0}
    win = sing = ood = 0
    for t in res["tunnels"]:
        for c in t["child_sas"]:
            geo[c["geometry"].get("confidence") or "None"] = geo.get(c["geometry"].get("confidence") or "None", 0) + 1
        pfs[t["pfs"].get("confidence") or "None"] = pfs.get(t["pfs"].get("confidence") or "None", 0) + 1
        s = (t.get("traffic") or {}).get("summary") or {}
        win += s.get("windows", 0) or 0
        sing += round((s.get("singleton_sets") or 0) * (s.get("windows", 0) or 0))   # fraction -> count
        ood += s.get("ood_windows", 0) or 0
    card = res.get("model_card") or {}
    conf = card.get("conformal") or {}
    return {"geometry": geo, "pfs": pfs, "windows": win, "singleton": sing, "ood": ood,
            "coverage_target": conf.get("target_coverage") or (1 - conf.get("alpha", 0.1)),
            "coverage_test": conf.get("test_coverage") or conf.get("empirical_coverage"),
            "test_accuracy": card.get("test_accuracy"), "macro_f1": card.get("macro_f1")}


def _tunnel_line(t):
    ic = (t.get("ike_crypto") or {}).get("names") or {}
    ike = " / ".join(x for x in (ic.get("encr"), ic.get("prf"), ic.get("group")) if x) or "-"
    if ic.get("addke"):
        ike += " + " + ", ".join(ic["addke"])
    esp = (t.get("posture") or {}).get("esp_label") or "-"
    return ike, esp


def _pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "-"


# ------------------------------------------------------------------ executive
def render_executive(res: dict, meta: dict) -> bytes:
    buf = io.BytesIO()
    doc = _doc(buf, "Nunmathi Executive Summary")
    g = res["grade"]
    risk = g.get("risk_score", 100 - g["score"])
    alerts = res["alerts"]
    counts = {r: sum(a["risk"] == r for a in alerts) for r in RISK_ORDER}
    f = res["file"]
    story = [P("Nunmathi - Executive Summary", "h1"),
             P(f"Capture <b>{html.escape(_a(meta.get('name')))}</b> - {f.get('frames')} frames, "
               f"{len(res['tunnels'])} IPsec tunnel(s), {_ts(f.get('first_ts'))} to {_ts(f.get('last_ts'))}. "
               f"Report generated {_ts(time.time())}.", "muted", raw=True), Spacer(1, 6)]
    worst = min(res["tunnels"], key=lambda t: t["grade"]["score"]) if res["tunnels"] else None
    verdict = {"A+": "The observed VPN configuration meets current best practice.",
               "A": "The observed VPN configuration is strong with minor hygiene items.",
               "B": "The VPN is sound but has medium-risk configuration gaps that should be scheduled for fixing.",
               "C": "At least one high-risk weakness exposes tunnel traffic or credentials and needs prompt action.",
               "D": "Several high-risk weaknesses were found; the VPN should be treated as partially exposed.",
               "F": "The VPN protection is materially broken; remediate before relying on it for sensitive data."}
    msg = verdict.get(g["letter"], "")
    if worst is not None and len(res["tunnels"]) > 1:
        msg += f" The overall grade is set by the weakest tunnel, {worst['id']} ({worst['initiator']} -> {worst['responder']})."
    head = Table([[grade_badge(g["letter"], g["score"]),
                   [P("Overall grade and risk", "h3"), P(msg), Spacer(1, 4), P("Risk score (0 = no risk, 100 = critical)",
                                                                              "muted"), risk_gauge(risk, 95 * mm)],
                   table([["Risk", "Findings"]] + [[r, str(counts[r])] for r in RISK_ORDER], [24 * mm, 16 * mm],
                         style=[("TEXTCOLOR", (0, i), (0, i), colors.HexColor(RISK_HEX[r]))
                                for i, r in enumerate(RISK_ORDER, 1)])]],
                 colWidths=[40 * mm, 100 * mm, W - 140 * mm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [head, Spacer(1, 8), P("Tunnels", "h2")]
    rows = [["Tunnel", "Peers", "IKE", "ESP", "PFS", "Grade", "Risk"]]
    for t in res["tunnels"][:12]:
        ike, esp = _tunnel_line(t)
        rows.append([t["id"], f"{t['initiator']} -> {t['responder']}", f"IKEv{t['version']} {ike}", esp,
                     t["pfs"]["status"], t["grade"]["letter"], str(t["grade"].get("risk_score", 100 - t['grade']['score']))])
    if len(res["tunnels"]) > 12:
        rows.append(["...", f"{len(res['tunnels']) - 12} more tunnels in the technical report", "", "", "", "", ""])
    story.append(table(rows, [12 * mm, 36 * mm, 50 * mm, 34 * mm, 15 * mm, 12 * mm, W - 159 * mm]))

    story.append(P("Top risks", "h2"))
    top = [grp for grp in _groups(alerts) if grp[0]["risk"] != "Informational"][:6]
    if not top:
        story.append(P("No findings above Informational level."))
    rows = [["Risk", "Finding", "Business impact", "Fix"]]
    for grp in top:
        a = grp[0]
        tun = sorted({x["tunnel"] for x in grp if x["tunnel"]})
        rows.append([a["risk"], f"{a['name']} ({a['id']}){' - ' + ', '.join(tun) if tun else ''}",
                     a["description"], a["solution"]])
    if top:
        story.append(table(rows, [16 * mm, 45 * mm, 60 * mm, W - 121 * mm],
                           style=[("TEXTCOLOR", (0, i), (0, i), colors.HexColor(RISK_HEX[grp[0]["risk"]]))
                                  for i, grp in enumerate(top, 1)]))

    ai = _ai_confidence(res)
    story.append(PageBreak())
    story.append(P("How confident is the analysis?", "h2"))
    geo_total = sum(ai["geometry"].values())
    rows = [["Inference", "Result", "Meaning"],
            ["ESP cipher geometry (L2)",
             f"{ai['geometry'].get('High', 0)}/{geo_total} SAs High, {ai['geometry'].get('Medium', 0)} Medium",
             "Arithmetic proof over observed packet lengths; High means every alternative was refuted."],
            ["PFS on rekey (L2)", f"{ai['pfs'].get('High', 0)}/{len(res['tunnels'])} tunnels High",
             "Size of CREATE_CHILD_SA messages shows whether a new key exchange ran."],
            ["Traffic type (L3 ML)",
             f"{ai['windows']} windows, {_pct(ai['singleton'], ai['windows'])} single-label, "
             f"{ai['ood']} out-of-distribution",
             f"Split-conformal prediction sets with {100 * (ai['coverage_target'] or 0.9):.0f}% target coverage; "
             f"model test accuracy {ai['test_accuracy']} on synthetic data."]]
    story.append(table(rows, [36 * mm, 52 * mm, W - 88 * mm]))

    story.append(P("Recommended actions", "h2"))
    rows = [["Tunnel", "Change", "Grade now", "Predicted after"]]
    for t in sorted(res["tunnels"], key=lambda t: t["grade"]["score"])[:6]:
        if not t.get("recommended"):
            continue
        w = assess.what_if(t["posture"], t["recommended"], t["id"], t)
        rows.append([t["id"], "; ".join(w["labels"]), t["grade"]["letter"],
                     f"{w['after']['grade']['letter']} (resolves {', '.join(w['resolved']) or '-'})"])
    if len(rows) > 1:
        story.append(table(rows, [14 * mm, 90 * mm, 18 * mm, W - 122 * mm]))
        story.append(P("Predictions come from the What-if digital twin; use 'Apply recommendation' in the dashboard to "
                       "rebuild the tunnel in the IPsecForge testbed and verify the new grade on a re-captured twin.",
                       "muted"))
    else:
        story.append(P("No configuration changes are recommended."))
    hits = res.get("attack", {}).get("hit_techniques") or []
    if hits:
        story.append(P("Adversary techniques enabled (MITRE ATT&CK)", "h2"))
        story.append(P(", ".join(f"{t} {attack.TECHNIQUES[t][0]}" for t in hits if t in attack.TECHNIQUES)))
    story.append(P("Metadata exposure", "h2"))
    rows = [["Tunnel", "MEI (0 hidden - 1 exposed)", "Dominant traffic", "TFC padding"]]
    for t in res["tunnels"][:10]:
        s_ = (t.get("traffic") or {}).get("summary") or {}
        cw = s_.get("class_windows") or {}
        rows.append([t["id"], str(s_.get("mei_mean")), max(cw, key=cw.get) if cw else "-",
                     "yes" if t["posture"].get("tfc_padding") else "no"])
    story.append(table(rows, [20 * mm, 50 * mm, 40 * mm, W - 110 * mm]))
    story.append(P("Next steps", "h2"))
    for x in ["Assign each High finding an owner and fix date; they cap the grade at C.",
              "Apply the recommended changes in a maintenance window, then re-capture 2-3 rekey intervals and "
              "re-run Nunmathi to confirm the new grade on the real network.",
              "Hand the technical report (vendor snippets for strongSwan, Libreswan and Cisco IOS) to the network team "
              "and the JSON export to the SIEM/SOAR pipeline."]:
        story.append(P("- " + x))
    story.append(Spacer(1, 6))
    story.append(P("Scope: passive analysis of captured IKE/ESP headers and packet metadata. No keys were used and no "
                   "traffic was decrypted. Traffic-type labels come from a model trained on synthetic traffic and are "
                   "indicative. Full evidence, proofs and vendor configuration are in the technical report.", "muted"))
    doc.build(story, onFirstPage=_page_deco("Executive Summary", meta), onLaterPages=_page_deco("Executive Summary", meta))
    return buf.getvalue()


# ------------------------------------------------------------------ technical
METHOD = [
    ("L1 - Parsing", "pcap/pcapng frames are decoded (Ethernet, Linux SLL/SLL2, raw IP, 802.1Q, IPv4/IPv6). IKE on "
     "UDP 500/4500 is parsed payload by payload (IKEv1 and IKEv2, including RFC 7383 fragments and RFC 9242 "
     "IKE_INTERMEDIATE). ESP is recognised on IP protocol 50 and in UDP-encapsulated form (RFC 3948). Messages are "
     "grouped into IKE SAs by SPI pair and Child SAs by ESP SPI pair."),
    ("L2 - Geometry solver with proofs", "An ESP packet's length is 8 (SPI+sequence) + IV + padded plaintext + ICV, "
     "where the padded plaintext is a multiple of the cipher block B. Every observed length L must therefore satisfy "
     "L = 8 + IV + ICV (mod B). Each candidate cipher family is tested against every distinct length: one "
     "counterexample refutes it, and the refutation is recorded. The coarsest block that survives wins; the chance "
     "that k distinct lengths share one residue by accident is bounded by 0.5^(k-1). Tunnel versus transport mode "
     "is inferred from an upper bound on the smallest inner packet."),
    ("L2 - Rekey and PFS", "Child SA and IKE SA rekeys are located in the encrypted CREATE_CHILD_SA exchange. The "
     "SK payload size minus the expected nonce/SA/TS overhead reveals whether a KE payload is present (PFS) and its "
     "size identifies the group. Rekey intervals give the configured lifetimes."),
    ("L3 - ML with conformal confidence", "ESP packets are cut into 5-second windows per tunnel. 34 size, timing and "
     "burst features are fed to a gradient-boosted classifier (voip, video, web, chat, email). Split-conformal "
     "calibration turns scores into prediction sets with a guaranteed 90% marginal coverage; a k-NN distance test "
     "flags out-of-distribution windows. Shapley values (antithetic permutation sampling against a background drawn "
     "from the training distribution) explain each decision. The Metadata Exposure Index (MEI) is the classifier's "
     "top-class probability normalised against chance: 0 means the traffic type cannot be told apart, 1 means it is "
     "fully exposed."),
    ("Assessment", "The posture of each tunnel is checked against the rule catalogue (Appendix C), which cites "
     "RFC 8247, RFC 8221, RFC 7296, RFC 9395, RFC 4303 and NIST SP 800-77r1. Penalties: High 25, Medium 10, Low 3. "
     "A High finding caps the grade at C, three or more cap it at F; the capture grade is that of the weakest tunnel "
     "and the risk score is 100 minus the score. Findings are mapped to MITRE ATT&CK techniques."),
    ("What-if twin and verification", "Recommended changes are applied to the posture symbolically (predicted grade). "
     "'Apply recommendation' then rebuilds the observed and the hardened configuration in the IPsecForge testbed "
     "with the same seed and traffic mix, captures both, and re-runs the full pipeline, so the new grade is measured "
     "rather than assumed."),
]


def _hexdump(data: bytes, limit: int = 128) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}  {hx:<47}  {asc}")
    if len(data) > limit:
        out.append(f"...   ({len(data) - limit} more bytes)")
    return "\n".join(out)


def _frames(path: str | None, wanted: set[int]) -> dict[int, bytes]:
    if not path or not wanted:
        return {}
    from .pcap import iter_frames
    got = {}
    try:
        with open(path, "rb") as fh:
            for i, fr in enumerate(iter_frames(fh), 1):
                if i in wanted:
                    got[i] = fr.data
                    if len(got) == len(wanted):
                        break
    except OSError:
        pass
    return got


def _tunnel_section(t: dict, res: dict, story: list, idx: int, detail: str, frames: dict) -> None:
    """detail: full | compact"""
    ike, esp = _tunnel_line(t)
    lt, p = t["lifetimes"], t["posture"]
    story.append(PageBreak())
    story.append(P(f"{idx}. Tunnel {t['id']}: {t['initiator']} -> {t['responder']}", "h1"))
    mode = p.get("mode") or {}
    story.append(Table([[grade_badge(t["grade"]["letter"], t["grade"]["score"], 26 * mm), kv([
        ("IKE", f"IKEv{t['version']} {ike}"),
        ("ESP", f"{esp} (geometry confidence {p.get('esp_confidence')})"),
        ("Mode", f"{mode.get('mode', '-')} ({mode.get('confidence', '-')}) - {mode.get('reason', '')}"),
        ("PFS", f"{t['pfs']['status']} {t['pfs'].get('group') or ''} (confidence {t['pfs']['confidence']}, "
                f"{t['pfs'].get('evidence', 0)} rekey(s) of evidence)"),
        ("Lifetimes", f"Child {_dur(lt['child_rekey_interval']) if lt['child_rekey_interval'] else '> ' + _dur(lt['child_lower_bound'])}"
                      f", IKE {_dur(lt['ike_rekey_interval']) if lt['ike_rekey_interval'] else '> ' + _dur(lt['ike_lower_bound'])}"),
        ("Traffic", f"{t['esp_packets']} ESP packets, {_bytes(t['esp_bytes'])}, observed {_dur(lt['observed_seconds'])}"),
        ("NAT-T / DPD / Frag", f"NAT {'yes' if t['nat_t'] else 'no'}, DPD {_dur(t['dpd_interval']) if t['dpd_interval'] else 'not seen'}, "
                                f"fragmentation {'yes' if p.get('fragmentation') else 'no'}, TFC padding {'yes' if p.get('tfc_padding') else 'no'}"),
        ("Vendor IDs", ", ".join(p.get("vendor_ids") or []) or "none"),
    ], 30 * mm)]], colWidths=[30 * mm, W - 30 * mm], style=[("VALIGN", (0, 0), (-1, -1), "TOP"),
                                                        ("LEFTPADDING", (0, 0), (-1, -1), 0)]))

    # IKE ladder
    story.append(P(f"{idx}.1 IKE exchange ladder", "h2"))
    msgs = [m for sa in t["ike_sas"] for m in sa.get("ladder", [])]
    msgs.sort(key=lambda m: m["t"])
    n_draw = 28 if detail == "full" else 14
    story.append(P(f"{len(msgs)} IKE messages across {len(t['ike_sas'])} IKE SA(s). Payload names in encrypted "
                   "messages are inferred from the exchange type and SK length (marked by the solver, not decrypted).",
                   "muted"))
    story.append(ladder_drawing(t, msgs[:n_draw]))
    if len(msgs) > n_draw:
        rows = [["#", "Time", "Dir", "Exchange", "mid", "Len", "Payloads / inferred"]]
        for m in msgs[n_draw:n_draw + (24 if detail == "full" else 10)]:
            rows.append([str(m["packet"]), f"+{m['t'] - t['first_ts']:.2f}s", "I->R" if m["from_initiator"] else "R->I",
                         f"{m['exchange']} {'resp' if m['response'] else 'req'}", str(m["msgid"]), str(m["length"]),
                         ", ".join(m.get("payloads") or []) or m.get("inferred") or ""])
        story.append(table(rows, [10 * mm, 16 * mm, 10 * mm, 34 * mm, 9 * mm, 10 * mm, W - 89 * mm], font="tiny"))
        if len(msgs) > len(rows) - 1 + n_draw:
            story.append(P(f"{len(msgs) - len(rows) + 1 - n_draw} further messages (mostly liveness checks) are in the "
                           "JSON export and the dashboard ladder.", "muted"))

    # IKE SAs + proposals
    rows = [["IKE SA (SPIi/SPIr)", "Origin", "Msgs", "Chosen", "Offered", "Identities"]]
    for sa in t["ike_sas"]:
        ch = sa.get("chosen") or {}
        chosen = " / ".join(str(v) for v in (ch.get("names") or ch).values() if v) if isinstance(ch, dict) else str(ch)
        off = "; ".join(" / ".join(str(v) for v in (o.get("names") or o).values() if v) if isinstance(o, dict) else str(o)
                        for o in (sa.get("offered") or [])[:4])
        ids = ", ".join(f"{i.get('type')}: {i.get('value')}" if isinstance(i, dict) else str(i)
                        for i in sa.get("identities") or []) or "encrypted"
        rows.append([f"{sa['ispi']}/{sa['rspi']}", sa["origin"], str(sa["messages"]), chosen[:120], off[:200], ids])
    story.append(Spacer(1, 4))
    story.append(table(rows, [34 * mm, 22 * mm, 10 * mm, 38 * mm, 42 * mm, W - 146 * mm], font="tiny"))

    # SA inspector
    story.append(CondPageBreak(90 * mm))
    story.append(P(f"{idx}.2 SA inspector: ESP geometry proofs", "h2"))
    shown = t["child_sas"] if detail == "full" else t["child_sas"][:2]
    shown = shown[:6]
    for ch in shown:
        geo = ch["geometry"]
        best = geo.get("best") or {}
        block = [P(f"Child SA {ch['id']} - SPI {ch['spi_out'] or '-'} / {ch['spi_in'] or '-'} - {ch['packets']} packets, "
                   f"{_bytes(ch['bytes'])}", "h3"),
                 P(f"Result: <b>{html.escape(_a(best.get('label', '?')))}</b> - confidence {geo.get('confidence')}, "
                   f"{geo.get('distinct_lengths')} distinct lengths, P(spurious) <= {geo.get('p_spurious')}", raw=True)]
        if geo.get("length_hist"):
            block.append(length_histogram(geo["length_hist"], height=48))
        rows = [["Hypothesis", "Claim", "Verdict", "Reason"]]
        for s in geo.get("proof") or []:
            rows.append([s.get("label") or s["hypothesis"], s.get("claim", ""), s.get("verdict", ""), s.get("reason", "")])
        vcol = [("TEXTCOLOR", (2, i), (2, i), colors.HexColor("#c62828" if r[2] == "rejected" else "#1b7f3b"))
                for i, r in enumerate(rows) if i and r[2] in ("rejected", "consistent")]
        block.append(table(rows, [38 * mm, 50 * mm, 16 * mm, W - 104 * mm], font="tiny", style=vcol))
        m = geo.get("mode") or {}
        if m:
            block.append(P(f"Mode: {m.get('mode')} ({m.get('confidence')}) - {m.get('reason')}", "small"))
        story.append(KeepTogether(block[:3]))
        story += block[3:]
    if len(t["child_sas"]) > len(shown):
        rest = t["child_sas"][len(shown):]
        story.append(P(f"{len(rest)} further Child SA(s):", "small"))
        rows = [["Child SA", "SPIs", "Packets", "Geometry", "Confidence"]]
        rows += [[c["id"], f"{c['spi_out']}/{c['spi_in']}", str(c["packets"]),
                  (c["geometry"].get("best") or {}).get("label", "?"), c["geometry"].get("confidence")] for c in rest[:30]]
        story.append(table(rows, [18 * mm, 40 * mm, 16 * mm, 70 * mm, W - 144 * mm], font="tiny"))

    # rekey timeline + PFS
    story.append(CondPageBreak(70 * mm))
    story.append(P(f"{idx}.3 Rekey timeline and PFS evidence", "h2"))
    story.append(rekey_timeline(t))
    rows = [["Time", "Kind", "Packet", "SK len", "Est. plaintext", "KE delta", "PFS", "Group", "Confidence"]]
    for e in t.get("rekey_events", [])[:40 if detail == "full" else 10]:
        rows.append([f"+{e['t'] - t['first_ts']:.1f}s", e["kind"], str(e.get("packet")), str(e.get("sk_len")),
                     str(e.get("plain_est")), str(e.get("delta")), "yes" if e.get("pfs") else "no",
                     e.get("pfs_group") or "-", e.get("confidence")])
    if len(rows) > 1:
        story.append(table(rows, [16 * mm, 24 * mm, 14 * mm, 14 * mm, 20 * mm, 16 * mm, 10 * mm, 20 * mm, W - 134 * mm],
                           font="tiny"))
    story.append(P(f"Child rekey interval {lt['child_rekey_interval']} s (range {lt.get('child_rekey_range')}), "
                   f"{lt['child_rekeys']} rekeys; IKE rekey interval {lt['ike_rekey_interval']} s "
                   f"(range {lt.get('ike_rekey_range')}), {lt['ike_rekeys']} rekeys.", "small"))

    # traffic + SHAP
    tr = t.get("traffic") or {}
    s = tr.get("summary") or {}
    story.append(CondPageBreak(80 * mm))
    story.append(P(f"{idx}.4 Traffic inference timeline and explanation", "h2"))
    story.append(P(f"{s.get('windows', 0)} windows; classes {', '.join(f'{k} {v}' for k, v in (s.get('class_windows') or {}).items() if v) or '-'}; "
                   f"MEI mean {s.get('mei_mean')}, p90 {s.get('mei_p90')}; {100 * (s.get('singleton_sets') or 0):.0f}% single-label "
                   f"prediction sets; {s.get('ood_windows', 0)} out-of-distribution windows.", "small"))
    story.append(segments_drawing(t))
    wins = tr.get("windows") or []
    if wins:
        step = max(1, len(wins) // (16 if detail == "full" else 8))
        rows = [["Start", "Pkts", "Label", "Conformal set", "p(label)", "MEI", "OOD"]]
        for w in wins[::step][:16 if detail == "full" else 8]:
            rows.append([f"+{float(w['start']) - t['first_ts']:.0f}s", str(w["packets"]), w["label"],
                         "{" + ", ".join(w["set"]) + "}", f"{w['probs'].get(w['label'], 0):.3f}", f"{float(w['mei']):.3f}",
                         "yes" if w.get("ood") else "no"])
        story.append(table(rows, [16 * mm, 12 * mm, 16 * mm, 50 * mm, 18 * mm, 16 * mm, W - 128 * mm], font="tiny"))
        try:
            ex = explain.explain_tunnel(wins, max_windows=8 if detail == "full" else 4)
        except Exception:  # noqa: BLE001 - explanation is best-effort in the report
            ex = None
        if ex and ex.get("features"):
            story.append(P(f"Global explanation: mean |Shapley value| over {ex['windows']} windows ({ex['method']}).",
                           "small"))
            story.append(bars([(f["feature"], f["mean_abs_phi"], "#2b6cb0") for f in ex["features"][:12]]))
            if detail == "full":
                w0 = max((w for w in wins if w.get("x")), key=lambda w: w["probs"].get(w["label"], 0), default=None)
                if w0:
                    e1 = explain.explain_window(w0, top=10)
                    story.append(P(f"Local explanation of the most confident window (+{float(w0['start']) - t['first_ts']:.0f}s, "
                                   f"{e1['label']}): base value {e1['base_value']}, prediction {e1['prediction']}, "
                                   f"sum of phi {e1['sum_phi']} (efficiency: base + sum = prediction).", "small"))
                    story.append(bars([(f"{f['feature']} = {f['value']}", f["phi"],
                                        "#2e7d32" if f["phi"] >= 0 else "#c62828") for f in e1["features"]],
                                      signed=True, fmt="{:+.4f}"))

    # findings
    story.append(CondPageBreak(60 * mm))
    story.append(P(f"{idx}.5 Findings", "h2"))
    al = [a for a in res["alerts"] if a["tunnel"] == t["id"]]
    if not al:
        story.append(P("No findings."))
    for a in sorted(al, key=lambda a: RISK_ORDER.index(a["risk"])):
        rows = [[P(f"{a['risk']} - {a['id']} {a['name']}", "headc"), ""],
                ["Evidence", a["evidence"]], ["Confidence", a["confidence"]],
                ["Standards", "; ".join(a.get("standards") or []) or "-"],
                ["ATT&CK", "; ".join(f"{x['id']} {x['name']}" for x in a.get("attack") or []) or "not mapped"],
                ["Solution", a["solution"]]]
        tt = table(rows, [26 * mm, W - 26 * mm], header=False, zebra=False,
                   style=[("SPAN", (0, 0), (-1, 0)), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(RISK_HEX[a["risk"]])),
                          ("BACKGROUND", (0, 1), (0, -1), TINT)])
        story += [KeepTogether([tt]), Spacer(1, 4)]

    # remediation
    story.append(CondPageBreak(90 * mm))
    story.append(P(f"{idx}.6 Remediation and vendor configuration", "h2"))
    changes = t.get("recommended") or []
    w = assess.what_if(t["posture"], changes, t["id"], t)
    if changes:
        story.append(P(f"Recommended: {'; '.join(w['labels'])}. Predicted grade {t['grade']['letter']} -> "
                       f"{w['after']['grade']['letter']}; resolves {', '.join(w['resolved']) or '-'}.", "small"))
        c = w.get("cost") or {}
        if c:
            story.append(P("Estimated cost: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in c.items()
                                                           if not isinstance(v, (dict, list))), "small"))
    else:
        story.append(P("No changes recommended; the snippets reproduce the observed configuration.", "small"))
    cfg = w["config"]
    for name, key in (("strongSwan (swanctl.conf)", "strongswan"), ("Libreswan (ipsec.conf)", "libreswan"),
                      ("Cisco IOS / IOS-XE", "cisco_ios")):
        if cfg.get(key):
            story.append(KeepTogether([P(name, "h3"), Preformatted(_a(cfg[key]), S["code"])]))

    # evidence packets
    if frames and detail == "full":
        story.append(CondPageBreak(60 * mm))
        story.append(P(f"{idx}.7 Evidence packets", "h2"))
        for num, why in _evidence_picks(t):
            if num in frames:
                story.append(KeepTogether([P(f"Frame {num} - {why}", "h3"),
                                           Preformatted(_hexdump(frames[num]), S["code"])]))


def _evidence_picks(t: dict) -> list[tuple[int, str]]:
    picks = []
    msgs = sorted((m for sa in t["ike_sas"] for m in sa.get("ladder", [])), key=lambda m: m["t"])
    for m in msgs:
        if m["exchange"] in ("IKE_SA_INIT", "Main Mode", "Aggressive Mode", "Identity Protection", "Aggressive") \
                and len(picks) < 2:
            picks.append((m["packet"], f"{m['exchange']} {'response' if m['response'] else 'request'} "
                                       f"(proposal, key exchange; cleartext)"))
    for e in t.get("rekey_events", [])[:1]:
        if e.get("packet"):
            picks.append((e["packet"], f"{e['kind']}: SK length {e.get('sk_len')} B -> PFS "
                                       f"{'yes' if e.get('pfs') else 'no'} {e.get('pfs_group') or ''}"))
    for ch in t["child_sas"][:2]:
        for n in (ch.get("first_packets") or [])[:1]:
            picks.append((n, f"first ESP packet of {ch['id']} (length used by the geometry proof)"))
    return picks


MIN_TECH_PAGES = 15


def render_technical(res: dict, meta: dict, capture_path: str | None = None) -> bytes:
    """15-30 page technical report. Short captures get Appendix E (hardened baselines) to stay complete."""
    data, pages = _render_technical(res, meta, capture_path, baseline=False)
    if pages < MIN_TECH_PAGES:
        data, pages = _render_technical(res, meta, capture_path, baseline=True)
    return data


def _baseline_appendix(tunnels: list[dict]) -> list:
    out = [PageBreak(), P("Appendix E. Hardened reference baseline and re-test checklist", "h1"),
           P("The configuration below applies every recommendation Nunmathi can make to the lowest-graded tunnel "
             "(IKEv2 with fragmentation, AEAD ciphers, PFS, 1 h Child SA and 8 h IKE SA lifetimes, no vendor IDs, "
             "TFC padding). Adapt identities, addresses and authentication to the site before deployment.")]
    t = tunnels[0] if tunnels else None
    base = assess.apply_changes(t["posture"], [c for c in assess.CHANGES if c != "pq_hybrid"]) if t else {}
    snips = assess.config_snippets(base)
    for key, title in (("strongswan", "strongSwan (swanctl.conf)"), ("libreswan", "Libreswan (ipsec.conf)"),
                       ("cisco_ios", "Cisco IOS / IOS-XE")):
        out.append(KeepTogether([P(title, "h3"), Preformatted(_a(snips[key]), S["code"])]))
    out += [P("Re-test checklist", "h2"),
            P("After the change window, capture at least one Child SA lifetime plus one rekey (about 70 minutes) "
              "on the same SPAN/TAP and upload it. Each control is confirmed passively as follows:", "small")]
    rows = [["Control", "Passive evidence Nunmathi checks", "Rules cleared"],
            ["IKEv2 only", "Exchange types 34-37 only; no Main/Aggressive Mode", "NM-100, NM-101, NM-102"],
            ["Strong IKE suite", "Decoded SA payload: AEAD or SHA-2 PRF, group 19/20/21/31", "NM-110 - NM-114"],
            ["AEAD ESP", "Geometry proof: 8-byte IV, 16-byte ICV, 4-byte alignment", "NM-120 - NM-122"],
            ["PFS", "CREATE_CHILD_SA rekeys carry a KE payload (SK length step)", "NM-130"],
            ["Lifetimes", "Measured rekey intervals <= 1 h (Child) and <= 8 h (IKE)", "NM-131, NM-132"],
            ["Fragmentation", "IKEV2_FRAGMENTATION_SUPPORTED notify in IKE_SA_INIT", "NM-161"],
            ["No vendor IDs", "No Vendor ID payloads in cleartext exchanges", "NM-170"],
            ["TFC padding", "Single ESP length per direction; MEI falls towards 0", "NM-150"]]
    out.append(table(rows, [30 * mm, W - 62 * mm, 32 * mm], font="small"))
    out.append(P("The same loop can be run before the change window with 'Apply recommendation' in the What-if twin, "
                 "which rebuilds the tunnel in the IPsecForge testbed, re-captures it and re-scores it.", "small"))
    return out


def _render_technical(res: dict, meta: dict, capture_path: str | None, baseline: bool) -> tuple[bytes, int]:
    buf = io.BytesIO()
    doc = _doc(buf, "Nunmathi Technical Report")
    g = res["grade"]
    f = res["file"]
    tunnels = sorted(res["tunnels"], key=lambda t: t["grade"]["score"])
    full = tunnels[:2]
    compact = tunnels[2:7]
    rest = tunnels[7:]
    wanted = {n for t in full for n, _ in _evidence_picks(t)}
    frames = _frames(capture_path, wanted)

    story = [Spacer(1, 30 * mm), P("Nunmathi", "sub"), P("IPsec VPN Technical Assessment Report", "title"),
             Spacer(1, 6), P(f"Capture: {meta.get('name')}", "sub"), Spacer(1, 14 * mm),
             Table([[grade_badge(g["letter"], g["score"], 42 * mm),
                     [P("Overall grade", "h3"), P(f"Risk score {g.get('risk_score', 100 - g['score'])}/100"),
                      risk_gauge(g.get("risk_score", 100 - g["score"]), 90 * mm)]]],
                   colWidths=[48 * mm, W - 48 * mm], style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE")]),
             Spacer(1, 14 * mm), P("Document control", "h3"),
             kv([("Analysis ID", meta.get("id")), ("Source", meta.get("source")),
                 ("Capture SHA-256", meta.get("sha256") or "-"),
                 ("Capture window", f"{_ts(f.get('first_ts'))} - {_ts(f.get('last_ts'))}"),
                 ("Frames", f"{f.get('frames')} ({f.get('ike')} IKE, {f.get('esp')} ESP, {f.get('nat_keepalive')} "
                            f"NAT-T keepalive, {f.get('other')} other), {_bytes(f.get('bytes'))}"),
                 ("Engine / schema", f"Nunmathi {res.get('engine')} / report schema {res.get('schema_version', '-')}"),
                 ("Generated", _ts(time.time())),
                 ("Classification", "Confidential - contains network addresses and configuration")]),
             PageBreak()]

    # contents
    story.append(P("Contents", "h1"))
    toc = ["1. Summary of findings", "2. Scope and methodology", "3. Capture inventory and audit log"]
    n = 4
    for t in full + compact:
        toc.append(f"{n}. Tunnel {t['id']} ({t['initiator']} -> {t['responder']}) - grade {t['grade']['letter']}")
        n += 1
    toc += [f"{n}. MITRE ATT&CK mapping", f"{n + 1}. Metadata exposure (MEI)",
            "Appendix A. Traffic model card", "Appendix B. Evidence packet index",
            "Appendix C. Rule catalogue with cited standards", "Appendix D. Limitations and glossary"]
    if baseline:
        toc.append("Appendix E. Hardened reference baseline and re-test checklist")
    story += [P(x) for x in toc]
    story.append(Spacer(1, 8))

    # 1 summary
    story.append(P("1. Summary of findings", "h1"))
    counts = {r: sum(a["risk"] == r for a in res["alerts"]) for r in RISK_ORDER}
    story.append(P(f"{len(res['tunnels'])} tunnel(s) and {len(res['alerts'])} finding(s): " +
                   ", ".join(f"{counts[r]} {r}" for r in RISK_ORDER) + "."))
    rows = [["Tunnel", "Peers", "IKE", "ESP", "PFS", "Child life", "Grade", "Risk"]]
    for t in tunnels:
        ike, esp = _tunnel_line(t)
        lt = t["lifetimes"]
        rows.append([t["id"], f"{t['initiator']} -> {t['responder']}", f"v{t['version']} {ike}", esp, t["pfs"]["status"],
                     _dur(lt["child_rekey_interval"]) if lt["child_rekey_interval"] else f"> {_dur(lt['child_lower_bound'])}",
                     t["grade"]["letter"], str(t["grade"].get("risk_score", 100 - t["grade"]["score"]))])
    story.append(table(rows, [11 * mm, 32 * mm, 46 * mm, 32 * mm, 14 * mm, 16 * mm, 11 * mm, W - 162 * mm], font="tiny"))
    story.append(Spacer(1, 6))
    rows = [["Rule", "Risk", "Finding", "Tunnels", "Standards"]]
    for grp in _groups(res["alerts"]):
        a = grp[0]
        rows.append([a["id"], a["risk"], a["name"], ", ".join(sorted({x["tunnel"] or "capture" for x in grp})),
                     "; ".join(a.get("standards") or [])])
    story.append(table(rows, [14 * mm, 18 * mm, 52 * mm, 24 * mm, W - 108 * mm], font="tiny",
                       style=[("TEXTCOLOR", (1, i), (1, i), colors.HexColor(RISK_HEX[r[1]]))
                              for i, r in enumerate(rows) if i]))
    ai = _ai_confidence(res)
    story.append(P("AI and inference confidence", "h3"))
    story.append(kv([("Geometry (L2)", ", ".join(f"{k} {v}" for k, v in ai["geometry"].items() if v) or "-"),
                     ("PFS (L2)", ", ".join(f"{k} {v}" for k, v in ai["pfs"].items() if v) or "-"),
                     ("Traffic (L3)", f"{ai['windows']} windows, {ai['singleton']} single-label sets "
                                      f"({_pct(ai['singleton'], ai['windows'])}), {ai['ood']} OOD; conformal target "
                                      f"{ai['coverage_target']}, measured {ai['coverage_test']}; test accuracy "
                                      f"{ai['test_accuracy']}, macro-F1 {ai['macro_f1']}")]))

    # 2 method
    story.append(PageBreak())
    story.append(P("2. Scope and methodology", "h1"))
    story.append(P("Nunmathi is a passive analyzer. It reads a packet capture (file upload or live SPAN/TAP) and "
                   "infers the IPsec configuration from headers and packet metadata alone. It never needs keys, "
                   "never decrypts traffic and never sends packets to the peers. The pipeline has four layers:"))
    for h, body in METHOD:
        story += [P(h, "h3"), P(body)]
    story.append(P("Grading", "h3"))
    story.append(table([["Letter", "Rule"], ["A+", "score >= 95 and no Medium or High"], ["A", "score >= 90"],
                        ["B", "score >= 80"], ["C", "score >= 65, or any High finding"], ["D", "score >= 50"],
                        ["F", "score < 50, or three or more High findings"]], [20 * mm, W - 20 * mm]))

    # 3 inventory
    story.append(PageBreak())
    story.append(P("3. Capture inventory and audit log", "h1"))
    story.append(kv([("File", meta.get("name")), ("SHA-256", meta.get("sha256") or "-"), ("Size", _bytes(meta.get("size"))),
                     ("Frames", str(f.get("frames"))), ("IKE / ESP / NAT-KA / AH / other",
                                                        f"{f.get('ike')} / {f.get('esp')} / {f.get('nat_keepalive')} / "
                                                        f"{f.get('ah')} / {f.get('other')}"),
                     ("IKE messages parsed", f"{res.get('ike_messages')} ({res.get('ike_parse_errors')} parse errors)"),
                     ("Half-open IKE attempts", str(sum(h.get("count", 1) for h in res.get("half_open") or []))),
                     ("Analysis time", f"{res.get('elapsed')} s on {(res.get('host') or {}).get('platform', '-')} "
                                       f"Python {(res.get('host') or {}).get('python', '-')}")]))
    story.append(P("Audit log", "h3"))
    rows = [["UTC time", "Elapsed", "Stage", "Detail"]]
    rows += [[e["t"], f"{e['elapsed']} s", e["stage"], e.get("detail", "")] for e in res.get("audit") or []]
    rows.append([_ts(time.time()), "-", "report", "technical PDF rendered"])
    story.append(table(rows, [44 * mm, 18 * mm, 24 * mm, W - 86 * mm], font="tiny"))
    if res.get("half_open"):
        story.append(P("Half-open IKE_SA_INIT sources", "h3"))
        rows = [["Responder", "Initiators", "Count", "Window"]]
        for h in res["half_open"][:20]:
            rows.append([h.get("responder"), ", ".join(h.get("initiators", [])[:5]) if isinstance(h.get("initiators"), list)
                         else str(h.get("initiator", "")), str(h.get("count")), str(h.get("window", ""))])
        story.append(table(rows, [34 * mm, 80 * mm, 16 * mm, W - 130 * mm], font="tiny"))

    n = 4
    for t in full:
        _tunnel_section(t, res, story, n, "full", frames)
        n += 1
    for t in compact:
        _tunnel_section(t, res, story, n, "compact", {})
        n += 1
    if rest:
        story.append(P(f"{len(rest)} further tunnel(s) are summarised in section 1 and in the JSON export.", "muted"))

    # ATT&CK
    story.append(PageBreak())
    story.append(P(f"{n}. MITRE ATT&CK mapping", "h1"))
    mx = res.get("attack") or attack.matrix(res["alerts"])
    story.append(P(f"{mx['version']}. A technique is marked when at least one finding enables it; the mapping is "
                   "conservative and hygiene rules are left unmapped.", "small"))
    rows = [["Tactic", "Technique", "Status", "Findings", "Rationale"]]
    stl = []
    for col in mx["tactics"]:
        for tq in col["techniques"]:
            hit = bool(tq["alerts"])
            rows.append([f"{col['id']} {col['name']}", f"{tq['id']} {tq['name']}",
                         tq["max_risk"] if hit else "not observed",
                         ", ".join(sorted({f"{a['id']}/{a['tunnel'] or '-'}" for a in tq["alerts"]})) or "-", tq["why"]])
            if hit:
                stl.append(("BACKGROUND", (2, len(rows) - 1), (2, len(rows) - 1), colors.HexColor(RISK_HEX[tq["max_risk"]])))
                stl.append(("TEXTCOLOR", (2, len(rows) - 1), (2, len(rows) - 1), colors.white))
    story.append(table(rows, [30 * mm, 42 * mm, 18 * mm, 30 * mm, W - 120 * mm], font="tiny", style=stl))
    if mx.get("unmapped_rules"):
        story.append(P("Findings without an ATT&CK technique: " + ", ".join(mx["unmapped_rules"]), "small"))

    # MEI
    story.append(P(f"{n + 1}. Metadata exposure (MEI)", "h1"))
    story.append(P("MEI measures how well an on-path observer can tell what kind of application runs inside the "
                   "tunnel. It is computed per window from the classifier's probabilities; 0 = indistinguishable, "
                   "1 = fully identifiable. TFC padding and traffic shaping lower it."))
    items = []
    for t in tunnels[:20]:
        s = (t.get("traffic") or {}).get("summary") or {}
        if s.get("mei_mean") is not None:
            v = float(s["mei_mean"])
            items.append((f"{t['id']} {t['initiator']}", v, "#c62828" if v >= 0.7 else "#f9a825" if v >= 0.4 else "#2e9e4f"))
    if items:
        story.append(bars(items, fmt="{:.2f}"))
    rows = [["Tunnel", "MEI mean", "MEI p90", "Windows", "Dominant class", "TFC padding"]]
    for t in tunnels[:20]:
        s = (t.get("traffic") or {}).get("summary") or {}
        cw = s.get("class_windows") or {}
        dom = max(cw, key=cw.get) if cw else "-"
        rows.append([t["id"], str(s.get("mei_mean")), str(s.get("mei_p90")), str(s.get("windows")), dom,
                     "yes" if t["posture"].get("tfc_padding") else "no"])
    story.append(table(rows, [20 * mm, 22 * mm, 22 * mm, 20 * mm, 30 * mm, W - 134 * mm]))

    # Appendix A model card
    story.append(PageBreak())
    story.append(P("Appendix A. Traffic model card", "h1"))
    card = res.get("model_card") or {}
    story.append(kv([(k.replace("_", " ").capitalize(), str(v) if not isinstance(v, (dict, list)) else
                      ", ".join(f"{a}: {b}" for a, b in v.items()) if isinstance(v, dict) else ", ".join(map(str, v)))
                     for k, v in card.items() if k not in ("confusion_matrix", "per_class", "features", "limitations")]))
    if card.get("per_class"):
        pc = card["per_class"]
        rows = [["Class"] + list(next(iter(pc.values())).keys())]
        rows += [[c] + [str(v) for v in d.values()] for c, d in pc.items()]
        story.append(Spacer(1, 4))
        story.append(table(rows, [30 * mm] + [(W - 30 * mm) / (len(rows[0]) - 1)] * (len(rows[0]) - 1)))
    if card.get("confusion_matrix"):
        cm = card["confusion_matrix"]
        cls = card.get("classes") or []
        story.append(P("Confusion matrix (rows = true class, columns = predicted)", "h3"))
        story.append(table([[""] + cls] + [[c] + [str(x) for x in r] for c, r in zip(cls, cm)],
                           [24 * mm] + [18 * mm] * len(cls)))
    if card.get("features"):
        story.append(P("Features", "h3"))
        story.append(P(", ".join(card["features"]), "small"))
    if card.get("limitations"):
        story.append(P("Limitations", "h3"))
        lim = card["limitations"]
        for x in (lim if isinstance(lim, list) else [lim]):
            story.append(P("- " + str(x), "small"))

    # Appendix B evidence index
    story.append(P("Appendix B. Evidence packet index", "h1"))
    story.append(P("Frame numbers are 1-based positions in the capture, matching Wireshark's frame.number. Hex dumps of "
                   "the key frames appear in each tunnel's evidence section.", "small"))
    rows = [["Tunnel", "Frame", "Evidence"]]
    for t in tunnels[:8]:
        for num, why in _evidence_picks(t):
            rows.append([t["id"], str(num), why])
        for a in [a for a in res["alerts"] if a["tunnel"] == t["id"]]:
            pk = (a.get("params") or {}).get("packets") or (a.get("params") or {}).get("packet")
            if pk:
                rows.append([t["id"], str(pk), f"{a['id']} {a['name']}"])
    story.append(table(rows, [18 * mm, 18 * mm, W - 36 * mm], font="tiny"))

    # Appendix C rule catalogue
    story.append(PageBreak())
    story.append(P("Appendix C. Rule catalogue with cited standards", "h1"))
    rows = [["Rule", "Name", "What is checked", "Standards", "Remediation", "ATT&CK"]]
    for rid, (name, desc) in assess.RULES.items():
        rows.append([rid, name, desc, "; ".join(assess.STANDARDS.get(rid, []) + assess.REFERENCES.get(rid, [])),
                     assess.REMEDIATION.get(rid, ""), ", ".join(attack.RULE_MAP.get(rid, [])) or "-"])
    story.append(table(rows, [13 * mm, 28 * mm, 42 * mm, 38 * mm, 42 * mm, W - 163 * mm], font="tiny"))

    # Appendix D limitations
    story.append(P("Appendix D. Limitations and glossary", "h1"))
    for x in ["Geometry inference identifies the cipher family (block size, IV and ICV lengths), not the key length: "
              "AES-128-GCM and AES-256-GCM have identical wire geometry.",
              "Lifetimes are measured from observed rekeys; a capture shorter than one lifetime yields only a lower "
              "bound (reported as '> x').",
              "Payloads of encrypted IKE messages are inferred from exchange type and length, never decrypted.",
              "Traffic classes come from a model trained on synthetic traffic; conformal coverage is guaranteed only "
              "for data exchangeable with the calibration set, which is why OOD windows are flagged.",
              "Shapley values are Monte-Carlo estimates (antithetic permutation sampling); each value carries a "
              "standard error in the dashboard.",
              "The What-if verification loop rebuilds tunnels in the IPsecForge synthetic testbed; it verifies the "
              "analyzer-visible effect of a change, not the behaviour of a specific vendor build."]:
        story.append(P("- " + x, "small"))
    story.append(Spacer(1, 4))
    story.append(table([["Term", "Meaning"], ["SA", "Security Association (IKE SA protects negotiation, Child SA protects data)"],
                        ["PFS", "Perfect Forward Secrecy: a fresh key exchange on every rekey"],
                        ["ICV", "Integrity Check Value appended to each ESP packet"],
                        ["AEAD", "Authenticated encryption (e.g. AES-GCM) combining cipher and integrity"],
                        ["TFC", "Traffic Flow Confidentiality padding (RFC 4303 section 2.7)"],
                        ["MEI", "Metadata Exposure Index (0 hidden - 1 exposed)"],
                        ["OOD", "Out-of-distribution: unlike anything the model was trained on"],
                        ["ML-KEM", "Module-lattice KEM (FIPS 203), negotiated as an additional key exchange (RFC 9370)"]],
                       [24 * mm, W - 24 * mm]))
    if baseline:
        story += _baseline_appendix(tunnels)
    deco = _page_deco("Technical Report", meta)
    doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=deco)
    return buf.getvalue(), doc.page
