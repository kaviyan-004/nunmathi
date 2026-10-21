"""End-to-end analysis of one capture file: packets -> sessions -> traffic -> assessment."""
from __future__ import annotations

import time

import datetime as _dt
import platform

from . import assess, attack, traffic
from .pcap import read_packets
from .sessions import analyze_sessions

ENGINE_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"


def _esp_overheads(tunnel: dict, resolved: dict | None = None) -> dict[str, int]:
    out = {}
    for ch in tunnel["child_sas"]:
        geo = ch["geometry"]
        best = geo.get("best") or {}
        if best.get("family") == "AMBIGUOUS" and resolved and \
                any(h["key"] == resolved.get("key") for h in geo.get("consistent", [])):
            best = resolved      # an ambiguous SA takes the geometry a sibling SA of the tunnel resolved
        o = 8 + (best.get("icv") or 0) + 2 if best.get("key") == "null" else traffic.overhead(best)
        for s in (ch["spi_out"], ch["spi_in"]):
            if s:
                out[s] = o
    return out


def analyze_file(path: str, limit: int | None = None, progress=None) -> dict:
    t0 = time.time()
    step = progress or (lambda *_: None)
    step("reading", 5)
    packets, stats = read_packets(path, limit)
    res = analyze_packets(packets, stats, progress, t0)
    res["file"]["path"] = path
    return res


def analyze_packets(packets: list, stats: dict, progress=None, t0: float | None = None) -> dict:
    """Analyze already-decoded packets (from a file or a live capture)."""
    t0 = time.time() if t0 is None else t0
    audit: list[dict] = []

    def step(stage, pct, _outer=progress or (lambda *_: None)):
        audit.append({"t": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds"),
                      "elapsed": round(time.time() - t0, 3), "stage": stage})
        _outer(stage, pct)
    step("sessions", 30)
    sess = analyze_sessions(packets)
    step("traffic", 55)
    for t in sess["tunnels"]:
        esp = [(p.ts, p.src == t["initiator"], p.size, p.payload[:4].hex())
               for p in packets if p.kind == "ESP" and {p.src, p.dst} == set(t["peers"])]
        ovh = _esp_overheads(t, assess.tunnel_geometry(t))
        t["traffic"] = traffic.classify_tunnel(esp, ovh, 34, stats.get("first_ts") or 0.0)
    step("assessment", 80)
    alerts, per_tunnel = [], []
    for t in sess["tunnels"]:
        post = assess.posture_from_tunnel(t)
        ho = [h for h in sess["half_open"] if h["responder"] in t["peers"]]
        a = assess.evaluate(post, t["id"], ho)
        t["posture"] = post
        t["grade"] = assess.grade(a)
        t["recommended"] = assess.recommended_changes(post)
        t["alert_ids"] = [x["id"] for x in a]
        alerts += a
        per_tunnel.append(t["grade"])
    # half-open floods against responders without an established tunnel
    known = {x for t in sess["tunnels"] for x in t["peers"]}
    for h in sess["half_open"]:
        if h["responder"] not in known:
            alerts += [x for x in assess.evaluate_half_open([h])]
    overall = assess.grade(alerts) if alerts else {"score": 100, "letter": "A+", "counts": {}}
    if per_tunnel:
        worst = min(per_tunnel, key=lambda g: g["score"])
        overall = dict(overall, letter=worst["letter"], score=worst["score"])
    for i, a in enumerate(alerts, 1):
        a["uid"] = i
    step("done", 100)
    audit.append({"t": audit[-1]["t"], "elapsed": audit[-1]["elapsed"], "stage": "summary",
                  "detail": f"{stats.get('frames', len(packets))} frames, {len(sess['tunnels'])} tunnels, "
                            f"{sess['ike_messages']} IKE messages, {len(alerts)} findings"})
    return {"schema_version": SCHEMA_VERSION, "engine": ENGINE_VERSION,
            "host": {"python": platform.python_version(), "platform": platform.system()},
            "attack": attack.matrix(alerts), "audit": audit, "file": {"path": None, **stats}, "tunnels": sess["tunnels"],
            "half_open": sess["half_open"], "alerts": alerts, "grade": overall,
            "ike_messages": sess["ike_messages"], "ike_parse_errors": sess["ike_parse_errors"],
            "model_card": traffic.get_model().card, "elapsed": round(time.time() - t0, 2)}
