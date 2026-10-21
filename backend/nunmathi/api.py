"""Nunmathi REST API (FastAPI). Serves the built frontend at / when present."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import threading
from collections import OrderedDict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import assess, attack, explain, ike, live, pdfreports, report, schema, store, testbed, traffic, verify
from .analyzer import ENGINE_VERSION, analyze_file
from .forge.generator import forge
from .forge.scenarios import SCENARIOS
from .pcap import CaptureError, decode, read_frame, read_packets

MAX_UPLOAD = int(os.environ.get("NUNMATHI_MAX_UPLOAD", 200 * 1024 * 1024))
FRONTEND = os.path.abspath(os.environ.get(
    "NUNMATHI_FRONTEND", os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")))

LIVE_ENABLED = os.environ.get("NUNMATHI_LIVE", "1") != "0"


@asynccontextmanager
async def _lifespan(_app):
    # a live capture interrupted by a server restart keeps its partial capture file: analyze it as a file
    for m in store.list_all():
        if m["status"] == "live" and live.get(m["id"]) is None:
            if os.path.exists(store.capture_path(m["id"])):
                store.update(m["id"], status="queued", stage="queued", error=None)
                _start(m["id"])
            else:
                store.update(m["id"], status="failed", error="live capture interrupted")
    yield
    await asyncio.to_thread(live.stop_all)


app = FastAPI(title="Nunmathi", version=ENGINE_VERSION, lifespan=_lifespan,
              description="Passive, AI-assisted IPsec VPN analyzer")


# ------------------------------------------------------------------ background jobs
def _run(aid: str) -> None:
    def prog(stage, pct):
        store.update(aid, stage=stage, progress=int(pct))
    try:
        store.update(aid, status="running")
        res = analyze_file(store.capture_path(aid), progress=prog)
        store.save_result(aid, res)
        counts = {r: sum(a["risk"] == r for a in res["alerts"]) for r in assess.RISK_ORDER}
        store.update(aid, status="done", stage="done", progress=100, grade=res["grade"]["letter"],
                     score=res["grade"]["score"], alerts=json.dumps(counts), tunnels=len(res["tunnels"]))
    except CaptureError as e:
        store.update(aid, status="failed", error=str(e))
    except Exception as e:  # noqa: BLE001 - surface any engine failure to the UI
        store.update(aid, status="failed", error=f"{type(e).__name__}: {e}")


def _start(aid: str, sync: bool = False) -> None:
    if sync:
        _run(aid)
    else:
        threading.Thread(target=_run, args=(aid,), daemon=True).start()


def _need(aid: str) -> dict:
    meta = store.get(aid)
    if not meta:
        raise HTTPException(404, "analysis not found")
    return meta


def _result(aid: str) -> tuple[dict, dict]:
    meta = _need(aid)
    res = store.load_result(aid)
    if res is None:
        raise HTTPException(409, f"analysis is {meta['status']}")
    return meta, res


# ------------------------------------------------------------------ packet cache
_pkt_cache: OrderedDict[str, list] = OrderedDict()
_pkt_lock = threading.Lock()


def _packets(aid: str) -> list:
    s = live.get(aid)
    if s is not None and s.running:
        return s.packets[:len(s.packets)]      # the growing in-memory list; never cached
    with _pkt_lock:
        if aid in _pkt_cache:
            _pkt_cache.move_to_end(aid)
            return _pkt_cache[aid]
    pkts, _ = read_packets(store.capture_path(aid))
    with _pkt_lock:
        _pkt_cache[aid] = pkts
        while len(_pkt_cache) > 4:
            _pkt_cache.popitem(last=False)
    return pkts


def _summary(p) -> dict:
    info = ""
    if p.kind == "IKE":
        try:
            m = ike.parse(p.payload)
            role = ("response" if m.response else "request") if m.version == 2 else ("encrypted" if m.encrypted else "cleartext")
            info = f"IKEv{m.version} {m.exchange_name} {role} mid={m.msgid}"
        except Exception:  # noqa: BLE001
            info = "IKE (unparsed)"
    elif p.kind == "ESP" and p.size >= 8:
        info = f"SPI=0x{p.payload[:4].hex()} seq={int.from_bytes(p.payload[4:8], 'big')}"
    elif p.kind == "NAT-KA":
        info = "NAT-T keepalive"
    return {"idx": p.idx, "ts": p.ts, "src": p.src, "dst": p.dst, "proto": p.l4, "kind": p.kind,
            "sport": p.sport, "dport": p.dport, "len": p.ip_len, "info": info}


# ------------------------------------------------------------------ routes
@app.get("/api/health")
def health():
    return {"status": "ok", "engine": ENGINE_VERSION}


@app.get("/api/scenarios")
def scenarios():
    return [{"id": k, "title": v["title"], "description": v["description"]} for k, v in SCENARIOS.items()]


@app.get("/api/analyses")
def analyses():
    return store.list_all()


@app.post("/api/analyses", status_code=201)
async def upload(request: Request, filename: str = "capture.pcap", sync: bool = False):
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_UPLOAD:
            raise HTTPException(413, f"capture larger than {MAX_UPLOAD // (1024 * 1024)} MB")
    if len(body) < 24:
        raise HTTPException(400, "empty or truncated capture")
    name = re.sub(r"[^\w.\-]+", "_", os.path.basename(filename))[:120] or "capture.pcap"
    aid = store.create(name, "upload", len(body), hashlib.sha256(body).hexdigest())
    with open(store.capture_path(aid), "wb") as fh:
        fh.write(body)
    _start(aid, sync)
    return store.get(aid)


@app.post("/api/analyses/demo/{scenario}", status_code=201)
def demo(scenario: str, sync: bool = False):
    prof = SCENARIOS.get(scenario)
    if not prof:
        raise HTTPException(404, "unknown scenario")
    aid = store.create(f"demo-{scenario}.pcap", "demo", 0, "")
    path = store.capture_path(aid)
    forge(prof, path, None, seed=prof.get("seed", 1))
    with open(path, "rb") as fh:
        data = fh.read()
    store.update(aid, size=len(data), sha256=hashlib.sha256(data).hexdigest())
    _start(aid, sync)
    return store.get(aid)


@app.get("/api/analyses/{aid}")
def status(aid: str):
    return _need(aid)


def _strip_features(res: dict) -> dict:
    """The per-window feature vectors are only needed server-side (SHAP); keep the response small."""
    out = dict(res)
    out["tunnels"] = []
    for t in res["tunnels"]:
        tr = t.get("traffic")
        if tr and tr.get("windows") and "x" in tr["windows"][0]:
            tr = dict(tr, windows=[{k: v for k, v in w.items() if k != "x"} for w in tr["windows"]])
            t = dict(t, traffic=tr)
        out["tunnels"].append(t)
    return out


@app.get("/api/analyses/{aid}/result")
def result(aid: str):
    return _strip_features(_result(aid)[1])


# ------------------------------------------------------------------ SHAP explanations
_explain_cache: OrderedDict[tuple, dict] = OrderedDict()


def _tunnel(res: dict, tid: str) -> dict:
    t = next((x for x in res["tunnels"] if x["id"] == tid), None)
    if not t:
        raise HTTPException(404, "unknown tunnel")
    return t


@app.get("/api/analyses/{aid}/tunnels/{tid}/explain")
def explain_route(aid: str, tid: str, window: int | None = None):
    _, res = _result(aid)
    t = _tunnel(res, tid)
    wins = (t.get("traffic") or {}).get("windows") or []
    key = (aid, tid, window)
    if key in _explain_cache:
        return _explain_cache[key]
    if window is None:
        out = explain.explain_tunnel(wins)
    else:
        if not 0 <= window < len(wins):
            raise HTTPException(404, "no such window")
        if not wins[window].get("x"):
            raise HTTPException(409, "this analysis predates feature capture; re-run it to get explanations")
        out = explain.explain_window(wins[window])
        out["window"] = window
    _explain_cache[key] = out
    while len(_explain_cache) > 256:
        _explain_cache.popitem(last=False)
    return out


@app.get("/api/analyses/{aid}/packets")
def packets(aid: str, offset: int = 0, limit: int = 200, kind: str | None = None):
    _result(aid)
    pk = _packets(aid)
    if kind:
        pk = [p for p in pk if p.kind == kind.upper()]
    limit = max(1, min(limit, 1000))
    return {"total": len(pk), "offset": offset, "items": [_summary(p) for p in pk[offset:offset + limit]]}


@app.get("/api/analyses/{aid}/packets/{idx}")
def packet(aid: str, idx: int):
    _result(aid)
    fr = read_frame(store.capture_path(aid), idx)
    if fr is None:
        raise HTTPException(404, "no such frame")
    p = decode(fr, idx)
    out = {"idx": idx, "ts": fr.ts, "linktype": fr.linktype, "hex": fr.data.hex(), "length": len(fr.data),
           "summary": _summary(p) if p else None,
           "layers": [{"name": n, "offset": o, "length": ln} for n, o, ln in (p.layers if p else [])],
           "ike": None, "ike_error": None}
    if p and p.kind == "IKE":
        try:
            out["ike"] = ike.parse(p.payload).to_dict()
        except Exception as e:  # noqa: BLE001
            out["ike_error"] = str(e)
    return out


class WhatIf(BaseModel):
    tunnel: str
    changes: list[str]


@app.post("/api/analyses/{aid}/whatif")
def whatif(aid: str, req: WhatIf):
    _, res = _result(aid)
    t = next((x for x in res["tunnels"] if x["id"] == req.tunnel), None)
    if not t:
        raise HTTPException(404, "unknown tunnel")
    bad = [c for c in req.changes if c not in assess.CHANGES]
    if bad:
        raise HTTPException(400, f"unknown change(s): {', '.join(bad)}")
    return assess.what_if(t["posture"], req.changes, t["id"], t)


@app.post("/api/analyses/{aid}/whatif/verify", status_code=202)
def whatif_verify(aid: str, req: WhatIf):
    """Apply recommendation: rebuild the tunnel in the testbed, re-capture, re-score (background job)."""
    _, res = _result(aid)
    t = _tunnel(res, req.tunnel)
    bad = [c for c in req.changes if c not in assess.CHANGES]
    if bad:
        raise HTTPException(400, f"unknown change(s): {', '.join(bad)}")
    if not req.changes:
        raise HTTPException(400, "choose at least one change")
    jid = verify.start(t["posture"], t, req.changes, {"analysis": aid, "tunnel": req.tunnel})
    return verify.get(jid)


@app.get("/api/verify/{jid}")
def verify_status(jid: str):
    job = verify.get(jid)
    if not job:
        raise HTTPException(404, "unknown verification job")
    return job


# ------------------------------------------------------------------ testbed
class TestbedReq(BaseModel):
    spec: str


@app.get("/api/testbed/example")
def testbed_example():
    return {"spec": testbed.EXAMPLE}


@app.post("/api/testbed/validate")
def testbed_validate(req: TestbedReq):
    try:
        v = testbed.load(req.spec)
    except testbed.SpecError as e:
        return {"valid": False, "error": str(e)}
    return {"valid": True, "name": v["name"], "duration": v["duration"], "tunnels": testbed.summary(v)}


@app.post("/api/testbed/run", status_code=201)
def testbed_run(req: TestbedReq, sync: bool = False):
    try:
        v = testbed.load(req.spec)
    except testbed.SpecError as e:
        raise HTTPException(400, str(e)) from None
    name = re.sub(r"[^\w.\-]+", "_", v["name"])[:80] or "testbed"
    aid = store.create(f"testbed-{name}.pcap", "testbed", 0, "")
    path = store.capture_path(aid)

    def build_and_run():
        try:
            store.update(aid, status="running", stage="building testbed", progress=2)
            testbed.build(v, path)
            with open(path + ".yaml", "w") as fh:
                fh.write(req.spec)
            with open(path, "rb") as fh:
                data = fh.read()
            store.update(aid, size=len(data), sha256=hashlib.sha256(data).hexdigest())
        except Exception as e:  # noqa: BLE001
            store.update(aid, status="failed", error=f"testbed: {type(e).__name__}: {e}")
            return
        _run(aid)
    if sync:
        build_and_run()
    else:
        threading.Thread(target=build_and_run, daemon=True).start()
    return store.get(aid)


@app.get("/api/analyses/{aid}/testbed.yaml")
def testbed_spec(aid: str):
    _need(aid)
    p = store.capture_path(aid) + ".yaml"
    if not os.path.exists(p):
        raise HTTPException(404, "this analysis was not built from a testbed spec")
    return FileResponse(p, media_type="text/yaml", filename=f"{aid}.yaml")


@app.get("/api/schema/report.json")
def report_schema():
    return JSONResponse(schema.report_schema(), media_type="application/schema+json")


@app.get("/api/changes")
def changes():
    return [{"id": k, "label": v} for k, v in assess.CHANGES.items()]


@app.get("/api/analyses/{aid}/report/{kind}.pdf")
def get_pdf(aid: str, kind: str):
    meta, res = _result(aid)
    base = os.path.splitext(meta["name"])[0]
    if kind == "executive":
        data = pdfreports.render_executive(res, meta)
    elif kind == "technical":
        data = pdfreports.render_technical(res, meta, store.capture_path(aid))
    else:
        raise HTTPException(404, "report kind must be executive or technical")
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="nunmathi-{kind}-{base}.pdf"'})


@app.get("/api/analyses/{aid}/report.{fmt}")
def get_report(aid: str, fmt: str):
    meta, res = _result(aid)
    base = os.path.splitext(meta["name"])[0]
    if fmt == "json":
        return Response(report.render_json(res, meta), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="nunmathi-{base}.json"'})
    if fmt == "html":
        return Response(report.render_html(res, meta), media_type="text/html")
    if fmt == "pdf":
        return Response(pdfreports.render_technical(res, meta, store.capture_path(aid)), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="nunmathi-{base}.pdf"'})
    raise HTTPException(404, "format must be html, json or pdf")


@app.delete("/api/analyses/{aid}")
def remove(aid: str):
    _need(aid)
    s = live.get(aid)
    if s is not None and s.running:
        s.stop("analysis deleted")
        s.join(15)
    with _pkt_lock:
        _pkt_cache.pop(aid, None)
    store.delete(aid)
    return {"deleted": aid}


@app.get("/api/rules")
def rules():
    return [{"id": k, "name": v[0], "description": v[1], "solution": assess.REMEDIATION.get(k, ""),
             "references": assess.REFERENCES.get(k, []), "standards": assess.STANDARDS.get(k, []),
             "attack": attack.techniques_for(k)} for k, v in assess.RULES.items()]


@app.get("/api/model-card")
def model_card():
    return traffic.get_model().card


# ------------------------------------------------------------------ live capture
class LiveReq(BaseModel):
    interface: str | None = None
    filter: str | None = None
    backend: str | None = None
    duration: float = 0
    max_packets: int = 1_000_000
    max_mb: int = 1024
    interval: float = 2.0
    replay_scenario: str | None = None      # forge a demo scenario and replay it in real time
    replay_analysis: str | None = None      # replay the capture of an existing analysis
    speed: float = 1.0


def _live_on() -> None:
    if not LIVE_ENABLED:
        raise HTTPException(403, "live capture is disabled on this server (NUNMATHI_LIVE=0)")


def _live_need(aid: str) -> "live.LiveSession":
    s = live.get(aid)
    if s is None:
        raise HTTPException(404, "no live session with this id (it may have finished before a server restart)")
    return s


@app.get("/api/live/capabilities")
def live_capabilities():
    return {"enabled": LIVE_ENABLED, **(live.capabilities() if LIVE_ENABLED else {})}


@app.get("/api/live")
def live_sessions():
    return [s.status(events=False) for s in live.active()]


@app.post("/api/live", status_code=201)
def live_start(req: LiveReq):
    _live_on()
    replay, rname = None, None
    if req.replay_scenario:
        prof = SCENARIOS.get(req.replay_scenario)
        if not prof:
            raise HTTPException(404, "unknown scenario")
        replay = os.path.join(store.DATA, "replay", f"{req.replay_scenario}.pcap")
        if not os.path.exists(replay):
            os.makedirs(os.path.dirname(replay), exist_ok=True)
            forge(prof, replay, None, seed=prof.get("seed", 1))
        rname = req.replay_scenario
    elif req.replay_analysis:
        m = _need(req.replay_analysis)
        replay, rname = store.capture_path(m["id"]), os.path.splitext(m["name"])[0]
        if not os.path.exists(replay):
            raise HTTPException(404, "that analysis has no capture file")
    try:
        s = live.start(interface=req.interface, bpf=req.filter, backend=req.backend, replay=replay,
                       replay_name=rname, speed=req.speed, duration=req.duration, max_packets=req.max_packets,
                       max_bytes=req.max_mb * (1 << 20), interval=max(0.5, req.interval))
    except live.LiveError as e:
        raise HTTPException(400, str(e)) from e
    return s.status()


@app.get("/api/live/{aid}")
def live_status(aid: str, after: int = 0):
    return _live_need(aid).status(after=after)


@app.post("/api/live/{aid}/stop")
def live_stop(aid: str):
    s = _live_need(aid)
    s.stop("stopped by user")
    return s.status(events=False)


@app.get("/api/live/{aid}/stream")
async def live_stream(aid: str, request: Request, after: int = 0):
    """Server-Sent Events: one `status` event per second (with new events only) until the capture ends."""
    s = _live_need(aid)

    async def gen():
        seq = after
        while True:
            st = s.status(after=seq)
            seq = st["last_seq"]
            yield f"event: status\ndata: {json.dumps(st, default=str)}\n\n"
            if not s.running:
                yield "event: end\ndata: {}\n\n"
                return
            if await request.is_disconnected():
                return
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ frontend
if os.path.isdir(FRONTEND):
    if os.path.isdir(os.path.join(FRONTEND, "assets")):
        app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND, "assets")), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "Not Found"}, 404)
        f = os.path.join(FRONTEND, path)
        if path and os.path.isfile(f) and os.path.realpath(f).startswith(FRONTEND):
            return FileResponse(f)
        return FileResponse(os.path.join(FRONTEND, "index.html"))
