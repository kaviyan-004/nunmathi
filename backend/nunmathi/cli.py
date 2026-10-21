"""Command-line interface: nunmathi analyze|live|testbed|verify|forge|serve|train|scenarios|schema."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

FORMATS = ["text", "json", "html", "pdf", "executive"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nunmathi", description="Passive, AI-assisted IPsec VPN analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a pcap/pcapng capture")
    a.add_argument("capture")
    a.add_argument("-f", "--format", choices=FORMATS, default="text",
                   help="pdf = technical report (15-30 pages), executive = 2-page executive PDF")
    a.add_argument("-o", "--output", help="write report to file (default stdout for text/json)")
    a.add_argument("--fail-on", choices=["High", "Medium", "Low"], help="exit 2 if an alert of this risk or worse exists")
    f = sub.add_parser("forge", help="generate a synthetic demo capture")
    f.add_argument("scenario")
    f.add_argument("output")
    f.add_argument("--truth", help="write ground-truth JSON here")
    sub.add_parser("scenarios", help="list demo scenarios")
    if not getattr(sys, "frozen", False):
        # the packaged desktop application contains no web server
        s = sub.add_parser("serve", help="development only: serve the UI + REST API over HTTP (the desktop app needs no server)")
        s.add_argument("--host", default="127.0.0.1")
        s.add_argument("--port", type=int, default=8750)
        s.add_argument("--open", action="store_true", help="open the UI in the default web browser")
    g = sub.add_parser("gui", help="open the standalone desktop application (native window, no browser)")
    g.add_argument("capture", nargs="?", help="capture to analyze right away")
    tb = sub.add_parser("testbed", help="build VPN topologies from a YAML spec in IPsecForge, capture and analyze")
    tb.add_argument("spec", nargs="?", help="YAML testbed spec (see --example)")
    tb.add_argument("--example", action="store_true", help="print an example spec and exit")
    tb.add_argument("--validate", action="store_true", help="only validate the spec")
    tb.add_argument("--pcap", help="where to write the generated capture (default <name>.pcap)")
    tb.add_argument("-f", "--format", choices=FORMATS, default="text")
    tb.add_argument("-o", "--output", help="write report to file")
    tb.add_argument("--fail-on", choices=["High", "Medium", "Low"], help="exit 2 if an alert of this risk or worse exists")
    vf = sub.add_parser("verify", help="apply recommendations to one tunnel in the testbed, re-capture and re-score")
    vf.add_argument("capture")
    vf.add_argument("-t", "--tunnel", help="tunnel id (default: worst-graded tunnel)")
    vf.add_argument("-c", "--changes", help="comma-separated change ids (default: the recommended set)")
    vf.add_argument("--json", action="store_true", help="print the full verification result as JSON")
    sub.add_parser("schema", help="print the versioned JSON Schema of the JSON report")
    sub.add_parser("train", help="(re)train the traffic model and print its model card")
    lv = sub.add_parser("live", help="capture and analyze IPsec traffic from a network interface in real time")
    lv.add_argument("-i", "--interface", help="interface to capture on (see --list)")
    lv.add_argument("--list", action="store_true", help="list interfaces and capture backends, then exit")
    lv.add_argument("--filter", default=None, help="BPF capture filter (default: IKE, NAT-T, ESP and AH)")
    lv.add_argument("--backend", choices=["dumpcap", "tcpdump"], help="capture tool (default: first usable)")
    lv.add_argument("-d", "--duration", type=float, default=0, help="stop after N seconds (default: Ctrl-C)")
    lv.add_argument("--max-packets", type=int, default=1_000_000, help="stop after N IPsec packets")
    lv.add_argument("--replay", metavar="CAPTURE", help="replay a capture file in real time instead of an interface")
    lv.add_argument("--speed", type=float, default=1.0, help="replay speed factor")
    lv.add_argument("--interval", type=float, default=2.0, help="seconds between re-analyses")
    lv.add_argument("-f", "--format", choices=FORMATS, default="text",
                    help="format of the final report")
    lv.add_argument("-o", "--output", help="write the final report to this file")
    lv.add_argument("--fail-on", choices=["High", "Medium", "Low"], help="exit 2 if an alert of this risk or worse exists")
    args = ap.parse_args(argv)

    if args.cmd == "schema":
        from .schema import report_schema
        print(json.dumps(report_schema(), indent=1))
        return 0
    if args.cmd == "verify":
        return _verify(args)
    if args.cmd == "scenarios":
        from .forge.scenarios import SCENARIOS
        for k, v in SCENARIOS.items():
            print(f"{k:20} {v['title']}")
        return 0
    if args.cmd == "forge":
        from .forge.generator import forge
        from .forge.scenarios import SCENARIOS
        if args.scenario not in SCENARIOS:
            print(f"unknown scenario; choose from {', '.join(SCENARIOS)}", file=sys.stderr)
            return 1
        p = SCENARIOS[args.scenario]
        forge(p, args.output, args.truth, seed=p.get("seed", 1))
        print(f"wrote {args.output}")
        return 0
    if args.cmd == "train":
        from . import traffic
        m = traffic.train()
        import pickle
        os.makedirs(os.path.dirname(traffic._cache_path()), exist_ok=True)
        with open(traffic._cache_path(), "wb") as fh:
            pickle.dump(m, fh)
        print(json.dumps({k: v for k, v in m.card.items() if k != "confusion"}, indent=1))
        return 0
    if args.cmd == "gui":
        from .gui import run
        return run(open_path=args.capture)
    if args.cmd == "serve":
        import uvicorn
        if args.open:
            import threading
            import webbrowser
            url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}/"
            threading.Timer(1.5, webbrowser.open, args=(url,)).start()
        if args.host not in ("127.0.0.1", "::1", "localhost") and os.environ.get("NUNMATHI_LIVE", "1") != "0":
            print("warning: the API has no authentication and lets clients start packet captures on this host. "
                  "Set NUNMATHI_LIVE=0 to disable live capture when binding to a non-loopback address.",
                  file=sys.stderr)
        from .api import app
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    from . import report
    from .analyzer import analyze_file
    from .assess import RISK_ORDER
    from .pcap import CaptureError
    if args.cmd == "live":
        res, meta, rc = _live(args)
        if res is None:
            return rc
    elif args.cmd == "testbed":
        res, meta, rc = _testbed(args)
        if res is None:
            return rc
    else:
        try:
            res = analyze_file(args.capture)
        except (CaptureError, OSError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        meta = {"id": "cli", "name": args.capture, "source": "cli"}
    meta.setdefault("created", time.time())
    if args.format == "text":
        out = _text(res).encode()
    elif args.format in ("pdf", "executive"):
        from . import pdfreports
        out = (pdfreports.render_executive(res, meta) if args.format == "executive" else
               pdfreports.render_technical(res, meta, meta.get("capture") or getattr(args, "capture", None)))
    else:
        out = {"json": report.render_json, "html": report.render_html}[args.format](res, meta)
    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(out)
        print(f"wrote {args.output}  grade {res['grade']['letter']}", file=sys.stderr)
    elif args.format in ("pdf", "executive"):
        print("pdf needs --output", file=sys.stderr)
        return 1
    else:
        sys.stdout.write(out.decode())
    if args.fail_on:
        worst = RISK_ORDER.index(args.fail_on)
        if any(RISK_ORDER.index(a["risk"]) <= worst for a in res["alerts"]):
            return 2
    return 0


def _live(args):
    """Run a live capture in the foreground, printing events as they happen. Returns (result, meta, rc)."""
    import signal
    import time
    from . import live, store
    if args.list:
        cap = live.capabilities()
        for b in cap["backends"]:
            print(f"backend {b['name']:8} {b['path']:22} {'usable' if b['privileged'] else 'NOT usable'}: {b['note']}")
        for i in cap["interfaces"]:
            print(f"  {i['name']:16} {'up  ' if i['up'] else 'down'} {' '.join(i['addresses'])}")
        return None, None, 0
    if not args.interface and not args.replay:
        print("error: give --interface (see --list) or --replay FILE", file=sys.stderr)
        return None, None, 1
    try:
        s = live.start(interface=args.interface, bpf=args.filter, backend=args.backend, replay=args.replay,
                       speed=args.speed, duration=args.duration, max_packets=args.max_packets,
                       interval=args.interval)
    except live.LiveError as e:
        print(f"error: {e}", file=sys.stderr)
        return None, None, 1
    if s.cmd:
        print(f"$ {s.status(events=False)['command']}", file=sys.stderr)
    signal.signal(signal.SIGINT, lambda *_: s.stop("interrupted (Ctrl-C)"))
    seq, last = 0, 0.0
    while s.running or seq < s._seq:
        for e in s.events_after(seq):
            seq = e["seq"]
            print(f"{time.strftime('%H:%M:%S', time.localtime(e['ts']))}  {e['level']:13} "
                  f"{'[' + e['tunnel'] + '] ' if e['tunnel'] else ''}{e['text']}", file=sys.stderr, flush=True)
        if time.time() - last >= 5 and s.running:
            st = s.status(events=False)
            sm = st["summary"]
            print(f"          {st['elapsed']:7.1f}s  frames {st['stats']['frames']}  IKE {st['stats']['ike']}  "
                  f"ESP {st['stats']['esp']}  {st['pps']} pkt/s  tunnels {sm.get('tunnels', 0)}  "
                  f"grade {sm.get('grade', '-')}", file=sys.stderr, flush=True)
            last = time.time()
        time.sleep(0.3)
    s.join(15)
    if s.state == "failed" or store.load_result(s.aid) is None:
        print(f"error: {s.error or 'no packets captured'}", file=sys.stderr)
        return None, None, 1
    print(f"saved as analysis {s.aid} ({store.capture_path(s.aid)})", file=sys.stderr)
    return store.load_result(s.aid), store.get(s.aid), 0


def _testbed(args):
    from . import testbed
    from .analyzer import analyze_file
    if args.example:
        sys.stdout.write(testbed.EXAMPLE)
        return None, None, 0
    if not args.spec:
        print("error: give a spec file (or --example)", file=sys.stderr)
        return None, None, 1
    try:
        with open(args.spec, encoding="utf-8") as fh:
            spec = testbed.load(fh.read())
    except (OSError, testbed.SpecError) as e:
        print(f"error: {e}", file=sys.stderr)
        return None, None, 1
    for t in testbed.summary(spec):
        print(f"  {t['name']:20} {t['initiator']} -> {t['responder']}  IKEv{t['ike_version']}  {t['ike']}  "
              f"ESP {t['esp']}  PFS {t['pfs'] or 'off'}", file=sys.stderr)
    if args.validate:
        print(f"spec OK: {len(spec['tunnels'])} tunnel(s), {spec['duration']} s", file=sys.stderr)
        return None, None, 0
    pcap = args.pcap or f"{spec['name']}.pcap"
    truth = testbed.build(spec, pcap)
    print(f"built {pcap}: {truth['frames']} frames", file=sys.stderr)
    res = analyze_file(pcap)
    return res, {"id": "cli", "name": os.path.basename(pcap), "source": "testbed", "capture": pcap}, 0


def _verify(args) -> int:
    from . import assess, verify
    from .analyzer import analyze_file
    from .pcap import CaptureError
    try:
        res = analyze_file(args.capture)
    except (CaptureError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not res["tunnels"]:
        print("error: no IPsec tunnels in this capture", file=sys.stderr)
        return 1
    t = (next((x for x in res["tunnels"] if x["id"] == args.tunnel), None) if args.tunnel
         else min(res["tunnels"], key=lambda x: x["grade"]["score"]))
    if t is None:
        print(f"error: unknown tunnel; choose from {', '.join(x['id'] for x in res['tunnels'])}", file=sys.stderr)
        return 1
    changes = args.changes.split(",") if args.changes else (t.get("recommended") or
                                                              assess.recommended_changes(t["posture"]))
    bad = [c for c in changes if c not in assess.CHANGES]
    if bad or not changes:
        print(f"error: choose changes from {', '.join(assess.CHANGES)}", file=sys.stderr)
        return 1
    v = verify.verify(t["posture"], t, changes,
                      lambda st, pct: print(f"  [{pct:3d}%] {st}", file=sys.stderr, flush=True))
    if args.json:
        print(json.dumps(v, indent=1, default=str))
        return 0
    b, h = v["baseline"]["measured"], v["hardened"]["measured"]
    print(f"tunnel {t['id']}  observed {v['observed']['grade']['letter']}  "
          f"baseline twin {b['grade']['letter']} ({b['grade']['score']})  "
          f"hardened twin {h['grade']['letter']} ({h['grade']['score']})  "
          f"predicted {v['predicted']['grade']['letter']}")
    for c in v["checks"]:
        mark = {True: "verified", False: "NOT verified", None: "n/a"}[c["verified"]]
        print(f"  {mark:13} {c['label']}: {c['evidence']}")
    print(f"resolved {', '.join(v['resolved']) or '-'}; introduced {', '.join(v['introduced']) or '-'}; "
          f"prediction {'confirmed' if v['prediction_agrees'] else 'differs'}  ({v['elapsed']} s)")
    return 0


def _text(res: dict) -> str:
    L = [f"Nunmathi {res['engine']}  {res['file']['frames']} frames  "
         f"({res['file']['ike']} IKE, {res['file']['esp']} ESP)  {res['elapsed']} s",
         f"Overall grade: {res['grade']['letter']} ({res['grade']['score']})", ""]
    for t in res["tunnels"]:
        n = (t.get("ike_crypto") or {}).get("names") or {}
        cls = {k: v for k, v in t["traffic"]["summary"]["class_windows"].items() if v}
        L += [f"[{t['id']}] {t['initiator']} -> {t['responder']}  IKEv{t['version']}  grade {t['grade']['letter']} "
              f"({t['grade']['score']})",
              f"    IKE  {n.get('encr')} / {n.get('prf')} / {n.get('group')} {'+ ' + ','.join(n['addke']) if n.get('addke') else ''}",
              f"    PFS  {t['pfs']['status']} {t['pfs'].get('group') or ''}",
              f"    traffic windows {cls}"]
    L.append("")
    for a in res["alerts"]:
        L.append(f"  {a['risk']:13} {a['id']}  {a['name']}  [{a['tunnel'] or '-'}]")
        L.append(f"                {a['evidence']}")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
