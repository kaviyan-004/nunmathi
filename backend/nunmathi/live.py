"""Live mode: analyze an IPsec packet stream from a network interface while it is being captured.

A capture tool (dumpcap, else tcpdump) writes pcap to a pipe. Nunmathi never opens a raw socket
itself, so it needs no privileges beyond what the capture tool already has. Every byte from the pipe
is also written to the analysis' capture file, so the finished session is an ordinary analysis whose
frames, reports and What-If all keep working. The stream is decoded frame by frame and re-analyzed
every few seconds; differences between successive results become events (new tunnel, new alert,
rekey, grade change).

A "replay" source paces an existing capture in real time through the same pipe/decoder path.
It is meant for demos and tests when no IPsec traffic is on the wire.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import threading
import time

from . import assess, store
from .analyzer import analyze_packets
from .pcap import CaptureError, account, iter_frames, new_stats

DEFAULT_FILTER = "udp port 500 or udp port 4500 or esp or ah"
MAX_SESSIONS = 4
IFACE_RE = re.compile(r"^[\w.\-@:]{1,64}$")
_PCAP_HDR = struct.Struct("<IHHiIII")
_REC_HDR = struct.Struct("<IIII")


class LiveError(ValueError):
    """Invalid live-capture request, or the capture tool is missing."""


# ------------------------------------------------------------------ environment
def _prefix() -> list[str]:
    """Optional command prefix, e.g. `nsenter -t PID -U -n --preserve-credentials` to capture in a netns."""
    return shlex.split(os.environ.get("NUNMATHI_CAPTURE_PREFIX", ""))


WINDOWS = os.name == "nt"


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _find_tool(name: str) -> str | None:
    if WINDOWS:
        dirs = [os.path.join(os.environ.get(v, ""), "Wireshark") for v in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)")]
        dirs += [os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")]
        return shutil.which(name) or next((os.path.join(d, name + ".exe") for d in dirs
                                           if os.path.exists(os.path.join(d, name + ".exe"))), None)
    return shutil.which(name) or next((p for p in (f"/usr/bin/{name}", f"/usr/sbin/{name}")
                                       if os.path.exists(p)), None)


def _caps(path: str) -> str:
    if WINDOWS:
        return ""
    getcap = shutil.which("getcap") or "/usr/sbin/getcap"
    try:
        return subprocess.run([getcap, path], capture_output=True, text=True, timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def backends() -> list[dict]:
    """Capture tools found on this host, best first, with a hint whether they can capture unprivileged."""
    out = []
    root = _is_root() or bool(_prefix())
    for name in ("dumpcap", "tcpdump"):
        path = _find_tool(name)
        if not path:
            continue
        if WINDOWS:
            # Npcap lets ordinary users capture unless it was installed in admin-only mode
            out.append({"name": name, "path": path, "privileged": True,
                        "note": "Windows: capture through Npcap (installed with Wireshark)"})
            continue
        caps = _caps(path)
        ok = root or "cap_net_raw" in caps
        runnable = os.access(path, os.X_OK)
        note = ("running as root / in a namespace" if root else
                "has cap_net_raw" if ok else "no capture privileges: run as root or grant cap_net_raw,cap_net_admin")
        if not runnable:
            ok, note = False, "not executable by this user (for dumpcap: add the user to the 'wireshark' group)"
        out.append({"name": name, "path": path, "privileged": ok, "note": note})
    return out


def _backend(name: str | None) -> dict:
    avail = backends()
    if not avail:
        raise LiveError("No capture tool found. Install Wireshark (dumpcap + Npcap) or tcpdump.")
    if name:
        b = next((x for x in avail if x["name"] == name), None)
        if not b:
            raise LiveError(f"capture backend '{name}' is not installed")
        return b
    return next((x for x in avail if x["privileged"]), avail[0])


def _dumpcap_interfaces() -> list[dict]:
    """`dumpcap -D` lines look like `3. \\Device\\NPF_{GUID} (Ethernet)`; dumpcap accepts the index as -i."""
    tool = _find_tool("dumpcap")
    if not tool:
        return []
    try:
        r = subprocess.run([tool, "-D"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line.strip())
        if m:
            desc = m.group(3) or m.group(2)
            out.append({"name": m.group(1), "up": True, "loopback": "loopback" in desc.lower(),
                        "addresses": [], "description": desc})
    return out


def list_interfaces() -> list[dict]:
    """Interfaces visible to the capture tool (inside the prefix namespace when one is set)."""
    if WINDOWS:
        return _dumpcap_interfaces()
    try:
        r = subprocess.run(_prefix() + ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
        data = json.loads(r.stdout or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        try:
            data = [{"ifname": n, "flags": [], "addr_info": []} for n in sorted(os.listdir("/sys/class/net"))]
        except OSError:
            data = []
    out = []
    for d in data:
        flags = d.get("flags", [])
        out.append({"name": d["ifname"], "up": "UP" in flags or d.get("operstate") == "UP",
                    "loopback": "LOOPBACK" in flags,
                    "addresses": [f"{a['local']}/{a.get('prefixlen', '')}" for a in d.get("addr_info", [])
                                  if a.get("local")]})
    out.append({"name": "any", "up": True, "loopback": False, "addresses": [], "pseudo": True})
    return out


def capture_command(backend: dict, iface: str, bpf: str) -> list[str]:
    if backend["name"] == "dumpcap":
        cmd = [backend["path"], "-i", iface, "-F", "pcap", "-w", "-", "-q", "--update-interval", "100"]
        if bpf:
            cmd += ["-f", bpf]
    else:
        cmd = [backend["path"], "-i", iface, "-U", "-n", "-s", "0", "-w", "-"]
        if _is_root() or _prefix():
            cmd += ["-Z", "root"]          # stay root inside a user namespace, where uid 'tcpdump' is unmapped
        if bpf:
            cmd += [bpf]
    return _prefix() + cmd


def capabilities() -> dict:
    return {"backends": backends(), "interfaces": list_interfaces(), "default_filter": DEFAULT_FILTER,
            "prefix": " ".join(_prefix()) or None, "max_sessions": MAX_SESSIONS}


# ------------------------------------------------------------------ stream plumbing
class _Tee:
    """File-like reader that copies everything read from `src` into `sink`."""

    def __init__(self, src, sink):
        self.src, self.sink, self.bytes = src, sink, 0

    def read(self, n: int = -1) -> bytes:
        b = self.src.read(n)
        if b:
            self.sink.write(b)
            self.bytes += len(b)
        return b


def _replay_writer(path: str, wfd: int, speed: float, stop: threading.Event) -> None:
    """Write `path` as a pcap stream into `wfd`, paced by the original inter-packet gaps / speed.
    Timestamps are shifted so the first packet is "now"."""
    try:
        with open(path, "rb") as fh, os.fdopen(wfd, "wb", buffering=0) as out:
            t0 = None
            wall0 = time.time()
            for fr in iter_frames(fh):
                if stop.is_set():
                    return
                if t0 is None:
                    t0 = fr.ts
                    out.write(_PCAP_HDR.pack(0xA1B2C3D4, 2, 4, 0, 0, 262144, fr.linktype))
                due = wall0 + (fr.ts - t0) / speed
                while not stop.is_set() and (d := due - time.time()) > 0:
                    time.sleep(min(d, 0.25))
                ts = wall0 + (fr.ts - t0)
                out.write(_REC_HDR.pack(int(ts), int((ts % 1) * 1e6), len(fr.data), len(fr.data)) + fr.data)
    except (BrokenPipeError, OSError, CaptureError):
        pass


# ------------------------------------------------------------------ session
class LiveSession:
    def __init__(self, aid: str, *, interface: str | None = None, bpf: str = DEFAULT_FILTER,
                 backend: str | None = None, replay: str | None = None, speed: float = 1.0,
                 duration: float = 0, max_packets: int = 1_000_000, max_bytes: int = 1 << 30,
                 interval: float = 2.0):
        self.aid, self.interface, self.bpf, self.replay, self.speed = aid, interface, bpf, replay, speed
        self.duration, self.max_packets, self.max_bytes, self.interval = duration, max_packets, max_bytes, interval
        self.backend = None if replay else _backend(backend)
        self.cmd = None if replay else capture_command(self.backend, interface, bpf)
        self.packets: list = []
        self.stats = new_stats()
        self.started = time.time()
        self.ended: float | None = None
        self.state = "starting"          # starting | capturing | stopping | done | failed
        self.stop_reason: str | None = None
        self.error: str | None = None
        self.events: list[dict] = []
        self.rates: collections.deque = collections.deque(maxlen=300)   # per-second buckets
        self.analyses = 0
        self.last_analysis: float | None = None
        self.analysis_time = 0.0
        self.summary: dict = {}
        self._seq = 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._stderr: collections.deque = collections.deque(maxlen=40)
        self._tee: _Tee | None = None
        self._seen_tunnels: dict = {}
        self._seen_alerts: dict = {}
        self._grade: str | None = None
        self._threads: list[threading.Thread] = []
        self._reader_thread: threading.Thread | None = None

    # ---------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self.replay:
            rfd, wfd = os.pipe()
            src = os.fdopen(rfd, "rb")
            self._threads.append(threading.Thread(target=_replay_writer, daemon=True,
                                                  args=(self.replay, wfd, self.speed, self._stop)))
            self._event("capture", "Info", f"Replaying {os.path.basename(self.replay)} at {self.speed:g}x")
        else:
            try:
                self._proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              stdin=subprocess.DEVNULL, start_new_session=True)
            except OSError as e:
                raise LiveError(f"cannot start {self.backend['name']}: {e}") from e
            src = self._proc.stdout
            self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
            self._threads.append(self._stderr_thread)
            self._event("capture", "Info", f"Capturing on {self.interface} with {self.backend['name']} "
                                           f"(filter: {self.bpf or 'none'})")
        self._reader_thread = threading.Thread(target=self._reader, args=(src,), daemon=True)
        self._threads.append(self._reader_thread)
        self._threads.append(threading.Thread(target=self._ticker, daemon=True))
        for t in self._threads:
            t.start()

    def stop(self, reason: str = "stopped by user") -> None:
        if self._stop.is_set():
            return
        self.stop_reason = self.stop_reason or reason
        self.state = "stopping" if self.state != "failed" else self.state
        self._stop.set()
        self._kill()

    def _kill(self) -> None:
        p = self._proc
        if not p:
            return
        if WINDOWS:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
            return
        # signal the whole process group: a prefix such as sudo forks, and its child holds the pipe open
        for sig, wait in ((signal.SIGTERM, 3), (signal.SIGKILL, 3)):
            try:
                os.killpg(p.pid, sig)
            except (ProcessLookupError, PermissionError):
                if p.poll() is None:
                    p.send_signal(sig)
            try:
                p.wait(wait)
                break
            except subprocess.TimeoutExpired:
                continue

    def join(self, timeout: float | None = None) -> None:
        for t in self._threads:
            t.join(timeout)

    @property
    def running(self) -> bool:
        return self.state in ("starting", "capturing", "stopping")

    # ---------------------------------------------------------- threads
    def _drain_stderr(self) -> None:
        for line in iter(self._proc.stderr.readline, b""):
            self._stderr.append(line.decode(errors="replace").rstrip())

    def _reader(self, src) -> None:
        path = store.capture_path(self.aid)
        try:
            with open(path, "wb") as sink:
                self._tee = _Tee(src, sink)
                last_flush = 0.0
                for idx, fr in enumerate(iter_frames(self._tee), 1):
                    if self.state == "starting":
                        self.state = "capturing"
                    p = account(self.stats, fr, idx)
                    if p is not None:
                        self.packets.append(p.trim())
                    self._rate(p, len(fr.data))
                    now = time.monotonic()
                    if now - last_flush > 0.5:
                        sink.flush()
                        last_flush = now
                    if self._stop.is_set():
                        break
                    if self.max_packets and len(self.packets) >= self.max_packets:
                        self.stop(f"packet limit reached ({self.max_packets})")
                        break
                    if self.max_bytes and self._tee.bytes >= self.max_bytes:
                        self.stop(f"size limit reached ({self.max_bytes // (1 << 20)} MB)")
                        break
        except CaptureError as e:
            # an empty stream means the tool died before writing a header: report its stderr below
            if not self._stop.is_set() and self._tee and self._tee.bytes >= 4:
                self._fail(f"capture stream unreadable: {e}")
        except Exception as e:  # noqa: BLE001 - surface to the UI
            self._fail(f"{type(e).__name__}: {e}")
        finally:
            self._kill()
            if not self._stop.is_set():       # the tool exited on its own
                rc = self._proc.wait() if self._proc else 0
                if self.stats["frames"] == 0 and (rc != 0 or (self._tee and self._tee.bytes < 24)):
                    self._fail(self._tool_error(rc))
                elif self.replay:
                    self.stop("replay finished")
                else:
                    self.stop(f"capture tool exited (status {rc})")
            self._stop.set()

    def _tool_error(self, rc: int) -> str:
        t = getattr(self, "_stderr_thread", None)
        if t:
            t.join(2)                     # the tool has exited: wait until its last stderr lines are collected
        msg = [ln for ln in self._stderr if ln and not ln.startswith(("Capturing on", "File:"))]
        text = " ".join(msg)[-600:] or f"exit status {rc}"
        if re.search(r"permission|not permitted|privilege", text, re.I) and not _prefix():
            text += (" — the capture tool needs cap_net_raw/cap_net_admin (e.g. `sudo setcap "
                     "cap_net_raw,cap_net_admin=eip $(which dumpcap)` and membership of the 'wireshark' group)")
        return f"{self.backend['name']} failed: {text}"

    def _fail(self, msg: str) -> None:
        self.error = msg
        self.state = "failed"
        self.stop_reason = self.stop_reason or "error"
        self._event("error", "High", msg)
        self._stop.set()

    def _rate(self, p, nbytes: int) -> None:
        sec = int(time.time())
        with self._lock:
            if not self.rates or self.rates[-1]["t"] != sec:
                self.rates.append({"t": sec, "frames": 0, "ike": 0, "esp": 0, "bytes": 0})
            b = self.rates[-1]
            b["frames"] += 1
            b["bytes"] += nbytes
            if p is not None and p.kind in ("IKE", "ESP"):
                b[p.kind.lower()] += 1

    def _ticker(self) -> None:
        next_at = time.monotonic() + min(1.0, self.interval)
        while not self._stop.is_set():
            if self.duration and time.time() - self.started >= self.duration:
                self.stop(f"duration limit reached ({self.duration:g} s)")
                break
            if time.monotonic() >= next_at:
                self._analyze()
                # never spend more than about a third of the time analyzing
                next_at = time.monotonic() + max(self.interval, 3 * self.analysis_time)
            self._stop.wait(0.2)
        if self._reader_thread:
            self._reader_thread.join(10)      # let the reader flush and close the capture file
        self._finish()

    # ---------------------------------------------------------- analysis
    def _analyze(self, final: bool = False) -> dict | None:
        n = len(self.packets)
        pkts = self.packets[:n]
        stats = dict(self.stats)
        if stats["frames"] == 0:
            return None
        t0 = time.time()
        try:
            res = analyze_packets(pkts, stats)
        except Exception as e:  # noqa: BLE001
            self._event("error", "Medium", f"analysis failed: {type(e).__name__}: {e}")
            return None
        self.analysis_time = time.time() - t0
        self.analyses += 1
        self.last_analysis = time.time()
        self._diff(res)
        res["file"]["path"] = store.capture_path(self.aid)
        res["live"] = self.status(events=False) | {"final": final}
        store.save_result(self.aid, res)
        counts = {r: sum(a["risk"] == r for a in res["alerts"]) for r in assess.RISK_ORDER}
        self.summary = {"grade": res["grade"]["letter"], "score": res["grade"]["score"], "alerts": counts,
                        "tunnels": len(res["tunnels"])}
        store.update(self.aid, grade=res["grade"]["letter"], score=res["grade"]["score"],
                     alerts=json.dumps(counts), tunnels=len(res["tunnels"]),
                     size=self._tee.bytes if self._tee else 0)
        return res

    def _diff(self, res: dict) -> None:
        now = time.time()
        tid_key = {t["id"]: "-".join(sorted(t["peers"])) for t in res["tunnels"]}
        for t in res["tunnels"]:
            k = tid_key[t["id"]]
            prev = self._seen_tunnels.get(k)
            n_child, n_ike = len(t["child_sas"]), len(t["ike_sas"])
            crypto = ((t.get("ike_crypto") or {}).get("names") or {})
            if prev is None:
                desc = " / ".join(str(v) for v in (crypto.get("encr"), crypto.get("group")) if v)
                self._event("tunnel", "Info", f"New tunnel {t['initiator']} → {t['responder']} "
                                              f"({'IKEv' + str(t['version']) if t['version'] else 'IKE not seen yet'}"
                                              f"{', ' + desc if desc else ''})", t["id"])
            else:
                if n_ike > prev["ike"]:
                    self._event("rekey", "Info", f"IKE SA rekey / re-authentication ({n_ike} IKE SAs so far)",
                                t["id"])
                if n_child > prev["child"]:
                    self._event("rekey", "Info", f"New Child SA ({n_child} so far; PFS {t['pfs']['status']})",
                                t["id"])
                if prev["grade"] != t["grade"]["letter"]:
                    self._event("grade", "Low", f"Tunnel grade {prev['grade']} → {t['grade']['letter']} "
                                                f"({t['grade']['score']})", t["id"])
            self._seen_tunnels[k] = {"ike": n_ike, "child": n_child, "grade": t["grade"]["letter"]}
        for a in res["alerts"]:
            k = (a["id"], tid_key.get(a["tunnel"], a["tunnel"]))
            if k not in self._seen_alerts:
                self._seen_alerts[k] = now
                self._event("alert", a["risk"], f"{a['id']} {a['name']}", a["tunnel"])
            a["first_seen"] = self._seen_alerts[k]
        g = res["grade"]["letter"]
        if self._grade is not None and g != self._grade:
            self._event("grade", "Low", f"Overall grade {self._grade} → {g}")
        self._grade = g

    def _finish(self) -> None:
        self.ended = time.time()
        failed = self.state == "failed"
        res = None if failed and self.stats["frames"] == 0 else self._analyze(final=True)
        path = store.capture_path(self.aid)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        sha = hashlib.sha256()
        if size:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    sha.update(chunk)
        if failed:
            store.update(self.aid, status="failed", stage="failed", error=self.error, size=size,
                         sha256=sha.hexdigest())
        elif res is None:
            self.state = "done"
            self._event("capture", "Info", f"Capture ended ({self.stop_reason}); no packets matched the filter")
            store.update(self.aid, status="failed", stage="done", progress=100, size=size, sha256=sha.hexdigest(),
                         error="No packets were captured. Check the interface and the capture filter.")
        else:
            self.state = "done"
            self._event("capture", "Info", f"Capture ended ({self.stop_reason}): {self.stats['frames']} frames, "
                                           f"{self.stats['ike']} IKE, {self.stats['esp']} ESP")
            res["live"] = self.status(events=False) | {"final": True}
            res["live"]["events"] = self.events[-500:]
            store.save_result(self.aid, res)
            store.update(self.aid, status="done", stage="done", progress=100, size=size, sha256=sha.hexdigest())
        _release(self.aid)

    # ---------------------------------------------------------- reporting
    def _event(self, kind: str, level: str, text: str, tunnel: str | None = None) -> None:
        with self._lock:
            self._seq += 1
            self.events.append({"seq": self._seq, "ts": time.time(), "type": kind, "level": level,
                                "text": text, "tunnel": tunnel})
            if len(self.events) > 2000:
                del self.events[:500]

    def events_after(self, seq: int = 0) -> list[dict]:
        with self._lock:
            return [e for e in self.events if e["seq"] > seq]

    def status(self, events: bool = True, after: int = 0) -> dict:
        now = self.ended or time.time()
        with self._lock:
            rates = list(self.rates)
        cur = int(time.time())
        recent = [r for r in rates if cur - 5 <= r["t"] < cur]
        pps = sum(r["frames"] for r in recent) / 5 if recent else 0.0
        bps = sum(r["bytes"] for r in recent) * 8 / 5 if recent else 0.0
        st = {"id": self.aid, "state": self.state, "running": self.running,
              "source": "replay" if self.replay else "interface", "interface": self.interface,
              "replay": os.path.basename(self.replay) if self.replay else None, "speed": self.speed,
              "backend": self.backend["name"] if self.backend else "replay", "filter": self.bpf,
              "command": " ".join(shlex.quote(c) for c in self.cmd) if self.cmd else None,
              "started": self.started, "ended": self.ended, "elapsed": round(now - self.started, 1),
              "limits": {"duration": self.duration, "max_packets": self.max_packets, "max_bytes": self.max_bytes},
              "stats": dict(self.stats), "ipsec_packets": len(self.packets),
              "captured_bytes": self._tee.bytes if self._tee else 0, "pps": round(pps, 1), "bps": round(bps),
              "rates": rates[-120:], "analyses": self.analyses, "last_analysis": self.last_analysis,
              "analysis_time": round(self.analysis_time, 3), "summary": self.summary,
              "stop_reason": self.stop_reason, "error": self.error, "last_seq": self._seq}
        if events:
            st["events"] = self.events_after(after)[-200:]
        return st


# ------------------------------------------------------------------ registry
_sessions: dict[str, LiveSession] = {}
_finished: dict[str, LiveSession] = {}       # kept briefly so clients can read the final status
_reg_lock = threading.Lock()


def _release(aid: str) -> None:
    with _reg_lock:
        s = _sessions.pop(aid, None)
        if s:
            _finished[aid] = s
            while len(_finished) > 16:
                _finished.pop(next(iter(_finished)))


def start(*, interface: str | None = None, bpf: str | None = None, backend: str | None = None,
          replay: str | None = None, replay_name: str | None = None, speed: float = 1.0,
          duration: float = 0, max_packets: int = 1_000_000, max_bytes: int = 1 << 30,
          interval: float = 2.0, name: str | None = None) -> LiveSession:
    bpf = DEFAULT_FILTER if bpf is None else bpf.strip()
    if len(bpf) > 1000 or "\n" in bpf or "\x00" in bpf:
        raise LiveError("invalid capture filter")
    if not replay:
        if not interface or not IFACE_RE.match(interface):
            raise LiveError("invalid or missing interface name")
    elif not os.path.isfile(replay):
        raise LiveError("replay capture not found")
    if not (0.1 <= speed <= 100):
        raise LiveError("speed must be between 0.1 and 100")
    if duration < 0 or max_packets < 0 or max_bytes < 0:
        raise LiveError("limits must be positive")
    with _reg_lock:
        if len(_sessions) >= MAX_SESSIONS:
            raise LiveError(f"at most {MAX_SESSIONS} live captures can run at once")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    label = name or (f"live-{interface}-{stamp}.pcap" if not replay else
                     f"live-replay-{replay_name or os.path.splitext(os.path.basename(replay))[0]}-{stamp}.pcap")
    label = re.sub(r"[^\w.\-]+", "_", label)[:120]
    aid = store.create(label, "live", 0, "")
    try:
        s = LiveSession(aid, interface=interface, bpf=bpf, backend=backend, replay=replay, speed=speed,
                        duration=duration, max_packets=max_packets, max_bytes=max_bytes, interval=interval)
        with _reg_lock:
            _sessions[aid] = s
        store.update(aid, status="live", stage="capturing", progress=0)
        s.start()
    except LiveError as e:
        with _reg_lock:
            _sessions.pop(aid, None)
        store.update(aid, status="failed", error=str(e))
        raise
    return s


def get(aid: str) -> LiveSession | None:
    with _reg_lock:
        return _sessions.get(aid) or _finished.get(aid)


def active() -> list[LiveSession]:
    with _reg_lock:
        return list(_sessions.values())


def stop_all(reason: str = "server shutting down") -> None:
    for s in active():
        s.stop(reason)
    for s in active():
        s.join(10)
