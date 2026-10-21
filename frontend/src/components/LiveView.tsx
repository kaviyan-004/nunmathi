import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, RISKS, type Analysis, type LiveCaps, type LiveEvent, type LiveStatus, type Risk } from "../api";
import { Flag, fmtBytes, fmtTime, Grade } from "../util";
import { isNative } from "../native";
import * as I from "../icons";

type Source = "interface" | "replay";

function fmtRate(bps: number) {
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbit/s`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} kbit/s`;
  return `${Math.round(bps)} bit/s`;
}

function clock(s: number) {
  s = Math.floor(s);
  const h = Math.floor(s / 3600),
    m = Math.floor((s % 3600) / 60),
    x = s % 60;
  return `${h ? `${h}:` : ""}${String(m).padStart(h ? 2 : 1, "0")}:${String(x).padStart(2, "0")}`;
}

/** Frames / IKE / ESP per second over the last two minutes. */
function Spark({ rates, now }: { rates: LiveStatus["rates"]; now: number }) {
  const W = 600,
    H = 70,
    N = 120;
  const end = Math.floor(now);
  const by = new Map(rates.map((r) => [r.t, r]));
  const series = (k: "frames" | "ike" | "esp") => Array.from({ length: N }, (_, i) => by.get(end - N + 1 + i)?.[k] ?? 0);
  const fr = series("frames"),
    ike = series("ike"),
    esp = series("esp");
  const max = Math.max(1, ...fr);
  const path = (v: number[]) => v.map((y, i) => `${i ? "L" : "M"}${((i / (N - 1)) * W).toFixed(1)},${(H - 4 - (y / max) * (H - 14)).toFixed(1)}`).join("");
  return (
    <svg className="spark" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-label="packet rate">
      <path d={`${path(fr)}L${W},${H}L0,${H}z`} fill="#3874c822" />
      <path d={path(fr)} fill="none" stroke="#3874c8" strokeWidth="1.3" vectorEffect="non-scaling-stroke" />
      <path d={path(esp)} fill="none" stroke="#3d9b35" strokeWidth="1.1" vectorEffect="non-scaling-stroke" />
      <path d={path(ike)} fill="none" stroke="#e8a317" strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
      <text x="4" y="11" fontSize="10" fill="#666">
        peak {max} frames/s · last 120 s
      </text>
      <text x={W - 4} y="11" fontSize="10" textAnchor="end" fill="#666">
        <tspan fill="#3874c8">■ all</tspan> <tspan fill="#3d9b35">■ ESP</tspan> <tspan fill="#e8a317">■ IKE</tspan>
      </text>
    </svg>
  );
}

function levelFlag(level: string) {
  if ((RISKS as string[]).includes(level)) return <Flag risk={level as Risk} size={12} />;
  return <Flag risk="Informational" size={12} />;
}

export default function LiveView({
  analyses,
  watchId,
  onWatch,
  onOpen,
  say,
}: {
  analyses: Analysis[];
  watchId: string | null;
  onWatch: (id: string | null) => void;
  onOpen: (id: string) => void;
  say: (msg: string, err?: boolean) => void;
}) {
  const [caps, setCaps] = useState<LiveCaps | null>(null);
  const [capsErr, setCapsErr] = useState("");
  const [scen, setScen] = useState<{ id: string; title: string }[]>([]);
  const [source, setSource] = useState<Source>("interface");
  const [iface, setIface] = useState("");
  const [backend, setBackend] = useState("");
  const [filter, setFilter] = useState("");
  const [duration, setDuration] = useState(0);
  const [maxPackets, setMaxPackets] = useState(1_000_000);
  const [interval, setIntervalS] = useState(2);
  const [replayKind, setReplayKind] = useState<"scenario" | "analysis">("scenario");
  const [replayScen, setReplayScen] = useState("");
  const [replayAid, setReplayAid] = useState("");
  const [speed, setSpeed] = useState(1);
  const [starting, setStarting] = useState(false);
  const [st, setSt] = useState<LiveStatus | null>(null);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [active, setActive] = useState<LiveStatus[]>([]);
  const [err, setErr] = useState("");
  const lastSeq = useRef(0);

  const loadCaps = useCallback(() => {
    api
      .liveCaps()
      .then((c) => {
        setCaps(c);
        setCapsErr("");
        setFilter((f) => f || c.default_filter || "");
        const usable = c.backends?.find((b) => b.privileged) ?? c.backends?.[0];
        setBackend((b) => b || usable?.name || "");
        const ifs = c.interfaces ?? [];
        setIface((i) => i || (ifs.find((x) => x.up && !x.loopback && !x.pseudo) ?? ifs[0])?.name || "");
      })
      .catch((e) => setCapsErr(e.message));
  }, []);

  useEffect(() => {
    loadCaps();
    api
      .scenarios()
      .then((s) => {
        setScen(s);
        setReplayScen((x) => x || s[0]?.id || "");
      })
      .catch(() => setScen([]));
  }, [loadCaps]);

  // other running sessions
  useEffect(() => {
    const f = () => api.liveList().then(setActive).catch(() => setActive([]));
    f();
    const t = setInterval(f, 3000);
    return () => clearInterval(t);
  }, []);

  const push = useCallback((s: LiveStatus) => {
    setSt(s);
    if (s.events?.length) {
      const fresh = s.events.filter((e) => e.seq > lastSeq.current);
      if (fresh.length) setEvents((ev) => [...ev, ...fresh].slice(-1000));
    }
    lastSeq.current = Math.max(lastSeq.current, s.last_seq);
  }, []);

  // follow the watched session with Server-Sent Events, falling back to polling
  useEffect(() => {
    setSt(null);
    setEvents([]);
    setErr("");
    lastSeq.current = 0;
    if (!watchId) return;
    let closed = false;
    let disposed = false;
    let poll: ReturnType<typeof setInterval> | null = null;
    const pollUntilEnd = () => {
      const tick = () =>
        api
          .liveStatus(watchId, lastSeq.current)
          .then((s) => {
            if (disposed) return;
            push(s);
            if (!s.running && poll) clearInterval(poll);
          })
          .catch((e) => {
            setErr(e.message);
            if (poll) clearInterval(poll);
          });
      tick();
      poll = setInterval(tick, isNative ? 1000 : 1500);
    };
    if (isNative) {
      // desktop app: no HTTP server to stream from, the in-process engine is polled instead
      pollUntilEnd();
      return () => {
        disposed = true;
        if (poll) clearInterval(poll);
      };
    }
    const es = new EventSource(api.liveStreamUrl(watchId, 0));
    es.addEventListener("status", (e) => push(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("end", () => {
      es.close();
      closed = true;
    });
    es.onerror = () => {
      if (closed) return;
      es.close();
      closed = true;
      // stream dropped (proxy, server restart…): poll until the capture has ended
      pollUntilEnd();
    };
    return () => {
      closed = disposed = true;
      es.close();
      if (poll) clearInterval(poll);
    };
  }, [watchId, push]);

  const ended = useRef<string | null>(null);
  useEffect(() => {
    if (st && !st.running && ended.current !== st.id) {
      ended.current = st.id;
      if (st.state === "failed") say(`Live capture ${st.id} failed: ${st.error}`, true);
      else say(`Live capture ${st.id} ended (${st.stop_reason}): ${st.stats.frames} frames, grade ${st.summary.grade ?? "–"}`);
    }
  }, [st, say]);

  const start = async () => {
    setStarting(true);
    setErr("");
    const req =
      source === "interface"
        ? { interface: iface, backend: backend || undefined, filter, duration, max_packets: maxPackets, interval }
        : {
            ...(replayKind === "scenario" ? { replay_scenario: replayScen } : { replay_analysis: replayAid }),
            speed,
            duration,
            max_packets: maxPackets,
            interval,
          };
    try {
      const s = await api.liveStart(req);
      say(`Live capture started: ${s.command ?? `replay of ${s.replay} at ${s.speed}×`}`);
      onWatch(s.id);
    } catch (e) {
      setErr((e as Error).message);
      say(`Cannot start live capture: ${(e as Error).message}`, true);
    } finally {
      setStarting(false);
    }
  };

  const stop = async () => {
    if (!watchId) return;
    try {
      await api.liveStop(watchId);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const be = caps?.backends?.find((b) => b.name === backend);
  const replayable = useMemo(() => analyses.filter((a) => a.status === "done" && a.size > 0), [analyses]);
  const canStart =
    !!caps?.enabled &&
    !starting &&
    (source === "interface" ? !!iface && !!caps.backends?.length : replayKind === "scenario" ? !!replayScen : !!replayAid);
  const running = !!st?.running;
  const nowTs = st ? (st.ended ?? st.started + st.elapsed) : Date.now() / 1000;
  const meta = analyses.find((a) => a.id === watchId);

  return (
    <div className="live">
      <div className="cfg">
        <h2 className="sec">
          <I.IcLive /> Live Capture
        </h2>
        <p className="muted" style={{ margin: "0 0 4px" }}>
          Streams packets from a network interface into the analyzer in real time. It only listens: nothing is sent,
          nothing is decrypted.
        </p>
        {capsErr && <div className="hint bad">Cannot read capture capabilities: {capsErr}</div>}
        {caps && !caps.enabled && <div className="hint bad">Live capture is disabled on this server (NUNMATHI_LIVE=0).</div>}

        <label>Source</label>
        <div className="radio">
          <label>
            <input type="radio" checked={source === "interface"} onChange={() => setSource("interface")} /> Network interface
          </label>
          <label>
            <input type="radio" checked={source === "replay"} onChange={() => setSource("replay")} /> Replay (real-time)
          </label>
        </div>

        {source === "interface" ? (
          <>
            <label htmlFor="lv-if">Interface</label>
            <div className="row">
              <div>
                <select id="lv-if" value={iface} onChange={(e) => setIface(e.target.value)}>
                  {caps?.interfaces?.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name}
                      {i.pseudo ? " (all interfaces)" : ""}
                      {!i.up ? " [down]" : ""}
                      {i.addresses.length ? ` — ${i.addresses.join(", ")}` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <button className="btn" style={{ flex: "none" }} title="Re-scan interfaces and capture tools" onClick={loadCaps}>
                <I.IcRefresh />
              </button>
            </div>
            {caps?.prefix && <div className="hint">Capturing inside: {caps.prefix}</div>}
            <label htmlFor="lv-be">Capture tool</label>
            <select id="lv-be" value={backend} onChange={(e) => setBackend(e.target.value)}>
              {caps?.backends?.map((b) => (
                <option key={b.name} value={b.name}>
                  {b.name} ({b.path}){b.privileged ? "" : " — no privileges"}
                </option>
              ))}
            </select>
            {caps && !caps.backends?.length && <div className="hint bad">No capture tool found. Install Wireshark's dumpcap or tcpdump.</div>}
            {be && <div className={`hint ${be.privileged ? "" : "bad"}`}>{be.note}</div>}
            <label htmlFor="lv-f">Capture filter (BPF)</label>
            <input id="lv-f" type="text" className="mono" value={filter} onChange={(e) => setFilter(e.target.value)} />
            <div className="hint">Default keeps only IKE (UDP 500/4500), ESP and AH, applied in the kernel.</div>
          </>
        ) : (
          <>
            <label>Replay</label>
            <div className="radio">
              <label>
                <input type="radio" checked={replayKind === "scenario"} onChange={() => setReplayKind("scenario")} /> Demo scenario
              </label>
              <label>
                <input type="radio" checked={replayKind === "analysis"} onChange={() => setReplayKind("analysis")} /> Stored capture
              </label>
            </div>
            {replayKind === "scenario" ? (
              <select style={{ marginTop: 4 }} value={replayScen} onChange={(e) => setReplayScen(e.target.value)}>
                {scen.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.title}
                  </option>
                ))}
              </select>
            ) : (
              <select style={{ marginTop: 4 }} value={replayAid} onChange={(e) => setReplayAid(e.target.value)}>
                <option value="">— choose an analysis —</option>
                {replayable.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({fmtBytes(a.size)})
                  </option>
                ))}
              </select>
            )}
            <label htmlFor="lv-sp">Speed</label>
            <select id="lv-sp" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
              {[1, 2, 5, 10, 30, 100].map((x) => (
                <option key={x} value={x}>
                  {x}× real time
                </option>
              ))}
            </select>
            <div className="hint">The capture is streamed through the same pipeline as an interface, with its original timing.</div>
          </>
        )}

        <div className="row">
          <div>
            <label htmlFor="lv-d">Stop after (s)</label>
            <input id="lv-d" type="number" min={0} value={duration} onChange={(e) => setDuration(Math.max(0, Number(e.target.value)))} />
          </div>
          <div>
            <label htmlFor="lv-n">Max packets</label>
            <input id="lv-n" type="number" min={1} value={maxPackets} onChange={(e) => setMaxPackets(Math.max(1, Number(e.target.value)))} />
          </div>
        </div>
        <div className="hint">0 s = run until stopped.</div>
        <label htmlFor="lv-i">Re-analyze every (s)</label>
        <input id="lv-i" type="number" min={0.5} step={0.5} value={interval} onChange={(e) => setIntervalS(Math.max(0.5, Number(e.target.value)))} />

        <div style={{ display: "flex", gap: 6, marginTop: 14 }}>
          <button className="btn primary" disabled={!canStart} onClick={start}>
            {starting ? "Starting…" : "Start capture"}
          </button>
          <button className="btn" disabled={!running} onClick={stop}>
            Stop
          </button>
        </div>
        {err && <div className="hint bad">{err}</div>}

        {active.length > 0 && (
          <>
            <label>Running sessions</label>
            <div className="sessions">
              {active.map((a) => (
                <button key={a.id} className={`btn ${a.id === watchId ? "primary" : ""}`} onClick={() => onWatch(a.id)}>
                  <span className="live-dot" />
                  {a.interface ?? a.replay} · {a.stats.frames}
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      <div className="run">
        {!watchId ? (
          <div className="empty">
            Choose an interface and press <b>Start capture</b>. Tunnels, rekeys and alerts appear here as they happen, and every
            other view (Summary, Tunnel, Alerts, History…) updates while the capture runs.
          </div>
        ) : !st ? (
          <div className="empty">{err || "Connecting to the live stream…"}</div>
        ) : (
          <>
            <div className="stats">
              <div className="stat">
                <span className="muted">State</span>
                <b>
                  {running && <span className="live-dot" />}
                  {st.state}
                </b>
              </div>
              <div className="stat">
                <span className="muted">Source</span>
                <b>{st.source === "replay" ? `replay ${st.replay} ${st.speed}×` : `${st.interface} (${st.backend})`}</b>
              </div>
              <div className="stat">
                <span className="muted">Elapsed</span>
                <b>{clock(st.elapsed)}</b>
              </div>
              <div className="stat">
                <span className="muted">Rate</span>
                <b>
                  {st.pps} pkt/s · {fmtRate(st.bps)}
                </b>
              </div>
              <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                <button className="btn" disabled={!meta || !st.analyses} onClick={() => onOpen(st.id)}>
                  Open analysis
                </button>
                {running && (
                  <button className="btn" onClick={stop}>
                    <I.IcStop /> Stop
                  </button>
                )}
              </div>
            </div>
            {st.command && <div className="cmd">$ {st.command}</div>}
            {st.error && <div className="pill bad" style={{ whiteSpace: "pre-wrap" }}>{st.error}</div>}
            {!running && st.stop_reason && !st.error && (
              <div className="muted">
                Capture ended: {st.stop_reason} at {fmtTime(st.ended ?? 0)}.
              </div>
            )}
            <div className="stats">
              {(
                [
                  ["Frames", st.stats.frames.toLocaleString()],
                  ["IKE", st.stats.ike.toLocaleString()],
                  ["ESP", st.stats.esp.toLocaleString()],
                  ["NAT-KA", st.stats.nat_keepalive.toLocaleString()],
                  ["AH", st.stats.ah.toLocaleString()],
                  ["Other", st.stats.other.toLocaleString()],
                  ["Recorded", fmtBytes(st.captured_bytes)],
                  ["Tunnels", st.summary.tunnels ?? "–"],
                ] as [string, React.ReactNode][]
              ).map(([k, v]) => (
                <div className="stat" key={k}>
                  <span className="muted">{k}</span>
                  <b>{v}</b>
                </div>
              ))}
              <div className="stat">
                <span className="muted">Grade</span>
                <b>{st.summary.grade ? <Grade letter={st.summary.grade} score={st.summary.score} /> : "–"}</b>
              </div>
            </div>
            {st.summary.alerts && (
              <div className="riskbar">
                {RISKS.map((r) => (
                  <span key={r}>
                    <Flag risk={r} /> {r}: <b>{st.summary.alerts![r] ?? 0}</b>
                  </span>
                ))}
                <span className="muted" style={{ marginLeft: "auto" }}>
                  analysis #{st.analyses}, {st.analysis_time}s each
                  {st.last_analysis ? `, last at ${fmtTime(st.last_analysis, false)}` : ""}
                </span>
              </div>
            )}
            <Spark rates={st.rates} now={nowTs} />
            <div className="feed">
              <table className="grid">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Level</th>
                    <th>Type</th>
                    <th>Tunnel</th>
                    <th style={{ width: "100%" }}>Event</th>
                  </tr>
                </thead>
                <tbody>
                  {events
                    .slice()
                    .reverse()
                    .map((e) => (
                      <tr key={e.seq}>
                        <td>{fmtTime(e.ts, false)}</td>
                        <td>
                          {levelFlag(e.level)} {e.level}
                        </td>
                        <td>{e.type}</td>
                        <td>{e.tunnel ?? ""}</td>
                        <td style={{ whiteSpace: "normal" }}>{e.text}</td>
                      </tr>
                    ))}
                  {!events.length && (
                    <tr>
                      <td colSpan={5} className="muted">
                        Waiting for IPsec traffic…
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
