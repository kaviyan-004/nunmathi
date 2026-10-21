import { useEffect, useMemo, useState } from "react";
import { api, type Result, type Tunnel } from "../api";
import { CLASS_COLOR, fmtDur, fmtTime } from "../util";
import TunnelPicker from "./TunnelPicker";

type R = Record<string, any>;
const CLASSES = ["voip", "video", "web", "chat", "email"];

function ShapBars({ rows, value, fmt }: { rows: R[]; value: (r: R) => number; fmt?: (r: R) => string }) {
  const max = Math.max(1e-9, ...rows.map((r) => Math.abs(value(r))));
  return (
    <div>
      {rows.map((r) => {
        const v = value(r);
        const w = (50 * Math.abs(v)) / max;
        return (
          <div className="shap-row" key={r.feature}>
            <span className="mono" title={r.feature}>{r.feature}</span>
            <span className="bar">
              <span style={{ position: "absolute", left: v >= 0 ? "50%" : `${50 - w}%`, width: `${w}%`, background: v >= 0 ? "#c0392b" : "#2e86c1" }} />
            </span>
            <span className="mono num">{fmt ? fmt(r) : v.toFixed(4)}</span>
          </div>
        );
      })}
    </div>
  );
}

function Explain({ aid, t, win, wins }: { aid: string; t: Tunnel; win: number | null; wins: R[] }) {
  const [glob, setGlob] = useState<R | null>(null);
  const [loc, setLoc] = useState<R | null>(null);
  const [err, setErr] = useState<string>("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setGlob(null);
    setErr("");
    setBusy(true);
    api
      .explain(aid, t.id)
      .then(setGlob)
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false));
  }, [aid, t.id]);
  useEffect(() => {
    setLoc(null);
    if (win == null) return;
    api
      .explain(aid, t.id, win)
      .then(setLoc)
      .catch((e) => setLoc({ error: e.message }));
  }, [aid, t.id, win]);
  return (
    <div className="two-col">
      <div>
        <h3 style={{ margin: "6px 0" }}>Global feature importance</h3>
        {busy && <p className="muted">Computing Shapley values…</p>}
        {err && <div className="err-box">{err}</div>}
        {glob && glob.features?.length ? (
          <>
            <ShapBars rows={glob.features} value={(r) => r.mean_abs_phi} />
            <p className="muted">
              Mean |SHAP| of the predicted-class probability over {glob.windows} windows ({glob.method}). Estimates are Monte-Carlo; treat
              small differences as noise.
            </p>
          </>
        ) : glob ? (
          <p className="muted">No windows carry feature vectors; re-run the analysis to enable explanations.</p>
        ) : null}
      </div>
      <div>
        <h3 style={{ margin: "6px 0" }}>Local explanation{win != null ? ` · window #${win}` : ""}</h3>
        {win == null ? (
          <p className="muted">Click a window on the timeline to explain its prediction.</p>
        ) : !loc ? (
          <p className="muted">Computing…</p>
        ) : loc.error ? (
          <div className="err-box">{loc.error}</div>
        ) : (
          <>
            <p>
              {fmtTime(wins[win]?.start)} → <b style={{ color: CLASS_COLOR[loc.label] }}>{loc.label}</b>: base {loc.base_value} + Σφ {loc.sum_phi} ={" "}
              <b>{loc.prediction}</b>
            </p>
            <ShapBars rows={loc.features} value={(r) => r.phi} fmt={(r) => `${r.phi >= 0 ? "+" : ""}${r.phi.toFixed(4)} ±${r.se.toFixed(4)}`} />
            <p className="muted">
              Red pushes towards {loc.label}, blue away. Remaining features contribute {loc.other_phi}. ± is the standard error of the
              sampling estimate.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

export default function TrafficView({ aid, result, tunnel: t, onTunnel }: { aid: string; result: Result; tunnel: Tunnel; onTunnel: (id: string) => void }) {
  const tr = t.traffic ?? {};
  const wins: R[] = tr.windows ?? [];
  const segs: R[] = tr.segments ?? [];
  const sm: R = tr.summary ?? {};
  const [hover, setHover] = useState<R | null>(null);
  const [zoom, setZoom] = useState<"active" | "full">("active");
  const [sel, setSel] = useState<number | null>(null);
  useEffect(() => setSel(null), [aid, t.id]);

  // Traffic is bursty: compress idle gaps so the active windows are readable.
  const layout = useMemo(() => {
    if (!wins.length) return null;
    const t0 = t.first_ts;
    const t1 = t.last_ts;
    if (zoom === "full") {
      const span = Math.max(1, t1 - t0);
      return { x: (ts: number) => (ts - t0) / span, gaps: [] as number[] };
    }
    const GAP = 30; // seconds shown for any idle gap
    const pos: [number, number][] = [];
    let acc = 0;
    let prevEnd = wins[0].start;
    const gaps: number[] = [];
    for (const w of wins) {
      if (w.start - prevEnd > GAP) {
        acc += GAP;
        gaps.push(acc - GAP / 2);
      } else acc += w.start - prevEnd;
      pos.push([w.start, acc]);
      acc += w.end - w.start;
      prevEnd = w.end;
    }
    const total = acc;
    const x = (ts: number) => {
      let lo = 0;
      for (let i = 0; i < pos.length; i++) if (pos[i][0] <= ts) lo = i;
      return Math.min(1, (pos[lo][1] + Math.max(0, ts - pos[lo][0])) / total);
    };
    return { x, gaps: gaps.map((g) => g / total) };
  }, [wins, zoom, t.first_ts, t.last_ts]);

  if (!wins.length) return <div className="empty">No ESP traffic observed for {t.id}.</div>;
  const W = 1000;
  const lane = 22;
  const top = 18;
  const meiY = top + lane * CLASSES.length + 16;
  const H = meiY + 70;
  const X = (ts: number) => 80 + layout!.x(ts) * (W - 100);

  return (
    <>
      <TunnelPicker result={result} value={t.id} onChange={onTunnel} />
      <div className="pad">
        <h2 className="sec">Application-class timeline (inferred from encrypted ESP)</h2>
        <div className="legend">
          {CLASSES.map((c) => (
            <span key={c}>
              <span className="sw" style={{ background: CLASS_COLOR[c] }} /> {c} ({sm.class_windows?.[c] ?? 0} windows)
            </span>
          ))}
          <span>
            <span className="sw" style={{ background: "none", border: "2px dashed #000" }} /> out of distribution
          </span>
          <span style={{ marginLeft: "auto" }}>
            Scale:{" "}
            <select value={zoom} onChange={(e) => setZoom(e.target.value as "active" | "full")}>
              <option value="active">active periods (idle gaps compressed)</option>
              <option value="full">wall clock</option>
            </select>
          </span>
        </div>
        <div className="timeline" style={{ overflowX: "auto" }}>
          <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ minWidth: 700, background: "#fff", border: "1px solid #ddd" }}>
            {CLASSES.map((c, i) => (
              <g key={c}>
                <rect x={80} y={top + i * lane} width={W - 100} height={lane - 4} fill="#f5f6f8" />
                <text x={72} y={top + i * lane + 13} textAnchor="end" fontSize="11" fill="#333">{c}</text>
              </g>
            ))}
            {layout!.gaps.map((g, i) => (
              <line key={i} x1={80 + g * (W - 100)} x2={80 + g * (W - 100)} y1={top - 6} y2={meiY + 50} stroke="#bbb" strokeDasharray="2 3" />
            ))}
            {wins.map((w, i) => {
              const li = CLASSES.indexOf(w.label);
              const x = X(w.start);
              const wd = Math.max(1.5, X(w.end) - x - 0.5);
              return (
                <g key={i} onMouseEnter={() => setHover(w)} onClick={() => setSel(i)} style={{ cursor: "pointer" }}>
                  <rect
                    x={x}
                    y={top + li * lane}
                    width={wd}
                    height={lane - 4}
                    fill={CLASS_COLOR[w.label]}
                    opacity={0.35 + 0.65 * (w.probs?.[w.label] ?? 1)}
                    stroke={sel === i ? "#111" : w.ood ? "#000" : "none"}
                    strokeWidth={sel === i ? 2 : 1}
                    strokeDasharray={w.ood && sel !== i ? "2 1" : undefined}
                  />
                  {w.set.length > 1 &&
                    w.set
                      .filter((c: string) => c !== w.label)
                      .map((c: string) => (
                        <rect key={c} x={x} y={top + CLASSES.indexOf(c) * lane + 6} width={wd} height={6} fill={CLASS_COLOR[c]} opacity={0.45} />
                      ))}
                </g>
              );
            })}
            <text x={72} y={meiY + 24} textAnchor="end" fontSize="11" fill="#333">MEI</text>
            <rect x={80} y={meiY} width={W - 100} height={46} fill="#fafafa" stroke="#eee" />
            <polyline
              fill="none"
              stroke="#7b3fb5"
              strokeWidth="1.4"
              points={wins.map((w) => `${X((w.start + w.end) / 2)},${meiY + 46 - 46 * w.mei}`).join(" ")}
            />
            <text x={W - 18} y={meiY + 9} fontSize="9" textAnchor="end" fill="#999">1.0</text>
            <text x={W - 18} y={meiY + 45} fontSize="9" textAnchor="end" fill="#999">0</text>
            <text x={80} y={H - 4} fontSize="10" fill="#666">{fmtTime(wins[0].start)}</text>
            <text x={W - 20} y={H - 4} fontSize="10" fill="#666" textAnchor="end">{fmtTime(wins[wins.length - 1].end)}</text>
          </svg>
        </div>
        <div style={{ minHeight: 40, marginTop: 6 }}>
          {hover ? (
            <div>
              <b>{fmtTime(hover.start)}</b> ({fmtDur(hover.end - hover.start)} window, {hover.packets} packets) → <b style={{ color: CLASS_COLOR[hover.label] }}>{hover.label}</b>{" "}
              · 90% prediction set {"{"}
              {hover.set.join(", ")}
              {"}"} · MEI {hover.mei.toFixed(2)} · entropy {hover.entropy.toFixed(2)} bits {hover.ood ? <span className="pill bad">OOD score {hover.ood_score.toFixed(2)}</span> : null}
              <div className="muted">
                {Object.entries(hover.probs as Record<string, number>)
                  .sort((a, b) => b[1] - a[1])
                  .map(([c, p]) => `${c} ${(p * 100).toFixed(1)}%`)
                  .join(" · ")}
              </div>
            </div>
          ) : (
            <span className="muted">Hover a window to see its class probabilities, conformal prediction set and exposure.</span>
          )}
        </div>

        <h2 className="sec">Why the model decided this (SHAP)</h2>
        <Explain aid={aid} t={t} win={sel} wins={wins} />

        <h2 className="sec">Metadata exposure</h2>
        <table className="kv">
          <tbody>
            <tr><th>Windows classified</th><td>{sm.windows} × 5 s</td></tr>
            <tr><th>Mean MEI</th><td><b>{sm.mei_mean}</b> (p90 {sm.mei_p90}). 1 = the application is fully identifiable; 0 = no information leaks.</td></tr>
            <tr><th>Singleton prediction sets</th><td>{((sm.singleton_sets ?? 0) * 100).toFixed(1)}% of windows (the 90% conformal set has exactly one class)</td></tr>
            <tr><th>Out-of-distribution windows</th><td>{sm.ood_windows} (kNN distance above the 99th percentile of calibration data)</td></tr>
          </tbody>
        </table>

        <h2 className="sec">Segments</h2>
        <table className="grid">
          <thead><tr><th>Start</th><th>Duration</th><th>Class</th><th className="num">Windows</th><th className="num">Packets</th><th className="num">Confidence</th><th className="num">MEI</th><th>OOD</th></tr></thead>
          <tbody>
            {segs.map((s, i) => (
              <tr key={i}>
                <td>{fmtTime(s.start)}</td>
                <td>{fmtDur(s.end - s.start)}</td>
                <td><span className="sw" style={{ background: CLASS_COLOR[s.label], marginRight: 5, verticalAlign: -1 }} />{s.label}</td>
                <td className="num">{s.windows}</td>
                <td className="num">{s.packets.toLocaleString()}</td>
                <td className="num">{(s.confidence * 100).toFixed(1)}%</td>
                <td className="num">{s.mei.toFixed(2)}</td>
                <td>{s.ood ? "yes" : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
