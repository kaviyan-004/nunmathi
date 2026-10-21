import { RISKS, type Analysis, type ReportFmt, type Result } from "../api";
import { Flag, fmtBytes, fmtDur, fmtTime, Grade, CLASS_COLOR, RiskGauge } from "../util";
import type { TopTab } from "../App";

type R = Record<string, any>;
const CONF = ["High", "Medium", "Low", "None"];
const RISK_RANK: Record<string, number> = { High: 0, Medium: 1, Low: 2, Informational: 3 };

function aiConfidence(result: Result) {
  const geo: Record<string, number> = { High: 0, Medium: 0, Low: 0, None: 0 };
  const pfs: Record<string, number> = { High: 0, Medium: 0, Low: 0, None: 0 };
  let windows = 0, singleton = 0, ood = 0;
  for (const t of result.tunnels) {
    for (const c of t.child_sas) geo[c.geometry?.confidence ?? "None"] = (geo[c.geometry?.confidence ?? "None"] ?? 0) + 1;
    pfs[t.pfs?.confidence ?? "None"] = (pfs[t.pfs?.confidence ?? "None"] ?? 0) + 1;
    const s: R = t.traffic?.summary ?? {};
    windows += s.windows ?? 0;
    singleton += Math.round((s.singleton_sets ?? 0) * (s.windows ?? 0)); // fraction -> count
    ood += s.ood_windows ?? 0;
  }
  const mc: R = result.model_card ?? {};
  const cf: R = mc.conformal ?? {};
  return {
    geo, pfs, windows, singleton, ood,
    coverageTarget: cf.target_coverage ?? 1 - (cf.alpha ?? 0.1),
    coverageTest: cf.test_coverage ?? cf.empirical_coverage,
    accuracy: mc.test_accuracy, f1: mc.macro_f1,
  };
}

function ConfBar({ counts }: { counts: Record<string, number> }) {
  const total = CONF.reduce((a, k) => a + (counts[k] ?? 0), 0) || 1;
  const col: Record<string, string> = { High: "#1e8449", Medium: "#7dab2f", Low: "#e6a100", None: "#bbb" };
  return (
    <span className="confbar" title={CONF.map((k) => `${k}: ${counts[k] ?? 0}`).join(", ")}>
      {CONF.filter((k) => counts[k]).map((k) => (
        <span key={k} style={{ width: `${(100 * counts[k]) / total}%`, background: col[k] }}>{counts[k]}</span>
      ))}
    </span>
  );
}

export default function Summary({
  result,
  meta,
  onTunnel,
  onReport,
}: {
  result: Result;
  meta: Analysis;
  onTunnel: (id: string, tab?: TopTab) => void;
  onReport: (f: ReportFmt) => void;
}) {
  const f = result.file;
  const counts = Object.fromEntries(RISKS.map((r) => [r, result.alerts.filter((a) => a.risk === r).length]));
  const risk = result.grade.risk_score ?? 100 - result.grade.score;
  const ai = aiConfidence(result);
  const top = [...result.alerts]
    .filter((a) => a.risk !== "Informational")
    .sort((a, b) => RISK_RANK[a.risk] - RISK_RANK[b.risk] || a.id.localeCompare(b.id))
    .slice(0, 6);
  return (
    <div className="pad">
      <div className="summary-top">
        <Grade letter={result.grade.letter} big />
        <div className="stat">
          <span className="muted">Score</span>
          <b>{result.grade.score}/100</b>
        </div>
        <div className="stat">
          <span className="muted">Risk score</span>
          <RiskGauge value={risk} />
        </div>
        <div className="stat">
          <span className="muted">Tunnels</span>
          <b>{result.tunnels.length}</b>
        </div>
        <div className="stat">
          <span className="muted">Frames</span>
          <b>{f.frames.toLocaleString()}</b>
        </div>
        <div className="stat">
          <span className="muted">Duration</span>
          <b>{fmtDur(f.last_ts - f.first_ts)}</b>
        </div>
        <div className="stat">
          <span className="muted">Analysis time</span>
          <b>{result.elapsed} s</b>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          <button className="btn primary" onClick={() => onReport("executive")} title="2-3 page executive summary">Executive PDF</button>
          <button className="btn" onClick={() => onReport("technical")} title="15-30 page technical report with proofs, evidence and vendor snippets">Technical PDF</button>
          <button className="btn" onClick={() => onReport("html")}>HTML</button>
          <button className="btn" onClick={() => onReport("json")} title={`Versioned JSON (schema ${result.schema_version ?? "1.0.0"}) for SIEM/SOAR`}>JSON</button>
        </div>
      </div>
      <div className="riskbar">
        {RISKS.map((r) => (
          <span key={r}>
            <Flag risk={r} /> {r}: <b>{counts[r]}</b>
          </span>
        ))}
      </div>
      <p className="muted" style={{ marginTop: 6 }}>
        The overall grade is that of the worst tunnel. Each alert lowers a tunnel's score: High −25, Medium −10,
        Low −3. Any High alert caps the grade at C, and three or more High alerts give F.
      </p>

      <div className="score-grid">
        <div>
          <h2 className="sec">Top risks</h2>
          {top.length ? (
            <table className="grid clickable">
              <thead><tr><th>Risk</th><th>Rule</th><th>Finding</th><th>Tunnel</th><th>ATT&amp;CK</th></tr></thead>
              <tbody>
                {top.map((a) => (
                  <tr key={a.uid} onClick={() => a.tunnel && onTunnel(a.tunnel, "security")}>
                    <td><Flag risk={a.risk} size={12} /> {a.risk}</td>
                    <td className="mono">{a.id}</td>
                    <td>{a.name}<div className="muted" style={{ fontSize: 11 }}>{(a.standards ?? a.references ?? []).slice(0, 2).join(" · ")}</div></td>
                    <td>{a.tunnel || "—"}</td>
                    <td className="mono">{(a.attack ?? []).map((t) => t.id).join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="muted">No High, Medium or Low findings.</p>
          )}
        </div>
        <div>
          <h2 className="sec">AI confidence</h2>
          <table className="kv">
            <tbody>
              <tr><th>ESP geometry proofs</th><td><ConfBar counts={ai.geo} /> <span className="muted">Child SAs by confidence</span></td></tr>
              <tr><th>PFS inference</th><td><ConfBar counts={ai.pfs} /> <span className="muted">tunnels by confidence</span></td></tr>
              <tr><th>Traffic windows</th><td>{ai.windows.toLocaleString()} classified · {ai.singleton.toLocaleString()} single-label sets ({ai.windows ? Math.round((100 * ai.singleton) / ai.windows) : 0}%) · {ai.ood} out-of-distribution</td></tr>
              <tr><th>Conformal coverage</th><td>target {Math.round(ai.coverageTarget * 100)}%{ai.coverageTest != null ? `, measured ${(ai.coverageTest * 100).toFixed(1)}% on held-out data` : ""}</td></tr>
              <tr><th>Classifier</th><td>accuracy {ai.accuracy != null ? `${(ai.accuracy * 100).toFixed(1)}%` : "—"} · macro-F1 {ai.f1 ?? "—"} <span className="muted">(synthetic test set)</span></td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <h2 className="sec">Capture</h2>
      <table className="kv">
        <tbody>
          <tr><th>File</th><td>{meta.name} <span className="muted">({fmtBytes(meta.size)}, sha256 {meta.sha256?.slice(0, 16)}…)</span></td></tr>
          <tr><th>Time span</th><td>{fmtTime(f.first_ts)} → {fmtTime(f.last_ts)} UTC</td></tr>
          <tr><th>Packets</th><td>{f.ike} IKE · {f.esp.toLocaleString()} ESP · {f.nat_keepalive} NAT-T keepalive · {f.ah} AH · {f.other.toLocaleString()} other</td></tr>
          <tr><th>IKE messages parsed</th><td>{result.ike_messages} ({result.ike_parse_errors} parse errors)</td></tr>
          <tr><th>Engine</th><td>Nunmathi {result.engine}, traffic model {result.model_card.version}</td></tr>
        </tbody>
      </table>

      <h2 className="sec">Tunnels</h2>
      <table className="grid clickable">
        <thead>
          <tr>
            <th>Grade</th><th>Tunnel</th><th>Peers</th><th>IKE</th><th>ESP</th><th>PFS</th>
            <th>Traffic mix</th><th className="num">ESP data</th><th>Alerts</th>
          </tr>
        </thead>
        <tbody>
          {result.tunnels.map((t) => {
            const n = t.ike_crypto?.names ?? {};
            const cls = t.traffic?.summary?.class_windows ?? {};
            const total = Object.values(cls as Record<string, number>).reduce((a, b) => a + b, 0) || 1;
            const ac = Object.fromEntries(RISKS.map((r) => [r, result.alerts.filter((a) => a.tunnel === t.id && a.risk === r).length]));
            return (
              <tr key={t.id} onClick={() => onTunnel(t.id)}>
                <td><Grade letter={t.grade.letter} score={t.grade.score} /></td>
                <td>{t.id}</td>
                <td>{t.initiator} ⇄ {t.responder}</td>
                <td>IKEv{t.version} {n.encr}/{n.prf}/{n.group}{n.addke?.length ? ` + ${n.addke.join(",")}` : ""}</td>
                <td>{t.posture?.esp_label}</td>
                <td>
                  <span className={`pill ${t.pfs.status === "enabled" ? "good" : t.pfs.status === "disabled" ? "bad" : "warn"}`}>{t.pfs.status}</span>
                </td>
                <td>
                  <svg width="120" height="10" style={{ verticalAlign: -1 }}>
                    {(() => {
                      let x = 0;
                      return Object.entries(cls as Record<string, number>).map(([c, v]) => {
                        const w = (120 * v) / total;
                        const el = <rect key={c} x={x} y={0} width={w} height={10} fill={CLASS_COLOR[c]}><title>{`${c}: ${v} windows`}</title></rect>;
                        x += w;
                        return el;
                      });
                    })()}
                  </svg>
                </td>
                <td className="num">{fmtBytes(t.esp_bytes)}</td>
                <td>
                  {RISKS.filter((r) => ac[r]).map((r) => (
                    <span key={r} style={{ marginRight: 6 }}><Flag risk={r} size={12} />{ac[r]}</span>
                  ))}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {result.half_open.length > 0 && (
        <>
          <h2 className="sec">Half-open IKE activity</h2>
          <table className="grid">
            <thead><tr><th>Responder</th><th className="num">Attempts</th><th className="num">Sources</th><th className="num">Cookies</th><th className="num">Rate /s</th><th>First</th></tr></thead>
            <tbody>
              {result.half_open.map((h) => (
                <tr key={h.responder}><td>{h.responder}</td><td className="num">{h.attempts}</td><td className="num">{h.distinct_sources}</td><td className="num">{h.cookies}</td><td className="num">{h.rate_per_s}</td><td>{fmtTime(h.first_ts)}</td></tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
