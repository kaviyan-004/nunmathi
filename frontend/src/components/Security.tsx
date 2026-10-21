import { useMemo, useState } from "react";
import { RISKS, type Result } from "../api";
import { Flag, Grade, RISK_COLOR } from "../util";

type R = Record<string, any>;

export default function Security({
  result,
  onTunnel,
  onAlert,
}: {
  result: Result;
  onTunnel: (id: string) => void;
  onAlert: (uid: number) => void;
}) {
  const atk: R = (result as R).attack ?? { tactics: [], hit_techniques: [] };
  const [tech, setTech] = useState<string | null>(null);
  const [risk, setRisk] = useState<string>("");
  const alerts = useMemo(
    () =>
      result.alerts
        .filter((a) => !risk || a.risk === risk)
        .filter((a) => !tech || (a.attack ?? []).some((x) => x.id === tech))
        .sort((a, b) => RISKS.indexOf(a.risk) - RISKS.indexOf(b.risk)),
    [result, risk, tech],
  );
  return (
    <div className="pad">
      <h2 className="sec">MITRE ATT&amp;CK coverage</h2>
      <p className="muted">
        Techniques an adversary could use against the weaknesses found in this capture ({atk.version ?? "MITRE ATT&amp;CK"}). Coloured cells are
        enabled by at least one finding; colour is the highest risk among them. Click a technique to filter the violations below.
      </p>
      {atk.tactics?.length ? (
        <div className="attack-matrix">
          {atk.tactics.map((ta: R) => (
            <div key={ta.id}>
              <div className="tac" title={ta.id}>{ta.name}</div>
              {ta.techniques.map((te: R) => {
                const hit = !!te.alerts?.length;
                return (
                  <div
                    key={te.id}
                    className={`tech ${hit ? "hit" : ""}`}
                    style={{
                      background: hit ? RISK_COLOR[te.max_risk as keyof typeof RISK_COLOR] ?? "#777" : undefined,
                      outline: tech === te.id ? "2px solid #111" : undefined,
                      cursor: hit ? "pointer" : "default",
                    }}
                    title={te.why ?? ""}
                    onClick={() => hit && setTech(tech === te.id ? null : te.id)}
                  >
                    <div className="tid">{te.id}</div>
                    {te.name}
                    {hit && <div style={{ fontSize: 10, opacity: 0.9 }}>{te.alerts.length} finding(s)</div>}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      ) : (
        <p className="muted">No ATT&amp;CK mapping in this result.</p>
      )}
      {atk.unmapped_rules?.length ? <p className="muted">Findings without an ATT&amp;CK technique: {atk.unmapped_rules.join(", ")}</p> : null}

      <h2 className="sec">Rule violations ({alerts.length})</h2>
      <div className="toolbar-inline">
        Risk:{" "}
        <select value={risk} onChange={(e) => setRisk(e.target.value)}>
          <option value="">all</option>
          {RISKS.map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
        {tech && (
          <button className="btn" onClick={() => setTech(null)}>
            Clear technique filter ({tech})
          </button>
        )}
      </div>
      <table className="grid wrap">
        <thead>
          <tr>
            <th>Risk</th><th>Rule</th><th>Finding</th><th>Tunnel</th><th>Confidence</th><th>Standards</th><th>ATT&amp;CK</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.uid} style={{ cursor: "pointer" }} onClick={() => onAlert(a.uid)}>
              <td><Flag risk={a.risk} /> {a.risk}</td>
              <td className="mono">{a.id}</td>
              <td>{a.name}</td>
              <td>
                {a.tunnel ? (
                  <a href="#" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onTunnel(a.tunnel); }}>{a.tunnel}</a>
                ) : "—"}
              </td>
              <td>{a.confidence}</td>
              <td style={{ fontSize: 11 }}>{(a.standards ?? []).join("; ") || "—"}</td>
              <td className="mono" style={{ fontSize: 11 }}>
                {(a.attack ?? []).map((x) => (
                  <a key={x.id} href={x.url} target="_blank" rel="noreferrer" title={x.name} onClick={(e) => e.stopPropagation()} style={{ marginRight: 4 }}>
                    {x.id}
                  </a>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className="sec">Metadata Exposure Index (MEI) per tunnel</h2>
      <p className="muted">
        MEI measures how much an on-path observer learns about the application inside the tunnel from packet sizes and timing alone (0 = nothing,
        1 = fully identifiable).
      </p>
      <table className="grid">
        <thead>
          <tr>
            <th>Tunnel</th><th>Grade</th><th className="num">Windows</th><th className="num">MEI mean</th><th className="num">MEI p90</th>
            <th className="num">Singleton sets</th><th className="num">OOD windows</th><th>TFC padding</th><th>Leakage</th>
          </tr>
        </thead>
        <tbody>
          {result.tunnels.map((t) => {
            const s: R = t.traffic?.summary ?? {};
            const mei = s.mei_mean;
            const lvl = mei == null ? "—" : mei >= 0.6 ? "High" : mei >= 0.3 ? "Medium" : "Low";
            return (
              <tr key={t.id} style={{ cursor: "pointer" }} onClick={() => onTunnel(t.id)}>
                <td>{t.id} <span className="muted">{t.initiator} ⇄ {t.responder}</span></td>
                <td><Grade letter={t.grade.letter} /></td>
                <td className="num">{s.windows ?? 0}</td>
                <td className="num"><b>{mei ?? "—"}</b></td>
                <td className="num">{s.mei_p90 ?? "—"}</td>
                <td className="num">{s.singleton_sets != null ? `${(s.singleton_sets * 100).toFixed(1)}%` : "—"}</td>
                <td className="num">{s.ood_windows ?? 0}</td>
                <td>{t.posture?.tfc_padding == null ? "unknown" : t.posture.tfc_padding ? "yes" : "no"}</td>
                <td style={{ color: lvl === "High" ? RISK_COLOR.High : lvl === "Medium" ? RISK_COLOR.Medium : undefined, fontWeight: 600 }}>{lvl}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
