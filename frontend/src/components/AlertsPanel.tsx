import { useMemo, useState } from "react";
import { RISKS, type Alert, type Result } from "../api";
import { Flag, RISK_COLOR } from "../util";

export default function AlertsPanel({
  result,
  sel,
  onSel,
  onTunnel,
}: {
  result: Result;
  sel: number | null;
  onSel: (uid: number) => void;
  onTunnel: (id: string) => void;
}) {
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const groups = useMemo(() => {
    const out: { risk: (typeof RISKS)[number]; rules: { id: string; name: string; items: Alert[] }[] }[] = [];
    for (const risk of RISKS) {
      const m = new Map<string, { id: string; name: string; items: Alert[] }>();
      for (const a of result.alerts.filter((x) => x.risk === risk)) {
        if (!m.has(a.id)) m.set(a.id, { id: a.id, name: a.name, items: [] });
        m.get(a.id)!.items.push(a);
      }
      if (m.size) out.push({ risk, rules: [...m.values()] });
    }
    return out;
  }, [result]);
  const a = result.alerts.find((x) => x.uid === sel) ?? null;
  const toggle = (k: string) => setClosed((c) => ({ ...c, [k]: !c[k] }));

  if (!result.alerts.length) return <div className="empty">No alerts raised for this capture.</div>;
  return (
    <div className="alerts">
      <div className="left">
        <div className="tree">
          <div className="node" onClick={() => toggle("_root")}>
            <span className="twist">{closed._root ? "▸" : "▾"}</span>
            <span className="lbl">Alerts ({result.alerts.length})</span>
          </div>
          {!closed._root && (
            <div className="children">
              {groups.map((g) =>
                g.rules.map((r) => {
                  const k = `${g.risk}:${r.id}`;
                  return (
                    <div key={k}>
                      <div className="node" onClick={() => toggle(k)} title={r.id}>
                        <span className="twist">{closed[k] ? "▸" : "▾"}</span>
                        <Flag risk={g.risk} />
                        <span className="lbl">
                          {r.name} ({r.items.length})
                        </span>
                      </div>
                      {!closed[k] && (
                        <div className="children">
                          {r.items.map((x) => (
                            <div key={x.uid} className={`node ${x.uid === sel ? "sel" : ""}`} onClick={() => onSel(x.uid)}>
                              <span className="twist" />
                              <Flag risk={g.risk} size={12} />
                              <span className="lbl">{x.tunnel ? `${x.tunnel}: ${tunnelName(result, x.tunnel)}` : "capture"}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                }),
              )}
            </div>
          )}
        </div>
      </div>
      <div className="right">
        {a ? (
          <>
            <div className="alert-title">
              <Flag risk={a.risk} size={16} /> {a.name}
            </div>
            <table className="kv alert-detail">
              <tbody>
                <tr>
                  <th>Tunnel</th>
                  <td>
                    {a.tunnel ? (
                      <a href="#" onClick={(e) => { e.preventDefault(); onTunnel(a.tunnel); }}>
                        {a.tunnel}: {tunnelName(result, a.tunnel)}
                      </a>
                    ) : (
                      "whole capture"
                    )}
                  </td>
                </tr>
                <tr><th>Risk</th><td style={{ color: RISK_COLOR[a.risk], fontWeight: 600 }}>{a.risk}</td></tr>
                <tr><th>Confidence</th><td>{a.confidence}</td></tr>
                <tr><th>Rule ID</th><td className="mono">{a.id}</td></tr>
                <tr><th>Source</th><td>Passive ({a.id.startsWith("NM-15") ? "traffic model" : "protocol analysis"})</td></tr>
                <tr><th>Evidence</th><td><pre>{a.evidence}</pre></td></tr>
                <tr><th>Description</th><td><pre>{a.description}</pre></td></tr>
                <tr><th>Solution</th><td><pre>{a.solution}</pre></td></tr>
                <tr><th>Reference</th><td>{a.references.length ? a.references.map((r) => <div key={r}>{r}</div>) : "—"}</td></tr>
              </tbody>
            </table>
          </>
        ) : (
          <div className="empty">Select an alert to see its details.</div>
        )}
      </div>
    </div>
  );
}

function tunnelName(r: Result, id: string) {
  const t = r.tunnels.find((x) => x.id === id);
  return t ? `${t.initiator} ⇄ ${t.responder}` : "";
}
