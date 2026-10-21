import { useState } from "react";
import type { Result, Tunnel } from "../api";
import { fmtTime, GRADE_COLOR } from "../util";

type R = Record<string, any>;

/** Hub-and-spoke map of every tunnel in the capture: peers are nodes, tunnels are edges coloured by grade. */
export function TopologyMap({ result, value, onChange }: { result: Result; value: string; onChange: (id: string) => void }) {
  const peers = new Map<string, number>();
  for (const t of result.tunnels) {
    peers.set(t.initiator, (peers.get(t.initiator) ?? 0) + 1);
    peers.set(t.responder, (peers.get(t.responder) ?? 0) + 1);
  }
  // hubs (peers in more than one tunnel) go in the middle column, everything else around them
  const hubs = [...peers].filter(([, n]) => n > 1).map(([p]) => p);
  const leaves = [...peers.keys()].filter((p) => !hubs.includes(p));
  const W = 760;
  const H = Math.max(150, 46 * Math.max(hubs.length, Math.ceil(leaves.length / 2)) + 40);
  const pos = new Map<string, [number, number]>();
  hubs.forEach((p, i) => pos.set(p, [W / 2, ((i + 1) * H) / (hubs.length + 1)]));
  const left = leaves.filter((_, i) => i % 2 === 0);
  const right = leaves.filter((_, i) => i % 2 === 1);
  if (!hubs.length) {
    // point-to-point tunnels only: initiators left, responders right
    const ini = [...new Set(result.tunnels.map((t) => t.initiator))];
    const rsp = [...new Set(result.tunnels.map((t) => t.responder))].filter((p) => !ini.includes(p));
    ini.forEach((p, i) => pos.set(p, [150, ((i + 1) * H) / (ini.length + 1)]));
    rsp.forEach((p, i) => pos.set(p, [W - 150, ((i + 1) * H) / (rsp.length + 1)]));
  } else {
    left.forEach((p, i) => pos.set(p, [130, ((i + 1) * H) / (left.length + 1)]));
    right.forEach((p, i) => pos.set(p, [W - 130, ((i + 1) * H) / (right.length + 1)]));
  }
  return (
    <svg className="topo" viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: W, background: "#fbfbfc", border: "1px solid #e2e2e2" }}>
      {result.tunnels.map((t) => {
        const a = pos.get(t.initiator)!;
        const b = pos.get(t.responder)!;
        const sel = t.id === value;
        const col = GRADE_COLOR[t.grade.letter] ?? "#777";
        const mx = (a[0] + b[0]) / 2;
        const my = (a[1] + b[1]) / 2;
        return (
          <g key={t.id} style={{ cursor: "pointer" }} onClick={() => onChange(t.id)}>
            <line x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} stroke={col} strokeWidth={sel ? 5 : 3} strokeDasharray={t.version === 1 ? "6 4" : undefined} opacity={sel ? 1 : 0.75} />
            <rect x={mx - 34} y={my - 10} width={68} height={20} rx={10} fill="#fff" stroke={col} strokeWidth={sel ? 2 : 1} />
            <text x={mx} y={my + 4} textAnchor="middle" fontWeight={600} fill={col}>
              {t.id} · {t.grade.letter}
            </text>
            <title>{`${t.id}: ${t.initiator} ⇄ ${t.responder}, IKEv${t.version}, grade ${t.grade.letter} (${t.grade.score})`}</title>
          </g>
        );
      })}
      {[...pos].map(([p, [x, y]]) => (
        <g key={p}>
          <rect x={x - 62} y={y - 13} width={124} height={26} rx={4} fill={hubs.includes(p) ? "#2f3e50" : "#fff"} stroke="#2f3e50" />
          <text x={x} y={y + 4} textAnchor="middle" fill={hubs.includes(p) ? "#fff" : "#222"} className="mono">
            {p}
          </text>
        </g>
      ))}
      <text x={8} y={H - 6} fontSize={10} fill="#888">
        solid = IKEv2 · dashed = IKEv1 · colour = tunnel grade · click a tunnel to inspect it
      </text>
    </svg>
  );
}

/** Message sequence (ladder) diagram of one IKE SA's exchanges, initiator on the left. */
export function IkeLadder({ tunnel: t, onPacket }: { tunnel: Tunnel; onPacket: (idx: number) => void }) {
  const sas: R[] = t.ike_sas ?? [];
  const [sa, setSa] = useState(0);
  const [limit, setLimit] = useState(40);
  const cur = sas[Math.min(sa, sas.length - 1)];
  const lad: R[] = cur?.ladder ?? [];
  if (!lad.length) return <p className="muted">No IKE messages were captured for this tunnel.</p>;
  const shown = lad.slice(0, limit);
  const W = 760;
  const L = 170;
  const Rx = W - 170;
  const row = 30;
  const H = 46 + shown.length * row;
  const t0 = lad[0].t;
  return (
    <>
      {sas.length > 1 && (
        <div className="toolbar-inline">
          IKE SA:{" "}
          <select value={sa} onChange={(e) => setSa(+e.target.value)}>
            {sas.map((s, i) => (
              <option key={i} value={i}>
                #{i + 1} {s.ispi?.slice(0, 8)}… {s.origin ?? ""} ({s.ladder?.length ?? 0} msgs)
              </option>
            ))}
          </select>
        </div>
      )}
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: W, background: "#fff", border: "1px solid #e2e2e2" }}>
        <defs>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#2f3e50" />
          </marker>
        </defs>
        <text x={L} y={16} textAnchor="middle" fontWeight={700} fontSize={12}>Initiator</text>
        <text x={L} y={30} textAnchor="middle" fontSize={10} className="mono">{cur.initiator ?? t.initiator}</text>
        <text x={Rx} y={16} textAnchor="middle" fontWeight={700} fontSize={12}>Responder</text>
        <text x={Rx} y={30} textAnchor="middle" fontSize={10} className="mono">{cur.responder ?? t.responder}</text>
        <line x1={L} y1={36} x2={L} y2={H} stroke="#999" />
        <line x1={Rx} y1={36} x2={Rx} y2={H} stroke="#999" />
        {shown.map((m, i) => {
          const y = 52 + i * row;
          const fromI = m.from_initiator;
          const x1 = fromI ? L : Rx;
          const x2 = fromI ? Rx : L;
          const pay: string[] = m.payloads ?? [];
          const warn = pay.some((p) => /INVALID|NO_PROPOSAL|AUTHENTICATION_FAILED/.test(p)) || m.exchange === "Aggressive";
          return (
            <g key={i} style={{ cursor: m.packet ? "pointer" : undefined }} onClick={() => m.packet && onPacket(m.packet)}>
              <text x={8} y={y + 4} fontSize={10} fill="#888">+{(m.t - t0).toFixed(3)}s</text>
              <line x1={x1} y1={y} x2={x2} y2={y + 8} stroke={warn ? "#c0392b" : "#2f3e50"} strokeWidth={1.4} markerEnd="url(#arr)" />
              <text x={(L + Rx) / 2} y={y - 3} textAnchor="middle" fontSize={11} fontWeight={600} fill={warn ? "#c0392b" : "#1c4f8c"}>
                {m.exchange}
                {m.response ? " (resp)" : ""} #{m.msgid}
                {m.fragment ? ` frag ${m.fragment}` : ""}
              </text>
              <text x={(L + Rx) / 2} y={y + 18} textAnchor="middle" fontSize={9.5} fill="#555">
                {m.sk_len ? `SK{${m.inferred ?? "encrypted"}} ${m.sk_len} B` : pay.slice(0, 6).join(", ") + (pay.length > 6 ? ", …" : "")}
                {m.ke_group ? ` · KE ${m.ke_group}` : ""}
              </text>
              <text x={W - 8} y={y + 4} fontSize={10} textAnchor="end" fill="#888">
                #{m.packet} · {m.length} B
              </text>
              <title>{`${fmtTime(m.t)} frame ${m.packet}\n${pay.join(", ")}`}</title>
            </g>
          );
        })}
      </svg>
      {lad.length > limit && (
        <button className="btn" style={{ marginTop: 4 }} onClick={() => setLimit(limit + 60)}>
          Show more ({lad.length - limit} further messages)
        </button>
      )}
    </>
  );
}
