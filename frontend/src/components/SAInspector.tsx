import { useEffect, useState } from "react";
import type { Result, Tunnel } from "../api";
import { fmtBytes, fmtDur, fmtTime, KV } from "../util";
import TunnelPicker from "./TunnelPicker";

type R = Record<string, any>;

function LengthHistogram({ h }: { h: R }) {
  const lengths: number[] = h?.lengths ?? [];
  if (!lengths.length) return <p className="muted">No ESP lengths recorded.</p>;
  const out: number[] = h.out ?? [];
  const inn: number[] = h.in ?? [];
  const max = Math.max(1, ...out, ...inn);
  const W = 720;
  const bw = Math.max(4, Math.min(34, (W - 60) / lengths.length - 3));
  const H = 190;
  const mid = 95;
  return (
    <svg viewBox={`0 0 ${W} ${H + 18}`} width="100%" style={{ maxWidth: W, background: "#fff", border: "1px solid #e2e2e2" }}>
      <line x1={40} x2={W - 10} y1={mid} y2={mid} stroke="#888" />
      <text x={6} y={20} fontSize={10} fill="#1c4f8c">→ out</text>
      <text x={6} y={H - 10} fontSize={10} fill="#a35b00">← in</text>
      {lengths.map((L, i) => {
        const x = 44 + i * (bw + 3);
        const ho = (80 * Math.log1p(out[i] ?? 0)) / Math.log1p(max);
        const hi = (80 * Math.log1p(inn[i] ?? 0)) / Math.log1p(max);
        return (
          <g key={L}>
            <rect x={x} y={mid - ho} width={bw} height={ho} fill="#2e86c1" />
            <rect x={x} y={mid} width={bw} height={hi} fill="#e67e22" />
            {(lengths.length <= 24 || i % Math.ceil(lengths.length / 24) === 0) && (
              <text x={x + bw / 2} y={H + 12} fontSize={9} textAnchor="middle" fill="#555">{L}</text>
            )}
            <title>{`${L} B: ${out[i] ?? 0} out, ${inn[i] ?? 0} in`}</title>
          </g>
        );
      })}
      <text x={W - 10} y={H + 12} fontSize={9} textAnchor="end" fill="#888">ESP length (bytes), log-scaled counts</text>
    </svg>
  );
}

function RekeyTimeline({ t }: { t: Tunnel }) {
  const kids: R[] = t.child_sas ?? [];
  const ev: R[] = t.rekey_events ?? [];
  const t0 = t.first_ts;
  const span = Math.max(1, t.last_ts - t0);
  const W = 760;
  const lane = 16;
  const top = 10;
  const H = top + Math.max(1, kids.length) * lane + 46;
  const X = (ts: number) => 90 + ((ts - t0) / span) * (W - 110);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: W, background: "#fff", border: "1px solid #e2e2e2" }}>
      {kids.map((c, i) => (
        <g key={c.id}>
          <text x={84} y={top + i * lane + 10} fontSize={10} textAnchor="end">{c.id}</text>
          <rect x={X(c.first_ts)} y={top + i * lane} width={Math.max(2, X(c.last_ts) - X(c.first_ts))} height={lane - 4} fill="#5b8cc9" rx={2}>
            <title>{`${c.id} SPI ${c.spi_out}: ${fmtTime(c.first_ts)} → ${fmtTime(c.last_ts)}, ${c.packets} packets`}</title>
          </rect>
        </g>
      ))}
      {ev.map((e, i) => {
        const x = X(e.t);
        const col = e.pfs == null ? "#999" : e.pfs ? "#1e8449" : "#c0392b";
        const y = top + kids.length * lane + 8;
        return (
          <g key={i}>
            <line x1={x} x2={x} y1={top} y2={y} stroke={col} strokeDasharray="2 2" />
            <path d={e.kind.startsWith("ike") ? `M${x - 5},${y + 12} L${x},${y} L${x + 5},${y + 12} z` : `M${x},${y} m-5,0 a5,5 0 1,0 10,0 a5,5 0 1,0 -10,0`} fill={col} transform={e.kind.startsWith("ike") ? undefined : "translate(0,6)"} />
            <title>{`${e.kind} at ${fmtTime(e.t)}: PFS ${e.pfs == null ? "unknown" : e.pfs ? `yes (${e.pfs_group})` : "no"}, SK ${e.sk_len} B`}</title>
          </g>
        );
      })}
      <text x={90} y={H - 4} fontSize={9} fill="#666">{fmtTime(t0)}</text>
      <text x={W - 20} y={H - 4} fontSize={9} fill="#666" textAnchor="end">{fmtTime(t.last_ts)}</text>
      <text x={W / 2} y={H - 4} fontSize={9} fill="#888" textAnchor="middle">● Child rekey ▲ IKE rekey · green = PFS, red = no PFS</text>
    </svg>
  );
}

export default function SAInspector({
  result,
  tunnel: t,
  onTunnel,
  onPacket,
}: {
  result: Result;
  tunnel: Tunnel;
  onTunnel: (id: string) => void;
  onPacket: (idx: number) => void;
}) {
  const kids: R[] = t.child_sas ?? [];
  const [sel, setSel] = useState(0);
  useEffect(() => setSel(0), [t.id]);
  const c = kids[Math.min(sel, kids.length - 1)];
  const g: R = c?.geometry ?? {};
  const lt: R = t.lifetimes ?? {};
  return (
    <>
      <TunnelPicker result={result} value={t.id} onChange={onTunnel} />
      <div className="pad">
        <h2 className="sec">Rekey timeline</h2>
        <RekeyTimeline t={t} />
        <KV
          rows={[
            ["Child SA lifetime", lt.child_rekey_interval ? fmtDur(lt.child_rekey_interval) : `> ${fmtDur(lt.child_lower_bound)}`],
            ["IKE SA lifetime", lt.ike_rekey_interval ? fmtDur(lt.ike_rekey_interval) : `> ${fmtDur(lt.ike_lower_bound)}`],
            ["PFS", `${t.pfs.status}${t.pfs.group ? ` (${t.pfs.group})` : ""}, confidence ${t.pfs.confidence}`],
          ]}
        />
        {!c ? (
          <div className="empty">No Child SA carried ESP traffic in this capture.</div>
        ) : (
          <>
            <h2 className="sec">Child SA</h2>
            <div className="toolbar-inline">
              <select value={sel} onChange={(e) => setSel(+e.target.value)}>
                {kids.map((k, i) => (
                  <option key={k.id} value={i}>
                    {k.id} · SPI {k.spi_out} · {k.packets.toLocaleString()} pkts
                  </option>
                ))}
              </select>
              {c.first_packets?.length ? (
                <button className="btn" onClick={() => onPacket(Math.min(...c.first_packets))}>First packet</button>
              ) : null}
            </div>
            <div className="two-col">
              <div>
                <KV
                  rows={[
                    ["SPI out / in", <span className="mono">{c.spi_out} / {c.spi_in ?? "—"}</span>],
                    ["Active", `${fmtTime(c.first_ts)} → ${fmtTime(c.last_ts, false)} (${fmtDur(c.last_ts - c.first_ts)})`],
                    ["Traffic", `${c.packets_out.toLocaleString()} out / ${c.packets_in.toLocaleString()} in, ${fmtBytes(c.bytes)}`],
                    ["Encapsulation", c.udp_encap ? "UDP 4500 (NAT-T)" : "ESP (IP proto 50)"],
                    ["Sequence numbers", c.seq ? `${c.seq.min ?? "?"} → ${c.seq.max ?? "?"}${c.seq.gaps ? `, ${c.seq.gaps} gaps` : ""}${c.seq.replays ? `, ${c.seq.replays} replays` : ""}` : "—"],
                  ]}
                />
              </div>
              <div>
                <KV
                  rows={[
                    ["Inferred geometry", g.best ? <b>{g.best.label}</b> : g.esp_null ? "ESP-NULL" : "undetermined"],
                    ["Candidates", (g.best?.members ?? []).join(", ") || "—"],
                    ["Confidence", `${g.confidence ?? "—"}${g.p_spurious != null ? ` (p spurious ${Number(g.p_spurious).toExponential(1)})` : ""}`],
                    ["Distinct lengths", `${g.distinct_lengths ?? "—"} over ${g.packets ?? c.packets} packets`],
                    ["Mode", g.mode ? <>{g.mode.mode} <span className="muted">({g.mode.confidence}) {g.mode.reason}</span></> : "—"],
                  ]}
                />
              </div>
            </div>
            <h2 className="sec">ESP length histogram</h2>
            <LengthHistogram h={g.length_hist} />
            {g.length_hist?.truncated && <p className="muted">Only the most frequent lengths are shown.</p>}

            <h2 className="sec">Geometry proof</h2>
            <p className="muted">
              Each hypothesis predicts a residue class for every ESP packet length (SPI + sequence + IV + ICV + padded
              payload). A single length that violates the congruence rejects the hypothesis; a hypothesis that survives
              every observed length is consistent.
            </p>
            <table className="grid proof">
              <thead>
                <tr><th>Hypothesis</th><th>Block / IV / ICV</th><th>Claim</th><th>Verdict</th><th>Reason</th></tr>
              </thead>
              <tbody>
                {(g.proof ?? []).map((p: R, i: number) => (
                  <tr key={i}>
                    <td>{p.label ?? p.hypothesis}</td>
                    <td className="mono">{p.block ?? "—"} / {p.iv ?? "—"} / {p.icv ?? "—"}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{p.claim}</td>
                    <td className={`v-${p.verdict}`}>{p.verdict}</td>
                    <td style={{ fontSize: 11 }}>{p.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </>
  );
}
