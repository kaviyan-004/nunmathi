import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { fmtTime } from "../util";

type R = Record<string, any>;
const LAYER_COLORS = ["#ffe38a", "#cfe8ff", "#d9f2d0", "#f6d4f0", "#ffd8b8", "#e3e0ff"];

function IkeTree({ ike }: { ike: R }) {
  const rows: [string, React.ReactNode][] = [
    ["Version", `IKEv${ike.version}`],
    ["Initiator SPI", ike.ispi],
    ["Responder SPI", ike.rspi],
    ["Exchange", `${ike.exchange_name} (${ike.exchange})`],
    ["Flags", `0x${ike.flags.toString(16).padStart(2, "0")} (${ike.initiator ? "Initiator" : "Responder"}, ${ike.response ? "Response" : "Request"})`],
    ["Message ID", ike.msgid],
    ["Length", ike.length],
  ];
  if (ike.encrypted) rows.push(["Encrypted (SK)", `${ike.sk_len} bytes${ike.fragment ? `, fragment ${ike.fragment[0]}/${ike.fragment[1]}` : ""}`]);
  if (ike.ke_group) rows.push(["Key Exchange", `group ${ike.ke_group}, ${ike.ke_len} bytes`]);
  return (
    <div>
      <div className="layer">▼ Internet Key Exchange</div>
      {rows.map(([k, v]) => (
        <div className="ikefield" key={k}>
          <span className="k">{k}:</span> {v}
        </div>
      ))}
      {ike.payloads?.length > 0 && (
        <div className="ikefield">
          <span className="k">Payloads:</span> {ike.payloads.map((p: R) => p.name ?? p.type).join(", ")}
        </div>
      )}
      {ike.proposals?.map((p: R, i: number) => (
        <div className="ikefield" key={i}>
          ▼ Proposal #{p.num ?? i + 1} ({p.protocol_name ?? p.protocol})
          {(p.transforms ?? []).map((t: R, j: number) => (
            <div className="ikefield" key={j}>
              <span className="k">{t.type_name ?? t.type}:</span> {t.name ?? t.id}
            </div>
          ))}
        </div>
      ))}
      {ike.notify_names?.length > 0 && (
        <div className="ikefield">
          <span className="k">Notify:</span> {ike.notify_names.join(", ")}
        </div>
      )}
      {ike.vendor_names?.length > 0 && (
        <div className="ikefield">
          <span className="k">Vendor ID:</span> {ike.vendor_names.join(", ")}
        </div>
      )}
      {ike.identities?.length > 0 && (
        <div className="ikefield">
          <span className="k">Identity (cleartext):</span> <b style={{ color: "#b3261e" }}>{ike.identities.join(", ")}</b>
        </div>
      )}
      {ike.cleartext_hash && (
        <div className="ikefield" style={{ color: "#b3261e" }}>
          HASH_R sent in cleartext (Aggressive Mode PSK)
        </div>
      )}
    </div>
  );
}

export default function PacketView({ aid, idx, onIdx }: { aid: string; idx: number | null; onIdx: (i: number) => void }) {
  const [pkt, setPkt] = useState<R | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [hl, setHl] = useState<number | null>(null);
  const [go, setGo] = useState("");

  useEffect(() => {
    if (idx == null) return;
    setErr(null);
    api
      .packet(aid, idx)
      .then((p) => {
        setPkt(p);
        setHl(null);
      })
      .catch((e) => setErr(e.message));
  }, [aid, idx]);

  const hex = useMemo(() => {
    if (!pkt) return null;
    const bytes: string[] = pkt.hex.match(/../g) ?? [];
    const layerOf = (i: number) => (pkt.layers as R[]).findIndex((l) => i >= l.offset && i < l.offset + l.length);
    const lines = [];
    for (let o = 0; o < bytes.length; o += 16) {
      const row = bytes.slice(o, o + 16);
      lines.push(
        <div key={o}>
          <span className="off">{o.toString(16).padStart(4, "0")}  </span>
          {row.map((b, i) => {
            const li = layerOf(o + i);
            return (
              <span
                key={i}
                className="b"
                style={hl != null && li === hl ? { background: LAYER_COLORS[hl % LAYER_COLORS.length] } : undefined}
              >
                {b}
                {i === 7 ? "  " : " "}
              </span>
            );
          })}
          {"   ".repeat(16 - row.length)}
          {row.length <= 8 ? " " : ""}
          <span className="off"> </span>
          {row.map((b) => {
            const c = parseInt(b, 16);
            return c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
          })}
        </div>,
      );
    }
    return lines;
  }, [pkt, hl]);

  if (idx == null)
    return <div className="empty">Select a packet in the History tab (or a node in the Sites tree) to inspect it.</div>;
  if (err) return <div className="empty">Error: {err}</div>;
  if (!pkt) return <div className="empty">Loading frame {idx}…</div>;
  const s = pkt.summary;
  return (
    <div className="pkt">
      <div className="head">
        <button className="btn" disabled={idx <= 1} onClick={() => onIdx(idx - 1)}>◀</button>{" "}
        <button className="btn" onClick={() => onIdx(idx + 1)}>▶</button>{" "}
        <b>Frame {pkt.idx}</b> · {fmtTime(pkt.ts)}.{String(Math.round((pkt.ts % 1) * 1e6)).padStart(6, "0")} · {pkt.length} bytes
        {s && (
          <>
            {" "}· {s.src}
            {s.sport ? `:${s.sport}` : ""} → {s.dst}
            {s.dport ? `:${s.dport}` : ""} · <span className={`kind-${s.kind}`}>{s.kind}</span> {s.info}
          </>
        )}
        <span style={{ float: "right" }}>
          Go to frame{" "}
          <input
            style={{ width: 70 }}
            value={go}
            onChange={(e) => setGo(e.target.value.replace(/\D/g, ""))}
            onKeyDown={(e) => e.key === "Enter" && go && onIdx(parseInt(go, 10))}
          />
        </span>
      </div>
      <div className="body">
        <div className="tree-side">
          <div className="layer">▼ Frame {pkt.idx}: {pkt.length} bytes (linktype {pkt.linktype})</div>
          {(pkt.layers as R[]).map((l, i) => (
            <div
              key={i}
              className={`layer ${hl === i ? "sel" : ""}`}
              onClick={() => setHl(hl === i ? null : i)}
              style={{ marginLeft: 10 }}
            >
              <span className="sw" style={{ background: LAYER_COLORS[i % LAYER_COLORS.length], marginRight: 5 }} />
              {l.name} <span className="muted">[{l.offset}..{l.offset + l.length - 1}] {l.length} B</span>
            </div>
          ))}
          {s?.kind === "ESP" && (
            <div style={{ marginLeft: 10, marginTop: 6 }}>
              <div className="layer">▼ Encapsulating Security Payload</div>
              <div className="ikefield">{s.info}</div>
              <div className="ikefield muted">Payload encrypted; Nunmathi only looks at its length and timing.</div>
            </div>
          )}
          {pkt.ike && (
            <div style={{ marginLeft: 10, marginTop: 6 }}>
              <IkeTree ike={pkt.ike} />
            </div>
          )}
          {pkt.ike_error && <div style={{ color: "#b3261e" }}>IKE parse error: {pkt.ike_error}</div>}
        </div>
        <div className="hex-side">{hex}</div>
      </div>
    </div>
  );
}
