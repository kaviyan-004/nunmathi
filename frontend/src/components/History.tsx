import { useEffect, useRef, useState } from "react";
import { api, type PacketRow } from "../api";
import { fmtTime } from "../util";

const PAGE = 200;

/** `tick` changes while a live capture grows the packet list: the current page is re-fetched in place. */
export default function History({
  aid,
  sel,
  onSel,
  tick = 0,
}: {
  aid: string;
  sel: number | null;
  onSel: (idx: number) => void;
  tick?: number;
}) {
  const [kind, setKind] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ total: number; items: PacketRow[] } | null>(null);
  const [err, setErr] = useState("");
  const box = useRef<HTMLDivElement>(null);
  const lastQuery = useRef("");

  useEffect(() => {
    setOffset(0);
  }, [aid, kind]);

  useEffect(() => {
    let live = true;
    setErr("");
    api
      .packets(aid, offset, PAGE, kind)
      .then((d) => {
        if (!live) return;
        setData(d);
        const q = `${aid}:${offset}:${kind}`;
        if (q !== lastQuery.current) box.current?.scrollTo({ top: 0 });
        lastQuery.current = q;
      })
      .catch((e) => live && setErr(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [aid, offset, kind, tick]);

  const total = data?.total ?? 0;
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div className="toolbar-inline">
        Show:
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All IPsec frames</option>
          <option value="IKE">IKE</option>
          <option value="ESP">ESP</option>
          <option value="NAT-KA">NAT-T keepalive</option>
          <option value="AH">AH</option>
        </select>
        <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
          ◀
        </button>
        <span>
          {total ? `${offset + 1}–${Math.min(offset + PAGE, total)} of ${total.toLocaleString()}` : "0 frames"}
        </span>
        <button className="btn" disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
          ▶
        </button>
        {err && <span style={{ color: "#b3261e" }}>{err}</span>}
      </div>
      <div ref={box} style={{ flex: 1, overflow: "auto" }}>
        <table className="grid clickable">
          <thead>
            <tr>
              <th className="num">Id</th>
              <th>Time (UTC)</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Proto</th>
              <th>Kind</th>
              <th className="num">Length</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody>
            {data?.items.map((p) => (
              <tr key={p.idx} className={p.idx === sel ? "sel" : ""} onClick={() => onSel(p.idx)}>
                <td className="num">{p.idx}</td>
                <td className="mono">{fmtTime(p.ts, false)}.{String(Math.floor((p.ts % 1) * 1000)).padStart(3, "0")}</td>
                <td className="mono">{p.src}{p.sport ? `:${p.sport}` : ""}</td>
                <td className="mono">{p.dst}{p.dport ? `:${p.dport}` : ""}</td>
                <td>{p.proto}</td>
                <td className={`kind-${p.kind}`}>{p.kind}</td>
                <td className="num">{p.len}</td>
                <td className="mono">{p.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
