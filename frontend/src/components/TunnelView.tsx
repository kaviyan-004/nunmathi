import type { Result, Tunnel } from "../api";
import { fmtBytes, fmtDur, fmtTime, Grade, KV } from "../util";
import TunnelPicker from "./TunnelPicker";
import { IkeLadder, TopologyMap } from "./TunnelMap";

type R = Record<string, any>;
const pillFor = (s: string) => (s === "enabled" ? "good" : s === "disabled" ? "bad" : "warn");

function crypto(n: R | undefined) {
  if (!n) return "—";
  return [n.encr, n.prf, n.integ, n.group].filter(Boolean).join(" / ") + (n.addke?.length ? ` + ${n.addke.join(", ")}` : "");
}

export default function TunnelView({
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
  const root: R = t.ike_sas[0] ?? {};
  const lt = t.lifetimes;
  const alerts = result.alerts.filter((a) => a.tunnel === t.id);
  return (
    <>
      <TunnelPicker result={result} value={t.id} onChange={onTunnel} />
      <div className="pad">
        <div className="summary-top">
          <Grade letter={t.grade.letter} big />
          <div>
            <div style={{ fontSize: 15, fontWeight: 700 }}>
              {t.id}: {t.initiator} ⇄ {t.responder}
            </div>
            <div className="muted">
              IKEv{t.version} · {fmtTime(t.first_ts)} → {fmtTime(t.last_ts)} · {t.esp_packets.toLocaleString()} ESP packets ({fmtBytes(t.esp_bytes)}) · {alerts.length} alerts
            </div>
          </div>
        </div>

        <h2 className="sec">Tunnel map</h2>
        <TopologyMap result={result} value={t.id} onChange={onTunnel} />

        <h2 className="sec">IKE ladder</h2>
        <IkeLadder tunnel={t} onPacket={onPacket} />

        <h2 className="sec">IKE security association</h2>
        <KV
          rows={[
            ["Negotiated", <span className="mono">{crypto(t.ike_crypto?.names)}</span>],
            [
              "Offered by initiator",
              <>
                {(root.offered ?? []).map((o: R, i: number) => (
                  <div key={i} className="mono">#{i + 1} {crypto(o.names)}</div>
                ))}
              </>,
            ],
            ["Mode", root.aggressive ? <span className="pill bad">IKEv1 Aggressive Mode</span> : t.version === 1 ? "IKEv1 Main Mode" : "IKEv2"],
            ["Authentication", root.v1_auth ? `IKEv1 auth method ${root.v1_auth}` : "encrypted (IKE_AUTH)"],
            ["Identities in cleartext", root.identities?.length ? <span className="pill bad">{root.identities.join(", ")}</span> : "none"],
            ["INVALID_KE_PAYLOAD", root.invalid_ke_wanted ? `responder wanted group ${root.invalid_ke_wanted}` : "no"],
            [
              "Fragmentation (RFC 7383)",
              root.fragmentation ? `initiator ${root.fragmentation.initiator ? "yes" : "no"}, responder ${root.fragmentation.responder ? "yes" : "no"}` : "—",
            ],
            ["IKE_INTERMEDIATE", root.intermediate?.length ? `${root.intermediate.length} message(s): ${root.intermediate.join(", ")} B` : "not used"],
            ["NAT traversal", t.nat_t ? <span className="pill warn">UDP-encapsulated ESP</span> : "no"],
            ["Dead Peer Detection", t.dpd_interval ? `every ~${fmtDur(t.dpd_interval)}` : "not observed"],
            [
              "Vendor IDs",
              <>
                {["initiator", "responder"].map((side) =>
                  (root.vendor_ids?.[side] ?? []).map((v: R) => (
                    <span key={side + v.hex} className="pill" title={v.hex}>
                      {side}: {v.name}
                    </span>
                  )),
                )}
              </>,
            ],
            ["Notify payloads", (root.notifies ?? []).map((n: string) => <span className="pill" key={n}>{n}</span>)],
            ["Exchanges", Object.entries(root.exchanges ?? {}).map(([k, v]) => `${k} ×${v}`).join(", ")],
          ]}
        />

        <h2 className="sec">Perfect Forward Secrecy</h2>
        <KV
          rows={[
            ["Status", <><span className={`pill ${pillFor(t.pfs.status)}`}>{t.pfs.status}</span> {t.pfs.group ?? ""} <span className="muted">confidence {t.pfs.confidence}</span></>],
            ["Evidence", t.pfs.evidence],
          ]}
        />
        {t.rekey_events.length > 0 && (
          <table className="grid clickable" style={{ marginBottom: 10 }}>
            <thead>
              <tr><th>Time</th><th>Event</th><th className="num">Frame</th><th className="num">SK bytes</th><th className="num">Plain est.</th><th className="num">Δ vs no-KE</th><th>KE inferred</th></tr>
            </thead>
            <tbody>
              {t.rekey_events.map((e: R, i: number) => (
                <tr key={i} onClick={() => e.packet && onPacket(e.packet)}>
                  <td>{fmtTime(e.t)}</td>
                  <td>{e.kind}</td>
                  <td className="num">{e.packet}</td>
                  <td className="num">{e.sk_len ?? "—"}</td>
                  <td className="num">{e.plain_est ?? "—"}</td>
                  <td className="num">{e.delta ?? "—"}</td>
                  <td>{e.pfs == null ? "—" : e.pfs ? `yes (${e.pfs_group ?? "?"})` : "no"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h2 className="sec">Lifetimes (from observed rekeys)</h2>
        <KV
          rows={[
            ["Child SA", lt.child_rekey_interval ? `${fmtDur(lt.child_rekey_interval)} (${lt.child_rekeys} rekeys)` : `> ${fmtDur(lt.child_lower_bound)} (no rekey observed)`],
            ["IKE SA", lt.ike_rekey_interval ? `${fmtDur(lt.ike_rekey_interval)} (${lt.ike_rekeys} rekeys)` : `> ${fmtDur(lt.ike_lower_bound)} (no rekey observed)`],
            ["IKEv1 proposed lifetime", lt.v1_proposed_ike_lifetime ? fmtDur(lt.v1_proposed_ike_lifetime) : "—"],
            ["Observed", fmtDur(lt.observed_seconds)],
          ]}
        />

        <h2 className="sec">Child SAs ({t.child_sas.length} with traffic, {t.negotiated_child_sas} negotiated)</h2>
        <table className="grid clickable">
          <thead>
            <tr>
              <th>ID</th><th>SPI out / in</th><th>Start</th><th>End</th><th className="num">Pkts →</th><th className="num">Pkts ←</th>
              <th className="num">Bytes</th><th>ESP geometry</th><th>Candidates</th><th>Conf.</th><th>Encap</th>
            </tr>
          </thead>
          <tbody>
            {t.child_sas.map((c: R) => (
              <tr key={c.id} onClick={() => c.first_packets?.length && onPacket(Math.min(...c.first_packets))}>
                <td>{c.id}</td>
                <td className="mono">{c.spi_out} / {c.spi_in ?? "—"}</td>
                <td>{fmtTime(c.first_ts, false)}</td>
                <td>{fmtTime(c.last_ts, false)}</td>
                <td className="num">{c.packets_out.toLocaleString()}</td>
                <td className="num">{c.packets_in.toLocaleString()}</td>
                <td className="num">{fmtBytes(c.bytes)}</td>
                <td>{c.geometry?.best ? (c.geometry.best.family === "AMBIGUOUS" ? c.geometry.best.label : `${c.geometry.best.label} (IV ${c.geometry.best.iv}, ICV ${c.geometry.best.icv})`) : c.geometry?.esp_null ? "ESP-NULL" : "?"}</td>
                <td title={(c.geometry?.best?.members ?? []).join(", ")}>{(c.geometry?.best?.members ?? []).slice(0, 3).join(", ")}{(c.geometry?.best?.members?.length ?? 0) > 3 ? "…" : ""}</td>
                <td>{c.geometry?.confidence}</td>
                <td>{c.udp_encap ? "UDP" : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted">
          ESP geometry is worked out from packet lengths alone: block alignment, IV size and ICV size, chosen by
          minimum description length. Several algorithms can share the same geometry, so all consistent candidates
          are listed.
        </p>
      </div>
    </>
  );
}
