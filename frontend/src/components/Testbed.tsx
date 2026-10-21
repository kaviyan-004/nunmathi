import { useEffect, useState } from "react";
import { api, type Analysis } from "../api";
import { fmtDur } from "../util";

type R = Record<string, any>;

export default function Testbed({ onRun, say }: { onRun: (p: Promise<Analysis>, label: string) => void; say: (m: string, err?: boolean) => void }) {
  const [spec, setSpec] = useState("");
  const [check, setCheck] = useState<R | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api
      .testbedExample()
      .then((r) => setSpec((s) => s || r.spec))
      .catch((e) => say(`Cannot load example testbed: ${e.message}`, true));
  }, [say]);

  const validate = async () => {
    setBusy(true);
    try {
      setCheck(await api.testbedValidate(spec));
    } catch (e) {
      setCheck({ valid: false, error: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const run = async () => {
    setBusy(true);
    try {
      const v = await api.testbedValidate(spec);
      setCheck(v);
      if (v.valid) onRun(api.testbedRun(spec), `testbed ${v.name}`);
    } finally {
      setBusy(false);
    }
  };
  const load = (f: File | undefined) => f && f.text().then((t) => { setSpec(t); setCheck(null); });

  return (
    <div className="pad two-col">
      <div>
        <h2 className="sec">Testbed specification (YAML)</h2>
        <textarea className="yaml" spellCheck={false} value={spec} onChange={(e) => { setSpec(e.target.value); setCheck(null); }} />
        <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
          <button className="btn" disabled={busy} onClick={validate}>Validate</button>
          <button className="btn primary" disabled={busy || !spec.trim()} onClick={run}>Build &amp; analyze</button>
          <label className="btn">
            Load YAML…
            <input type="file" accept=".yaml,.yml,.txt" hidden onChange={(e) => { load(e.target.files?.[0]); e.target.value = ""; }} />
          </label>
          <button className="btn" onClick={() => api.testbedExample().then((r) => { setSpec(r.spec); setCheck(null); })}>Reset to example</button>
        </div>
      </div>
      <div>
        <h2 className="sec">What this does</h2>
        <p>
          IPsecForge turns the specification into a synthetic VPN topology: it runs real IKEv1/IKEv2 exchanges and ESP with the configured
          proposals, lifetimes, PFS, NAT-T and traffic mix, writes the result as a pcap, then passes it through the full passive pipeline (parse →
          geometry proofs → ML with conformal confidence → assessment) exactly like an uploaded capture.
        </p>
        <p className="muted">
          The testbed is a deterministic simulator, not a live strongSwan deployment, so treat grades as a reference for how the configuration
          would look on the wire.
        </p>
        {check &&
          (check.valid ? (
            <>
              <div className="ok-box">
                Valid: <b>{check.name}</b>, {check.tunnels?.length ?? 0} tunnel(s), {fmtDur(check.duration)} of traffic
              </div>
              <table className="grid">
                <thead><tr><th>Tunnel</th><th>Peers</th><th>IKE</th><th>ESP</th><th>PFS</th><th>Lifetimes (IKE / Child)</th><th>NAT-T</th></tr></thead>
                <tbody>
                  {(check.tunnels ?? []).map((t: R, i: number) => (
                    <tr key={i}>
                      <td>{t.name}</td>
                      <td className="mono">{t.initiator} ⇄ {t.responder}</td>
                      <td>IKEv{t.ike_version}: {t.ike}</td>
                      <td>{t.esp}</td>
                      <td>{t.pfs ?? "none"}</td>
                      <td>{fmtDur(t.ike_lifetime)} / {fmtDur(t.child_lifetime)}</td>
                      <td>{t.nat_t ? "yes" : "no"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <div className="err-box">{check.error}</div>
          ))}
      </div>
    </div>
  );
}
