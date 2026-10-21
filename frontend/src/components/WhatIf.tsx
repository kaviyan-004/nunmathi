import { useEffect, useState } from "react";
import { api, type Result, type Tunnel, type VerifyJob } from "../api";
import { fmtBytes, fmtDur, Grade } from "../util";
import TunnelPicker from "./TunnelPicker";

type R = Record<string, any>;
type Cfg = "strongswan" | "libreswan" | "cisco_ios";

function Col({ title, m, note }: { title: string; m: R; note?: string }) {
  return (
    <div className="col">
      <h3>{title}</h3>
      <div style={{ textAlign: "center" }}>
        <Grade letter={m.grade.letter} big />
        <div className="muted">score {m.grade.score} · risk {100 - m.grade.score}</div>
      </div>
      <table className="kv">
        <tbody>
          <tr><th>Alerts</th><td>{m.alerts ? (m.alerts.length ? m.alerts.join(", ") : "none") : "—"}</td></tr>
          <tr><th>IKE</th><td>{m.ike_version ? `IKEv${m.ike_version}` : "—"}</td></tr>
          <tr><th>ESP</th><td>{m.esp ?? "—"}{m.esp_confidence ? ` (${m.esp_confidence})` : ""}</td></tr>
          <tr><th>PFS</th><td>{m.pfs == null ? "—" : m.pfs ? `yes ${m.pfs_group ?? ""}` : "no"}</td></tr>
          <tr><th>Child lifetime</th><td>{m.child_life ? fmtDur(m.child_life) : "—"}</td></tr>
          <tr><th>MEI mean</th><td>{m.mei_mean ?? "—"}</td></tr>
        </tbody>
      </table>
      {note && <p className="muted" style={{ fontSize: 11 }}>{note}</p>}
    </div>
  );
}

export default function WhatIf({
  aid,
  result,
  tunnel: t,
  onTunnel,
  say,
}: {
  aid: string;
  result: Result;
  tunnel: Tunnel;
  onTunnel: (id: string) => void;
  say: (msg: string, err?: boolean) => void;
}) {
  const [changes, setChanges] = useState<{ id: string; label: string }[]>([]);
  const [on, setOn] = useState<Set<string>>(new Set());
  const [out, setOut] = useState<R | null>(null);
  const [busy, setBusy] = useState(false);
  const [cfg, setCfg] = useState<Cfg>("strongswan");
  const [job, setJob] = useState<VerifyJob | null>(null);
  const rec: string[] = t.recommended ?? [];

  useEffect(() => {
    api.changes().then(setChanges).catch((e) => say(`Could not load changes: ${e.message}`, true));
  }, [say]);

  useEffect(() => {
    setOn(new Set(t.recommended ?? []));
    setOut(null);
    setJob(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aid, t.id]);

  const run = async () => {
    setBusy(true);
    try {
      const r = await api.whatif(aid, t.id, [...on]);
      setOut(r);
      say(`What-if on ${t.id}: ${r.before.grade.letter} → ${r.after.grade.letter} with ${r.changes.length} change(s)`);
    } catch (e) {
      say(`What-if failed: ${(e as Error).message}`, true);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (!job || job.status !== "running") return;
    const h = setTimeout(
      () =>
        api
          .verifyStatus(job.id)
          .then((j) => {
            setJob(j);
            if (j.status === "done")
              say(`Verified ${t.id} in the testbed: ${j.result!.baseline.measured.grade.letter} → ${j.result!.hardened.measured.grade.letter}`);
            if (j.status === "failed") say(`Verification failed: ${j.error}`, true);
          })
          .catch((e) => say(`Verification status: ${e.message}`, true)),
      900,
    );
    return () => clearTimeout(h);
  }, [job, say, t.id]);

  const apply = async () => {
    try {
      if (!out) await run();
      setJob(await api.verify(aid, t.id, [...on]));
      say(`Rebuilding ${t.id} in the testbed with ${on.size} change(s)…`);
    } catch (e) {
      say(`Cannot start verification: ${(e as Error).message}`, true);
    }
  };
  const vr: R | null = job?.status === "done" ? job.result : null;
  const observed: R = {
    grade: t.grade,
    alerts: [...new Set(result.alerts.filter((a) => a.tunnel === t.id).map((a) => a.id))].sort(),
    ike_version: t.version,
    esp: t.posture?.esp_label,
    esp_confidence: t.posture?.esp_confidence,
    pfs: t.pfs?.status === "enabled" ? true : t.pfs?.status === "disabled" ? false : null,
    pfs_group: t.pfs?.group,
    child_life: t.lifetimes?.child_rekey_interval,
    mei_mean: t.traffic?.summary?.mei_mean,
  };

  const alertName = (id: string) => result.alerts.find((a) => a.id === id)?.name ?? id;
  const flip = (id: string) =>
    setOn((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <>
      <TunnelPicker result={result} value={t.id} onChange={onTunnel} />
      <div className="pad wi">
        <div>
          <h2 className="sec">Candidate changes for {t.id}</h2>
          {changes.map((c) => (
            <label key={c.id}>
              <input type="checkbox" checked={on.has(c.id)} onChange={() => flip(c.id)} />
              <span>
                {c.label}
                {rec.includes(c.id) && <span className="rec">recommended</span>}
              </span>
            </label>
          ))}
          <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
            <button className="btn primary" disabled={busy} onClick={run}>
              {busy ? "Simulating…" : "Simulate"}
            </button>
            <button className="btn" onClick={() => setOn(new Set(rec))}>Recommended</button>
            <button className="btn" onClick={() => setOn(new Set())}>Clear</button>
          </div>
          <div style={{ marginTop: 8 }}>
            <button className="btn primary" disabled={!on.size || job?.status === "running"} onClick={apply} title="Rebuild the tunnel in the IPsecForge testbed before and after the changes, re-capture and re-score both">
              {job?.status === "running" ? "Verifying…" : "Apply recommendation (verify in testbed)"}
            </button>
          </div>
          {job && job.status === "running" && (
            <>
              <div className="progress"><div style={{ width: `${job.progress}%` }} /></div>
              <div className="muted">{job.stage} · {job.progress}%</div>
            </>
          )}
          {job?.status === "failed" && <div className="err-box">{job.error}</div>}
          <p className="muted">
            The simulation re-scores this tunnel's observed posture with the selected changes applied. Nothing is sent to the peers.
          </p>
        </div>
        <div>
          {!out && !vr ? (
            <div className="empty">Pick changes and press Simulate to see the new grade, the alerts it resolves, its cost and a ready-to-use configuration.</div>
          ) : !out ? null : (
            <>
              <h2 className="sec">Result</h2>
              <div className="wi-result">
                <div style={{ textAlign: "center" }}>
                  <Grade letter={out.before.grade.letter} big />
                  <div className="muted">now · {out.before.grade.score}</div>
                </div>
                <span className="arrow">➜</span>
                <div style={{ textAlign: "center" }}>
                  <Grade letter={out.after.grade.letter} big />
                  <div className="muted">after · {out.after.grade.score}</div>
                </div>
                <table className="kv">
                  <tbody>
                    <tr><th>Alerts</th><td>{out.before.alerts.length} → {out.after.alerts.length}</td></tr>
                  </tbody>
                </table>
              </div>

              <h2 className="sec">Resolved alerts ({out.resolved.length})</h2>
              {out.resolved.length ? (
                <ul style={{ margin: "4px 0 0 18px", padding: 0 }}>
                  {out.resolved.map((id: string) => (
                    <li key={id}><span className="mono">{id}</span> {alertName(id)}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted">None.</p>
              )}
              {out.after.alerts.length > 0 && (
                <p className="muted">Still raised: {out.after.alerts.join(", ")}</p>
              )}

              <h2 className="sec">Estimated cost</h2>
              <table className="kv">
                <tbody>
                  <tr><th>Extra bytes in this capture</th><td>{fmtBytes(out.cost.extra_bytes)} ({out.cost.extra_pct}% of ESP volume)</td></tr>
                  <tr><th>Extra per hour</th><td>{fmtBytes(out.cost.extra_bytes_per_hour)}</td></tr>
                  <tr><th>Child SA rekeys per day</th><td>{out.cost.rekeys_per_day}</td></tr>
                  <tr><th>Handshake size</th><td>{fmtBytes(out.cost.handshake_bytes)}</td></tr>
                </tbody>
              </table>

              <div className="subtabs">
                <button className={cfg === "strongswan" ? "on" : ""} onClick={() => setCfg("strongswan")}>strongSwan (swanctl.conf)</button>
                <button className={cfg === "libreswan" ? "on" : ""} onClick={() => setCfg("libreswan")}>libreswan (ipsec.conf)</button>
                <button className={cfg === "cisco_ios" ? "on" : ""} onClick={() => setCfg("cisco_ios")}>Cisco IOS</button>
                <button
                  style={{ marginLeft: "auto" }}
                  onClick={() =>
                    navigator.clipboard
                      .writeText(out.config[cfg])
                      .then(() => say(`Copied ${cfg} configuration`))
                      .catch(() => say("Clipboard not available", true))
                  }
                >
                  Copy
                </button>
              </div>
              <pre className="cfg">{out.config[cfg] ?? "(not available)"}</pre>
            </>
          )}
          {vr && (
            <>
              <h2 className="sec">Verified side-by-side</h2>
              <div className="side3">
                <Col title="Observed (this capture)" m={observed} />
                <Col
                  title="Predicted (digital twin)"
                  m={{ grade: vr.predicted.grade, alerts: observed.alerts.filter((a: string) => !vr.predicted.resolved.includes(a)) }}
                  note={`Predicted to resolve: ${vr.predicted.resolved.join(", ") || "nothing"}`}
                />
                <Col title="Verified (rebuilt & re-captured)" m={vr.hardened.measured} />
              </div>
              <p>
                Testbed baseline {vr.baseline.measured.grade.letter} ({vr.baseline.measured.grade.score}) → hardened{" "}
                <b>{vr.hardened.measured.grade.letter} ({vr.hardened.measured.grade.score})</b>. Resolved{" "}
                <span className="delta-good">{vr.resolved.join(", ") || "none"}</span>
                {vr.introduced.length ? <>; introduced <span className="delta-bad">{vr.introduced.join(", ")}</span></> : null}.
              </p>
              {vr.prediction_agrees ? (
                <div className="ok-box">Prediction confirmed: every finding the twin predicted fixed is gone from the re-captured traffic and the grade matches.</div>
              ) : (
                <div className="err-box">
                  Prediction differs from the verified result.
                  {vr.prediction_diff.predicted_only.length ? ` Still present despite prediction: ${vr.prediction_diff.predicted_only.join(", ")}.` : ""}
                  {vr.prediction_diff.verified_only.length ? ` Fixed but not predicted: ${vr.prediction_diff.verified_only.join(", ")}.` : ""}
                </div>
              )}
              {vr.prediction_diff.not_reproduced.length ? (
                <p className="muted">Not reproducible in a short testbed run (e.g. long lifetimes): {vr.prediction_diff.not_reproduced.join(", ")}.</p>
              ) : null}
              <table className="grid wrap">
                <thead><tr><th>Change</th><th>Verified</th><th>Evidence from re-captured traffic</th></tr></thead>
                <tbody>
                  {vr.checks.map((c: R) => (
                    <tr key={c.change}>
                      <td>{c.label}</td>
                      <td className={c.verified === true ? "delta-good" : c.verified === false ? "delta-bad" : ""}>
                        {c.verified === true ? "✔ yes" : c.verified === false ? "✘ no" : "n/a"}
                      </td>
                      <td style={{ fontSize: 11 }}>{c.evidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="muted">{vr.method}; {vr.elapsed}s.</p>
            </>
          )}
        </div>
      </div>
    </>
  );
}
