import { useEffect, useRef, useState } from "react";
import { api, RISKS, type Analysis, type ReportFmt } from "../api";
import { isNative, nativeSave } from "../native";
import type { BottomTab, LogLine, TopTab } from "../App";
import { Flag, fmtBytes, fmtTime, Grade } from "../util";

/* ------------------------------------------------------------------ menu bar */
type Item = { label: string; on?: () => void; disabled?: boolean } | "sep";

export function MenuBar({
  hasResult,
  onOpen,
  onDemo,
  onReport,
  onTab,
  onLive,
  onBottom,
  onAbout,
  onDelete,
}: {
  hasResult: boolean;
  onOpen: () => void;
  onDemo: (s: string) => void;
  onReport: (fmt: ReportFmt) => void;
  onTab: (t: TopTab) => void;
  onLive: () => void;
  onBottom: (b: BottomTab) => void;
  onAbout: () => void;
  onDelete: () => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const [scen, setScen] = useState<{ id: string; title: string }[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.scenarios().then(setScen).catch(() => setScen([]));
  }, []);
  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(null);
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  const menus: [string, Item[]][] = [
    [
      "File",
      [
        { label: "Open Capture…", on: onOpen },
        { label: "Live Capture…", on: onLive },
        { label: "Build Testbed from YAML…", on: () => onTab("testbed") },
        "sep",
        ...scen.map((s) => ({ label: `Load demo: ${s.title}`, on: () => onDemo(s.id) })),
        "sep",
        { label: "Delete Current Analysis", on: onDelete, disabled: !hasResult },
      ],
    ],
    [
      "View",
      [
        { label: "Quick Start", on: () => onTab("quick") },
        { label: "Live Capture", on: () => onTab("live") },
        { label: "Summary", on: () => onTab("summary"), disabled: !hasResult },
        { label: "Tunnel", on: () => onTab("tunnel"), disabled: !hasResult },
        { label: "Packet", on: () => onTab("packet"), disabled: !hasResult },
        { label: "Traffic", on: () => onTab("traffic"), disabled: !hasResult },
        { label: "SA Inspector", on: () => onTab("sa"), disabled: !hasResult },
        { label: "Security & Leakage", on: () => onTab("security"), disabled: !hasResult },
        { label: "What-If Twin", on: () => onTab("whatif"), disabled: !hasResult },
        { label: "Testbed", on: () => onTab("testbed") },
        "sep",
        { label: "History", on: () => onBottom("history") },
        { label: "Alerts", on: () => onBottom("alerts") },
        { label: "Analyses", on: () => onBottom("analyses") },
        { label: "Output", on: () => onBottom("output") },
        { label: "Scan Rules", on: () => onBottom("rules") },
        { label: "Model Card", on: () => onBottom("model") },
      ],
    ],
    [
      "Report",
      [
        { label: "Executive PDF (2-3 pages)…", on: () => onReport("executive"), disabled: !hasResult },
        { label: "Technical PDF (15-30 pages)…", on: () => onReport("technical"), disabled: !hasResult },
        { label: "Generate HTML Report…", on: () => onReport("html"), disabled: !hasResult },
        "sep",
        { label: "Export JSON (SIEM/SOAR)…", on: () => onReport("json"), disabled: !hasResult },
        { label: "JSON Schema…", on: () => (isNative ? nativeSave(api.schemaUrl, "nunmathi-report.schema.json") : window.open(api.schemaUrl, "_blank")) },
      ],
    ],
    [
      "Help",
      [
        { label: "Scan Rules", on: () => onBottom("rules") },
        { label: "Model Card", on: () => onBottom("model") },
        ...(isNative ? [] : [{ label: "API Documentation", on: () => window.open("/docs", "_blank") }]),
        "sep",
        { label: "About Nunmathi", on: onAbout },
      ],
    ],
  ];

  return (
    <div className="menubar" ref={ref}>
      {menus.map(([name, items]) => (
        <div
          key={name}
          className={`menu ${open === name ? "open" : ""}`}
          onMouseEnter={() => open && setOpen(name)}
        >
          <span onClick={() => setOpen(open === name ? null : name)}>{name}</span>
          {open === name && (
            <div className="menu-drop">
              {items.map((it, i) =>
                it === "sep" ? (
                  <hr key={i} />
                ) : (
                  <div
                    key={i}
                    className={it.disabled ? "disabled" : ""}
                    onClick={() => {
                      setOpen(null);
                      it.on?.();
                    }}
                  >
                    {it.label}
                  </div>
                ),
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ analyses */
export function AnalysesPanel({
  analyses,
  currentId,
  onSel,
  onDelete,
}: {
  analyses: Analysis[];
  currentId: string | null;
  onSel: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  if (!analyses.length) return <div className="empty">No analyses yet. Open a capture or load a demo from Quick Start.</div>;
  return (
    <table className="grid clickable">
      <thead>
        <tr>
          <th>Id</th>
          <th>Capture</th>
          <th>Source</th>
          <th>Created</th>
          <th className="num">Size</th>
          <th>Status</th>
          <th>Grade</th>
          <th>Alerts</th>
          <th className="num">Tunnels</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {analyses.map((a) => (
          <tr key={a.id} className={a.id === currentId ? "sel" : ""} onClick={() => onSel(a.id)}>
            <td className="mono">{a.id}</td>
            <td>{a.name}</td>
            <td>{a.source}</td>
            <td>{fmtTime(a.created)}</td>
            <td className="num">{fmtBytes(a.size)}</td>
            <td style={{ minWidth: 150 }}>
              {a.status === "running" || a.status === "queued" ? (
                <div>
                  <div className="progress">
                    <div style={{ width: `${a.progress}%` }} />
                  </div>
                  <span className="muted">
                    {a.stage} {a.progress}%
                  </span>
                </div>
              ) : a.status === "live" ? (
                <span className="pill live">
                  <span className="live-dot" />
                  LIVE
                </span>
              ) : a.status === "failed" ? (
                <span className="pill bad" title={a.error ?? ""}>
                  failed: {a.error}
                </span>
              ) : (
                <span className="pill good">done</span>
              )}
            </td>
            <td>{a.grade ? <Grade letter={a.grade} score={a.score ?? undefined} /> : ""}</td>
            <td>
              {a.alerts &&
                RISKS.map((r) => (
                  <span key={r} style={{ marginRight: 6, whiteSpace: "nowrap" }}>
                    <Flag risk={r} size={12} /> {a.alerts![r] ?? 0}
                  </span>
                ))}
            </td>
            <td className="num">{a.tunnels ?? ""}</td>
            <td>
              <button
                className="btn"
                title="Delete"
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(a.id);
                }}
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/* ------------------------------------------------------------------ output */
export function OutputPanel({ log }: { log: LogLine[] }) {
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => end.current?.scrollIntoView({ block: "end" }), [log]);
  return (
    <div className="output">
      {log.map((l, i) => (
        <div key={i} className={l.err ? "e" : ""}>
          {new Date(l.t).toLocaleTimeString()} {l.err ? "ERROR " : "INFO  "}
          {l.msg}
        </div>
      ))}
      <div ref={end} />
    </div>
  );
}

/* ------------------------------------------------------------------ rules */
type Rule = Awaited<ReturnType<typeof api.rules>>[number];
export function RulesPanel() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  useEffect(() => {
    api.rules().then(setRules).catch((e) => setErr(e.message));
  }, []);
  if (err) return <div className="empty">Cannot load rules: {err}</div>;
  if (!rules) return <div className="empty">Loading…</div>;
  const f = q.toLowerCase();
  const shown = rules.filter((r) => !f || `${r.id} ${r.name} ${r.description}`.toLowerCase().includes(f));
  return (
    <>
      <div className="toolbar-inline">
        Filter: <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="rule id or text" />
        <span className="muted">{shown.length} of {rules.length} passive scan rules</span>
      </div>
      <table className="grid">
        <thead>
          <tr>
            <th>Id</th>
            <th>Name</th>
            <th>Description</th>
            <th>Solution</th>
            <th>Standards</th>
            <th>ATT&amp;CK</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((r) => (
            <tr key={r.id}>
              <td className="mono">{r.id}</td>
              <td>{r.name}</td>
              <td>{r.description}</td>
              <td>{r.solution || "—"}</td>
              <td>{[...(r.standards ?? []), ...r.references].join("; ") || "—"}</td>
              <td className="mono">{(r.attack ?? []).map((a) => a.id).join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

/* ------------------------------------------------------------------ model card */
export function ModelCardPanel() {
  const [mc, setMc] = useState<Record<string, any> | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.modelCard().then(setMc).catch((e) => setErr(e.message));
  }, []);
  if (err) return <div className="empty">Cannot load model card: {err}</div>;
  if (!mc) return <div className="empty">Loading model…</div>;
  const classes: string[] = mc.classes;
  const cm: number[][] = mc.confusion_matrix;
  const max = Math.max(...cm.flat());
  return (
    <div className="pad" style={{ display: "grid", gridTemplateColumns: "minmax(300px, 1fr) minmax(300px, 1fr)", gap: 18 }}>
      <div>
        <h2 className="sec">Traffic classifier</h2>
        <table className="kv">
          <tbody>
            <tr><th>Model</th><td>{mc.model}</td></tr>
            <tr><th>Version</th><td>{mc.version}</td></tr>
            <tr><th>Window</th><td>{mc.window_seconds} s, {mc.features.length} features (sizes, timing, direction; no payload)</td></tr>
            <tr><th>Training data</th><td>{mc.training.source}; {mc.training.train_windows} train / {mc.training.calibration_windows} calibration / {mc.training.test_windows} test windows across {mc.training.geometries.length} ESP geometries</td></tr>
            <tr><th>Test accuracy</th><td><b>{(mc.test_accuracy * 100).toFixed(2)}%</b> (macro F1 {mc.macro_f1}) on held-out synthetic data</td></tr>
            <tr><th>Conformal sets</th><td>α = {mc.conformal.alpha}; empirical coverage {mc.conformal.empirical_coverage}, mean set size {mc.conformal.mean_set_size}</td></tr>
            <tr><th>OOD detection</th><td>{mc.ood.method}; threshold {mc.ood.threshold} ({mc.ood.threshold_quantile} quantile)</td></tr>
          </tbody>
        </table>
        <h2 className="sec">Limitations</h2>
        <ul style={{ margin: "4px 0 0 18px", padding: 0 }}>
          {mc.limitations.map((l: string) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </div>
      <div>
        <h2 className="sec">Confusion matrix (rows = true, columns = predicted)</h2>
        <table className="grid" style={{ width: "auto" }}>
          <thead>
            <tr>
              <th />
              {classes.map((c) => (
                <th key={c} className="num">{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cm.map((row, i) => (
              <tr key={i}>
                <th>{classes[i]}</th>
                {row.map((v, k) => (
                  <td
                    key={k}
                    className="num"
                    style={{ background: v ? `rgba(${i === k ? "39,174,96" : "224,48,30"},${0.12 + (0.6 * v) / max})` : undefined }}
                  >
                    {v}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <h2 className="sec">Per-class metrics</h2>
        <table className="grid" style={{ width: "auto" }}>
          <thead>
            <tr><th>Class</th><th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th></tr>
          </thead>
          <tbody>
            {classes.map((c) => (
              <tr key={c}>
                <td>{c}</td>
                <td className="num">{mc.per_class[c].precision.toFixed(3)}</td>
                <td className="num">{mc.per_class[c].recall.toFixed(3)}</td>
                <td className="num">{mc.per_class[c].f1.toFixed(3)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ about */
export function AboutDialog({ engine, onClose }: { engine: string; onClose: () => void }) {
  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="mt">About Nunmathi</div>
        <div className="mb">
          <b>Nunmathi</b> {engine && `engine ${engine}`}
          <br />
          Passive, AI-assisted IPsec VPN analyzer (SIH 2025 PS 26160).
          <br />
          <br />
          Reads pcap/pcapng captures, reconstructs IKEv1/IKEv2 negotiations and ESP Child SAs, infers ESP cipher geometry, PFS and
          lifetimes without keys, classifies encrypted traffic and proposes configuration fixes.
          <br />
          <br />
          <span className="muted">The interface follows the layout of the OWASP ZAP desktop client. Nunmathi is not affiliated with OWASP.</span>
        </div>
        <div className="mf">
          <button className="btn primary" onClick={onClose}>OK</button>
        </div>
      </div>
    </div>
  );
}
