/* eslint-disable @typescript-eslint/no-explicit-any */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, j, RISKS, type Analysis, type ReportFmt, type Result } from "./api";
import { installLinkHandler, isNative, nativeOpenCapture, nativeSave, nativeShowHtml } from "./native";
import { Flag } from "./util";
import * as I from "./icons";
import QuickStart from "./components/QuickStart";
import SitesTree from "./components/SitesTree";
import Summary from "./components/Summary";
import TunnelView from "./components/TunnelView";
import PacketView from "./components/PacketView";
import TrafficView from "./components/TrafficView";
import WhatIf from "./components/WhatIf";
import History from "./components/History";
import AlertsPanel from "./components/AlertsPanel";
import LiveView from "./components/LiveView";
import SAInspector from "./components/SAInspector";
import Security from "./components/Security";
import Testbed from "./components/Testbed";
import { AboutDialog, AnalysesPanel, MenuBar, ModelCardPanel, OutputPanel, RulesPanel } from "./components/Misc";

export type TopTab = "quick" | "live" | "testbed" | "summary" | "tunnel" | "sa" | "packet" | "traffic" | "security" | "whatif";
export type BottomTab = "history" | "alerts" | "analyses" | "output" | "rules" | "model";
export interface LogLine {
  t: number;
  msg: string;
  err?: boolean;
}

const TOP_TABS: [TopTab, string, React.ReactNode][] = [
  ["quick", "Quick Start", <I.IcHome key="h" />],
  ["live", "Live Capture", <I.IcLive key="l" />],
  ["testbed", "Testbed", <I.IcTunnel key="tb" />],
  ["summary", "Overview", <I.IcReport key="r" />],
  ["tunnel", "Tunnel Map", <I.IcKey key="k" />],
  ["sa", "SA Inspector", <I.IcLock key="sa" />],
  ["packet", "Packet", <I.IcHex key="x" />],
  ["traffic", "Traffic & SHAP", <I.IcChart key="c" />],
  ["security", "Security & Leakage", <I.IcWarn key="w" />],
  ["whatif", "What-If Twin", <I.IcSliders key="s" />],
];

function useDrag(initial: number, axis: "x" | "y", min: number, max: number, invert = false) {
  const [size, setSize] = useState(initial);
  const start = useRef<{ p: number; s: number } | null>(null);
  const onDown = (e: React.MouseEvent) => {
    start.current = { p: axis === "x" ? e.clientX : e.clientY, s: size };
    const move = (ev: MouseEvent) => {
      if (!start.current) return;
      const d = (axis === "x" ? ev.clientX : ev.clientY) - start.current.p;
      setSize(Math.max(min, Math.min(max, start.current.s + (invert ? -d : d))));
    };
    const up = () => {
      start.current = null;
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
    e.preventDefault();
  };
  return [size, onDown] as const;
}

export default function App() {
  const [engine, setEngine] = useState<string>("");
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [tunnelId, setTunnelId] = useState<string | null>(null);
  const [top, setTop] = useState<TopTab>("quick");
  const [bottom, setBottom] = useState<BottomTab>("history");
  const [packetIdx, setPacketIdx] = useState<number | null>(null);
  const [alertUid, setAlertUid] = useState<number | null>(null);
  const [siteSel, setSiteSel] = useState<string>("");
  const [log, setLog] = useState<LogLine[]>([]);
  const [about, setAbout] = useState(false);
  const [liveWatch, setLiveWatch] = useState<string | null>(null);
  const [sitesW, dragSites] = useDrag(290, "x", 170, 560);
  const [bottomH, dragBottom] = useDrag(Math.round(window.innerHeight * 0.36), "y", 110, 700, true);
  const fileRef = useRef<HTMLInputElement>(null);
  const loadedFor = useRef<string | null>(null);

  const say = useCallback((msg: string, err = false) => setLog((l) => [...l.slice(-400), { t: Date.now(), msg, err }]), []);

  const refresh = useCallback(async () => {
    try {
      setAnalyses(await api.analyses());
    } catch (e) {
      say(`Cannot list analyses: ${(e as Error).message}`, true);
    }
  }, [say]);

  useEffect(() => {
    api
      .health()
      .then((h) => {
        setEngine(h.engine);
        say(`Connected to Nunmathi engine ${h.engine}`);
      })
      .catch((e) => say(`API unreachable: ${e.message}`, true));
    refresh();
  }, [refresh, say]);

  const current = analyses.find((a) => a.id === currentId) ?? null;
  const busy = analyses.some((a) => a.status === "queued" || a.status === "running");
  const liveCount = analyses.filter((a) => a.status === "live").length;
  const isLive = current?.status === "live";

  // poll while analyses are running (faster for file analyses, which report progress)
  useEffect(() => {
    if (!busy && !liveCount) return;
    const t = setInterval(refresh, busy ? 800 : 2000);
    return () => clearInterval(t);
  }, [busy, liveCount, refresh]);

  // while the current analysis is a running live capture, follow its interim results
  useEffect(() => {
    if (!isLive || !currentId) return;
    let stop = false;
    const pull = () =>
      api
        .result(currentId)
        .then((r) => {
          if (stop) return;
          setResult(r);
          setTunnelId((t) => (t && r.tunnels.some((x) => x.id === t) ? t : (r.tunnels[0]?.id ?? null)));
        })
        .catch(() => {
          /* no interim result yet */
        });
    pull();
    const t = setInterval(pull, 2500);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [isLive, currentId]);

  // load result when the current analysis finishes
  useEffect(() => {
    if (!current) {
      setResult(null);
      loadedFor.current = null;
      return;
    }
    if (current.status === "failed" && loadedFor.current !== current.id + ":failed") {
      loadedFor.current = current.id + ":failed";
      say(`Analysis of ${current.name} failed: ${current.error}`, true);
      setResult(null);
    }
    if (current.status !== "done" || loadedFor.current === current.id) return;
    loadedFor.current = current.id;
    api
      .result(current.id)
      .then((r) => {
        setResult(r);
        setTunnelId(r.tunnels[0]?.id ?? null);
        setPacketIdx(null);
        setAlertUid(null);
        const c = RISKS.map((k) => `${k[0]}:${r.alerts.filter((a) => a.risk === k).length}`).join(" ");
        say(
          `Loaded ${current.name}: ${r.file.frames} frames, ${r.tunnels.length} tunnel(s), grade ${r.grade.letter} (${r.grade.score}), alerts ${c}, ${r.elapsed}s`,
        );
        setTop((t) => (t === "quick" ? "summary" : t));
        setBottom((b) => (b === "analyses" || b === "output" ? "alerts" : b));
      })
      .catch((e) => say(`Cannot load result: ${e.message}`, true));
  }, [current, say]);

  const start = useCallback(
    async (p: Promise<Analysis>, label: string) => {
      say(`Starting analysis: ${label}`);
      try {
        const a = await p;
        setCurrentId(a.id);
        setResult(null);
        loadedFor.current = null;
        await refresh();
        setBottom("analyses");
      } catch (e) {
        say(`Failed to start ${label}: ${(e as Error).message}`, true);
      }
    },
    [refresh, say],
  );

  const onFile = useCallback(
    (f: File | undefined) => {
      if (f) start(api.upload(f), f.name);
    },
    [start],
  );
  const openFile = useCallback(async () => {
    if (!isNative) return fileRef.current?.click();
    // desktop app: native Open dialog, the engine reads the file straight from disk
    try {
      const r = await nativeOpenCapture();
      if (r) start(j<Analysis>(r), "capture");
    } catch (e) {
      say(`Cannot open capture: ${(e as Error).message}`, true);
    }
  }, [start, say]);

  // desktop app: a capture passed on the command line / opened from the file manager
  useEffect(() => {
    installLinkHandler();
    if (!isNative) return;
    (window as any).__nunmathiOpened = (p: { status: number; text?: string }) => {
      const r = new Response(p.text ?? "", { status: p.status, headers: { "content-type": "application/json" } });
      start(j<Analysis>(r), "capture");
    };
  }, [start]);

  const select = (id: string) => {
    if (id === currentId) return;
    setCurrentId(id);
    setResult(null);
    loadedFor.current = null;
  };

  const remove = async (id: string) => {
    const a = analyses.find((x) => x.id === id);
    if (!a || !confirm(`Delete analysis ${a.name}? The stored capture and results are removed.`)) return;
    await api.remove(id);
    say(`Deleted ${a.name}`);
    if (id === currentId) {
      setCurrentId(null);
      setTop("quick");
    }
    refresh();
  };

  const openReport = (fmt: ReportFmt) => {
    if (!currentId || !result) return;
    const label = fmt === "executive" ? "executive PDF" : fmt === "technical" || fmt === "pdf" ? "technical PDF" : fmt.toUpperCase();
    if (!isNative) {
      window.open(api.reportUrl(currentId, fmt), "_blank");
      say(`Generated ${label} report for ${current?.name}`);
      return;
    }
    const base = (current?.name ?? "nunmathi").replace(/\.[^.]+$/, "");
    const done = (r: { ok: boolean; path?: string; error?: string; cancelled?: boolean }) => {
      if (r.ok) say(`Generated ${label} report for ${current?.name}${r.path ? ` → ${r.path}` : ""}`);
      else if (!r.cancelled) say(`Report failed: ${r.error}`, true);
    };
    say(`Generating ${label} report for ${current?.name}…`);
    if (fmt === "html") nativeShowHtml(api.reportUrl(currentId, fmt), `Nunmathi report: ${current?.name}`).then(done);
    else {
      const suffix = fmt === "executive" ? "-executive.pdf" : fmt === "json" ? "-report.json" : "-technical.pdf";
      nativeSave(api.reportUrl(currentId, fmt), base + suffix).then(done);
    }
  };

  const showPacket = (idx: number) => {
    setPacketIdx(idx);
    setTop("packet");
  };
  const showTunnel = (id: string, tab: TopTab = "tunnel") => {
    setTunnelId(id);
    setTop(tab);
  };

  const tunnel = useMemo(() => result?.tunnels.find((t) => t.id === tunnelId) ?? result?.tunnels[0] ?? null, [result, tunnelId]);
  const counts = useMemo(() => {
    const c: Record<string, number> = { High: 0, Medium: 0, Low: 0, Informational: 0 };
    result?.alerts.forEach((a) => c[a.risk]++);
    return c;
  }, [result]);

  const needResult = (node: React.ReactNode) =>
    result ? (
      node
    ) : (
      <div className="empty">
        {current
          ? current.status === "live"
            ? `${current.name}: live capture running, waiting for the first interim analysis…`
            : `${current.name}: ${current.status} ${current.status === "running" ? `(${current.stage} ${current.progress}%)` : ""}`
          : "Open a capture, start a Live Capture, or load a demo scenario from Quick Start."}
      </div>
    );

  const watchLive = (id: string | null) => {
    setLiveWatch(id);
    if (id) {
      setCurrentId(id);
      setResult(null);
      loadedFor.current = null;
      refresh();
    }
  };

  return (
    <div className="app">
      <MenuBar
        hasResult={!!result}
        onOpen={openFile}
        onDemo={(s) => start(api.demo(s), `demo ${s}`)}
        onReport={openReport}
        onTab={(t) => setTop(t)}
        onLive={() => setTop("live")}
        onBottom={(b) => setBottom(b)}
        onAbout={() => setAbout(true)}
        onDelete={() => currentId && remove(currentId)}
      />
      <div className="toolbar">
        <select title="Analysis mode" defaultValue="passive">
          <option value="passive">Passive Mode</option>
        </select>
        <div className="sep" />
        <button className="tb" title="Live capture from a network interface" onClick={() => setTop("live")}>
          <I.IcLive /> Live
        </button>
        <div className="sep" />
        <button className="tb" title="Build a VPN testbed from a YAML spec" onClick={() => setTop("testbed")}>
          <I.IcTunnel /> Testbed
        </button>
        <button className="tb" title="Open capture (pcap / pcapng)" onClick={openFile}>
          <I.IcOpen />
        </button>
        <button className="tb" title="Load demo: misconfigured lab" onClick={() => start(api.demo("misconfigured-lab"), "demo misconfigured-lab")}>
          <I.IcPlay />
        </button>
        <button className="tb" title="Refresh analyses" onClick={refresh}>
          <I.IcRefresh />
        </button>
        <button className="tb" title="Delete current analysis" disabled={!currentId} onClick={() => currentId && remove(currentId)}>
          <I.IcTrash />
        </button>
        <div className="sep" />
        <button className="tb" title="Generate HTML report" disabled={!result} onClick={() => openReport("html")}>
          <I.IcReport /> HTML
        </button>
        <button className="tb" title="Executive PDF (2-3 pages)" disabled={!result} onClick={() => openReport("executive")}>
          Exec PDF
        </button>
        <button className="tb" title="Technical PDF (15-30 pages, audit log, proofs, evidence, configs)" disabled={!result} onClick={() => openReport("technical")}>
          Tech PDF
        </button>
        <button className="tb" title="Export JSON" disabled={!result} onClick={() => openReport("json")}>
          JSON
        </button>
        <div className="sep" />
        <button className="tb" title="What-if simulator" disabled={!result} onClick={() => setTop("whatif")}>
          <I.IcBolt /> What-If
        </button>
        <div className="spacer" />
        <span className="engine">Nunmathi {engine}</span>
        <button className="tb" title="About" onClick={() => setAbout(true)}>
          <I.IcHelp />
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          onChange={(e) => {
            onFile(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
      </div>

      <div className="main">
        <div className="top">
          <div className="sites tabpane" style={{ width: sitesW }}>
            <div className="tabs">
              <span className="tab active">
                <I.IcFolder /> Sites
              </span>
            </div>
            <div className="tabbody">
              <SitesTree
                analyses={analyses}
                currentId={currentId}
                result={result}
                sel={siteSel}
                onSel={setSiteSel}
                onAnalysis={(id) => {
                  select(id);
                  setTop("summary");
                }}
                onTunnel={(id) => showTunnel(id)}
                onPacket={showPacket}
                onHalfOpen={() => setBottom("alerts")}
              />
            </div>
          </div>
          <div className="split-v" onMouseDown={dragSites} />
          <div className="tabpane">
            <div className="tabs">
              {TOP_TABS.map(([k, label, icon]) => (
                <span key={k} className={`tab ${top === k ? "active" : ""}`} onClick={() => setTop(k)}>
                  {icon}
                  {label}
                </span>
              ))}
            </div>
            <div className="tabbody">
              {top === "quick" && <QuickStart current={current} onFile={onFile} onDemo={(s) => start(api.demo(s), `demo ${s}`)} />}
              {top === "live" && (
                <LiveView
                  analyses={analyses}
                  watchId={liveWatch}
                  onWatch={watchLive}
                  onOpen={(id) => {
                    select(id);
                    setTop("summary");
                  }}
                  say={say}
                />
              )}
              {top === "summary" && needResult(result && current && <Summary result={result} meta={current} onTunnel={showTunnel} onReport={openReport} />)}
              {top === "tunnel" &&
                needResult(tunnel && <TunnelView result={result!} tunnel={tunnel} onTunnel={setTunnelId} onPacket={showPacket} />)}
              {top === "testbed" && <Testbed onRun={start} say={say} />}
              {top === "sa" &&
                needResult(tunnel && <SAInspector result={result!} tunnel={tunnel} onTunnel={setTunnelId} onPacket={showPacket} />)}
              {top === "security" &&
                needResult(
                  result && (
                    <Security
                      result={result}
                      onTunnel={(id) => showTunnel(id)}
                      onAlert={(uid) => {
                        setAlertUid(uid);
                        setBottom("alerts");
                      }}
                    />
                  ),
                )}
              {top === "packet" && needResult(currentId && <PacketView aid={currentId} idx={packetIdx} onIdx={setPacketIdx} />)}
              {top === "traffic" && needResult(tunnel && <TrafficView aid={currentId!} result={result!} tunnel={tunnel} onTunnel={setTunnelId} />)}
              {top === "whatif" &&
                needResult(tunnel && currentId && <WhatIf aid={currentId} result={result!} tunnel={tunnel} onTunnel={setTunnelId} say={say} />)}
            </div>
          </div>
        </div>
        <div className="split-h" onMouseDown={dragBottom} />
        <div className="bottom tabpane" style={{ height: bottomH }}>
          <div className="tabs">
            <span className={`tab ${bottom === "history" ? "active" : ""}`} onClick={() => setBottom("history")}>
              <I.IcHistory /> History
            </span>
            <span className={`tab ${bottom === "alerts" ? "active" : ""}`} onClick={() => setBottom("alerts")}>
              <Flag risk="High" size={13} /> Alerts {result ? <span className="badge">{result.alerts.length}</span> : null}
            </span>
            <span className={`tab ${bottom === "analyses" ? "active" : ""}`} onClick={() => setBottom("analyses")}>
              <I.IcCapture /> Analyses {busy ? <span className="badge">…</span> : null}
              {liveCount ? <span className="badge" style={{ background: "#d9331f" }}>LIVE {liveCount}</span> : null}
            </span>
            <span className={`tab ${bottom === "output" ? "active" : ""}`} onClick={() => setBottom("output")}>
              <I.IcTerminal /> Output
            </span>
            <span className={`tab ${bottom === "rules" ? "active" : ""}`} onClick={() => setBottom("rules")}>
              <I.IcRules /> Rules
            </span>
            <span className={`tab ${bottom === "model" ? "active" : ""}`} onClick={() => setBottom("model")}>
              <I.IcBrain /> Model Card
            </span>
          </div>
          <div className="tabbody">
            {bottom === "history" &&
              (result && currentId ? <History aid={currentId} sel={packetIdx} onSel={showPacket} tick={isLive ? result.file.frames : 0} /> : <div className="empty">No capture loaded.</div>)}
            {bottom === "alerts" &&
              (result ? (
                <AlertsPanel result={result} sel={alertUid} onSel={setAlertUid} onTunnel={(id) => showTunnel(id)} />
              ) : (
                <div className="empty">No alerts yet.</div>
              ))}
            {bottom === "analyses" && <AnalysesPanel analyses={analyses} currentId={currentId} onSel={select} onDelete={remove} />}
            {bottom === "output" && <OutputPanel log={log} />}
            {bottom === "rules" && <RulesPanel />}
            {bottom === "model" && <ModelCardPanel />}
          </div>
        </div>
      </div>

      <div className="statusbar">
        <span className="alerts-count" title="Alerts by risk (High / Medium / Low / Informational)">
          Alerts
          {RISKS.map((r) => (
            <span key={r}>
              <Flag risk={r} size={13} /> {counts[r]}
            </span>
          ))}
        </span>
        <span>
          {current ? (
            <>
              {isLive && <span className="live-dot" />}
              Capture: <b>{current.name}</b>
              {result ? ` · grade ${result.grade.letter} (${result.grade.score})` : ` · ${current.status}`}
            </>
          ) : (
            "No capture"
          )}
        </span>
        <div className="right">
          <span>Mode: Passive (no decryption, no traffic injected)</span>
          {liveCount > 0 && (
            <span style={{ cursor: "pointer" }} onClick={() => setTop("live")}>
              <span className="live-dot" />
              Live captures: {liveCount}
            </span>
          )}
          <span>
            Current Analyses: {analyses.filter((a) => a.status === "running" || a.status === "queued").length}
          </span>
        </div>
      </div>
      {about && <AboutDialog engine={engine} onClose={() => setAbout(false)} />}
    </div>
  );
}
