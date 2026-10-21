/* eslint-disable @typescript-eslint/no-explicit-any */
import { http, isNative, nativeUpload } from "./native";
export type Risk = "High" | "Medium" | "Low" | "Informational";
export const RISKS: Risk[] = ["High", "Medium", "Low", "Informational"];

export interface Analysis {
  id: string;
  name: string;
  source: string;
  created: number;
  status: "queued" | "running" | "live" | "done" | "failed";
  stage: string;
  progress: number;
  size: number;
  sha256: string;
  grade: string | null;
  score: number | null;
  alerts: Record<Risk, number> | null;
  tunnels: number | null;
  error: string | null;
}

export interface Alert {
  uid: number;
  id: string;
  name: string;
  risk: Risk;
  confidence: string;
  description: string;
  evidence: string;
  solution: string;
  references: string[];
  standards?: string[];
  attack?: { id: string; name: string; tactic: string; url: string }[];
  params: Record<string, any>;
  tunnel: string;
}

export type Tunnel = Record<string, any>;
export interface Result {
  engine: string;
  file: Record<string, any>;
  tunnels: Tunnel[];
  half_open: any[];
  alerts: Alert[];
  grade: { score: number; letter: string; counts: Record<string, number>; risk_score?: number };
  schema_version?: string;
  attack?: Record<string, any>;
  audit?: { t: string; elapsed: number; stage: string; detail?: string }[];
  ike_messages: number;
  ike_parse_errors: number;
  model_card: Record<string, any>;
  elapsed: number;
}

export interface PacketRow {
  idx: number;
  ts: number;
  src: string;
  dst: string;
  proto: string;
  kind: string;
  sport: number;
  dport: number;
  len: number;
  info: string;
}

export interface LiveBackend {
  name: string;
  path: string;
  privileged: boolean;
  note: string;
}
export interface LiveIface {
  name: string;
  up: boolean;
  loopback: boolean;
  addresses: string[];
  pseudo?: boolean;
}
export interface LiveCaps {
  enabled: boolean;
  backends?: LiveBackend[];
  interfaces?: LiveIface[];
  default_filter?: string;
  prefix?: string | null;
  max_sessions?: number;
}
export interface LiveEvent {
  seq: number;
  ts: number;
  type: string;
  level: string;
  text: string;
  tunnel: string | null;
}
export interface LiveStatus {
  id: string;
  state: string;
  running: boolean;
  source: "replay" | "interface";
  interface: string | null;
  replay: string | null;
  speed: number;
  backend: string;
  filter: string | null;
  command: string | null;
  started: number;
  ended: number | null;
  elapsed: number;
  limits: { duration: number; max_packets: number; max_bytes: number };
  stats: { frames: number; ike: number; esp: number; nat_keepalive: number; ah: number; other: number; bytes: number };
  ipsec_packets: number;
  captured_bytes: number;
  pps: number;
  bps: number;
  rates: { t: number; frames: number; ike: number; esp: number; bytes: number }[];
  analyses: number;
  last_analysis: number | null;
  analysis_time: number;
  summary: { grade?: string; score?: number; alerts?: Record<Risk, number>; tunnels?: number };
  stop_reason: string | null;
  error: string | null;
  last_seq: number;
  events?: LiveEvent[];
}
export interface LiveReq {
  interface?: string;
  filter?: string;
  backend?: string;
  duration?: number;
  max_packets?: number;
  max_mb?: number;
  interval?: number;
  replay_scenario?: string;
  replay_analysis?: string;
  speed?: number;
}

export async function j<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      const b = await r.json();
      if (b.detail) msg = typeof b.detail === "string" ? b.detail : JSON.stringify(b.detail);
    } catch {
      /* not json */
    }
    throw new Error(msg);
  }
  return r.json();
}

export const api = {
  health: () => http("/api/health").then(j<{ status: string; engine: string }>),
  scenarios: () => http("/api/scenarios").then(j<{ id: string; title: string; description: string }[]>),
  analyses: () => http("/api/analyses").then(j<Analysis[]>),
  status: (id: string) => http(`/api/analyses/${id}`).then(j<Analysis>),
  result: (id: string) => http(`/api/analyses/${id}/result`).then(j<Result>),
  upload: (file: File) =>
    (isNative ? nativeUpload(file) : http(`/api/analyses?filename=${encodeURIComponent(file.name)}`, {
      method: "POST",
      body: file,
      headers: { "Content-Type": "application/octet-stream" },
    })).then(j<Analysis>),
  demo: (s: string) => http(`/api/analyses/demo/${s}`, { method: "POST" }).then(j<Analysis>),
  remove: (id: string) => http(`/api/analyses/${id}`, { method: "DELETE" }).then(j<unknown>),
  packets: (id: string, offset: number, limit: number, kind: string) =>
    http(`/api/analyses/${id}/packets?offset=${offset}&limit=${limit}${kind ? `&kind=${kind}` : ""}`).then(
      j<{ total: number; offset: number; items: PacketRow[] }>,
    ),
  packet: (id: string, idx: number) => http(`/api/analyses/${id}/packets/${idx}`).then(j<Record<string, any>>),
  whatif: (id: string, tunnel: string, changes: string[]) =>
    http(`/api/analyses/${id}/whatif`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tunnel, changes }),
    }).then(j<Record<string, any>>),
  changes: () => http("/api/changes").then(j<{ id: string; label: string }[]>),
  rules: () =>
    http("/api/rules").then(
      j<
        {
          id: string;
          name: string;
          description: string;
          solution: string;
          references: string[];
          standards: string[];
          attack: { id: string; name: string; tactic: string }[];
        }[]
      >,
    ),
  modelCard: () => http("/api/model-card").then(j<Record<string, any>>),
  liveCaps: () => http("/api/live/capabilities").then(j<LiveCaps>),
  liveList: () => http("/api/live").then(j<LiveStatus[]>),
  liveStart: (req: LiveReq) =>
    http("/api/live", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req) }).then(
      j<LiveStatus>,
    ),
  liveStatus: (id: string, after = 0) => http(`/api/live/${id}?after=${after}`).then(j<LiveStatus>),
  liveStop: (id: string) => http(`/api/live/${id}/stop`, { method: "POST" }).then(j<LiveStatus>),
  liveStreamUrl: (id: string, after = 0) => `/api/live/${id}/stream?after=${after}`,
  reportUrl: (id: string, fmt: ReportFmt) =>
    fmt === "executive" || fmt === "technical" ? `/api/analyses/${id}/report/${fmt}.pdf` : `/api/analyses/${id}/report.${fmt}`,
  schemaUrl: "/api/schema/report.json",
  explain: (id: string, tunnel: string, window?: number) =>
    http(`/api/analyses/${id}/tunnels/${tunnel}/explain${window != null ? `?window=${window}` : ""}`).then(j<Record<string, any>>),
  verify: (id: string, tunnel: string, changes: string[]) =>
    http(`/api/analyses/${id}/whatif/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tunnel, changes }),
    }).then(j<VerifyJob>),
  verifyStatus: (jid: string) => http(`/api/verify/${jid}`).then(j<VerifyJob>),
  testbedExample: () => http("/api/testbed/example").then(j<{ spec: string }>),
  testbedValidate: (spec: string) =>
    http("/api/testbed/validate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ spec }) }).then(
      j<{ valid: boolean; error?: string; name?: string; duration?: number; tunnels?: Record<string, any>[] }>,
    ),
  testbedRun: (spec: string) =>
    http("/api/testbed/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ spec }) }).then(
      j<Analysis>,
    ),
};

export type ReportFmt = "html" | "json" | "pdf" | "executive" | "technical";
export interface VerifyJob {
  id: string;
  status: "running" | "done" | "failed";
  stage: string;
  progress: number;
  error: string | null;
  result: Record<string, any> | null;
}
