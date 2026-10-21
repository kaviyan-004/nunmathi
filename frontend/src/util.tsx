import type { Risk } from "./api";

export const RISK_COLOR: Record<Risk, string> = {
  High: "#e0301e",
  Medium: "#f08c00",
  Low: "#e6c700",
  Informational: "#3b82c4",
};

export const CLASS_COLOR: Record<string, string> = {
  voip: "#d9534f",
  video: "#8e44ad",
  web: "#2e86c1",
  chat: "#27ae60",
  email: "#e67e22",
};

export const GRADE_COLOR: Record<string, string> = {
  "A+": "#1e8449",
  A: "#27ae60",
  B: "#7dab2f",
  C: "#e6a100",
  D: "#e06c00",
  F: "#c0392b",
};

export function Flag({ risk, size = 14 }: { risk: Risk; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" className="flag" aria-label={`${risk} risk`}>
      <rect x="2" y="1" width="1.6" height="14" fill="#555" />
      <path d="M3.6 2h9.4l-2.4 3.4 2.4 3.4H3.6z" fill={RISK_COLOR[risk]} stroke="#00000055" strokeWidth=".6" />
    </svg>
  );
}

export function fmtTime(ts: number | null | undefined, withDate = true) {
  if (ts == null) return "—";
  const d = new Date(ts * 1000);
  const iso = d.toISOString().replace("T", " ").slice(0, 19);
  return withDate ? iso : iso.slice(11);
}

export function fmtDur(s: number | null | undefined) {
  if (s == null) return "—";
  s = Math.round(s);
  if (s < 90) return `${s} s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${(s / 3600).toFixed(s % 3600 ? 1 : 0)} h`;
  return `${(s / 86400).toFixed(1)} d`;
}

export function fmtBytes(n: number | null | undefined) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function Grade({ letter, score, big }: { letter: string; score?: number; big?: boolean }) {
  return (
    <span className={big ? "grade big" : "grade"} style={{ background: GRADE_COLOR[letter] ?? "#777" }}>
      {letter}
      {score != null && !big ? <small> {score}</small> : null}
    </span>
  );
}

export function KV({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <table className="kv">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <th>{k}</th>
            <td>{v ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function RiskGauge({ value, width = 150 }: { value: number; width?: number }) {
  const v = Math.max(0, Math.min(100, value));
  const col = v >= 60 ? "#c0392b" : v >= 30 ? "#e06c00" : v >= 10 ? "#e6a100" : "#1e8449";
  return (
    <span className="gauge" title="Risk score: 0 = no findings, 100 = worst">
      <svg width={width} height={14} aria-label={`risk score ${v} of 100`}>
        <defs>
          <linearGradient id="rg" x1="0" x2="1">
            <stop offset="0" stopColor="#1e8449" />
            <stop offset=".35" stopColor="#e6a100" />
            <stop offset=".7" stopColor="#e06c00" />
            <stop offset="1" stopColor="#c0392b" />
          </linearGradient>
        </defs>
        <rect x={0} y={4} width={width} height={6} rx={3} fill="url(#rg)" opacity={0.35} />
        <rect x={0} y={4} width={(width * v) / 100} height={6} rx={3} fill={col} />
        <rect x={(width * v) / 100 - 1.5} y={0} width={3} height={14} fill="#222" />
      </svg>
      <b style={{ color: col, marginLeft: 6 }}>{v}</b>
    </span>
  );
}
