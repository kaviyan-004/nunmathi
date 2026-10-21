import type { Result } from "../api";
import { Grade } from "../util";

export default function TunnelPicker({ result, value, onChange }: { result: Result; value: string; onChange: (id: string) => void }) {
  if (result.tunnels.length < 2) return null;
  return (
    <div className="toolbar-inline">
      Tunnel:
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {result.tunnels.map((t) => (
          <option key={t.id} value={t.id}>
            {t.id} {t.initiator} ⇄ {t.responder}
          </option>
        ))}
      </select>
      <Grade letter={result.tunnels.find((t) => t.id === value)?.grade.letter ?? "?"} />
    </div>
  );
}
