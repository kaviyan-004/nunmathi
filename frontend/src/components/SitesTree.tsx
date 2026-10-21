import { useState } from "react";
import type { Analysis, Result } from "../api";
import { Grade } from "../util";
import * as I from "../icons";

interface Props {
  analyses: Analysis[];
  currentId: string | null;
  result: Result | null;
  sel: string;
  onSel: (k: string) => void;
  onAnalysis: (id: string) => void;
  onTunnel: (id: string) => void;
  onPacket: (idx: number) => void;
  onHalfOpen: () => void;
}

export default function SitesTree(p: Props) {
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const toggle = (k: string) => setClosed((c) => ({ ...c, [k]: !c[k] }));

  const Node = ({
    k,
    icon,
    label,
    sub,
    onClick,
    children,
    extra,
  }: {
    k: string;
    icon: React.ReactNode;
    label: React.ReactNode;
    sub?: React.ReactNode;
    onClick?: () => void;
    children?: React.ReactNode;
    extra?: React.ReactNode;
  }) => {
    const open = !closed[k];
    return (
      <div>
        <div
          className={`node ${p.sel === k ? "sel" : ""}`}
          onClick={() => {
            p.onSel(k);
            onClick?.();
          }}
          onDoubleClick={() => children && toggle(k)}
          title={typeof label === "string" ? label : undefined}
        >
          <span
            className="twist"
            onClick={(e) => {
              e.stopPropagation();
              if (children) toggle(k);
            }}
          >
            {children ? (open ? "▼" : "▶") : ""}
          </span>
          {icon}
          <span className="lbl">
            {label} {sub && <span className="sub">{sub}</span>}
          </span>
          {extra}
        </div>
        {children && open && <div className="children">{children}</div>}
      </div>
    );
  };

  return (
    <div className="tree">
      <Node k="root" icon={<I.IcFolder />} label="Captures">
        {p.analyses.length === 0 && <div className="node muted" style={{ paddingLeft: 20 }}>(none)</div>}
        {p.analyses.map((a) => {
          const isCur = a.id === p.currentId;
          const r = isCur ? p.result : null;
          return (
            <Node
              key={a.id}
              k={`a:${a.id}`}
              icon={<I.IcCapture />}
              label={a.name}
              sub={a.status !== "done" ? `(${a.status === "running" ? `${a.progress}%` : a.status})` : undefined}
              extra={a.grade ? <Grade letter={a.grade} /> : null}
              onClick={() => p.onAnalysis(a.id)}
            >
              {r
                ? [
                    ...r.tunnels.map((t) => (
                      <Node
                        key={t.id}
                        k={`t:${t.id}`}
                        icon={<I.IcTunnel />}
                        label={`${t.id} ${t.initiator} ⇄ ${t.responder}`}
                        sub={`IKEv${t.version}`}
                        extra={<Grade letter={t.grade.letter} />}
                        onClick={() => p.onTunnel(t.id)}
                      >
                        <Node k={`t:${t.id}:ike`} icon={<I.IcFolder />} label={`IKE SAs (${t.ike_sas.length})`}>
                          {t.ike_sas.map((s: Record<string, any>) => (
                            <Node
                              key={s.ispi}
                              k={`ike:${s.ispi}`}
                              icon={<I.IcKey />}
                              label={`${s.ispi.slice(0, 8)}… ${s.origin}`}
                              sub={`${s.messages} msgs${s.established ? "" : ", not established"}`}
                              onClick={() => {
                                p.onTunnel(t.id);
                                if (s.packets?.length) p.onPacket(s.packets[0]);
                              }}
                            />
                          ))}
                        </Node>
                        <Node k={`t:${t.id}:child`} icon={<I.IcFolder />} label={`Child SAs (${t.child_sas.length})`}>
                          {t.child_sas.map((c: Record<string, any>) => (
                            <Node
                              key={c.id}
                              k={`c:${c.id}`}
                              icon={<I.IcLock />}
                              label={`${c.id} 0x${c.spi_out ?? "?"}`}
                              sub={`${c.packets} pkts · ${c.geometry?.best?.label ?? "?"}`}
                              onClick={() => {
                                p.onTunnel(t.id);
                                if (c.first_packets?.length) p.onPacket(Math.min(...c.first_packets));
                              }}
                            />
                          ))}
                        </Node>
                      </Node>
                    )),
                    ...r.half_open.map((h) => (
                      <Node
                        key={`h${h.responder}`}
                        k={`h:${h.responder}`}
                        icon={<I.IcWarn />}
                        label={`Half-open IKE → ${h.responder}`}
                        sub={`${h.attempts} attempts`}
                        onClick={p.onHalfOpen}
                      />
                    )),
                  ]
                : isCur && a.status === "done"
                  ? [<div key="l" className="node muted" style={{ paddingLeft: 20 }}>loading…</div>]
                  : null}
            </Node>
          );
        })}
      </Node>
    </div>
  );
}
