"use client";

import { ArrowUpRight } from "lucide-react";
import { useEffect, useState, useTransition, type ReactNode } from "react";
import { riskHistoryAction, setAcceptanceAction } from "@/app/(app)/risks/actions";
import { Button } from "@/components/ui/button";
import { SEGMENT_FRAME, segmentClass } from "@/components/ui/segmented";
import { EVIDENCE_KEYS, readEvidence } from "@/lib/domain/evidence";
import { cweUrl, wascUrl, zapAlertUrl } from "@/lib/domain/owasp";
import { cx } from "@/lib/ui/cx";
import { SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import { SEVERITY_TONE } from "@/lib/ui/severity";
import type { AuditEntry, Risk } from "@/types/aegis";
import { RiskInstances } from "./risk-instances";
import { StatusPill } from "./status-pill";
import { ThreatBars } from "./threat-bars";

type View = "formatted" | "table" | "json";
type Tab = "instances" | "references" | "history";

const LABEL = "font-mono text-[11px] uppercase tracking-[0.16em] text-text-faint";

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <p className={LABEL}>{label}</p>
      <div className="mt-1.5 text-[15px] font-medium">{children}</div>
    </div>
  );
}

function Ext({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 hover:text-accent">
      {children} <ArrowUpRight className="h-3.5 w-3.5" />
    </a>
  );
}

function Acceptance({ risk }: { risk: Risk }) {
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const submit = (accepted: boolean) =>
    start(async () => {
      const result = await setAcceptanceAction(risk.id, accepted, reason);
      setMessage(result.ok ? null : result.message);
    });
  if (risk.isAccepted) {
    return (
      <div className="rounded-xl border border-signal-live/30 bg-signal-live/[0.06] p-4 text-sm">
        <p className="font-medium text-signal-live">Accepted {risk.acceptedBy === "manual" ? "by hand" : "by an acceptance rule"}</p>
        <p className="mt-1 text-text-dim">{risk.acceptedReason ?? "No reason given."}</p>
        <Button size="sm" className="mt-3" disabled={pending} onClick={() => submit(false)}>{pending ? "Saving…" : "Un-accept"}</Button>
      </div>
    );
  }
  return (
    <div id={`accept-${risk.id}`} className="rounded-xl border border-border p-4">
      <label htmlFor={`reason-${risk.id}`} className="text-sm font-medium">Accept this risk</label>
      <p className="mt-0.5 text-xs text-text-dim">It stays listed but stops counting toward the health score.</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <input
          id={`reason-${risk.id}`}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Why is this acceptable?"
          className="min-w-64 flex-1 rounded-lg border border-border bg-control px-3 py-2 text-sm focus:border-accent/60 focus:outline-none"
        />
        <Button variant="primary" disabled={pending || !reason.trim()} onClick={() => submit(true)}>{pending ? "Saving…" : "Accept risk"}</Button>
      </div>
      {message && <p className="mt-2 text-xs text-signal-critical">{message}</p>}
    </div>
  );
}

function History({ risk }: { risk: Risk }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  useEffect(() => {
    let live = true;
    riskHistoryAction(risk.id).then((e) => live && setEntries(e));
    return () => {
      live = false;
    };
  }, [risk.id, risk.isAccepted]);
  const timeline = [
    { at: risk.firstDetectedAt, text: "First detected" },
    ...entries.map((e) => ({ at: e.at, text: e.action === "risk.accepted" ? `Accepted: ${String(e.details.reason ?? "")}` : e.action === "risk.unaccepted" ? "Un-accepted" : e.action })),
    ...(risk.closedAt ? [{ at: risk.closedAt, text: "No longer found (closed)" }] : []),
    { at: risk.lastDetectedAt, text: "Last detected" },
  ].sort((a, b) => b.at.localeCompare(a.at));
  return (
    <ol className="space-y-2 border-l border-border-soft pl-4">
      {timeline.map((item, i) => (
        <li key={`${item.at}-${i}`} className="relative text-sm">
          <span className={cx("absolute -left-[21px] top-1.5 h-2 w-2 rounded-full", i === 0 ? "bg-accent" : "bg-border-strong")} />
          {item.text} <span className="ml-2 text-xs text-text-faint">{timeAgo(item.at)}</span>
        </li>
      ))}
    </ol>
  );
}

function TableView({ risk, targetName }: { risk: Risk; targetName: string }) {
  const d = risk.definition;
  const extra = Object.entries(d.additionalInfo).filter(([k]) => !EVIDENCE_KEYS.has(k));
  const ev = readEvidence(d.additionalInfo);
  const rows: [string, string][] = [
    ["Title", d.title], ["Severity", d.threatLevel], ["Status", risk.status], ["Accepted", risk.isAccepted ? `yes (${risk.acceptedReason ?? ""})` : "no"],
    ["Scanner", SCAN_TYPE_LABEL[d.scanType]], ["Target", targetName], ["OWASP Top 10", ev.owasp ? `${ev.owasp.code} ${ev.owasp.name}` : ""],
    ["CWE", ev.cweId ?? ""], ["WASC", ev.wascId ?? ""], ["Confidence", ev.confidence ?? ""], ["CVSS", d.cvss ?? ""],
    ["First detected", risk.firstDetectedAt], ["Last detected", risk.lastDetectedAt], ["Closed", risk.closedAt ?? ""],
    ["Instances", String(ev.instances?.length ?? 0)], ...extra.map(([k, v]): [string, string] => [k, typeof v === "string" ? v : JSON.stringify(v)]),
  ];
  return (
    <table className="w-full text-sm">
      <tbody className="divide-y divide-border-soft">
        {rows.filter(([, v]) => v !== "").map(([k, v]) => (
          <tr key={k}><td className="w-44 py-2 pr-4 align-top text-text-faint">{k}</td><td className="break-all py-2 font-mono text-xs">{v}</td></tr>
        ))}
      </tbody>
    </table>
  );
}

export function RiskDetail({ risk, targetName }: { risk: Risk; targetName: string }) {
  const [view, setView] = useState<View>("formatted");
  const [tab, setTab] = useState<Tab>("instances");
  const d = risk.definition;
  const ev = readEvidence(d.additionalInfo);
  const instances = ev.instances ?? (typeof d.additionalInfo.host === "string" ? [{ uri: d.additionalInfo.host }] : []);

  return (
    <div className="min-w-0 space-y-6 px-6 py-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <h3 className="text-2xl font-semibold tracking-tight">{d.title}</h3>
        <div className={SEGMENT_FRAME} role="radiogroup" aria-label="View">
          {(["formatted", "table", "json"] as View[]).map((v) => (
            <button key={v} type="button" role="radio" aria-checked={view === v} className={segmentClass(view === v)} onClick={() => setView(v)}>
              {v === "json" ? "JSON" : v[0].toUpperCase() + v.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {view === "json" && (
        <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-all rounded-xl border border-border-soft bg-control p-4 font-mono text-[11px] text-text-dim">
          {JSON.stringify({ ...risk, target: targetName }, null, 2)}
        </pre>
      )}
      {view === "table" && <TableView risk={risk} targetName={targetName} />}
      {view === "formatted" && (
        <>
          <div className="grid gap-x-8 gap-y-5 sm:grid-cols-3 xl:grid-cols-6">
            <Meta label="Severity"><span className="flex items-center gap-2"><ThreatBars level={d.threatLevel} />{SEVERITY_TONE[d.threatLevel].label}</span></Meta>
            <Meta label="Status"><StatusPill risk={risk} /></Meta>
            <Meta label="Scan">{SCAN_TYPE_LABEL[d.scanType]}</Meta>
            {ev.owasp && <Meta label="OWASP Top 10"><Ext href={ev.owasp.url}>{ev.owasp.name}</Ext></Meta>}
            {ev.cweId && <Meta label="CWE ID"><Ext href={cweUrl(ev.cweId)}>{ev.cweId}</Ext></Meta>}
            {ev.wascId && <Meta label="WASC ID"><Ext href={wascUrl(ev.wascId)}>{ev.wascId}</Ext></Meta>}
            {ev.confidence && <Meta label="Confidence">{ev.confidence}</Meta>}
            {d.cvss && <Meta label="CVSS">{d.cvss}</Meta>}
            {ev.pluginId && <Meta label="ZAP rule"><Ext href={zapAlertUrl(ev.pluginId)}>{ev.pluginId}</Ext></Meta>}
          </div>
          <div className="grid gap-8 lg:grid-cols-2">
            <section>
              <h4 className="mb-2 text-lg font-semibold">Description</h4>
              <p className="text-sm leading-relaxed text-text-dim">{d.description || "No description."}</p>
            </section>
            <section>
              <h4 className="mb-2 text-lg font-semibold">Solution</h4>
              <p className="text-sm leading-relaxed text-text-dim">{d.solution || "No guidance recorded."}</p>
            </section>
          </div>
          {risk.status === "OPEN" && <Acceptance key={String(risk.isAccepted)} risk={risk} />}
          <div>
            <div role="tablist" className="mb-4 flex gap-5 border-b border-border-soft">
              {([["instances", `Instances (${instances.length})`], ["references", `References (${d.references.length})`], ["history", "History"]] as [Tab, string][]).map(([value, label]) => (
                <button key={value} type="button" role="tab" aria-selected={tab === value} onClick={() => setTab(value)}
                  className={cx("-mb-px border-b-2 pb-2 text-[15px] font-medium", tab === value ? "border-accent text-text" : "border-transparent text-text-faint hover:text-text")}>
                  {label}
                </button>
              ))}
            </div>
            {tab === "instances" && <RiskInstances instances={instances} />}
            {tab === "references" && (
              d.references.length === 0 ? <p className="text-sm text-text-faint">No references recorded.</p> : (
                <ul className="space-y-1.5 text-sm">
                  {d.references.map((ref) => <li key={ref}><Ext href={ref}><span className="break-all">{ref}</span></Ext></li>)}
                </ul>
              )
            )}
            {tab === "history" && <History risk={risk} />}
          </div>
        </>
      )}
    </div>
  );
}
