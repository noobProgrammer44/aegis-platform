"use client";

import { useEffect, useState, useTransition } from "react";
import { riskHistoryAction, setAcceptanceAction } from "@/app/(app)/risks/actions";
import { Chip, SeverityBadge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/overlays";
import { cx } from "@/lib/ui/cx";
import { SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import type { AuditEntry, Risk } from "@/types/aegis";

const LABEL = "mb-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-text-faint";

const stamp = (iso: string) => new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });

function Evidence({ info }: { info: Record<string, unknown> }) {
  const entries = Object.entries(info).filter(([, v]) => v !== null && v !== undefined && v !== "");
  if (entries.length === 0) return <p className="text-sm text-text-faint">No extra evidence recorded.</p>;
  return (
    <dl className="grid grid-cols-[110px_1fr] gap-y-1.5 text-sm">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="capitalize text-text-faint">{key}</dt>
          <dd className="break-all font-mono text-xs">{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function Acceptance({ risk, onDone }: { risk: Risk; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [pending, start] = useTransition();
  const submit = (accepted: boolean) =>
    start(async () => {
      const result = await setAcceptanceAction(risk.id, accepted, reason);
      setMessage(result.message);
      if (result.ok) onDone();
    });

  if (risk.isAccepted) {
    return (
      <div className="rounded-lg border border-signal-live/30 bg-signal-live/[0.06] p-4 text-sm">
        <p className="font-medium text-signal-live">Accepted</p>
        <p className="mt-1 text-text-dim">{risk.acceptedReason ?? "No reason given."}</p>
        <p className="mt-1 text-xs text-text-faint">
          {risk.acceptedBy === "manual" ? "Accepted by hand" : "Accepted by an acceptance rule"}
        </p>
        <Button size="sm" className="mt-3" disabled={pending} onClick={() => submit(false)}>
          {pending ? "Saving…" : "Un-accept"}
        </Button>
        {message && <p className="mt-2 text-xs text-text-dim">{message}</p>}
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-border p-4">
      <label htmlFor="accept-reason" className="text-sm font-medium">Accept this risk</label>
      <p className="mt-0.5 text-xs text-text-dim">
        It stays listed but stops counting toward the health score. Use for expected behaviour,
        false positives or low priority items.
      </p>
      <textarea
        id="accept-reason"
        rows={2}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Why is this acceptable?"
        className="mt-3 w-full rounded-lg border border-border bg-control px-3 py-2 text-sm focus:border-accent/60 focus:outline-none"
      />
      <div className="mt-2 flex items-center gap-3">
        <Button size="sm" variant="primary" disabled={pending || !reason.trim()} onClick={() => submit(true)}>
          {pending ? "Saving…" : "Accept risk"}
        </Button>
        {message && <span className="text-xs text-signal-critical">{message}</span>}
      </div>
    </div>
  );
}

export function RiskDrawer({ risk, targetName, onClose }: { risk: Risk | null; targetName: string; onClose: () => void }) {
  const [history, setHistory] = useState<AuditEntry[]>([]);
  useEffect(() => {
    if (!risk) return;
    let live = true;
    riskHistoryAction(risk.id).then((entries) => live && setHistory(entries));
    return () => {
      live = false;
    };
  }, [risk]);
  if (!risk) return null;
  const d = risk.definition;

  const timeline = [
    { at: risk.firstDetectedAt, text: "First detected" },
    ...history.map((e) => ({ at: e.at, text: e.action === "risk.accepted" ? `Accepted: ${String(e.details.reason ?? "")}` : e.action === "risk.unaccepted" ? "Un-accepted" : e.action })),
    ...(risk.closedAt ? [{ at: risk.closedAt, text: "No longer found (closed)" }] : []),
    { at: risk.lastDetectedAt, text: risk.status === "OPEN" ? "Last detected" : "Last seen before closing" },
  ].sort((a, b) => b.at.localeCompare(a.at));

  return (
    <Drawer
      open
      onClose={onClose}
      title={
        <div className="min-w-0">
          <p className="truncate">{d.title}</p>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-xs font-normal text-text-faint">
            <SeverityBadge level={d.threatLevel} />
            <Chip>{risk.status === "OPEN" ? "Open" : "Closed"}</Chip>
            {SCAN_TYPE_LABEL[d.scanType]} · {targetName}
          </p>
        </div>
      }
    >
      <div className="space-y-6">
        <section>
          <h3 className={LABEL}>Description</h3>
          <p className="text-sm leading-relaxed text-text-dim">{d.description || "No description."}</p>
        </section>
        <section>
          <h3 className={LABEL}>Solution</h3>
          <p className="text-sm leading-relaxed text-text-dim">{d.solution || "No guidance recorded."}</p>
        </section>
        {(d.cvss || d.references.length > 0) && (
          <section>
            <h3 className={LABEL}>References</h3>
            {d.cvss && <p className="mb-1.5 text-sm">CVSS <span className="font-mono">{d.cvss}</span></p>}
            <ul className="space-y-1 text-sm">
              {d.references.map((ref) => (
                <li key={ref}>
                  <a href={ref} target="_blank" rel="noopener noreferrer" className="break-all text-accent hover:text-accent-hover">{ref}</a>
                </li>
              ))}
            </ul>
          </section>
        )}
        <section>
          <h3 className={LABEL}>Evidence</h3>
          <Evidence info={d.additionalInfo} />
        </section>
        {risk.status === "OPEN" && <Acceptance key={`${risk.id}-${risk.isAccepted}`} risk={risk} onDone={() => riskHistoryAction(risk.id).then(setHistory)} />}
        <section>
          <h3 className={LABEL}>History</h3>
          <ol className="space-y-2 border-l border-border-soft pl-4">
            {timeline.map((item, i) => (
              <li key={`${item.at}-${i}`} className="relative text-sm">
                <span className={cx("absolute -left-[21px] top-1.5 h-2 w-2 rounded-full", i === 0 ? "bg-accent" : "bg-border-strong")} />
                <span>{item.text}</span>
                <span className="ml-2 text-xs text-text-faint" title={stamp(item.at)}>{timeAgo(item.at)}</span>
              </li>
            ))}
          </ol>
        </section>
      </div>
    </Drawer>
  );
}
