"use client";

import { FileText, Radar, Trash2 } from "lucide-react";
import { useActionState, useState, useTransition } from "react";
import { deleteTargetAction, updateTargetAction } from "@/app/(app)/targets/actions";
import { INITIAL_RESULT } from "@/lib/actions/result";
import { Chip, SeverityDot } from "@/components/ui/badges";
import { Button, ButtonLink } from "@/components/ui/button";
import { HealthGauge } from "@/components/ui/gauge";
import { Drawer } from "@/components/ui/overlays";
import type { TargetRow } from "@/lib/domain/target-table";
import type { TargetAuthView, TargetDetail } from "@/lib/services/targets";
import { AuthorizationPanel } from "./authorization-panel";
import { cx } from "@/lib/ui/cx";
import { SCAN_STATE_LABEL, SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import { SEVERITY_TONE } from "@/lib/ui/severity";
import { THREAT_LEVELS } from "@/types/aegis";

type Tab = "risks" | "scans" | "metadata";
const TABS: readonly [Tab, string][] = [
  ["risks", "Risks"],
  ["scans", "Recent scans"],
  ["metadata", "Metadata"],
];

function StatStrip({ row }: { row: TargetRow }) {
  const stats = [
    { label: "Open risks", value: row.openTotal, className: "text-text" },
    ...THREAT_LEVELS.map((level) => ({
      label: SEVERITY_TONE[level].label,
      value: row.counts[level],
      className: SEVERITY_TONE[level].text,
    })),
    { label: "No longer found", value: row.closedTotal, className: "text-signal-closed" },
  ];
  return (
    <dl className="grid grid-cols-3 gap-px overflow-hidden rounded-lg border border-border bg-border">
      {stats.map((s) => (
        <div key={s.label} className="bg-surface px-3 py-2.5">
          <dt className="text-[11px] text-text-faint">{s.label}</dt>
          <dd className={cx("font-mono text-lg font-semibold tabular-nums", s.className)}>{s.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function RisksTab({ detail }: { detail: TargetDetail }) {
  const [showClosed, setShowClosed] = useState(false);
  const risks = detail.risks.filter((r) => showClosed || r.status === "OPEN");
  return (
    <div>
      <label className="mb-3 flex items-center gap-2 text-xs text-text-dim">
        <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} />
        Include risks that are no longer found
      </label>
      {risks.length === 0 ? (
        <p className="py-6 text-center text-sm text-text-faint">No risks on this target.</p>
      ) : (
        <ul className="divide-y divide-border-soft rounded-lg border border-border">
          {risks.map((risk) => (
            <li key={risk.id} className="flex items-start gap-3 px-4 py-3">
              <span className="mt-1.5"><SeverityDot level={risk.threatLevel} /></span>
              <div className="min-w-0 flex-1">
                <p className={cx("text-sm", risk.status === "CLOSED" && "text-text-faint line-through")}>
                  {risk.title}
                </p>
                <p className="text-xs text-text-faint">
                  {SCAN_TYPE_LABEL[risk.scanType]} · first seen {timeAgo(risk.firstDetectedAt)} · last seen{" "}
                  {timeAgo(risk.lastDetectedAt)}
                </p>
              </div>
              {risk.isAccepted && <Chip>Accepted</Chip>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ScansTab({ detail }: { detail: TargetDetail }) {
  if (detail.scans.length === 0) {
    return <p className="py-6 text-center text-sm text-text-faint">This target hasn&apos;t been scanned yet.</p>;
  }
  return (
    <ul className="divide-y divide-border-soft rounded-lg border border-border">
      {detail.scans.map((scan) => (
        <li key={scan.id} className="flex items-center justify-between gap-3 px-4 py-3 text-sm">
          <span>{SCAN_TYPE_LABEL[scan.type]}</span>
          <span className="text-xs text-text-faint">
            {SCAN_STATE_LABEL[scan.state]} · {timeAgo(scan.createdAt)}
          </span>
        </li>
      ))}
    </ul>
  );
}

function MetadataTab({ row }: { row: TargetRow }) {
  const [result, formAction, pending] = useActionState(updateTargetAction, INITIAL_RESULT);
  const field = "w-full rounded-lg border border-border bg-control px-3 py-2 text-sm focus:border-accent/60 focus:outline-none";
  const t = row.target;
  return (
    <form action={formAction} className="space-y-4">
      <input type="hidden" name="id" value={t.id} />
      <dl className="grid grid-cols-[120px_1fr] gap-y-2 text-sm">
        <dt className="text-text-faint">Target</dt><dd className="font-mono">{t.target}</dd>
        <dt className="text-text-faint">Type</dt><dd>{t.kind}</dd>
        <dt className="text-text-faint">Source</dt><dd>{t.source}</dd>
        <dt className="text-text-faint">Added</dt><dd>{new Date(t.createdAt).toLocaleString()}</dd>
      </dl>
      <label className="block text-sm">
        <span className="mb-1.5 block font-medium">Label</span>
        <input name="label" defaultValue={t.label} className={field} />
      </label>
      <label className="block text-sm">
        <span className="mb-1.5 block font-medium">Tags</span>
        <input name="tags" defaultValue={t.tags.join(", ")} className={field} />
      </label>
      <div className="flex items-center gap-3">
        <Button type="submit" variant="secondary" size="sm" disabled={pending}>
          {pending ? "Saving…" : "Save changes"}
        </Button>
        {result.message && (
          <span className={cx("text-xs", result.ok ? "text-signal-live" : "text-signal-critical")}>{result.message}</span>
        )}
      </div>
    </form>
  );
}

export function TargetDrawer({
  row,
  detail,
  auth,
  onClose,
}: {
  row: TargetRow | null;
  detail: TargetDetail | undefined;
  auth: TargetAuthView | undefined;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>("risks");
  const [confirming, setConfirming] = useState(false);
  const [deleting, startDelete] = useTransition();
  if (!row) return null;
  const t = row.target;
  const remove = () =>
    startDelete(async () => {
      const result = await deleteTargetAction(t.id);
      if (result.ok) onClose();
    });

  return (
    <Drawer
      open
      onClose={onClose}
      title={
        <div className="min-w-0">
          <p className="truncate">{t.label || t.target}</p>
          {t.label && <p className="truncate font-mono text-xs font-normal text-text-faint">{t.target}</p>}
        </div>
      }
    >
      <div className="flex flex-wrap gap-2">
        <ButtonLink href={`/scans?new=1&target=${t.id}`} variant="primary" size="sm">
          <Radar className="h-3.5 w-3.5" /> Scan this target again
        </ButtonLink>
        <ButtonLink href={`/reports?target=${t.id}`} size="sm">
          <FileText className="h-3.5 w-3.5" /> Generate report
        </ButtonLink>
        {confirming ? (
          <span className="flex items-center gap-2 text-xs text-text-dim">
            Delete with all its risks?
            <Button variant="danger" size="sm" onClick={remove} disabled={deleting}>
              {deleting ? "Deleting…" : "Delete"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>Cancel</Button>
          </span>
        ) : (
          <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </Button>
        )}
      </div>

      {auth && (
        <div className="mt-5">
          <AuthorizationPanel key={`${t.id}-${auth.tier}-${auth.pendingDnsValue ?? ""}`} targetId={t.id} auth={auth} />
        </div>
      )}

      <div className="mt-5 grid items-center gap-5 sm:grid-cols-[200px_1fr]">
        <HealthGauge score={t.health.score} grade={t.health.grade} />
        <StatStrip row={row} />
      </div>

      <div role="tablist" className="mt-6 flex gap-1 border-b border-border-soft">
        {TABS.map(([value, label]) => (
          <button
            key={value}
            role="tab"
            aria-selected={tab === value}
            onClick={() => setTab(value)}
            className={cx(
              "-mb-px border-b-2 px-3 py-2 text-sm",
              tab === value ? "border-accent text-text" : "border-transparent text-text-faint hover:text-text",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="pt-4">
        {tab === "risks" && detail && <RisksTab detail={detail} />}
        {tab === "scans" && detail && <ScansTab detail={detail} />}
        {tab === "metadata" && <MetadataTab key={t.id} row={row} />}
      </div>
    </Drawer>
  );
}
