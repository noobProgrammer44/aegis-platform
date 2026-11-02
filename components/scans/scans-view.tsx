"use client";

import { Plus, Radar, Square, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState, useTransition } from "react";
import { deleteScanAction, stopScanAction } from "@/app/(app)/scans/actions";
import { AutoRefresh } from "@/components/ui/auto-refresh";
import { Button, ButtonLink } from "@/components/ui/button";
import { EmptyState, PageHeader } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { SCAN_STATE_LABEL, SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import { cx } from "@/lib/ui/cx";
import type { Scan, ScheduledScan, Target } from "@/types/aegis";
import { ScheduledTable } from "./scheduled-table";
import { ScanStateBadge } from "./scan-state";

const ACTIVE_STATES = ["QUEUED", "RUNNING", "STOPPING"];

function RowActions({ scan }: { scan: Scan }) {
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const run = (action: (id: string) => Promise<{ ok: boolean; message: string }>) =>
    start(async () => {
      const result = await action(scan.id);
      setError(result.ok ? null : result.message);
    });
  const live = ACTIVE_STATES.includes(scan.state);
  return (
    <span className="flex items-center justify-end gap-1">
      {error && <span className="mr-2 text-xs text-signal-critical">{error}</span>}
      {live ? (
        <Button size="sm" variant="ghost" disabled={pending || scan.state === "STOPPING"} onClick={() => run(stopScanAction)}>
          <Square className="h-3.5 w-3.5" /> Stop
        </Button>
      ) : (
        <Button size="sm" variant="ghost" aria-label="Delete scan" disabled={pending} onClick={() => run(deleteScanAction)}>
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      )}
    </span>
  );
}

export function ScansView({
  scans,
  schedules,
  targets,
  tab,
}: {
  scans: Scan[];
  schedules: ScheduledScan[];
  targets: Target[];
  tab: "scans" | "scheduled";
}) {
  const anyLive = scans.some((s) => ACTIVE_STATES.includes(s.state));
  const tabs = [["scans", "Scans", "/scans"], ["scheduled", `Scheduled Scans (${schedules.length})`, "/scans?tab=scheduled"]] as const;

  return (
    <div className="px-8 py-8">
      <AutoRefresh active={anyLive} />
      <PageHeader
        title="Scans"
        description="Every scan of your targets. Running scans update live; finished ones keep their raw results."
        actions={
          <ButtonLink href="/scans/new" variant="primary">
            <Plus className="h-4 w-4" /> New scan
          </ButtonLink>
        }
      />

      <nav className="mb-5 flex gap-1 border-b border-border-soft" aria-label="Scan views">
        {tabs.map(([value, label, href]) => (
          <Link key={value} href={href} aria-current={tab === value ? "page" : undefined}
            className={cx("-mb-px border-b-2 px-3 py-2 text-sm", tab === value ? "border-accent text-text" : "border-transparent text-text-faint hover:text-text")}>
            {label}
          </Link>
        ))}
      </nav>

      {tab === "scheduled" ? (
        <ScheduledTable schedules={schedules} targets={targets} />
      ) : scans.length === 0 ? (
        <EmptyState
          icon={<Radar className="h-6 w-6" />}
          title="No scans yet"
          description="Start a scan of one or more targets. Findings become risks you can track over time."
          action={<ButtonLink href="/scans/new" variant="primary"><Plus className="h-4 w-4" /> New scan</ButtonLink>}
        />
      ) : (
        <Table>
          <THead>
            <tr>
              <TH>Scan</TH>
              <TH>Targets</TH>
              <TH>State</TH>
              <TH>New</TH>
              <TH>Open</TH>
              <TH>Closed</TH>
              <TH>Started</TH>
              <TH className="text-right">Actions</TH>
            </tr>
          </THead>
          <TBody>
            {scans.map((scan) => (
              <TR key={scan.id}>
                <TD>
                  <Link href={`/scans/${scan.id}`} className="font-medium hover:text-accent">
                    {SCAN_TYPE_LABEL[scan.type]}
                  </Link>
                  {scan.scheduledBy && <span className="block text-xs text-text-faint">Scheduled</span>}
                </TD>
                <TD className="max-w-64 truncate font-mono text-xs text-text-dim" title={scan.targets.join(", ")}>
                  {scan.targets.join(", ")}
                </TD>
                <TD><ScanStateBadge scan={scan} /></TD>
                <TD className="font-mono tabular-nums">{scan.risks.newOpen}</TD>
                <TD className="font-mono tabular-nums">{scan.risks.stillOpen}</TD>
                <TD className="font-mono tabular-nums">{scan.risks.closed}</TD>
                <TD className="whitespace-nowrap text-text-dim" title={SCAN_STATE_LABEL[scan.state]}>
                  {timeAgo(scan.startedAt ?? scan.createdAt)}
                </TD>
                <TD><RowActions scan={scan} /></TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

    </div>
  );
}
