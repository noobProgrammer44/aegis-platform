"use client";

import { Plus, Radar, Square, Trash2 } from "lucide-react";
import Link from "next/link";
import { useCallback, useState, useTransition } from "react";
import { deleteScanAction, stopScanAction } from "@/app/(app)/scans/actions";
import { AutoRefresh } from "@/components/ui/auto-refresh";
import { Button } from "@/components/ui/button";
import { EmptyState, PageHeader } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { SCAN_STATE_LABEL, SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import type { Scan, Target } from "@/types/aegis";
import { NewScanModal } from "./new-scan-modal";
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
  targets,
  openNew,
  preselected,
  authorizedIds,
  unavailable,
}: {
  scans: Scan[];
  targets: Target[];
  openNew: boolean;
  preselected: string[];
  authorizedIds: string[];
  unavailable: Record<string, string>;
}) {
  const [creating, setCreating] = useState(openNew);
  const close = useCallback(() => setCreating(false), []);
  const anyLive = scans.some((s) => ACTIVE_STATES.includes(s.state));

  return (
    <div className="px-8 py-8">
      <AutoRefresh active={anyLive} />
      <PageHeader
        title="Scans"
        description="Every scan of your targets. Running scans update live; finished ones keep their raw results."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" /> New scan
          </Button>
        }
      />

      {scans.length === 0 ? (
        <EmptyState
          icon={<Radar className="h-6 w-6" />}
          title="No scans yet"
          description="Start a scan of one or more targets. Findings become risks you can track over time."
          action={<Button variant="primary" onClick={() => setCreating(true)}><Plus className="h-4 w-4" /> New scan</Button>}
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

      <NewScanModal open={creating} onClose={close} targets={targets} preselected={preselected} authorizedIds={authorizedIds} unavailable={unavailable} />
    </div>
  );
}
