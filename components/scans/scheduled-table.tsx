"use client";

import { Pause, Play, Trash2, Zap } from "lucide-react";
import Link from "next/link";
import { useState, useTransition } from "react";
import { deleteScheduleAction, runScheduleNowAction, toggleScheduleAction } from "@/app/(app)/scans/actions";
import { Chip } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { SCHEDULE_LABEL } from "@/lib/domain/schedule";
import { SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import type { ScheduledScan, Target } from "@/types/aegis";

const POLICY_LABEL = { NEVER: "Off", ON_CHANGES: "On changes", ALWAYS: "Always" } as const;

function targetsLabel(s: ScheduledScan, targets: Target[]): string {
  const { targetIds, tags } = s.targetsFilter;
  if (targetIds.length === 0 && tags.length === 0) return "All targets";
  if (tags.length > 0) return `Tagged ${tags.join(", ")}`;
  const names = targets.filter((t) => targetIds.includes(t.id)).map((t) => t.label || t.target);
  return names.length > 2 ? `${names.slice(0, 2).join(", ")} +${names.length - 2}` : names.join(", ") || "Deleted targets";
}

function Actions({ schedule }: { schedule: ScheduledScan }) {
  const [pending, start] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  const run = (action: () => Promise<{ ok: boolean; message: string }>) =>
    start(async () => {
      const result = await action();
      setMessage(result.message);
    });
  return (
    <span className="flex items-center justify-end gap-1">
      {message && <span className="mr-2 text-xs text-text-dim">{message}</span>}
      <Button size="sm" variant="ghost" disabled={pending} onClick={() => run(() => runScheduleNowAction(schedule.id))}><Zap className="h-3.5 w-3.5" /> Run now</Button>
      <Button size="sm" variant="ghost" disabled={pending} aria-label={schedule.enabled ? "Pause schedule" : "Resume schedule"} onClick={() => run(() => toggleScheduleAction(schedule.id, !schedule.enabled))}>
        {schedule.enabled ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
      </Button>
      <Button size="sm" variant="ghost" disabled={pending} aria-label="Delete schedule" onClick={() => run(() => deleteScheduleAction(schedule.id))}><Trash2 className="h-3.5 w-3.5" /></Button>
    </span>
  );
}

export function ScheduledTable({ schedules, targets }: { schedules: ScheduledScan[]; targets: Target[] }) {
  if (schedules.length === 0) {
    return (
      <EmptyState
        title="No scheduled scans"
        description="Choose Daily, Weekly, Monthly or a custom interval in the New Scan wizard to scan your targets automatically."
        action={<Link href="/scans/new" className="text-sm text-accent hover:text-accent-hover">New scan</Link>}
      />
    );
  }
  return (
    <Table>
      <THead>
        <tr>
          <TH>Name</TH><TH>Targets</TH><TH>Schedule</TH><TH>Scan types</TH><TH>Last run</TH><TH>Next run</TH><TH>Email</TH><TH><span className="sr-only">Actions</span></TH>
        </tr>
      </THead>
      <TBody>
        {schedules.map((s) => (
          <TR key={s.id}>
            <TD className="font-medium">{s.name}{!s.enabled && <span className="ml-2 text-xs font-normal text-text-faint">(paused)</span>}</TD>
            <TD><Chip>{targetsLabel(s, targets)}</Chip></TD>
            <TD>{SCHEDULE_LABEL[s.schedule]}{s.schedule === "CUSTOM" && s.intervalDays ? ` (${s.intervalDays} days)` : ""}</TD>
            <TD className="text-text-dim" title={s.scanTypes.map((t) => SCAN_TYPE_LABEL[t]).join(", ")}>{s.scanTypes.length} scan type{s.scanTypes.length === 1 ? "" : "s"}</TD>
            <TD className="whitespace-nowrap text-text-dim">{s.lastRan ? timeAgo(s.lastRan) : "-"}</TD>
            <TD className="whitespace-nowrap text-text-dim">{s.enabled && s.nextRun ? timeAgo(s.nextRun) : "-"}</TD>
            <TD className="text-text-dim">{POLICY_LABEL[s.notifyPolicy]}{s.notifyEmails.length > 0 ? `: ${s.notifyEmails.length}` : ""}</TD>
            <TD><Actions schedule={s} /></TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}
