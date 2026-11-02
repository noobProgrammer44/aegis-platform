import Link from "next/link";
import type { ReactNode } from "react";
import { Chip, SeverityDot } from "@/components/ui/badges";
import { Card } from "@/components/ui/card";
import { cx } from "@/lib/ui/cx";
import { SCAN_STATE_LABEL, SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import { targetName, type DashboardData } from "@/lib/services/dashboard";
import type { ScanState } from "@/types/aegis";

const STATE_TONE: Record<ScanState, string> = {
  QUEUED: "text-text-dim",
  RUNNING: "text-accent",
  SUCCEEDED: "text-signal-live",
  FAILED: "text-signal-critical",
  BLOCKED: "text-caution",
  STOPPING: "text-text-dim",
  STOPPED: "text-text-dim",
};

function Panel({
  title,
  href,
  linkLabel,
  empty,
  children,
  count,
}: {
  title: string;
  href: string;
  linkLabel: string;
  empty: string;
  children: ReactNode[];
  count?: number;
}) {
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          {title}
          {count !== undefined && <Chip tone="accent">{count}</Chip>}
        </span>
      }
      action={
        <Link href={href} className="text-xs text-accent hover:text-accent-hover">
          {linkLabel}
        </Link>
      }
      bodyClassName="p-0"
    >
      {children.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm text-text-faint">{empty}</p>
      ) : (
        <ul className="divide-y divide-border-soft">{children}</ul>
      )}
    </Card>
  );
}

export function RecentPanels({ data, now }: { data: DashboardData; now: Date }) {
  return (
    <div className="grid gap-5 xl:grid-cols-3">
      <Panel title="Recent scans" href="/scans" linkLabel="All scans" empty="No scans in this period.">
        {data.recentScans.map((scan) => (
          <li key={scan.id} className="px-5 py-3">
            <div className="flex items-center justify-between gap-3">
              <span className="truncate text-sm font-medium">{SCAN_TYPE_LABEL[scan.type]}</span>
              <span className={cx("shrink-0 text-xs", STATE_TONE[scan.state])}>
                {SCAN_STATE_LABEL[scan.state]}
              </span>
            </div>
            <div className="mt-0.5 flex items-center justify-between gap-3 text-xs text-text-faint">
              <span className="truncate font-mono">{scan.targets.join(", ") || "No targets"}</span>
              <span className="shrink-0">{timeAgo(scan.createdAt, now)}</span>
            </div>
          </li>
        ))}
      </Panel>

      <Panel title="Recent risks" href="/risks" linkLabel="All risks" empty="No new risks in this period.">
        {data.recentRisks.map((risk) => (
          <li key={risk.id} className="flex items-start gap-3 px-5 py-3">
            <span className="mt-1.5"><SeverityDot level={risk.definition.threatLevel} /></span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm">{risk.definition.title}</p>
              <p className="truncate text-xs text-text-faint">
                {SCAN_TYPE_LABEL[risk.definition.scanType]} · {targetName(data.targetsById.get(risk.targetId))}
              </p>
            </div>
          </li>
        ))}
      </Panel>

      <Panel
        title="Discovered domains"
        href="/targets?tab=discovered"
        linkLabel="See all targets"
        empty="Subdomain discovery hasn't found anything new."
        count={data.discoveredTotal}
      >
        {data.discovered.map((domain) => (
          <li key={domain.id} className="px-5 py-3">
            <p className="truncate font-mono text-sm">{domain.name}</p>
            <p className="truncate text-xs text-text-faint">
              {domain.viaTarget ? `via ${domain.viaTarget}` : "source unknown"} · seen{" "}
              {timeAgo(domain.lastSeen, now)}
            </p>
          </li>
        ))}
      </Panel>
    </div>
  );
}
