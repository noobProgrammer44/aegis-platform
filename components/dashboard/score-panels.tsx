import { TrendingDown, TrendingUp } from "lucide-react";
import Link from "next/link";
import { SeverityDot } from "@/components/ui/badges";
import { Card } from "@/components/ui/card";
import { HealthGauge } from "@/components/ui/gauge";
import { SeverityTile, StatBar } from "@/components/ui/tiles";
import { pluralize, SCAN_TYPE_LABEL } from "@/lib/ui/format";
import type { DashboardData } from "@/lib/services/dashboard";
import { THREAT_LEVELS } from "@/types/aegis";

function Trend({ trend }: { trend: DashboardData["trend"] }) {
  if (!trend) {
    return <p className="text-sm text-text-faint">No history yet. The trend appears after a month of scans.</p>;
  }
  if (trend.delta === 0) {
    return <p className="text-sm text-text-dim">Unchanged since {trend.previousDay}.</p>;
  }
  const better = trend.delta < 0;
  const Icon = better ? TrendingDown : TrendingUp;
  return (
    <p className={better ? "flex items-center gap-1.5 text-sm text-signal-live" : "flex items-center gap-1.5 text-sm text-signal-high"}>
      <Icon className="h-4 w-4" />
      {better ? "Improved" : "Worse"} by {Math.abs(trend.delta)} points since {trend.previousDay}
    </p>
  );
}

export function HealthPanel({ data }: { data: DashboardData }) {
  return (
    <Card title="Health score">
      <div className="grid gap-6 sm:grid-cols-[minmax(200px,240px)_1fr]">
        <HealthGauge score={data.health.score} grade={data.health.grade} />
        <div className="min-w-0 space-y-4">
          <div>
            <h3 className="mb-1.5 font-mono text-[11px] uppercase tracking-[0.14em] text-text-faint">
              About your score
            </h3>
            <Trend trend={data.trend} />
          </div>
          <div>
            <h3 className="mb-2 font-mono text-[11px] uppercase tracking-[0.14em] text-text-faint">
              Top issues dragging it down
            </h3>
            {data.topIssues.length === 0 ? (
              <p className="text-sm text-text-faint">No open risks. Nice.</p>
            ) : (
              <ol className="space-y-2">
                {data.topIssues.map((issue) => (
                  <li key={`${issue.scanType}-${issue.title}`} className="flex items-start gap-2.5 text-sm">
                    <span className="mt-1.5"><SeverityDot level={issue.threatLevel} /></span>
                    <span className="min-w-0">
                      <span className="block truncate">{issue.title}</span>
                      <span className="text-xs text-text-faint">
                        {SCAN_TYPE_LABEL[issue.scanType]} · {pluralize(issue.targetCount, "target")}
                      </span>
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </div>
          <Link href="/help" className="inline-block text-xs text-accent hover:text-accent-hover">
            How the score works
          </Link>
        </div>
      </div>
    </Card>
  );
}

export function RisksPanel({ data }: { data: DashboardData }) {
  return (
    <Card
      title={
        <>
          Risks detected <span className="ml-1 font-normal text-text-faint">Total {data.openTotal}</span>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {THREAT_LEVELS.map((level) => (
          <SeverityTile key={level} level={level} count={data.counts[level]} href={`/risks?level=${level}`} />
        ))}
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <StatBar label="Accepted" count={data.accepted} tone="accepted" href="/risks?accepted=1" />
        <StatBar label="Closed" count={data.closedInPeriod} tone="closed" href="/risks?status=CLOSED" />
      </div>
    </Card>
  );
}
