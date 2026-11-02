import type { ReactNode } from "react";
import { GradeBadge, SeverityBadge } from "@/components/ui/badges";
import { pluralize, SCAN_TYPE_LABEL } from "@/lib/ui/format";
import { targetName, type DashboardData } from "@/lib/services/dashboard";

function Insight({ label, children, empty }: { label: string; children: ReactNode; empty: boolean }) {
  return (
    <section className="rounded-xl border border-border bg-surface p-5">
      <h3 className="font-mono text-[11px] uppercase tracking-[0.14em] text-text-faint">{label}</h3>
      <div className="mt-3">
        {empty ? <p className="text-sm text-text-faint">Nothing to show yet.</p> : children}
      </div>
    </section>
  );
}

export function InsightCards({ data }: { data: DashboardData }) {
  const { mostVulnerable, mostCritical, mostFrequent } = data;
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <Insight label="Most vulnerable target" empty={!mostVulnerable}>
        {mostVulnerable && (
          <>
            <p className="truncate text-base font-medium">{targetName(mostVulnerable)}</p>
            <div className="mt-2 flex items-center gap-2">
              <GradeBadge grade={mostVulnerable.health.grade} withLabel />
              <span className="font-mono text-sm text-text-dim">{mostVulnerable.health.score} / 1000</span>
            </div>
          </>
        )}
      </Insight>

      <Insight label="Most critical vulnerability" empty={!mostCritical}>
        {mostCritical && (
          <>
            <p className="line-clamp-2 text-base font-medium">{mostCritical.risk.definition.title}</p>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-text-dim">
              <SeverityBadge level={mostCritical.risk.definition.threatLevel} />
              <span>open {pluralize(mostCritical.ageDays, "day")}</span>
              <span className="truncate text-text-faint">
                on {targetName(data.targetsById.get(mostCritical.risk.targetId))}
              </span>
            </div>
          </>
        )}
      </Insight>

      <Insight label="Most frequent vulnerability" empty={!mostFrequent}>
        {mostFrequent && (
          <>
            <p className="line-clamp-2 text-base font-medium">{mostFrequent.title}</p>
            <p className="mt-2 text-sm text-text-dim">
              {pluralize(mostFrequent.count, "encounter")} on {pluralize(mostFrequent.targetCount, "target")}
              <span className="text-text-faint"> · {SCAN_TYPE_LABEL[mostFrequent.scanType]}</span>
            </p>
          </>
        )}
      </Insight>
    </div>
  );
}
