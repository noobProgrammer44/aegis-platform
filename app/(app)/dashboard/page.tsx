import { Radar, Zap } from "lucide-react";
import type { Metadata } from "next";
import { ButtonLink } from "@/components/ui/button";
import { Card, EmptyState, PageHeader } from "@/components/ui/card";
import { HealthGauge } from "@/components/ui/gauge";
import { SeverityTile, StatBar } from "@/components/ui/tiles";
import { getDb } from "@/lib/db/client";
import { listRisks } from "@/lib/db/repos/risks";
import { countScoredRisks, healthFromRisks } from "@/lib/domain/health-score";
import { currentWorkspaceId } from "@/lib/workspace";
import { THREAT_LEVELS } from "@/types/aegis";

export const metadata: Metadata = { title: "Dashboard" };

export default function DashboardPage() {
  const risks = listRisks(getDb(), currentWorkspaceId());
  const counts = countScoredRisks(risks);
  const health = healthFromRisks(risks);
  const accepted = risks.filter((r) => r.status === "OPEN" && r.isAccepted).length;
  const closed = risks.filter((r) => r.status === "CLOSED").length;
  const openTotal = THREAT_LEVELS.reduce((sum, level) => sum + counts[level], 0);

  return (
    <div className="px-8 py-8">
      <PageHeader
        title="Dashboard"
        description="Health of your external attack surface across every target you track."
        actions={
          <ButtonLink href="/quick-scan" variant="primary">
            <Zap className="h-4 w-4" />
            Quick scan
          </ButtonLink>
        }
      />

      <div className="grid gap-5 lg:grid-cols-[minmax(280px,1fr)_2fr]">
        <Card title="Health score">
          <HealthGauge score={health.score} grade={health.grade} />
          <p className="mt-4 text-center text-xs leading-relaxed text-text-faint">
            0 is best, 1000 is worst. Only open risks you haven&apos;t accepted count.
          </p>
        </Card>

        <Card title={<>Risks detected <span className="ml-1 font-normal text-text-faint">Total {openTotal}</span></>}>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {THREAT_LEVELS.map((level) => (
              <SeverityTile key={level} level={level} count={counts[level]} />
            ))}
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <StatBar label="Accepted" count={accepted} tone="accepted" />
            <StatBar label="Closed" count={closed} tone="closed" />
          </div>
        </Card>
      </div>

      {risks.length === 0 && (
        <div className="mt-5">
          <EmptyState
            icon={<Radar className="h-6 w-6" />}
            title="Nothing scanned yet"
            description="Risks appear here once scans of your targets finish. Run a quick scan against a host you own to see what Aegis finds."
            action={
              <ButtonLink href="/quick-scan" variant="secondary">
                Open quick scan
              </ButtonLink>
            }
          />
        </div>
      )}
    </div>
  );
}
