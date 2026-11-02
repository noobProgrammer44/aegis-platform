import { Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { InsightCards } from "@/components/dashboard/insight-cards";
import { RecentPanels } from "@/components/dashboard/recent-panels";
import { HealthPanel, RisksPanel } from "@/components/dashboard/score-panels";
import { ButtonLink } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/card";
import { SegmentedLinks } from "@/components/ui/segmented";
import { getDb } from "@/lib/db/client";
import { parsePeriod, PERIODS } from "@/lib/domain/insights";
import { loadDashboard } from "@/lib/services/dashboard";
import { cx } from "@/lib/ui/cx";
import { pluralize } from "@/lib/ui/format";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Dashboard" };

export default async function DashboardPage({
  searchParams,
}: {
  searchParams: Promise<{ period?: string }>;
}) {
  const { period: rawPeriod } = await searchParams;
  const now = new Date();
  const data = loadDashboard(getDb(), currentWorkspaceId(), parsePeriod(rawPeriod), now);

  return (
    <div className="space-y-5 px-8 py-8">
      <PageHeader
        title="Dashboard"
        actions={
          <>
            <Link
              href="/scans"
              className="hidden h-9 items-center gap-2 rounded-full border border-border bg-surface/70 px-3.5 text-xs text-text-dim hover:text-text md:flex"
            >
              <span className="relative flex h-2 w-2">
                {data.scansInProgress > 0 && <span className="anim-ping absolute inset-0 rounded-full bg-accent" />}
                <span className={cx("relative h-2 w-2 rounded-full", data.scansInProgress > 0 ? "bg-accent" : "bg-signal-live")} />
              </span>
              <span className={data.scansInProgress > 0 ? "text-accent" : undefined}>
                {pluralize(data.scansInProgress, "scan")} in progress
              </span>
              <span className="mx-2 text-text-faint">|</span>
              {data.scheduledCount} scheduled
            </Link>
            <ButtonLink href="/scans?new=1" variant="primary">
              <Plus className="h-4 w-4" />
              New scan
            </ButtonLink>
          </>
        }
      />

      <div className="-mt-2">
        <SegmentedLinks
          label="Period"
          active={data.period}
          items={PERIODS.map((p) => ({ value: p.value, label: p.label, href: `/dashboard?period=${p.value}` }))}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <HealthPanel data={data} />
        <RisksPanel data={data} />
      </div>
      <RecentPanels data={data} now={now} />
      <InsightCards data={data} />
    </div>
  );
}
