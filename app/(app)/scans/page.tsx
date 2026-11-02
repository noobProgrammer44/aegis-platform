import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { ScansView } from "@/components/scans/scans-view";
import { getDb } from "@/lib/db/client";
import { listScans } from "@/lib/db/repos/scans";
import { listScheduledScans } from "@/lib/db/repos/scheduled-scans";
import { listTargets } from "@/lib/db/repos/targets";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Scans" };

export default async function ScansPage({
  searchParams,
}: {
  searchParams: Promise<{ new?: string; target?: string; tab?: string }>;
}) {
  const params = await searchParams;
  // Older links (?new=1) open the New Scan wizard.
  if (params.new === "1") redirect(params.target ? `/scans/new?target=${encodeURIComponent(params.target)}` : "/scans/new");
  const db = getDb();
  const ws = currentWorkspaceId();
  return (
    <ScansView
      scans={listScans(db, ws, { limit: 100 })}
      schedules={listScheduledScans(db, ws)}
      targets={listTargets(db, ws)}
      tab={params.tab === "scheduled" ? "scheduled" : "scans"}
    />
  );
}
