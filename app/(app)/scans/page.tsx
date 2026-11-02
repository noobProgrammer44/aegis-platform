import type { Metadata } from "next";
import { ScansView } from "@/components/scans/scans-view";
import { getDb } from "@/lib/db/client";
import { listVerifiedAuthorizations } from "@/lib/db/repos/authorizations";
import { listScans } from "@/lib/db/repos/scans";
import { listTargets } from "@/lib/db/repos/targets";
import { ACTIVE_SCAN_MIN_TIER, targetAuthorization } from "@/lib/domain/authorization";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Scans" };

export default async function ScansPage({
  searchParams,
}: {
  searchParams: Promise<{ new?: string; target?: string }>;
}) {
  const params = await searchParams;
  const db = getDb();
  const ws = currentWorkspaceId();
  const targets = listTargets(db, ws);
  const preselected = targets.filter((t) => t.id === params.target).map((t) => t.id);
  const records = listVerifiedAuthorizations(db, ws);
  const authorizedIds = targets
    .filter((t) => targetAuthorization(t, records).tier >= ACTIVE_SCAN_MIN_TIER)
    .map((t) => t.id);
  return (
    <ScansView
      scans={listScans(db, ws, { limit: 100 })}
      targets={targets}
      openNew={params.new === "1"}
      preselected={preselected}
      authorizedIds={authorizedIds}
    />
  );
}
