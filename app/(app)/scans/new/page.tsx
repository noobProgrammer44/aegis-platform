import type { Metadata } from "next";
import { ScanWizard } from "@/components/scans/wizard/scan-wizard";
import { getDb } from "@/lib/db/client";
import { listVerifiedAuthorizations } from "@/lib/db/repos/authorizations";
import { listTargets } from "@/lib/db/repos/targets";
import { ACTIVE_SCAN_MIN_TIER, targetAuthorization } from "@/lib/domain/authorization";
import { unavailableScanners } from "@/lib/scans/availability";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "New scan" };

export default async function NewScanPage({ searchParams }: { searchParams: Promise<{ target?: string }> }) {
  const { target } = await searchParams;
  const db = getDb();
  const ws = currentWorkspaceId();
  const targets = listTargets(db, ws);
  const records = listVerifiedAuthorizations(db, ws);
  return (
    <ScanWizard
      targets={targets}
      authorizedIds={targets.filter((t) => targetAuthorization(t, records).tier >= ACTIVE_SCAN_MIN_TIER).map((t) => t.id)}
      unavailable={await unavailableScanners()}
      preselected={targets.some((t) => t.id === target) ? [target as string] : []}
    />
  );
}
