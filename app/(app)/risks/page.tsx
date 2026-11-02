import type { Metadata } from "next";
import { RisksView } from "@/components/risks/risks-view";
import { getDb } from "@/lib/db/client";
import { listAcceptanceRules } from "@/lib/db/repos/acceptance-rules";
import { listRisks } from "@/lib/db/repos/risks";
import { listTargets } from "@/lib/db/repos/targets";
import { filtersFromParams } from "@/lib/domain/risk-table";
import { AVAILABLE_SCANNERS } from "@/lib/scans/catalog";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Risks" };

export default async function RisksPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;
  const db = getDb();
  const ws = currentWorkspaceId();
  const risks = listRisks(db, ws);
  // Scanners that can produce risks today, plus any type already present in the data.
  const scanTypes = [...new Set([...AVAILABLE_SCANNERS.map((s) => s.type), ...risks.map((r) => r.definition.scanType)])];
  return (
    <RisksView
      risks={risks}
      targets={listTargets(db, ws)}
      rules={listAcceptanceRules(db, ws)}
      scanTypes={scanTypes}
      initialFilters={filtersFromParams(params)}
    />
  );
}
