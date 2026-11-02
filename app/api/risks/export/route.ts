import { getDb } from "@/lib/db/client";
import { listRisks } from "@/lib/db/repos/risks";
import { listTargets } from "@/lib/db/repos/targets";
import { filterRisks, filtersFromParams, risksToCsv } from "@/lib/domain/risk-table";
import { currentWorkspaceId } from "@/lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** CSV of the risks matching the same filters as the Risks page URL. */
export async function GET(request: Request) {
  const params = Object.fromEntries(new URL(request.url).searchParams);
  const db = getDb();
  const ws = currentWorkspaceId();
  const targets = new Map(listTargets(db, ws).map((t) => [t.id, t] as const));
  const filters = { ...filtersFromParams(params), search: (params.q ?? "").slice(0, 200), tag: params.tag ?? null };
  const csv = risksToCsv(filterRisks(listRisks(db, ws), targets, filters), targets);
  const day = new Date().toISOString().slice(0, 10);
  return new Response(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="aegis-risks-${day}.csv"`,
      "X-Content-Type-Options": "nosniff",
    },
  });
}
