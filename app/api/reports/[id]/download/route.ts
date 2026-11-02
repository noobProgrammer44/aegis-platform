import { getDb } from "@/lib/db/client";
import { loadReport, snapshotToCsv } from "@/lib/services/reports";
import { currentWorkspaceId } from "@/lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Downloads a report's frozen data as JSON or its risks as CSV (?format=json|csv). */
export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const loaded = loadReport(getDb(), currentWorkspaceId(), id);
  if (!loaded) return Response.json({ error: "Report not found." }, { status: 404 });
  const format = new URL(request.url).searchParams.get("format") === "csv" ? "csv" : "json";
  const base = loaded.report.name.replace(/[^\w.-]+/g, "-").slice(0, 60) || "report";
  const body = format === "csv" ? snapshotToCsv(loaded.snapshot) : JSON.stringify(loaded.snapshot, null, 2);
  return new Response(body, {
    headers: {
      "Content-Type": format === "csv" ? "text/csv; charset=utf-8" : "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="${base}.${format}"`,
      "X-Content-Type-Options": "nosniff",
    },
  });
}
