import { getDb } from "@/lib/db/client";
import { getScanResultContent } from "@/lib/db/repos/scan-results";
import { currentWorkspaceId } from "@/lib/workspace";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Downloads one raw result file of a scan (workspace-scoped). */
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string; fileId: string }> },
) {
  const { id, fileId } = await params;
  const result = getScanResultContent(getDb(), currentWorkspaceId(), fileId);
  if (!result || result.file.scanId !== id) {
    return Response.json({ error: "Result file not found." }, { status: 404 });
  }
  const safeName = result.file.filename.replace(/[^\w.-]/g, "_");
  return new Response(new Uint8Array(result.content), {
    headers: {
      "Content-Type": result.file.contentType,
      "Content-Disposition": `attachment; filename="${id}-${safeName}"`,
      "X-Content-Type-Options": "nosniff",
    },
  });
}
