import { NextResponse } from "next/server";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { buildMarkdownReport } from "@/lib/report/markdown";
import type { ScanResult } from "@/types/recon";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const SCANS_DIR = path.join(process.cwd(), "scans");

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const scan = (body as { scanResult?: ScanResult })?.scanResult;
  if (!scan || typeof scan !== "object" || typeof scan.target !== "string") {
    return NextResponse.json(
      { error: "Expected a 'scanResult' object." },
      { status: 400 },
    );
  }

  const markdown = buildMarkdownReport(scan);

  // Persist the full scan as JSON. If writing fails (e.g. read-only FS), still
  // return the Markdown so the download works.
  let savedAs: string | null = null;
  try {
    await mkdir(SCANS_DIR, { recursive: true });
    const safeTarget =
      scan.target.replace(/[^a-z0-9.-]/gi, "_").slice(0, 60) || "scan";
    const stamp = (scan.endedAt || new Date().toISOString()).replace(/[:.]/g, "-");
    const fileName = `${safeTarget}-${stamp}.json`;
    await writeFile(
      path.join(SCANS_DIR, fileName),
      JSON.stringify(scan, null, 2),
      "utf8",
    );
    savedAs = `scans/${fileName}`;
  } catch (err) {
    console.error("[report] failed to persist scan JSON:", err);
  }

  return NextResponse.json({ markdown, savedAs });
}
