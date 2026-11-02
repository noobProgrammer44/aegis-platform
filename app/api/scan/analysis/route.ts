import { NextResponse } from "next/server";
import { authorizationGuard } from "@/lib/scans/route-guard";
import { analyze } from "@/lib/recon/analysis";
import type { Fingerprint, LiveHost } from "@/types/recon";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const { liveHosts, fingerprints, activeAllowed } = (body ?? {}) as {
    liveHosts?: unknown;
    fingerprints?: unknown;
    activeAllowed?: unknown;
  };

  if (!Array.isArray(liveHosts) || !Array.isArray(fingerprints)) {
    return NextResponse.json(
      { error: "Expected 'liveHosts' and 'fingerprints' arrays." },
      { status: 400 },
    );
  }

  // Server-side authorization: every requested host must be local, attested or verified.
  const denied = authorizationGuard(liveHosts as unknown[]);
  if (denied) return denied;

  try {
    const findings = await analyze(
      liveHosts as LiveHost[],
      fingerprints as Fingerprint[],
      activeAllowed === true,
    );
    return NextResponse.json(findings);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Analysis failed.";
    const status = /not authorized/i.test(message) ? 403 : 502;
    return NextResponse.json({ error: message }, { status });
  }
}
