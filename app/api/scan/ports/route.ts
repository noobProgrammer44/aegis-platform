import { NextResponse } from "next/server";
import { authorizationGuard } from "@/lib/scans/route-guard";
import { scanPorts } from "@/lib/recon/ports";
import { resolveIntensity } from "@/lib/recon/intensity";
import type { LiveHost } from "@/types/recon";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 120;

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const { liveHosts, activeAllowed, scanIntensity } = (body ?? {}) as {
    liveHosts?: unknown;
    activeAllowed?: unknown;
    scanIntensity?: unknown;
  };

  if (!Array.isArray(liveHosts)) {
    return NextResponse.json({ error: "Expected a 'liveHosts' array." }, { status: 400 });
  }

  // Server-side authorization: every requested host must be local, attested or verified.
  const denied = authorizationGuard(liveHosts as unknown[]);
  if (denied) return denied;

  try {
    const result = await scanPorts(
      liveHosts as LiveHost[],
      activeAllowed === true,
      resolveIntensity(scanIntensity),
    );
    return NextResponse.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Port scan failed.";
    const status = /not authorized/i.test(message) ? 403 : 502;
    return NextResponse.json({ error: message }, { status });
  }
}
