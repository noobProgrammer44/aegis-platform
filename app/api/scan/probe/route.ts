import { NextResponse } from "next/server";
import { authorizationGuard } from "@/lib/scans/route-guard";
import { probe } from "@/lib/recon/probe";
import { resolveIntensity } from "@/lib/recon/intensity";
import type { Subdomain } from "@/types/recon";

// Active probing opens real connections — needs the Node.js runtime.
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

  const { subdomains, activeAllowed, scanIntensity } = (body ?? {}) as {
    subdomains?: unknown;
    activeAllowed?: unknown;
    scanIntensity?: unknown;
  };

  if (!Array.isArray(subdomains)) {
    return NextResponse.json(
      { error: "Expected a 'subdomains' array." },
      { status: 400 },
    );
  }

  // Server-side authorization: every requested host must be local, attested or verified.
  const denied = authorizationGuard(subdomains as unknown[]);
  if (denied) return denied;

  try {
    const liveHosts = await probe(
      subdomains as Subdomain[],
      activeAllowed === true,
      resolveIntensity(scanIntensity),
    );
    return NextResponse.json(liveHosts);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Probe failed.";
    // Authorization guard rejection -> 403; anything else -> 502.
    const status = /not authorized/i.test(message) ? 403 : 502;
    return NextResponse.json({ error: message }, { status });
  }
}
