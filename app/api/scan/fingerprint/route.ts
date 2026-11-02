import { NextResponse } from "next/server";
import { authorizationGuard } from "@/lib/scans/route-guard";
import { fingerprint } from "@/lib/recon/fingerprint";
import { resolveIntensity } from "@/lib/recon/intensity";
import type { LiveHost } from "@/types/recon";

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

  const { hosts, activeAllowed, scanIntensity } = (body ?? {}) as {
    hosts?: unknown;
    activeAllowed?: unknown;
    scanIntensity?: unknown;
  };

  if (!Array.isArray(hosts)) {
    return NextResponse.json(
      { error: "Expected a 'hosts' array." },
      { status: 400 },
    );
  }

  // Server-side authorization: every requested host must be local, attested or verified.
  const denied = authorizationGuard(hosts as unknown[]);
  if (denied) return denied;

  try {
    const fingerprints = await fingerprint(
      hosts as LiveHost[],
      activeAllowed === true,
      resolveIntensity(scanIntensity),
    );
    return NextResponse.json(fingerprints);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Fingerprint failed.";
    const status = /not authorized/i.test(message) ? 403 : 502;
    return NextResponse.json({ error: message }, { status });
  }
}
