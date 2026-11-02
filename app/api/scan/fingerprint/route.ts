import { NextResponse } from "next/server";
import { fingerprint } from "@/lib/recon/fingerprint";
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

  const { hosts, activeAllowed } = (body ?? {}) as {
    hosts?: unknown;
    activeAllowed?: unknown;
  };

  if (!Array.isArray(hosts)) {
    return NextResponse.json(
      { error: "Expected a 'hosts' array." },
      { status: 400 },
    );
  }

  try {
    const fingerprints = await fingerprint(hosts as LiveHost[], activeAllowed === true);
    return NextResponse.json(fingerprints);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Fingerprint failed.";
    const status = /not authorized/i.test(message) ? 403 : 502;
    return NextResponse.json({ error: message }, { status });
  }
}
