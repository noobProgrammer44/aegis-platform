import { NextResponse } from "next/server";
import { discover } from "@/lib/recon/discovery";

// dns + external fetch require the Node.js runtime (not Edge).
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

/** Accept a bare domain or a pasted URL; return a clean hostname or null. */
function normalizeDomain(input: unknown): string | null {
  if (typeof input !== "string") return null;
  let value = input.trim().toLowerCase();
  if (!value) return null;

  try {
    value = new URL(value.includes("://") ? value : `https://${value}`).hostname;
  } catch {
    return null;
  }

  const valid =
    /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(value);
  return valid ? value : null;
}

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const domain = normalizeDomain((body as { domain?: unknown })?.domain);
  if (!domain) {
    return NextResponse.json(
      { error: "Provide a valid domain, e.g. example.com." },
      { status: 400 },
    );
  }

  try {
    const subdomains = await discover(domain);
    return NextResponse.json(subdomains);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Discovery failed.";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
