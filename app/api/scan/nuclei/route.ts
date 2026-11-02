import { runNucleiStream } from "@/lib/recon/nuclei";
import { resolveIntensity } from "@/lib/recon/intensity";
import type { LiveHost, NucleiEvent } from "@/types/recon";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 600; // first run downloads templates; real hosts take minutes

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const { liveHosts, activeAllowed, deepCve, scanIntensity } = (body ?? {}) as {
    liveHosts?: unknown;
    activeAllowed?: unknown;
    deepCve?: unknown;
    scanIntensity?: unknown;
  };

  if (!Array.isArray(liveHosts)) {
    return Response.json({ error: "Expected a 'liveHosts' array." }, { status: 400 });
  }
  // Authorization guard is a hard rejection (not graceful) — reject before streaming.
  if (activeAllowed !== true) {
    return Response.json(
      {
        error:
          "Active scanning is not authorized. Enable 'Active scan' before running nuclei.",
      },
      { status: 403 },
    );
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: NucleiEvent) => {
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          /* controller closed (client disconnected) */
        }
      };

      const result = await runNucleiStream(
        liveHosts as LiveHost[],
        {
          onFinding: (finding) => send({ type: "finding", finding }),
          onProgress: (message) => send({ type: "progress", message }),
        },
        {
          signal: request.signal,
          deepCve: deepCve === true,
          intensity: resolveIntensity(scanIntensity),
        },
      );

      send({ type: "status", status: result.status, message: result.message });
      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    },
  });
}
