import { unauthorizedHosts } from "@/lib/services/authorization";
import { currentWorkspaceId } from "@/lib/workspace";

/**
 * Server-side authorization for the quick-scan routes. The request body says which
 * hosts it wants to touch; any host that isn't local, attested or DNS-verified makes
 * the whole request fail with 403, whatever `activeAllowed` the browser sent.
 */

const hostOf = (value: unknown): string | null => {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) return null;
  if (!value.includes("://")) return value;
  try {
    return new URL(value).host;
  } catch {
    return null;
  }
};

/** Hosts from `[{ name }]` (discovery output) or `[{ url }]` (live hosts). */
export function requestedHosts(items: readonly unknown[]): string[] {
  return items.flatMap((item) => {
    const record = (item ?? {}) as { name?: unknown; url?: unknown };
    const host = hostOf(record.url ?? record.name);
    return host ? [host] : [];
  });
}

export function authorizationGuard(items: readonly unknown[]): Response | null {
  const hosts = requestedHosts(items);
  if (items.length > 0 && hosts.length === 0) {
    return Response.json({ error: "No valid hosts in the request." }, { status: 400 });
  }
  const blocked = unauthorizedHosts(hosts, currentWorkspaceId());
  if (blocked.length === 0) return null;
  const list = blocked.slice(0, 5).join(", ") + (blocked.length > 5 ? ` and ${blocked.length - 5} more` : "");
  return Response.json(
    {
      error:
        `Active scanning is not authorized for ${list}. Add it on the Targets page and confirm ` +
        "you're authorized or verify ownership. Local and private-network hosts are allowed automatically.",
      unauthorizedHosts: blocked,
    },
    { status: 403 },
  );
}
