import { randomBytes } from "node:crypto";
import { promises as dns } from "node:dns";
import { getDb, nowIso, type DB } from "@/lib/db/client";
import { appendAudit } from "@/lib/db/repos/audit-log";
import {
  deleteAuthorization,
  getAuthorization,
  getAuthorizationById,
  listVerifiedAuthorizations,
  markAuthorizationVerified,
  saveAuthorization,
} from "@/lib/db/repos/authorizations";
import {
  ACTIVE_SCAN_MIN_TIER,
  DNS_TOKEN_PREFIX,
  hostAuthorization,
  targetAuthorization,
  txtRecordsContainToken,
  type TargetAuthorization,
} from "@/lib/domain/authorization";
import type { Target } from "@/types/aegis";

/** Records and checks authorizations (server only). Every change is audit-logged. */

export type TxtResolver = (domain: string) => Promise<string[][]>;
const systemResolver: TxtResolver = (domain) => dns.resolveTxt(domain);

export function authorizationForTarget(db: DB, workspaceId: string, target: Target): TargetAuthorization {
  return targetAuthorization(target, listVerifiedAuthorizations(db, workspaceId));
}

export function attestTarget(db: DB, workspaceId: string, target: Target, actor: string, note: string | null): TargetAuthorization {
  const auth = authorizationForTarget(db, workspaceId, target);
  const at = nowIso();
  saveAuthorization(db, workspaceId, { scope: auth.scope, method: "attested", verified: true, attestedBy: actor, note, verifiedAt: at });
  appendAudit(db, workspaceId, { actor, action: "authorization.attested", subject: auth.scope, details: { target: target.target, note }, at });
  return authorizationForTarget(db, workspaceId, target);
}

/** Issues (or re-issues) the TXT token the owner must publish on the domain. */
export function startDnsVerification(db: DB, workspaceId: string, target: Target, actor: string): { domain: string; value: string } {
  const auth = authorizationForTarget(db, workspaceId, target);
  if (!auth.dnsVerifiable) throw new Error("DNS verification only works for domain targets.");
  const existing = getAuthorization(db, workspaceId, auth.scope, "dns");
  const token = existing && !existing.verified && existing.token ? existing.token : randomBytes(16).toString("hex");
  saveAuthorization(db, workspaceId, { scope: auth.scope, method: "dns", token, verified: existing?.verified ?? false, verifiedAt: existing?.verifiedAt ?? null });
  appendAudit(db, workspaceId, { actor, action: "authorization.dns_token_issued", subject: auth.scope });
  return { domain: auth.scope, value: `${DNS_TOKEN_PREFIX}${token}` };
}

export type DnsCheckResult =
  | { ok: true }
  | { ok: false; reason: string };

/** Looks up the domain's TXT records and marks the DNS record verified if the token is there. */
export async function checkDnsVerification(
  db: DB,
  workspaceId: string,
  target: Target,
  actor: string,
  resolveTxt: TxtResolver = systemResolver,
): Promise<DnsCheckResult> {
  const auth = authorizationForTarget(db, workspaceId, target);
  const pending = getAuthorization(db, workspaceId, auth.scope, "dns");
  if (!pending?.token) return { ok: false, reason: "Start DNS verification first to get a token." };
  if (pending.verified) return { ok: true };

  let records: string[][];
  try {
    records = await resolveTxt(auth.scope);
  } catch (err) {
    const code = (err as { code?: string }).code;
    records = [];
    if (code && code !== "ENODATA" && code !== "ENOTFOUND") {
      return { ok: false, reason: `DNS lookup failed (${code}). Try again in a minute.` };
    }
  }
  if (!txtRecordsContainToken(records, pending.token)) {
    appendAudit(db, workspaceId, { actor, action: "authorization.dns_check_failed", subject: auth.scope });
    return { ok: false, reason: "The TXT record isn't visible yet. DNS changes can take a few minutes to appear." };
  }
  markAuthorizationVerified(db, workspaceId, pending.id);
  appendAudit(db, workspaceId, { actor, action: "authorization.dns_verified", subject: auth.scope });
  return { ok: true };
}

export function revokeAuthorization(db: DB, workspaceId: string, id: string, actor: string): boolean {
  const record = getAuthorizationById(db, workspaceId, id);
  if (!record || !deleteAuthorization(db, workspaceId, id)) return false;
  appendAudit(db, workspaceId, { actor, action: "authorization.revoked", subject: record.scope, details: { method: record.method } });
  return true;
}

/**
 * Hosts in an active quick-scan request that nothing authorizes. The quick-scan API
 * routes refuse the whole request if this is non-empty, so a browser can't switch the
 * check off by sending `activeAllowed: true`.
 */
export function unauthorizedHosts(hosts: readonly string[], workspaceId: string, db: DB = getDb()): string[] {
  const records = listVerifiedAuthorizations(db, workspaceId);
  const unique = [...new Set(hosts.filter(Boolean))];
  return unique.filter((host) => hostAuthorization(host, records).tier < ACTIVE_SCAN_MIN_TIER);
}
