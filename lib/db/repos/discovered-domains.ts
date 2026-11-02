import type { DiscoveredDomain } from "@/types/aegis";
import { newId, nowIso, parseJson, toBool, toJson, type DB } from "../client";

/** Subdomains found by discovery scans, waiting to be promoted to targets. */

interface DiscoveredRow {
  id: string;
  workspace_id: string;
  name: string;
  via_target_id: string | null;
  via_target: string | null;
  resolves: number;
  records: string;
  first_seen: string;
  last_seen: string;
  promoted_target_id: string | null;
}

export interface DiscoveredDomainInput {
  name: string;
  viaTargetId: string | null;
  viaTarget: string | null;
  resolves: boolean;
  records: Record<string, string[]>;
}

const toDomain = (row: DiscoveredRow): DiscoveredDomain => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  viaTargetId: row.via_target_id,
  viaTarget: row.via_target,
  resolves: toBool(row.resolves),
  records: parseJson<Record<string, string[]>>(row.records, {}),
  firstSeen: row.first_seen,
  lastSeen: row.last_seen,
  promotedTargetId: row.promoted_target_id,
});

function getByName(db: DB, workspaceId: string, name: string): DiscoveredDomain | null {
  const row = db
    .prepare("SELECT * FROM discovered_domains WHERE workspace_id = ? AND name = ?")
    .get(workspaceId, name) as DiscoveredRow | undefined;
  return row ? toDomain(row) : null;
}

/**
 * Records a sighting. A domain seen again keeps its id, first-seen time and the
 * target it was first found through; resolution status and records are refreshed.
 */
export function upsertDiscoveredDomain(
  db: DB,
  workspaceId: string,
  input: DiscoveredDomainInput,
  at: string = nowIso(),
): DiscoveredDomain {
  db.prepare(
    `INSERT INTO discovered_domains (id, workspace_id, name, via_target_id, via_target, resolves,
       records, first_seen, last_seen)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (workspace_id, name) DO UPDATE SET resolves = excluded.resolves,
       records = excluded.records, last_seen = excluded.last_seen,
       via_target_id = COALESCE(discovered_domains.via_target_id, excluded.via_target_id),
       via_target = COALESCE(discovered_domains.via_target, excluded.via_target)`,
  ).run(
    newId("dsc"),
    workspaceId,
    input.name,
    input.viaTargetId,
    input.viaTarget,
    input.resolves ? 1 : 0,
    toJson(input.records),
    at,
    at,
  );
  const saved = getByName(db, workspaceId, input.name);
  if (!saved) throw new Error(`Discovered domain ${input.name} was not saved`);
  return saved;
}

export function getDiscoveredDomain(
  db: DB,
  workspaceId: string,
  id: string,
): DiscoveredDomain | null {
  const row = db
    .prepare("SELECT * FROM discovered_domains WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as DiscoveredRow | undefined;
  return row ? toDomain(row) : null;
}

/** Most recently seen first. */
export function listDiscoveredDomains(
  db: DB,
  workspaceId: string,
  options: { unpromotedOnly?: boolean; viaTargetId?: string } = {},
): DiscoveredDomain[] {
  const clauses = ["workspace_id = ?"];
  const params: unknown[] = [workspaceId];
  if (options.unpromotedOnly) clauses.push("promoted_target_id IS NULL");
  if (options.viaTargetId) {
    clauses.push("via_target_id = ?");
    params.push(options.viaTargetId);
  }
  const rows = db
    .prepare(
      `SELECT * FROM discovered_domains WHERE ${clauses.join(" AND ")}
       ORDER BY last_seen DESC, name`,
    )
    .all(...params) as DiscoveredRow[];
  return rows.map(toDomain);
}

/** Links the domain to the target it was added as. */
export function markDomainPromoted(
  db: DB,
  workspaceId: string,
  id: string,
  targetId: string,
): DiscoveredDomain | null {
  const result = db
    .prepare(
      "UPDATE discovered_domains SET promoted_target_id = ? WHERE workspace_id = ? AND id = ?",
    )
    .run(targetId, workspaceId, id);
  return result.changes > 0 ? getDiscoveredDomain(db, workspaceId, id) : null;
}

export function deleteDiscoveredDomain(db: DB, workspaceId: string, id: string): boolean {
  return (
    db
      .prepare("DELETE FROM discovered_domains WHERE workspace_id = ? AND id = ?")
      .run(workspaceId, id).changes > 0
  );
}
