import type { AcceptanceQuery, AcceptanceRule } from "@/types/aegis";
import { newId, nowIso, parseJson, toBool, toJson, type DB } from "../client";

interface RuleRow {
  id: string;
  workspace_id: string;
  name: string;
  query: string;
  note: string;
  enabled: number;
  created_at: string;
}

export interface NewAcceptanceRule {
  name: string;
  query: Partial<AcceptanceQuery>;
  note?: string;
  enabled?: boolean;
}

export type AcceptanceRulePatch = Partial<Pick<AcceptanceRule, "name" | "note" | "enabled">> & {
  /** Replaces the whole query; fields left out become empty (match anything). */
  query?: Partial<AcceptanceQuery>;
};

export const EMPTY_ACCEPTANCE_QUERY: AcceptanceQuery = {
  scanTypes: [],
  threatLevels: [],
  targetTags: [],
  targetIds: [],
  titlePattern: null,
  ports: [],
};

/** Fills missing fields so a partial or older stored query is always complete. */
export const normalizeQuery = (query: Partial<AcceptanceQuery>): AcceptanceQuery => ({
  ...EMPTY_ACCEPTANCE_QUERY,
  ...query,
});

const toRule = (row: RuleRow): AcceptanceRule => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  query: normalizeQuery(parseJson<Partial<AcceptanceQuery>>(row.query, {})),
  note: row.note,
  enabled: toBool(row.enabled),
  createdAt: row.created_at,
});

const toParams = (r: AcceptanceRule) => ({
  id: r.id,
  workspace_id: r.workspaceId,
  name: r.name,
  query: toJson(r.query),
  note: r.note,
  enabled: r.enabled ? 1 : 0,
  created_at: r.createdAt,
});

export function createAcceptanceRule(
  db: DB,
  workspaceId: string,
  input: NewAcceptanceRule,
): AcceptanceRule {
  const rule: AcceptanceRule = {
    id: newId("rul"),
    workspaceId,
    name: input.name,
    query: normalizeQuery(input.query),
    note: input.note ?? "",
    enabled: input.enabled ?? true,
    createdAt: nowIso(),
  };
  db.prepare(
    `INSERT INTO acceptance_rules (id, workspace_id, name, query, note, enabled, created_at)
     VALUES (@id, @workspace_id, @name, @query, @note, @enabled, @created_at)`,
  ).run(toParams(rule));
  return rule;
}

export function getAcceptanceRule(db: DB, workspaceId: string, id: string): AcceptanceRule | null {
  const row = db
    .prepare("SELECT * FROM acceptance_rules WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as RuleRow | undefined;
  return row ? toRule(row) : null;
}

export function listAcceptanceRules(
  db: DB,
  workspaceId: string,
  options: { enabledOnly?: boolean } = {},
): AcceptanceRule[] {
  const rows = db
    .prepare(
      `SELECT * FROM acceptance_rules WHERE workspace_id = ? ${options.enabledOnly ? "AND enabled = 1" : ""}
       ORDER BY created_at, id`,
    )
    .all(workspaceId) as RuleRow[];
  return rows.map(toRule);
}

export function updateAcceptanceRule(
  db: DB,
  workspaceId: string,
  id: string,
  patch: AcceptanceRulePatch,
): AcceptanceRule | null {
  const current = getAcceptanceRule(db, workspaceId, id);
  if (!current) return null;
  const next: AcceptanceRule = {
    ...current,
    name: patch.name ?? current.name,
    note: patch.note ?? current.note,
    enabled: patch.enabled ?? current.enabled,
    query: patch.query ? normalizeQuery(patch.query) : current.query,
  };
  db.prepare(
    `UPDATE acceptance_rules SET name = @name, query = @query, note = @note, enabled = @enabled
     WHERE workspace_id = @workspace_id AND id = @id`,
  ).run(toParams(next));
  return next;
}

export function deleteAcceptanceRule(db: DB, workspaceId: string, id: string): boolean {
  return (
    db
      .prepare("DELETE FROM acceptance_rules WHERE workspace_id = ? AND id = ?")
      .run(workspaceId, id).changes > 0
  );
}
