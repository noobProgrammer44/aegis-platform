import type {
  HealthGrade,
  HealthScore,
  Target,
  TargetKind,
  TargetSource,
  TargetsFilter,
} from "@/types/aegis";
import { newId, nowIso, parseJson, toJson, type DB } from "../client";
import { insertOrDuplicate } from "../errors";

interface TargetRow {
  id: string;
  workspace_id: string;
  target: string;
  kind: TargetKind;
  label: string;
  tags: string;
  source: TargetSource;
  health_score: number;
  health_grade: HealthGrade;
  last_scanned_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface NewTarget {
  target: string;
  kind: TargetKind;
  label?: string;
  tags?: string[];
  source?: TargetSource;
}

export interface TargetPatch {
  label?: string;
  tags?: string[];
  health?: HealthScore;
  lastScannedAt?: string | null;
}

const toTarget = (row: TargetRow): Target => ({
  id: row.id,
  workspaceId: row.workspace_id,
  target: row.target,
  kind: row.kind,
  label: row.label,
  tags: parseJson<string[]>(row.tags, []),
  source: row.source,
  health: { score: row.health_score, grade: row.health_grade },
  lastScannedAt: row.last_scanned_at,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const toParams = (t: Target) => ({
  id: t.id,
  workspace_id: t.workspaceId,
  target: t.target,
  kind: t.kind,
  label: t.label,
  tags: toJson(t.tags),
  source: t.source,
  health_score: t.health.score,
  health_grade: t.health.grade,
  last_scanned_at: t.lastScannedAt,
  created_at: t.createdAt,
  updated_at: t.updatedAt,
});

export function createTarget(db: DB, workspaceId: string, input: NewTarget): Target {
  const now = nowIso();
  const target: Target = {
    id: newId("tgt"),
    workspaceId,
    target: input.target,
    kind: input.kind,
    label: input.label ?? "",
    tags: [...(input.tags ?? [])],
    source: input.source ?? "manual",
    health: { score: 0, grade: "A" },
    lastScannedAt: null,
    createdAt: now,
    updatedAt: now,
  };
  insertOrDuplicate(
    () =>
      db
        .prepare(
          `INSERT INTO targets (id, workspace_id, target, kind, label, tags, source,
             health_score, health_grade, last_scanned_at, created_at, updated_at)
           VALUES (@id, @workspace_id, @target, @kind, @label, @tags, @source,
             @health_score, @health_grade, @last_scanned_at, @created_at, @updated_at)`,
        )
        .run(toParams(target)),
    `Target ${input.target} already exists`,
  );
  return target;
}

export function getTarget(db: DB, workspaceId: string, id: string): Target | null {
  const row = db
    .prepare("SELECT * FROM targets WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as TargetRow | undefined;
  return row ? toTarget(row) : null;
}

export function findTargetByValue(db: DB, workspaceId: string, value: string): Target | null {
  const row = db
    .prepare("SELECT * FROM targets WHERE workspace_id = ? AND target = ?")
    .get(workspaceId, value) as TargetRow | undefined;
  return row ? toTarget(row) : null;
}

export function listTargets(db: DB, workspaceId: string): Target[] {
  const rows = db
    .prepare("SELECT * FROM targets WHERE workspace_id = ? ORDER BY created_at, id")
    .all(workspaceId) as TargetRow[];
  return rows.map(toTarget);
}

/**
 * Targets selected by a filter: the listed ids plus every target carrying one of the
 * listed tags. An empty filter means all targets in the workspace.
 */
export function listTargetsMatching(
  db: DB,
  workspaceId: string,
  filter: TargetsFilter,
): Target[] {
  const all = listTargets(db, workspaceId);
  if (filter.targetIds.length === 0 && filter.tags.length === 0) return all;
  const ids = new Set(filter.targetIds);
  const tags = new Set(filter.tags);
  return all.filter((t) => ids.has(t.id) || t.tags.some((tag) => tags.has(tag)));
}

export function updateTarget(
  db: DB,
  workspaceId: string,
  id: string,
  patch: TargetPatch,
): Target | null {
  const current = getTarget(db, workspaceId, id);
  if (!current) return null;
  const next: Target = {
    ...current,
    label: patch.label ?? current.label,
    tags: patch.tags ? [...patch.tags] : current.tags,
    health: patch.health ? { ...patch.health } : current.health,
    lastScannedAt: patch.lastScannedAt !== undefined ? patch.lastScannedAt : current.lastScannedAt,
    updatedAt: nowIso(),
  };
  db.prepare(
    `UPDATE targets SET label = @label, tags = @tags, health_score = @health_score,
       health_grade = @health_grade, last_scanned_at = @last_scanned_at, updated_at = @updated_at
     WHERE workspace_id = @workspace_id AND id = @id`,
  ).run(toParams(next));
  return next;
}

/** Deletes the target; its risks go with it (ON DELETE CASCADE). */
export function deleteTarget(db: DB, workspaceId: string, id: string): boolean {
  return (
    db.prepare("DELETE FROM targets WHERE workspace_id = ? AND id = ?").run(workspaceId, id)
      .changes > 0
  );
}
