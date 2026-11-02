import type { Scan, ScanIntensityLevel, ScanRiskCounts, ScanState, ScanType } from "@/types/aegis";
import { newId, nowIso, parseJson, toJson, type DB } from "../client";
import { definedOnly, placeholders } from "../sql";

interface ScanRow {
  id: string;
  workspace_id: string;
  type: ScanType;
  intensity: ScanIntensityLevel;
  state: ScanState;
  progress: number;
  progress_message: string | null;
  target_ids: string;
  targets: string;
  skipped_targets: string;
  risks: string;
  scheduled_by: string | null;
  error: string | null;
  ai_summary: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface NewScan {
  type: ScanType;
  intensity?: ScanIntensityLevel;
  targetIds: string[];
  targets: string[];
  scheduledBy?: string | null;
}

export type ScanPatch = Partial<
  Pick<
    Scan,
    | "state"
    | "progress"
    | "progressMessage"
    | "skippedTargets"
    | "risks"
    | "error"
    | "aiSummary"
    | "startedAt"
    | "finishedAt"
  >
>;

const NO_RISKS: ScanRiskCounts = { newOpen: 0, stillOpen: 0, closed: 0 };

const toScan = (row: ScanRow): Scan => ({
  id: row.id,
  workspaceId: row.workspace_id,
  type: row.type,
  intensity: row.intensity,
  state: row.state,
  progress: row.progress,
  progressMessage: row.progress_message,
  targetIds: parseJson<string[]>(row.target_ids, []),
  targets: parseJson<string[]>(row.targets, []),
  skippedTargets: parseJson<Scan["skippedTargets"]>(row.skipped_targets, []),
  risks: { ...NO_RISKS, ...parseJson<Partial<ScanRiskCounts>>(row.risks, {}) },
  scheduledBy: row.scheduled_by,
  error: row.error,
  aiSummary: row.ai_summary,
  createdAt: row.created_at,
  startedAt: row.started_at,
  finishedAt: row.finished_at,
});

const toParams = (s: Scan) => ({
  id: s.id,
  workspace_id: s.workspaceId,
  type: s.type,
  intensity: s.intensity,
  state: s.state,
  progress: s.progress,
  progress_message: s.progressMessage,
  target_ids: toJson(s.targetIds),
  targets: toJson(s.targets),
  skipped_targets: toJson(s.skippedTargets),
  risks: toJson(s.risks),
  scheduled_by: s.scheduledBy,
  error: s.error,
  ai_summary: s.aiSummary,
  created_at: s.createdAt,
  started_at: s.startedAt,
  finished_at: s.finishedAt,
});

export function createScan(db: DB, workspaceId: string, input: NewScan): Scan {
  const scan: Scan = {
    id: newId("scn"),
    workspaceId,
    type: input.type,
    intensity: input.intensity ?? "polite",
    state: "QUEUED",
    progress: 0,
    progressMessage: null,
    targetIds: [...input.targetIds],
    targets: [...input.targets],
    skippedTargets: [],
    risks: { ...NO_RISKS },
    scheduledBy: input.scheduledBy ?? null,
    error: null,
    aiSummary: null,
    createdAt: nowIso(),
    startedAt: null,
    finishedAt: null,
  };
  db.prepare(
    `INSERT INTO scans (id, workspace_id, type, intensity, state, progress, progress_message,
       target_ids, targets, skipped_targets, risks, scheduled_by, error, ai_summary, created_at,
       started_at, finished_at)
     VALUES (@id, @workspace_id, @type, @intensity, @state, @progress, @progress_message,
       @target_ids, @targets, @skipped_targets, @risks, @scheduled_by, @error, @ai_summary,
       @created_at, @started_at, @finished_at)`,
  ).run(toParams(scan));
  return scan;
}

export function getScan(db: DB, workspaceId: string, id: string): Scan | null {
  const row = db
    .prepare("SELECT * FROM scans WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as ScanRow | undefined;
  return row ? toScan(row) : null;
}

/** Newest first. */
export function listScans(
  db: DB,
  workspaceId: string,
  options: { states?: ScanState[]; limit?: number } = {},
): Scan[] {
  const states = options.states ?? [];
  const stateClause = states.length > 0 ? `AND state IN (${placeholders(states.length)})` : "";
  const rows = db
    .prepare(
      `SELECT * FROM scans WHERE workspace_id = ? ${stateClause}
       ORDER BY created_at DESC, id DESC LIMIT ?`,
    )
    .all(workspaceId, ...states, options.limit ?? 200) as ScanRow[];
  return rows.map(toScan);
}

/**
 * Scans in the given states across every workspace, oldest first. Only the runner
 * uses this (queue pickup and crash recovery); request handlers stay workspace-scoped.
 */
export function listScansInStates(db: DB, states: ScanState[]): Scan[] {
  if (states.length === 0) return [];
  const rows = db
    .prepare(
      `SELECT * FROM scans WHERE state IN (${placeholders(states.length)})
       ORDER BY created_at, id`,
    )
    .all(...states) as ScanRow[];
  return rows.map(toScan);
}

export function updateScan(
  db: DB,
  workspaceId: string,
  id: string,
  patch: ScanPatch,
): Scan | null {
  const current = getScan(db, workspaceId, id);
  if (!current) return null;
  const next: Scan = {
    ...current,
    ...definedOnly(patch),
    id: current.id,
    workspaceId: current.workspaceId,
    skippedTargets: patch.skippedTargets ? [...patch.skippedTargets] : current.skippedTargets,
    risks: patch.risks ? { ...patch.risks } : current.risks,
  };
  db.prepare(
    `UPDATE scans SET state = @state, progress = @progress, progress_message = @progress_message,
       skipped_targets = @skipped_targets, risks = @risks, error = @error,
       ai_summary = @ai_summary, started_at = @started_at, finished_at = @finished_at
     WHERE workspace_id = @workspace_id AND id = @id`,
  ).run(toParams(next));
  return next;
}

/** Deletes the scan and its result files (ON DELETE CASCADE). */
export function deleteScan(db: DB, workspaceId: string, id: string): boolean {
  return (
    db.prepare("DELETE FROM scans WHERE workspace_id = ? AND id = ?").run(workspaceId, id)
      .changes > 0
  );
}
