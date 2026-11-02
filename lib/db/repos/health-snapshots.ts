import type { HealthGrade, HealthSnapshot, ThreatLevel } from "@/types/aegis";
import { parseJson, toJson, type DB } from "../client";

/**
 * One health snapshot per day, per target and for the workspace as a whole (the
 * dashboard trend charts and the target drawer's Trends tab read these).
 */

/** `target_key` for the workspace-wide snapshot (`targetId: null`). */
export const WORKSPACE_SNAPSHOT_KEY = "*";

interface SnapshotRow {
  workspace_id: string;
  target_key: string;
  day: string;
  score: number;
  grade: HealthGrade;
  counts: string;
  assets: number;
}

const EMPTY_COUNTS: Record<ThreatLevel, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

const toKey = (targetId: string | null): string => targetId ?? WORKSPACE_SNAPSHOT_KEY;

const toSnapshot = (row: SnapshotRow): HealthSnapshot => ({
  workspaceId: row.workspace_id,
  targetId: row.target_key === WORKSPACE_SNAPSHOT_KEY ? null : row.target_key,
  day: row.day,
  score: row.score,
  grade: row.grade,
  counts: { ...EMPTY_COUNTS, ...parseJson<Partial<Record<ThreatLevel, number>>>(row.counts, {}) },
  assets: row.assets,
});

/** Writes the snapshot for its day, replacing an earlier one from the same day. */
export function upsertHealthSnapshot(db: DB, snapshot: HealthSnapshot): HealthSnapshot {
  db.prepare(
    `INSERT INTO health_snapshots (workspace_id, target_key, day, score, grade, counts, assets)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (workspace_id, target_key, day) DO UPDATE SET score = excluded.score,
       grade = excluded.grade, counts = excluded.counts, assets = excluded.assets`,
  ).run(
    snapshot.workspaceId,
    toKey(snapshot.targetId),
    snapshot.day,
    snapshot.score,
    snapshot.grade,
    toJson(snapshot.counts),
    snapshot.assets,
  );
  return snapshot;
}

/**
 * Snapshots for one target (or the workspace when `targetId` is null), oldest day first.
 * `sinceDay` / `untilDay` are inclusive `YYYY-MM-DD` bounds.
 */
export function listHealthSnapshots(
  db: DB,
  workspaceId: string,
  options: { targetId: string | null; sinceDay?: string; untilDay?: string },
): HealthSnapshot[] {
  const rows = db
    .prepare(
      `SELECT * FROM health_snapshots WHERE workspace_id = ? AND target_key = ?
       AND day >= ? AND day <= ? ORDER BY day`,
    )
    .all(
      workspaceId,
      toKey(options.targetId),
      options.sinceDay ?? "0000-00-00",
      options.untilDay ?? "9999-12-31",
    ) as SnapshotRow[];
  return rows.map(toSnapshot);
}
