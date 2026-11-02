import { parseJson, toJson, type DB } from "../client";

/**
 * Per-workspace key/value settings stored as JSON (health threshold, branding, AI model,
 * SMTP config, ...). Callers validate values with zod; this module only stores them.
 */

export function getSetting<T>(db: DB, workspaceId: string, key: string, fallback: T): T {
  const row = db
    .prepare("SELECT value FROM settings WHERE workspace_id = ? AND key = ?")
    .get(workspaceId, key) as { value: string } | undefined;
  return row ? parseJson<T>(row.value, fallback) : fallback;
}

export function setSetting(db: DB, workspaceId: string, key: string, value: unknown): void {
  db.prepare(
    `INSERT INTO settings (workspace_id, key, value) VALUES (?, ?, ?)
     ON CONFLICT (workspace_id, key) DO UPDATE SET value = excluded.value`,
  ).run(workspaceId, key, toJson(value));
}

export function deleteSetting(db: DB, workspaceId: string, key: string): boolean {
  return (
    db.prepare("DELETE FROM settings WHERE workspace_id = ? AND key = ?").run(workspaceId, key)
      .changes > 0
  );
}

export function listSettings(db: DB, workspaceId: string): Record<string, unknown> {
  const rows = db
    .prepare("SELECT key, value FROM settings WHERE workspace_id = ? ORDER BY key")
    .all(workspaceId) as { key: string; value: string }[];
  return Object.fromEntries(rows.map((row) => [row.key, parseJson<unknown>(row.value, null)]));
}
