import type { AuditEntry } from "@/types/aegis";
import { newId, nowIso, parseJson, toJson, type DB } from "../client";

/** Append-only audit log: there is deliberately no update or delete here. */

interface AuditRow {
  id: string;
  workspace_id: string;
  at: string;
  actor: string;
  action: string;
  subject: string;
  details: string;
}

export interface NewAuditEntry {
  actor: string;
  action: string;
  subject: string;
  details?: Record<string, unknown>;
  at?: string;
}

const toEntry = (row: AuditRow): AuditEntry => ({
  id: row.id,
  workspaceId: row.workspace_id,
  at: row.at,
  actor: row.actor,
  action: row.action,
  subject: row.subject,
  details: parseJson<Record<string, unknown>>(row.details, {}),
});

export function appendAudit(db: DB, workspaceId: string, input: NewAuditEntry): AuditEntry {
  const entry: AuditEntry = {
    id: newId("aud"),
    workspaceId,
    at: input.at ?? nowIso(),
    actor: input.actor,
    action: input.action,
    subject: input.subject,
    details: { ...(input.details ?? {}) },
  };
  db.prepare(
    `INSERT INTO audit_log (id, workspace_id, at, actor, action, subject, details)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    entry.id,
    entry.workspaceId,
    entry.at,
    entry.actor,
    entry.action,
    entry.subject,
    toJson(entry.details),
  );
  return entry;
}

/** Newest first. `subject` and `action` narrow the list to exact matches. */
export function listAudit(
  db: DB,
  workspaceId: string,
  options: { subject?: string; action?: string; limit?: number; offset?: number } = {},
): AuditEntry[] {
  const clauses = ["workspace_id = ?"];
  const params: unknown[] = [workspaceId];
  if (options.subject) {
    clauses.push("subject = ?");
    params.push(options.subject);
  }
  if (options.action) {
    clauses.push("action = ?");
    params.push(options.action);
  }
  const rows = db
    .prepare(
      `SELECT * FROM audit_log WHERE ${clauses.join(" AND ")}
       ORDER BY at DESC, rowid DESC LIMIT ? OFFSET ?`,
    )
    .all(...params, options.limit ?? 200, options.offset ?? 0) as AuditRow[];
  return rows.map(toEntry);
}
