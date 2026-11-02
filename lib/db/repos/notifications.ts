import type { Notification, NotificationStatus } from "@/types/aegis";
import { newId, nowIso, parseJson, toJson, type DB } from "../client";

/** Email notifications: sent, failed, or held in the outbox when SMTP isn't configured. */

interface NotificationRow {
  id: string;
  workspace_id: string;
  channel: "email";
  recipients: string;
  subject: string;
  body: string;
  status: NotificationStatus;
  error: string | null;
  created_at: string;
}

export interface NewNotification {
  to: string[];
  subject: string;
  body: string;
  status: NotificationStatus;
  error?: string | null;
}

const toNotification = (row: NotificationRow): Notification => ({
  id: row.id,
  workspaceId: row.workspace_id,
  channel: row.channel,
  to: parseJson<string[]>(row.recipients, []),
  subject: row.subject,
  body: row.body,
  status: row.status,
  error: row.error,
  createdAt: row.created_at,
});

export function createNotification(
  db: DB,
  workspaceId: string,
  input: NewNotification,
): Notification {
  const notification: Notification = {
    id: newId("ntf"),
    workspaceId,
    channel: "email",
    to: [...input.to],
    subject: input.subject,
    body: input.body,
    status: input.status,
    error: input.error ?? null,
    createdAt: nowIso(),
  };
  db.prepare(
    `INSERT INTO notifications (id, workspace_id, channel, recipients, subject, body, status,
       error, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    notification.id,
    notification.workspaceId,
    notification.channel,
    toJson(notification.to),
    notification.subject,
    notification.body,
    notification.status,
    notification.error,
    notification.createdAt,
  );
  return notification;
}

export function getNotification(db: DB, workspaceId: string, id: string): Notification | null {
  const row = db
    .prepare("SELECT * FROM notifications WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as NotificationRow | undefined;
  return row ? toNotification(row) : null;
}

/** Newest first. */
export function listNotifications(
  db: DB,
  workspaceId: string,
  options: { status?: NotificationStatus; limit?: number } = {},
): Notification[] {
  const statusClause = options.status ? "AND status = ?" : "";
  const params: unknown[] = options.status ? [workspaceId, options.status] : [workspaceId];
  const rows = db
    .prepare(
      `SELECT * FROM notifications WHERE workspace_id = ? ${statusClause}
       ORDER BY created_at DESC, rowid DESC LIMIT ?`,
    )
    .all(...params, options.limit ?? 200) as NotificationRow[];
  return rows.map(toNotification);
}

/** E.g. an outbox message that was sent once SMTP was configured. */
export function setNotificationStatus(
  db: DB,
  workspaceId: string,
  id: string,
  status: NotificationStatus,
  error: string | null = null,
): Notification | null {
  const result = db
    .prepare("UPDATE notifications SET status = ?, error = ? WHERE workspace_id = ? AND id = ?")
    .run(status, error, workspaceId, id);
  return result.changes > 0 ? getNotification(db, workspaceId, id) : null;
}
