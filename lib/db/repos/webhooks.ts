import type { Webhook, WebhookDelivery, WebhookEvent, WebhookKind } from "@/types/aegis";
import { newId, nowIso, parseJson, toBool, toJson, type DB } from "../client";
import { definedOnly } from "../sql";

interface WebhookRow {
  id: string;
  workspace_id: string;
  name: string;
  kind: WebhookKind;
  url: string;
  secret: string;
  events: string;
  enabled: number;
  created_at: string;
}

interface DeliveryRow {
  id: string;
  webhook_id: string;
  event: WebhookEvent;
  ok: number;
  status_code: number | null;
  error: string | null;
  at: string;
}

export interface NewWebhook {
  name: string;
  kind: WebhookKind;
  url: string;
  secret: string;
  events: WebhookEvent[];
  enabled?: boolean;
}

export type WebhookPatch = Partial<Pick<Webhook, "name" | "url" | "events" | "enabled">>;

export interface NewWebhookDelivery {
  webhookId: string;
  event: WebhookEvent;
  ok: boolean;
  statusCode: number | null;
  error: string | null;
  at?: string;
}

const toWebhook = (row: WebhookRow): Webhook => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  kind: row.kind,
  url: row.url,
  secret: row.secret,
  events: parseJson<WebhookEvent[]>(row.events, []),
  enabled: toBool(row.enabled),
  createdAt: row.created_at,
});

const toDelivery = (row: DeliveryRow): WebhookDelivery => ({
  id: row.id,
  webhookId: row.webhook_id,
  event: row.event,
  ok: toBool(row.ok),
  statusCode: row.status_code,
  error: row.error,
  at: row.at,
});

const toParams = (w: Webhook) => ({
  id: w.id,
  workspace_id: w.workspaceId,
  name: w.name,
  kind: w.kind,
  url: w.url,
  secret: w.secret,
  events: toJson(w.events),
  enabled: w.enabled ? 1 : 0,
  created_at: w.createdAt,
});

export function createWebhook(db: DB, workspaceId: string, input: NewWebhook): Webhook {
  const webhook: Webhook = {
    id: newId("whk"),
    workspaceId,
    name: input.name,
    kind: input.kind,
    url: input.url,
    secret: input.secret,
    events: [...input.events],
    enabled: input.enabled ?? true,
    createdAt: nowIso(),
  };
  db.prepare(
    `INSERT INTO webhooks (id, workspace_id, name, kind, url, secret, events, enabled, created_at)
     VALUES (@id, @workspace_id, @name, @kind, @url, @secret, @events, @enabled, @created_at)`,
  ).run(toParams(webhook));
  return webhook;
}

export function getWebhook(db: DB, workspaceId: string, id: string): Webhook | null {
  const row = db
    .prepare("SELECT * FROM webhooks WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as WebhookRow | undefined;
  return row ? toWebhook(row) : null;
}

export function listWebhooks(db: DB, workspaceId: string): Webhook[] {
  const rows = db
    .prepare("SELECT * FROM webhooks WHERE workspace_id = ? ORDER BY created_at, id")
    .all(workspaceId) as WebhookRow[];
  return rows.map(toWebhook);
}

/** Enabled webhooks subscribed to `event`. */
export function listWebhooksForEvent(db: DB, workspaceId: string, event: WebhookEvent): Webhook[] {
  return listWebhooks(db, workspaceId).filter((w) => w.enabled && w.events.includes(event));
}

export function updateWebhook(
  db: DB,
  workspaceId: string,
  id: string,
  patch: WebhookPatch,
): Webhook | null {
  const current = getWebhook(db, workspaceId, id);
  if (!current) return null;
  const next: Webhook = {
    ...current,
    ...definedOnly(patch),
    id: current.id,
    workspaceId: current.workspaceId,
  };
  db.prepare(
    `UPDATE webhooks SET name = @name, url = @url, events = @events, enabled = @enabled
     WHERE workspace_id = @workspace_id AND id = @id`,
  ).run(toParams(next));
  return next;
}

export function deleteWebhook(db: DB, workspaceId: string, id: string): boolean {
  return (
    db.prepare("DELETE FROM webhooks WHERE workspace_id = ? AND id = ?").run(workspaceId, id)
      .changes > 0
  );
}

export function recordWebhookDelivery(db: DB, input: NewWebhookDelivery): WebhookDelivery {
  const delivery: WebhookDelivery = {
    id: newId("dlv"),
    webhookId: input.webhookId,
    event: input.event,
    ok: input.ok,
    statusCode: input.statusCode,
    error: input.error,
    at: input.at ?? nowIso(),
  };
  db.prepare(
    `INSERT INTO webhook_deliveries (id, webhook_id, event, ok, status_code, error, at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    delivery.id,
    delivery.webhookId,
    delivery.event,
    delivery.ok ? 1 : 0,
    delivery.statusCode,
    delivery.error,
    delivery.at,
  );
  return delivery;
}

/** Newest first, scoped to the webhook's workspace. */
export function listWebhookDeliveries(
  db: DB,
  workspaceId: string,
  webhookId: string,
  limit = 50,
): WebhookDelivery[] {
  const rows = db
    .prepare(
      `SELECT d.* FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id
       WHERE w.workspace_id = ? AND d.webhook_id = ? ORDER BY d.at DESC, d.rowid DESC LIMIT ?`,
    )
    .all(workspaceId, webhookId, limit) as DeliveryRow[];
  return rows.map(toDelivery);
}
