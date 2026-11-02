import type { ApiKey } from "@/types/aegis";
import { newId, nowIso, type DB } from "../client";
import { insertOrDuplicate } from "../errors";

/**
 * API keys are stored as a hash only. Generating the key and hashing it is the API-key
 * service's job; the plaintext key never reaches this module.
 */

interface ApiKeyRow {
  id: string;
  workspace_id: string;
  name: string;
  prefix: string;
  hash: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface NewApiKey {
  name: string;
  prefix: string;
  hash: string;
}

const toApiKey = (row: ApiKeyRow): ApiKey => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  prefix: row.prefix,
  createdAt: row.created_at,
  lastUsedAt: row.last_used_at,
  revokedAt: row.revoked_at,
});

export function createApiKey(db: DB, workspaceId: string, input: NewApiKey): ApiKey {
  const key: ApiKey = {
    id: newId("key"),
    workspaceId,
    name: input.name,
    prefix: input.prefix,
    createdAt: nowIso(),
    lastUsedAt: null,
    revokedAt: null,
  };
  insertOrDuplicate(
    () =>
      db
        .prepare(
          `INSERT INTO api_keys (id, workspace_id, name, prefix, hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(key.id, key.workspaceId, key.name, key.prefix, input.hash, key.createdAt),
    "An API key with this hash already exists",
  );
  return key;
}

/** Revoked keys included, newest first. */
export function listApiKeys(db: DB, workspaceId: string): ApiKey[] {
  const rows = db
    .prepare("SELECT * FROM api_keys WHERE workspace_id = ? ORDER BY created_at DESC, id")
    .all(workspaceId) as ApiKeyRow[];
  return rows.map(toApiKey);
}

/**
 * Looks a presented key up by its hash. Not workspace-scoped on purpose: the key is
 * what tells the REST API which workspace the caller belongs to.
 */
export function findActiveApiKeyByHash(db: DB, hash: string): ApiKey | null {
  const row = db
    .prepare("SELECT * FROM api_keys WHERE hash = ? AND revoked_at IS NULL")
    .get(hash) as ApiKeyRow | undefined;
  return row ? toApiKey(row) : null;
}

export function touchApiKey(db: DB, id: string, at: string = nowIso()): void {
  db.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?").run(at, id);
}

/** Returns false when the key doesn't exist or was already revoked. */
export function revokeApiKey(db: DB, workspaceId: string, id: string, at: string = nowIso()): boolean {
  return (
    db
      .prepare(
        `UPDATE api_keys SET revoked_at = ?
         WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL`,
      )
      .run(at, workspaceId, id).changes > 0
  );
}
