import type { Authorization, AuthorizationMethod } from "@/types/aegis";
import { newId, nowIso, toBool, type DB } from "../client";

/**
 * Authorization records (one per scope + method). Deciding what a record allows (tiers,
 * subdomain inheritance, local auto-auth) belongs to the authorization service; this
 * module only stores the records.
 */

interface AuthorizationRow {
  id: string;
  workspace_id: string;
  scope: string;
  method: AuthorizationMethod;
  token: string | null;
  verified: number;
  attested_by: string | null;
  note: string | null;
  created_at: string;
  verified_at: string | null;
}

export interface AuthorizationInput {
  scope: string;
  method: AuthorizationMethod;
  token?: string | null;
  verified: boolean;
  attestedBy?: string | null;
  note?: string | null;
  verifiedAt?: string | null;
}

const toAuthorization = (row: AuthorizationRow): Authorization => ({
  id: row.id,
  workspaceId: row.workspace_id,
  scope: row.scope,
  method: row.method,
  token: row.token,
  verified: toBool(row.verified),
  attestedBy: row.attested_by,
  note: row.note,
  createdAt: row.created_at,
  verifiedAt: row.verified_at,
});

const toParams = (a: Authorization) => ({
  id: a.id,
  workspace_id: a.workspaceId,
  scope: a.scope,
  method: a.method,
  token: a.token,
  verified: a.verified ? 1 : 0,
  attested_by: a.attestedBy,
  note: a.note,
  created_at: a.createdAt,
  verified_at: a.verifiedAt,
});

export function getAuthorization(
  db: DB,
  workspaceId: string,
  scope: string,
  method: AuthorizationMethod,
): Authorization | null {
  const row = db
    .prepare("SELECT * FROM authorizations WHERE workspace_id = ? AND scope = ? AND method = ?")
    .get(workspaceId, scope, method) as AuthorizationRow | undefined;
  return row ? toAuthorization(row) : null;
}

export function getAuthorizationById(
  db: DB,
  workspaceId: string,
  id: string,
): Authorization | null {
  const row = db
    .prepare("SELECT * FROM authorizations WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as AuthorizationRow | undefined;
  return row ? toAuthorization(row) : null;
}

/**
 * Creates the record for `scope` + `method`, or replaces the existing one's fields
 * (keeping its id and creation time). Re-attesting or issuing a new DNS token goes here.
 */
export function saveAuthorization(
  db: DB,
  workspaceId: string,
  input: AuthorizationInput,
): Authorization {
  return db.transaction(() => {
    const existing = getAuthorization(db, workspaceId, input.scope, input.method);
    const next: Authorization = {
      id: existing?.id ?? newId("aut"),
      workspaceId,
      scope: input.scope,
      method: input.method,
      token: input.token ?? null,
      verified: input.verified,
      attestedBy: input.attestedBy ?? null,
      note: input.note ?? null,
      createdAt: existing?.createdAt ?? nowIso(),
      verifiedAt: input.verifiedAt ?? null,
    };
    db.prepare(
      `INSERT INTO authorizations (id, workspace_id, scope, method, token, verified, attested_by,
         note, created_at, verified_at)
       VALUES (@id, @workspace_id, @scope, @method, @token, @verified, @attested_by, @note,
         @created_at, @verified_at)
       ON CONFLICT (workspace_id, scope, method) DO UPDATE SET token = excluded.token,
         verified = excluded.verified, attested_by = excluded.attested_by, note = excluded.note,
         verified_at = excluded.verified_at`,
    ).run(toParams(next));
    return next;
  })();
}

export function markAuthorizationVerified(
  db: DB,
  workspaceId: string,
  id: string,
  at: string = nowIso(),
): Authorization | null {
  const result = db
    .prepare(
      "UPDATE authorizations SET verified = 1, verified_at = ? WHERE workspace_id = ? AND id = ?",
    )
    .run(at, workspaceId, id);
  return result.changes > 0 ? getAuthorizationById(db, workspaceId, id) : null;
}

export function listAuthorizations(db: DB, workspaceId: string): Authorization[] {
  const rows = db
    .prepare("SELECT * FROM authorizations WHERE workspace_id = ? ORDER BY scope, method")
    .all(workspaceId) as AuthorizationRow[];
  return rows.map(toAuthorization);
}

/** Verified records only: the ones that actually unlock active scanning. */
export function listVerifiedAuthorizations(db: DB, workspaceId: string): Authorization[] {
  return listAuthorizations(db, workspaceId).filter((a) => a.verified);
}

export function deleteAuthorization(db: DB, workspaceId: string, id: string): boolean {
  return (
    db
      .prepare("DELETE FROM authorizations WHERE workspace_id = ? AND id = ?")
      .run(workspaceId, id).changes > 0
  );
}
