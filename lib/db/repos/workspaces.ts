import type { Workspace } from "@/types/aegis";
import { DEFAULT_WORKSPACE_ID, newId, nowIso, type DB } from "../client";

interface WorkspaceRow {
  id: string;
  name: string;
  created_at: string;
}

const toWorkspace = (row: WorkspaceRow): Workspace => ({
  id: row.id,
  name: row.name,
  createdAt: row.created_at,
});

/** The default workspace first, then the others oldest first. */
export function listWorkspaces(db: DB): Workspace[] {
  const rows = db
    .prepare("SELECT * FROM workspaces ORDER BY id = ? DESC, created_at, id")
    .all(DEFAULT_WORKSPACE_ID) as WorkspaceRow[];
  return rows.map(toWorkspace);
}

export function getWorkspace(db: DB, id: string): Workspace | null {
  const row = db.prepare("SELECT * FROM workspaces WHERE id = ?").get(id) as
    | WorkspaceRow
    | undefined;
  return row ? toWorkspace(row) : null;
}

export function createWorkspace(db: DB, name: string): Workspace {
  const workspace: Workspace = { id: newId("ws"), name, createdAt: nowIso() };
  db.prepare("INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)").run(
    workspace.id,
    workspace.name,
    workspace.createdAt,
  );
  return workspace;
}

export function renameWorkspace(db: DB, id: string, name: string): Workspace | null {
  const result = db.prepare("UPDATE workspaces SET name = ? WHERE id = ?").run(name, id);
  return result.changes > 0 ? getWorkspace(db, id) : null;
}

/** Deletes a workspace and, through cascades, everything in it. The default one is kept. */
export function deleteWorkspace(db: DB, id: string): boolean {
  if (id === DEFAULT_WORKSPACE_ID) {
    throw new Error("The default workspace cannot be deleted");
  }
  return db.prepare("DELETE FROM workspaces WHERE id = ?").run(id).changes > 0;
}
