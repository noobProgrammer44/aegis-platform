import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import Database from "better-sqlite3";
import { MIGRATIONS } from "./migrations";

/**
 * SQLite connection (better-sqlite3, synchronous). One connection per process,
 * cached on globalThis so Next.js dev-mode module reloads don't open a new handle
 * on every request.
 */

export type DB = Database.Database;

export const DEFAULT_WORKSPACE_ID = "ws_default";

const globalForDb = globalThis as unknown as { __aegisDb?: DB };

export function dbPath(): string {
  return process.env.AEGIS_DB_PATH ?? path.join(process.cwd(), "data", "aegis.db");
}

export function openDb(file: string): DB {
  if (file !== ":memory:") fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");
  migrate(db);
  ensureDefaultWorkspace(db);
  return db;
}

export function getDb(): DB {
  if (!globalForDb.__aegisDb) globalForDb.__aegisDb = openDb(dbPath());
  return globalForDb.__aegisDb;
}

/** Swap the process-wide connection (tests use an in-memory database). */
export function setDbForTesting(db: DB | undefined): void {
  globalForDb.__aegisDb = db;
}

function migrate(db: DB): void {
  const current = db.pragma("user_version", { simple: true }) as number;
  for (let version = current; version < MIGRATIONS.length; version++) {
    db.transaction(() => {
      db.exec(MIGRATIONS[version]);
      db.pragma(`user_version = ${version + 1}`);
    })();
  }
}

function ensureDefaultWorkspace(db: DB): void {
  db.prepare(
    "INSERT OR IGNORE INTO workspaces (id, name, created_at) VALUES (?, ?, ?)",
  ).run(DEFAULT_WORKSPACE_ID, "Default workspace", nowIso());
}

export function nowIso(): string {
  return new Date().toISOString();
}

/** Short random id with a readable prefix, e.g. `tgt_k3j9x0q2m1ab`. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(9).toString("base64url").toLowerCase().replace(/[-_]/g, "x")}`;
}

export function parseJson<T>(raw: string | null | undefined, fallback: T): T {
  if (raw === null || raw === undefined || raw === "") return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export const toJson = (value: unknown): string => JSON.stringify(value);
export const toBool = (value: unknown): boolean => value === 1 || value === true;
