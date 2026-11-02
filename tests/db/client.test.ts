import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_WORKSPACE_ID, newId, openDb, parseJson } from "@/lib/db/client";
import { MIGRATIONS } from "@/lib/db/migrations";
import { createTarget, listTargets } from "@/lib/db/repos/targets";
import { useMemoryDb, WS } from "./helpers";

describe("openDb", () => {
  const db = useMemoryDb();

  it("applies every migration and records the schema version", () => {
    expect(db().pragma("user_version", { simple: true })).toBe(MIGRATIONS.length);
  });

  it("creates the default workspace", () => {
    const row = db().prepare("SELECT name FROM workspaces WHERE id = ?").get(DEFAULT_WORKSPACE_ID);
    expect(row).toEqual({ name: "Default workspace" });
  });

  it("enforces foreign keys", () => {
    expect(() =>
      db()
        .prepare(
          `INSERT INTO targets (id, workspace_id, target, kind, created_at, updated_at)
           VALUES ('t', 'missing_ws', 'x.test', 'domain', 'now', 'now')`,
        )
        .run(),
    ).toThrow(/FOREIGN KEY/);
  });
});

describe("openDb on a file", () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  it("keeps data across reopen without re-running migrations", () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-db-"));
    const file = path.join(dir, "nested", "aegis.db");
    const first = openDb(file);
    createTarget(first, WS, { target: "example.com", kind: "domain" });
    first.close();

    const second = openDb(file);
    expect(listTargets(second, WS).map((t) => t.target)).toEqual(["example.com"]);
    expect(second.pragma("user_version", { simple: true })).toBe(MIGRATIONS.length);
    second.close();
  });
});

describe("helpers", () => {
  it("newId uses the prefix and a 12-character url-safe body", () => {
    const id = newId("tgt");
    expect(id).toMatch(/^tgt_[a-z0-9]{12}$/);
    expect(newId("tgt")).not.toBe(id);
  });

  it("parseJson falls back on empty or invalid input", () => {
    expect(parseJson("[1,2]", [])).toEqual([1, 2]);
    expect(parseJson("not json", ["fallback"])).toEqual(["fallback"]);
    expect(parseJson(null, 7)).toBe(7);
    expect(parseJson("", 7)).toBe(7);
  });
});
