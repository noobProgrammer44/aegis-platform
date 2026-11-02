import { describe, expect, it } from "vitest";
import { DuplicateError } from "@/lib/db/errors";
import { createRisk, listRisks } from "@/lib/db/repos/risks";
import {
  createTarget,
  deleteTarget,
  findTargetByValue,
  getTarget,
  listTargets,
  listTargetsMatching,
  updateTarget,
} from "@/lib/db/repos/targets";
import { createWorkspace } from "@/lib/db/repos/workspaces";
import { riskDefinition, useMemoryDb, WS } from "./helpers";

describe("targets repository", () => {
  const db = useMemoryDb();

  it("creates a target with defaults and reads it back", () => {
    const created = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    expect(created).toMatchObject({
      workspaceId: WS,
      target: "example.com",
      kind: "domain",
      label: "",
      tags: [],
      source: "manual",
      health: { score: 0, grade: "A" },
      lastScannedAt: null,
    });
    expect(getTarget(db(), WS, created.id)).toEqual(created);
    expect(findTargetByValue(db(), WS, "example.com")).toEqual(created);
  });

  it("does not keep a reference to the caller's tags array", () => {
    const tags = ["prod"];
    const created = createTarget(db(), WS, { target: "a.test", kind: "domain", tags });
    tags.push("mutated");
    expect(created.tags).toEqual(["prod"]);
    expect(getTarget(db(), WS, created.id)?.tags).toEqual(["prod"]);
  });

  it("rejects the same target twice in a workspace but allows it in another", () => {
    createTarget(db(), WS, { target: "example.com", kind: "domain" });
    expect(() => createTarget(db(), WS, { target: "example.com", kind: "domain" })).toThrow(
      DuplicateError,
    );
    const other = createWorkspace(db(), "Client B");
    expect(createTarget(db(), other.id, { target: "example.com", kind: "domain" }).workspaceId).toBe(
      other.id,
    );
  });

  it("updates only the patched fields and returns a new object", () => {
    const created = createTarget(db(), WS, {
      target: "example.com",
      kind: "domain",
      label: "Marketing site",
      tags: ["web"],
    });
    const updated = updateTarget(db(), WS, created.id, {
      health: { score: 420, grade: "C" },
      lastScannedAt: "2026-11-02T10:00:00.000Z",
    });
    expect(updated).not.toBe(created);
    expect(updated).toMatchObject({
      label: "Marketing site",
      tags: ["web"],
      health: { score: 420, grade: "C" },
      lastScannedAt: "2026-11-02T10:00:00.000Z",
    });
    expect(created.health).toEqual({ score: 0, grade: "A" });
    expect(getTarget(db(), WS, created.id)).toEqual(updated);
  });

  it("keeps targets isolated per workspace", () => {
    const created = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    const other = createWorkspace(db(), "Client B");
    expect(getTarget(db(), other.id, created.id)).toBeNull();
    expect(updateTarget(db(), other.id, created.id, { label: "x" })).toBeNull();
    expect(deleteTarget(db(), other.id, created.id)).toBe(false);
    expect(listTargets(db(), other.id)).toEqual([]);
  });

  it("selects targets by ids, tags, or all when the filter is empty", () => {
    const a = createTarget(db(), WS, { target: "a.test", kind: "domain", tags: ["web"] });
    const b = createTarget(db(), WS, { target: "b.test", kind: "domain", tags: ["db"] });
    const c = createTarget(db(), WS, { target: "10.0.0.0/24", kind: "cidr" });
    // Sorted: targets created in the same millisecond have no defined order.
    const ids = (filter: { targetIds: string[]; tags: string[] }) =>
      listTargetsMatching(db(), WS, filter)
        .map((t) => t.id)
        .sort();
    const sorted = (...values: string[]) => [...values].sort();

    expect(ids({ targetIds: [], tags: [] })).toEqual(sorted(a.id, b.id, c.id));
    expect(ids({ targetIds: [c.id], tags: [] })).toEqual([c.id]);
    expect(ids({ targetIds: [], tags: ["web"] })).toEqual([a.id]);
    expect(ids({ targetIds: [c.id], tags: ["db"] })).toEqual(sorted(b.id, c.id));
  });

  it("deletes a target together with its risks", () => {
    const created = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    createRisk(db(), WS, {
      targetId: created.id,
      fingerprint: "csp",
      definition: riskDefinition(),
      lastScanId: null,
    });
    expect(deleteTarget(db(), WS, created.id)).toBe(true);
    expect(getTarget(db(), WS, created.id)).toBeNull();
    expect(listRisks(db(), WS)).toEqual([]);
  });
});
