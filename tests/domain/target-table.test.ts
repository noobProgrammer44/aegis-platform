import { describe, expect, it } from "vitest";
import {
  allTags,
  filterTargets,
  groupTargets,
  NO_FILTERS,
  sortTargets,
  type TargetRow,
} from "@/lib/domain/target-table";
import { parseLabel, parseTags } from "@/lib/validation/targets";
import type { HealthGrade, Target } from "@/types/aegis";

const row = (
  id: string,
  overrides: Partial<Target> & { score?: number; grade?: HealthGrade } = {},
): TargetRow => {
  const { score = 0, grade = "A", ...rest } = overrides;
  return {
    target: {
      id,
      workspaceId: "ws_default",
      target: `${id}.example.com`,
      kind: "domain",
      label: "",
      tags: [],
      source: "manual",
      health: { score, grade },
      lastScannedAt: null,
      createdAt: "2026-11-01T00:00:00.000Z",
      updatedAt: "2026-11-01T00:00:00.000Z",
      ...rest,
    },
    counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    openTotal: 0,
    closedTotal: 0,
    discoveredCount: 0,
  };
};

const rows = [
  row("app", { label: "Customer app", tags: ["web", "prod"], score: 715, grade: "D", lastScannedAt: "2026-11-02T00:00:00.000Z" }),
  row("api", { label: "Public API", tags: ["api", "prod"], score: 350, grade: "B", lastScannedAt: "2026-11-01T00:00:00.000Z", createdAt: "2026-11-02T00:00:00.000Z" }),
  row("www", { tags: ["web"], score: 150, grade: "A" }),
  row("office", { kind: "cidr" }),
];
const ids = (list: TargetRow[]) => list.map((r) => r.target.id);

describe("filterTargets", () => {
  it("searches target, label and tags case-insensitively", () => {
    expect(ids(filterTargets(rows, { ...NO_FILTERS, search: "PUBLIC" }))).toEqual(["api"]);
    expect(ids(filterTargets(rows, { ...NO_FILTERS, search: "www.example" }))).toEqual(["www"]);
    expect(ids(filterTargets(rows, { ...NO_FILTERS, search: "prod" }))).toEqual(["app", "api"]);
  });

  it("filters by grade and tag", () => {
    expect(ids(filterTargets(rows, { ...NO_FILTERS, grades: ["A"] }))).toEqual(["www", "office"]);
    expect(ids(filterTargets(rows, { ...NO_FILTERS, tag: "web" }))).toEqual(["app", "www"]);
    expect(filterTargets(rows, NO_FILTERS)).toHaveLength(4);
  });
});

describe("sortTargets", () => {
  it("sorts worst health first, by name, by last scan and by date added", () => {
    expect(ids(sortTargets(rows, "health"))).toEqual(["app", "api", "www", "office"]);
    expect(ids(sortTargets(rows, "name"))).toEqual(["app", "office", "api", "www"]);
    expect(ids(sortTargets(rows, "lastScanned"))).toEqual(["app", "api", "office", "www"]);
    expect(ids(sortTargets(rows, "added"))[0]).toBe("api");
  });

  it("does not reorder the input", () => {
    const input = [...rows];
    sortTargets(input, "name");
    expect(ids(input)).toEqual(["app", "api", "www", "office"]);
  });
});

describe("groupTargets", () => {
  it("groups by tag with untagged targets last", () => {
    const groups = groupTargets(rows, "tag");
    expect(groups.map((g) => [g.label, ids(g.rows)])).toEqual([
      ["api", ["api"]],
      ["prod", ["app", "api"]],
      ["web", ["app", "www"]],
      ["No tag", ["office"]],
    ]);
    expect(groupTargets(rows, "none")).toHaveLength(1);
    expect(allTags(rows)).toEqual(["api", "prod", "web"]);
  });
});

describe("tag and label validation", () => {
  it("normalizes tags and enforces the limits", () => {
    expect(parseTags(" Web, prod  web ")).toEqual({ ok: true, tags: ["web", "prod"] });
    expect(parseTags("")).toEqual({ ok: true, tags: [] });
    expect(parseTags("a b c d e f")).toEqual({ ok: false, error: "Use at most 5 tags." });
    expect(parseTags("bad/tag")).toMatchObject({ ok: false });
    expect(parseTags("x".repeat(33))).toMatchObject({ ok: false });
  });

  it("trims labels and caps their length", () => {
    expect(parseLabel("  Customer app ")).toEqual({ ok: true, label: "Customer app" });
    expect(parseLabel("x".repeat(81))).toMatchObject({ ok: false });
  });
});
