import type { HealthGrade, Target, ThreatLevel } from "@/types/aegis";

/** Search, filter, sort and grouping for the targets table. Pure, runs in the browser. */

export interface TargetRow {
  target: Target;
  /** Open, non-accepted risks per severity. */
  counts: Record<ThreatLevel, number>;
  openTotal: number;
  closedTotal: number;
  discoveredCount: number;
}

export type TargetSort = "health" | "name" | "lastScanned" | "added";
export type TargetGrouping = "none" | "tag";

export interface TargetFilters {
  search: string;
  grades: HealthGrade[];
  tag: string | null;
}

export const NO_FILTERS: TargetFilters = { search: "", grades: [], tag: null };

const displayName = (t: Target) => (t.label || t.target).toLowerCase();

export function filterTargets(rows: readonly TargetRow[], filters: TargetFilters): TargetRow[] {
  const query = filters.search.trim().toLowerCase();
  return rows.filter(({ target }) => {
    const matchesSearch =
      !query ||
      target.target.toLowerCase().includes(query) ||
      target.label.toLowerCase().includes(query) ||
      target.tags.some((tag) => tag.includes(query));
    const matchesGrade = filters.grades.length === 0 || filters.grades.includes(target.health.grade);
    const matchesTag = !filters.tag || target.tags.includes(filters.tag);
    return matchesSearch && matchesGrade && matchesTag;
  });
}

/** Worst health first for "health"; A-Z for "name"; newest first for dates (never scanned last). */
export function sortTargets(rows: readonly TargetRow[], sort: TargetSort): TargetRow[] {
  const byName = (a: TargetRow, b: TargetRow) => displayName(a.target).localeCompare(displayName(b.target));
  const compare: Record<TargetSort, (a: TargetRow, b: TargetRow) => number> = {
    health: (a, b) => b.target.health.score - a.target.health.score || byName(a, b),
    name: byName,
    lastScanned: (a, b) =>
      (b.target.lastScannedAt ?? "").localeCompare(a.target.lastScannedAt ?? "") || byName(a, b),
    added: (a, b) => b.target.createdAt.localeCompare(a.target.createdAt) || byName(a, b),
  };
  return [...rows].sort(compare[sort]);
}

export interface TargetGroup {
  key: string;
  label: string;
  rows: TargetRow[];
}

/** Groups by tag (a target with two tags appears in both); untagged targets last. */
export function groupTargets(rows: readonly TargetRow[], grouping: TargetGrouping): TargetGroup[] {
  if (grouping === "none") return [{ key: "all", label: "All targets", rows: [...rows] }];
  const tags = [...new Set(rows.flatMap((row) => row.target.tags))].sort();
  const tagged = tags.map((tag) => ({
    key: `tag:${tag}`,
    label: tag,
    rows: rows.filter((row) => row.target.tags.includes(tag)),
  }));
  const untagged = rows.filter((row) => row.target.tags.length === 0);
  return untagged.length > 0
    ? [...tagged, { key: "untagged", label: "No tag", rows: untagged }]
    : tagged;
}

export function allTags(rows: readonly TargetRow[]): string[] {
  return [...new Set(rows.flatMap((row) => row.target.tags))].sort();
}
