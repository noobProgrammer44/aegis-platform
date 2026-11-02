import { describe, expect, it } from "vitest";
import {
  groupOpenIssues,
  healthTrend,
  mostCriticalRisk,
  mostFrequentIssue,
  mostVulnerableTarget,
  parsePeriod,
  periodStart,
  topIssues,
} from "@/lib/domain/insights";
import { timeAgo } from "@/lib/ui/format";
import type { HealthSnapshot, Target } from "@/types/aegis";
import { definition, risk } from "./fixtures";

const NOW = new Date("2026-11-02T12:00:00.000Z");

const issues = [
  risk({ id: "1", targetId: "a", definition: definition({ title: "Missing HSTS", threatLevel: "MEDIUM" }), firstDetectedAt: "2026-10-01T00:00:00.000Z" }),
  risk({ id: "2", targetId: "b", definition: definition({ title: "Missing HSTS", threatLevel: "MEDIUM" }), firstDetectedAt: "2026-09-01T00:00:00.000Z" }),
  risk({ id: "3", targetId: "b", definition: definition({ title: "Missing HSTS", threatLevel: "MEDIUM" }), firstDetectedAt: "2026-10-05T00:00:00.000Z" }),
  risk({ id: "4", targetId: "a", definition: definition({ title: "Old jQuery", threatLevel: "HIGH", scanType: "SURFACE" }), firstDetectedAt: "2026-10-20T00:00:00.000Z" }),
  risk({ id: "5", targetId: "a", definition: definition({ title: "Accepted crit", threatLevel: "CRITICAL" }), isAccepted: true, acceptedBy: "manual" }),
  risk({ id: "6", targetId: "a", definition: definition({ title: "Closed crit", threatLevel: "CRITICAL" }), status: "CLOSED" }),
];

const target = (id: string, score: number): Target => ({
  id,
  workspaceId: "ws_default",
  target: `${id}.test`,
  kind: "domain",
  label: "",
  tags: [],
  source: "manual",
  health: { score, grade: "C" },
  lastScannedAt: null,
  createdAt: "",
  updatedAt: "",
});

describe("periods", () => {
  it("parses known periods and falls back to the last year", () => {
    expect(parsePeriod("30d")).toBe("30d");
    expect(parsePeriod("forever")).toBe("1y");
    expect(parsePeriod(undefined)).toBe("1y");
  });

  it("computes the period start", () => {
    expect(periodStart("30d", NOW)).toBe("2026-10-03T12:00:00.000Z");
    expect(periodStart("all", NOW)).toBeNull();
  });
});

describe("issue grouping", () => {
  it("groups open, non-accepted risks by scanner and title, worst then most common first", () => {
    expect(groupOpenIssues(issues)).toEqual([
      { title: "Old jQuery", scanType: "SURFACE", threatLevel: "HIGH", count: 1, targetCount: 1, oldestDetectedAt: "2026-10-20T00:00:00.000Z" },
      { title: "Missing HSTS", scanType: "SURFACE", threatLevel: "MEDIUM", count: 3, targetCount: 2, oldestDetectedAt: "2026-09-01T00:00:00.000Z" },
    ]);
    expect(topIssues(issues, 1).map((i) => i.title)).toEqual(["Old jQuery"]);
  });

  it("picks the most frequent issue by count", () => {
    expect(mostFrequentIssue(issues)?.title).toBe("Missing HSTS");
    expect(mostFrequentIssue([])).toBeNull();
  });

  it("picks the most severe open risk and its age", () => {
    expect(mostCriticalRisk(issues, NOW)).toEqual({ risk: issues[3], ageDays: 13 });
    expect(mostCriticalRisk([issues[4], issues[5]], NOW)).toBeNull();
  });
});

describe("targets and trend", () => {
  it("finds the target with the worst score, ignoring clean ones", () => {
    expect(mostVulnerableTarget([target("a", 350), target("b", 720), target("c", 0)])?.id).toBe("b");
    expect(mostVulnerableTarget([target("c", 0)])).toBeNull();
  });

  it("compares with the latest snapshot at least 30 days old", () => {
    const snap = (day: string, score: number): HealthSnapshot => ({
      workspaceId: "ws_default", targetId: null, day, score, grade: "C", counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }, assets: 1,
    });
    const snapshots = [snap("2026-09-01", 600), snap("2026-10-02", 500), snap("2026-10-20", 100)];
    expect(healthTrend(450, snapshots, NOW)).toEqual({ delta: -50, previousScore: 500, previousDay: "2026-10-02" });
    expect(healthTrend(450, [snap("2026-10-20", 100)], NOW)).toBeNull();
  });
});

describe("timeAgo", () => {
  it("formats relative times", () => {
    expect(timeAgo("2026-11-02T11:59:30.000Z", NOW)).toBe("just now");
    expect(timeAgo("2026-11-02T09:00:00.000Z", NOW)).toBe("3 hours ago");
    expect(timeAgo("2026-11-01T12:00:00.000Z", NOW)).toBe("yesterday");
    expect(timeAgo("2026-10-12T12:00:00.000Z", NOW)).toBe("3 weeks ago");
    expect(timeAgo("not a date", NOW)).toBe("");
  });
});
