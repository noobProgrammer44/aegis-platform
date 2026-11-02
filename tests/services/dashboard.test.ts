import { describe, expect, it } from "vitest";
import { upsertDiscoveredDomain } from "@/lib/db/repos/discovered-domains";
import { createRisk } from "@/lib/db/repos/risks";
import { createScan } from "@/lib/db/repos/scans";
import { createScheduledScan } from "@/lib/db/repos/scheduled-scans";
import { createTarget } from "@/lib/db/repos/targets";
import { loadDashboard } from "@/lib/services/dashboard";
import { riskDefinition, useMemoryDb, WS } from "../db/helpers";

const NOW = new Date("2026-11-03T10:00:00.000Z");

describe("loadDashboard target filter", () => {
  const db = useMemoryDb();

  function seed() {
    const a = createTarget(db(), WS, { target: "a.example.com", kind: "host" });
    const b = createTarget(db(), WS, { target: "b.example.com", kind: "host", tags: ["prod"] });
    createRisk(db(), WS, { targetId: a.id, fingerprint: "a1", definition: riskDefinition({ threatLevel: "HIGH" }), lastScanId: null, detectedAt: "2026-11-02T00:00:00.000Z" });
    createRisk(db(), WS, { targetId: b.id, fingerprint: "b1", definition: riskDefinition(), lastScanId: null, detectedAt: "2026-11-02T00:00:00.000Z" });
    createRisk(db(), WS, { targetId: b.id, fingerprint: "b2", definition: riskDefinition({ threatLevel: "LOW", title: "Other" }), lastScanId: null, detectedAt: "2026-11-02T00:00:00.000Z" });
    createScan(db(), WS, { type: "SURFACE", targetIds: [a.id], targets: [a.target] });
    createScan(db(), WS, { type: "TLS", targetIds: [b.id], targets: [b.target] });
    createScan(db(), WS, { type: "EMAIL", targetIds: [a.id, b.id], targets: [a.target, b.target] });
    return { a, b };
  }

  it("covers the whole workspace without a target", () => {
    seed();
    const data = loadDashboard(db(), WS, "all", NOW);
    expect(data.target).toBeNull();
    expect(data.openTotal).toBe(3);
    expect(data.recentScans).toHaveLength(3);
    expect(data.targets).toHaveLength(2);
  });

  it("narrows risks, scans and insights to one target", () => {
    const { a, b } = seed();
    const onlyB = loadDashboard(db(), WS, "all", NOW, b.id);
    expect(onlyB.target?.id).toBe(b.id);
    expect(onlyB.openTotal).toBe(2);
    expect(onlyB.counts).toMatchObject({ HIGH: 0, MEDIUM: 1, LOW: 1 });
    expect(onlyB.recentRisks.every((r) => r.targetId === b.id)).toBe(true);
    expect(onlyB.recentScans.map((s) => s.type).sort()).toEqual(["EMAIL", "TLS"]);
    expect(onlyB.topIssues.every((g) => g.title !== riskDefinition({ threatLevel: "HIGH" }).title || g.count === 1)).toBe(true);
    expect(onlyB.targets).toHaveLength(2);

    const onlyA = loadDashboard(db(), WS, "all", NOW, a.id);
    expect(onlyA.openTotal).toBe(1);
    expect(onlyA.mostCritical?.risk.targetId).toBe(a.id);
  });

  it("counts only schedules and discovered names that involve the target", () => {
    const { a, b } = seed();
    const base = { scanTypes: ["SURFACE" as const], schedule: "WEEKLY" as const, startAt: "2026-11-03T00:00:00.000Z", nextRun: "2026-11-10T00:00:00.000Z" };
    createScheduledScan(db(), WS, { ...base, name: "all", targetsFilter: { targetIds: [], tags: [] } });
    createScheduledScan(db(), WS, { ...base, name: "just a", targetsFilter: { targetIds: [a.id], tags: [] } });
    createScheduledScan(db(), WS, { ...base, name: "prod", targetsFilter: { targetIds: [], tags: ["prod"] } });
    upsertDiscoveredDomain(db(), WS, { name: "x.a.example.com", viaTargetId: a.id, viaTarget: a.target, resolves: true, records: {} });

    expect(loadDashboard(db(), WS, "all", NOW).scheduledCount).toBe(3);
    expect(loadDashboard(db(), WS, "all", NOW, a.id)).toMatchObject({ scheduledCount: 2, discoveredTotal: 1 });
    expect(loadDashboard(db(), WS, "all", NOW, b.id)).toMatchObject({ scheduledCount: 2, discoveredTotal: 0 });
  });

  it("ignores an unknown target id", () => {
    seed();
    const data = loadDashboard(db(), WS, "all", NOW, "tgt_missing");
    expect(data.target).toBeNull();
    expect(data.openTotal).toBe(3);
  });
});
