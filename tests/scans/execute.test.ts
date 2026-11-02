import { describe, expect, it } from "vitest";
import { listAudit } from "@/lib/db/repos/audit-log";
import { listDiscoveredDomains } from "@/lib/db/repos/discovered-domains";
import { listHealthSnapshots } from "@/lib/db/repos/health-snapshots";
import { listRisks } from "@/lib/db/repos/risks";
import { getScanResultContent, listScanResults } from "@/lib/db/repos/scan-results";
import { createScan } from "@/lib/db/repos/scans";
import { createScheduledScan, getScheduledScan } from "@/lib/db/repos/scheduled-scans";
import { createTarget, getTarget } from "@/lib/db/repos/targets";
import { executeScan } from "@/lib/scans/execute";
import type { Scanner, ScannerOutput } from "@/lib/scans/scanners";
import { queueDueSchedules } from "@/lib/scans/scheduler";
import { attestTarget } from "@/lib/services/authorization";
import type { DetectedRisk, Target } from "@/types/aegis";
import { useMemoryDb, WS } from "../db/helpers";

const risk = (target: Target, fingerprint: string, threatLevel: DetectedRisk["definition"]["threatLevel"] = "HIGH"): DetectedRisk => ({
  targetId: target.id,
  fingerprint,
  definition: {
    scanType: "SURFACE",
    title: `Finding ${fingerprint}`,
    threatLevel,
    description: "",
    solution: "",
    references: [],
    cvss: null,
    additionalInfo: {},
  },
});

function fakeScanner(mode: "active" | "passive", run: (target: Target) => ScannerOutput | Promise<ScannerOutput>): Scanner {
  return { type: "SURFACE", label: "Fake", description: "", mode, run: ({ target }) => Promise.resolve(run(target)) };
}

const signal = () => new AbortController().signal;

describe("executeScan", () => {
  const db = useMemoryDb();
  const local = () => createTarget(db(), WS, { target: "localhost:3100", kind: "host" });
  const queue = (targets: Target[]) =>
    createScan(db(), WS, { type: "SURFACE", targetIds: targets.map((t) => t.id), targets: targets.map((t) => t.target) });

  it("stores findings as risks, updates health and records results", async () => {
    const t = local();
    const scanner = fakeScanner("active", (target) => ({
      risks: [risk(target, "a", "CRITICAL"), risk(target, "b", "LOW")],
      discovered: [],
      raw: { ok: true },
    }));
    const done = await executeScan(db(), queue([t]), signal(), { SURFACE: scanner });

    expect(done).toMatchObject({ state: "SUCCEEDED", progress: 100, risks: { newOpen: 2, stillOpen: 0, closed: 0 } });
    expect(listRisks(db(), WS).map((r) => r.definition.threatLevel).sort()).toEqual(["CRITICAL", "LOW"]);
    expect(getTarget(db(), WS, t.id)?.health.grade).toBe("D");
    expect(getTarget(db(), WS, t.id)?.lastScannedAt).not.toBeNull();
    expect(listHealthSnapshots(db(), WS, { targetId: null })).toHaveLength(1);

    const [file] = listScanResults(db(), WS, done!.id);
    const content = JSON.parse(getScanResultContent(db(), WS, file.id)!.content.toString());
    expect(content.targets[0]).toEqual({ target: "localhost:3100", raw: { ok: true } });
    expect(listAudit(db(), WS).map((e) => e.action)).toEqual(["scan.finished", "scan.started"]);
  });

  it("closes risks a later scan no longer finds", async () => {
    const t = local();
    await executeScan(db(), queue([t]), signal(), { SURFACE: fakeScanner("active", (x) => ({ risks: [risk(x, "a"), risk(x, "b")], discovered: [], raw: null })) });
    const second = await executeScan(db(), queue([t]), signal(), { SURFACE: fakeScanner("active", (x) => ({ risks: [risk(x, "a")], discovered: [], raw: null })) });

    expect(second?.risks).toEqual({ newOpen: 0, stillOpen: 1, closed: 1 });
    expect(listRisks(db(), WS, { status: "OPEN" })).toHaveLength(1);
  });

  it("never runs an active scanner against a target that isn't authorized", async () => {
    const external = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    let calls = 0;
    const scanner = fakeScanner("active", () => {
      calls += 1;
      return { risks: [], discovered: [], raw: null };
    });
    const done = await executeScan(db(), queue([external]), signal(), { SURFACE: scanner });

    expect(calls).toBe(0);
    expect(done?.state).toBe("BLOCKED");
    expect(done?.skippedTargets[0].reason).toMatch(/Not authorized/);
    expect(listAudit(db(), WS, { action: "scan.blocked" })).toHaveLength(1);
  });

  it("runs active scanners on an external target once it is attested", async () => {
    const external = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    attestTarget(db(), WS, external, "local user", "We own it");
    const scanner = fakeScanner("active", (target) => ({ risks: [risk(target, "a")], discovered: [], raw: null }));
    const done = await executeScan(db(), queue([external]), signal(), { SURFACE: scanner });
    expect(done?.state).toBe("SUCCEEDED");
    expect(listRisks(db(), WS)).toHaveLength(1);
  });

  it("runs passive scanners on any target and saves discovered domains", async () => {
    const external = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    const scanner = fakeScanner("passive", (target) => ({
      risks: [],
      discovered: [{ name: "vpn.example.com", viaTargetId: target.id, viaTarget: target.target, resolves: true, records: {} }],
      raw: null,
    }));
    const done = await executeScan(db(), queue([external]), signal(), { SURFACE: scanner });

    expect(done?.state).toBe("SUCCEEDED");
    expect(listDiscoveredDomains(db(), WS).map((d) => d.name)).toEqual(["vpn.example.com"]);
  });

  it("records a scanner error per target and fails when nothing ran", async () => {
    const t = local();
    const done = await executeScan(db(), queue([t]), signal(), {
      SURFACE: fakeScanner("active", () => {
        throw new Error("probe timed out");
      }),
    });
    expect(done).toMatchObject({ state: "FAILED", error: "probe timed out" });
    expect(done?.skippedTargets).toEqual([{ target: "localhost:3100", reason: "probe timed out" }]);
  });

  it("merges nothing when stopped, so unchecked risks aren't closed", async () => {
    const t = local();
    await executeScan(db(), queue([t]), signal(), { SURFACE: fakeScanner("active", (x) => ({ risks: [risk(x, "a")], discovered: [], raw: null })) });
    const controller = new AbortController();
    controller.abort();
    const stopped = await executeScan(db(), queue([t]), controller.signal, { SURFACE: fakeScanner("active", () => ({ risks: [], discovered: [], raw: null })) });

    expect(stopped?.state).toBe("STOPPED");
    expect(listRisks(db(), WS, { status: "OPEN" })).toHaveLength(1);
  });

  it("fails cleanly when the scan type has no scanner yet", async () => {
    const t = local();
    const scan = createScan(db(), WS, { type: "ZAP_ACTIVE", targetIds: [t.id], targets: [t.target] });
    expect((await executeScan(db(), scan, signal(), {}))?.state).toBe("FAILED");
  });
});

describe("queueDueSchedules", () => {
  const db = useMemoryDb();

  it("queues one scan per scan type for matching targets and advances the schedule", () => {
    createTarget(db(), WS, { target: "localhost:3100", kind: "host", tags: ["web"] });
    createTarget(db(), WS, { target: "10.0.0.1", kind: "ipv4", tags: ["db"] });
    const schedule = createScheduledScan(db(), WS, {
      name: "Daily web",
      schedule: "DAILY",
      scanTypes: ["SURFACE", "NMAP"],
      targetsFilter: { targetIds: [], tags: ["web"] },
      startAt: "2026-11-01T09:00:00.000Z",
      nextRun: "2026-11-02T09:00:00.000Z",
    });

    expect(queueDueSchedules(db(), "2026-11-02T09:00:30.000Z")).toBe(2);
    expect(getScheduledScan(db(), WS, schedule.id)).toMatchObject({
      lastRan: "2026-11-02T09:00:30.000Z",
      nextRun: "2026-11-03T09:00:00.000Z",
    });
    expect(queueDueSchedules(db(), "2026-11-02T09:01:00.000Z")).toBe(0);
  });
});
