import { describe, expect, it } from "vitest";
import { asReportSnapshot, buildReportSnapshot } from "@/lib/domain/report";
import type { ReportFilters, Scan, Target } from "@/types/aegis";
import { definition, risk } from "./fixtures";

const NOW = new Date("2026-11-03T09:00:00.000Z");

const target = (id: string, tags: string[], score = 0): Target => ({
  id,
  workspaceId: "ws_default",
  target: `${id}.example.com`,
  kind: "domain",
  label: "",
  tags,
  source: "manual",
  health: { score, grade: score > 600 ? "D" : "A" },
  lastScannedAt: score > 0 ? "2026-11-02T00:00:00.000Z" : null,
  createdAt: "",
  updatedAt: "",
});

const scan = (id: string, type: Scan["type"], targetIds: string[]): Scan => ({
  id,
  workspaceId: "ws_default",
  type,
  intensity: "polite",
  state: "SUCCEEDED",
  progress: 100,
  progressMessage: null,
  targetIds,
  targets: [],
  skippedTargets: [],
  risks: { newOpen: 0, stillOpen: 0, closed: 0 },
  scheduledBy: null,
  error: null,
  aiSummary: null,
  createdAt: "2026-11-02T00:00:00.000Z",
  startedAt: null,
  finishedAt: "2026-11-02T00:05:00.000Z",
});

const targets = [target("web", ["web"], 700), target("db", ["db"], 150), target("idle", [])];
const risks = [
  risk({ id: "r1", targetId: "web", definition: definition({ title: "Exposed .env", threatLevel: "CRITICAL", additionalInfo: { host: "web.example.com", port: 443 } }) }),
  risk({ id: "r2", targetId: "web", definition: definition({ title: "Missing CSP", threatLevel: "MEDIUM" }) }),
  risk({ id: "r3", targetId: "db", definition: definition({ title: "Missing CSP", threatLevel: "MEDIUM" }), isAccepted: true, acceptedBy: "manual", acceptedReason: "internal" }),
  risk({ id: "r4", targetId: "db", definition: definition({ title: "Old TLS", threatLevel: "HIGH" }), status: "CLOSED", closedAt: "2026-11-01T00:00:00.000Z" }),
];
const scans = [scan("s1", "SURFACE", ["web", "db"]), scan("s2", "NMAP", ["db"])];
const filters = (overrides: Partial<ReportFilters> = {}): ReportFilters => ({
  targets: { targetIds: [], tags: [] },
  threatLevels: [],
  includeAccepted: false,
  includeClosed: false,
  ...overrides,
});

describe("buildReportSnapshot", () => {
  it("covers every target and open, unaccepted risks by default", () => {
    const s = buildReportSnapshot({ workspaceName: "Default", filters: filters(), targets, risks, scans, now: NOW });
    expect(s.risks.map((r) => r.id)).toEqual(["r1", "r2"]);
    expect(s.totals).toEqual({ byLevel: { CRITICAL: 1, HIGH: 0, MEDIUM: 1, LOW: 0 }, included: 2, accepted: 1, closed: 1 });
    expect(s.coverage).toEqual({
      targets: 3,
      scannedTargets: 2,
      scans: 2,
      byScanType: [{ type: "SURFACE", count: 1 }, { type: "NMAP", count: 1 }],
      lastScanAt: "2026-11-02T00:05:00.000Z",
    });
    expect(s.targets.map((t) => t.id)).toEqual(["web", "db", "idle"]);
    expect(s.risks[0]).toMatchObject({ host: "web.example.com", port: 443, target: "web.example.com" });
    expect(s.health.grade).toBe("D");
    expect(s.generatedAt).toBe(NOW.toISOString());
  });

  it("narrows by tag, severity, and opts into accepted and closed risks", () => {
    const db = buildReportSnapshot({ workspaceName: "Default", filters: filters({ targets: { targetIds: [], tags: ["db"] }, includeAccepted: true, includeClosed: true }), targets, risks, scans, now: NOW });
    expect(db.risks.map((r) => r.id)).toEqual(["r4", "r3"]);
    expect(db.coverage.targets).toBe(1);
    expect(db.coverage.scans).toBe(2);

    const critical = buildReportSnapshot({ workspaceName: "Default", filters: filters({ threatLevels: ["CRITICAL"] }), targets, risks, scans, now: NOW });
    expect(critical.risks.map((r) => r.id)).toEqual(["r1"]);
  });

  it("validates stored snapshots", () => {
    const s = buildReportSnapshot({ workspaceName: "Default", filters: filters(), targets, risks, scans, now: NOW });
    expect(asReportSnapshot(JSON.parse(JSON.stringify(s)))).toEqual(s);
    expect(asReportSnapshot({ version: 2 })).toBeNull();
    expect(asReportSnapshot(null)).toBeNull();
  });
});
