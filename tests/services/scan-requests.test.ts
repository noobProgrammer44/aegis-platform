import { describe, expect, it } from "vitest";
import { listScans } from "@/lib/db/repos/scans";
import { listScheduledScans } from "@/lib/db/repos/scheduled-scans";
import { createTarget } from "@/lib/db/repos/targets";
import { submitScanRequest } from "@/lib/services/scan-requests";
import { parseScanRequest, type ScanRequest } from "@/lib/validation/scan-request";
import { useMemoryDb, WS } from "../db/helpers";

const NOW = new Date("2026-11-03T10:00:00.000Z");
const base: ScanRequest = {
  scanTypes: ["SURFACE", "NMAP"],
  targetMode: "selected",
  targetIds: [],
  tags: [],
  intensity: "polite",
  schedule: "ONCE",
  runAt: null,
  intervalDays: null,
  notifyPolicy: "NEVER",
  notifyEmails: [],
};

describe("parseScanRequest", () => {
  it("accepts a complete request and reports the first problem otherwise", () => {
    expect(parseScanRequest({ ...base, targetIds: ["tgt_1"] }).ok).toBe(true);
    expect(parseScanRequest({ ...base, scanTypes: [] })).toEqual({ ok: false, error: "Pick at least one scanner." });
    expect(parseScanRequest(base)).toEqual({ ok: false, error: "Pick at least one target." });
    expect(parseScanRequest({ ...base, targetMode: "tags" })).toEqual({ ok: false, error: "Pick at least one tag." });
    expect(parseScanRequest({ ...base, targetMode: "all", schedule: "CUSTOM" })).toEqual({ ok: false, error: "Say how many days between runs." });
    expect(parseScanRequest({ ...base, targetMode: "all", notifyPolicy: "ALWAYS" }).ok).toBe(false);
    expect(parseScanRequest({ ...base, targetMode: "all", notifyPolicy: "ALWAYS", notifyEmails: ["not-an-email"] }).ok).toBe(false);
    expect(parseScanRequest({ ...base, targetMode: "all", runAt: "tomorrow" }).ok).toBe(false);
  });
});

describe("submitScanRequest", () => {
  const db = useMemoryDb();

  it("queues one scan per scanner right away for a one-time scan", () => {
    const t = createTarget(db(), WS, { target: "localhost:3100", kind: "host" });
    const outcome = submitScanRequest(db(), WS, { ...base, targetIds: [t.id], intensity: "normal" }, NOW, "u");
    expect(outcome.kind).toBe("queued");
    expect(listScans(db(), WS).map((s) => [s.type, s.intensity, s.targets])).toEqual(
      expect.arrayContaining([["SURFACE", "normal", ["localhost:3100"]], ["NMAP", "normal", ["localhost:3100"]]]),
    );
  });

  it("resolves tag and all-target selections when running now", () => {
    createTarget(db(), WS, { target: "a.test", kind: "domain", tags: ["web"] });
    createTarget(db(), WS, { target: "b.test", kind: "domain" });
    const byTag = submitScanRequest(db(), WS, { ...base, scanTypes: ["SURFACE"], targetMode: "tags", tags: ["web"] }, NOW, "u");
    expect(byTag.kind === "queued" && byTag.scans[0].targets).toEqual(["a.test"]);
    const all = submitScanRequest(db(), WS, { ...base, scanTypes: ["SURFACE"], targetMode: "all" }, NOW, "u");
    expect(all.kind === "queued" && all.scans[0].targets.length).toBe(2);
  });

  it("creates a schedule for recurring or future scans, keeping the tag filter live", () => {
    const weekly = submitScanRequest(
      db(), WS,
      { ...base, targetMode: "tags", tags: ["web"], schedule: "WEEKLY", intensity: "aggressive", notifyPolicy: "ON_CHANGES", notifyEmails: ["sec@example.com"] },
      NOW, "u",
    );
    expect(weekly).toMatchObject({
      kind: "scheduled",
      schedule: { schedule: "WEEKLY", intensity: "aggressive", targetsFilter: { tags: ["web"] }, notifyEmails: ["sec@example.com"], nextRun: NOW.toISOString(), name: "Web surface, Port scan" },
    });
    const later = submitScanRequest(db(), WS, { ...base, targetMode: "all", runAt: "2026-11-05T09:00:00.000Z" }, NOW, "u");
    expect(later).toMatchObject({ kind: "scheduled", schedule: { schedule: "ONCE", nextRun: "2026-11-05T09:00:00.000Z" } });
    expect(listScheduledScans(db(), WS)).toHaveLength(2);
    expect(listScans(db(), WS)).toHaveLength(0);
  });

  it("refuses unknown scanners and missing targets", () => {
    expect(submitScanRequest(db(), WS, { ...base, scanTypes: ["NESSUS"], targetMode: "all" }, NOW, "u")).toEqual({ kind: "error", message: "Pick at least one scanner." });
    expect(submitScanRequest(db(), WS, { ...base, targetIds: ["tgt_gone"] }, NOW, "u")).toEqual({ kind: "error", message: "None of those targets exist." });
  });
});
