import { describe, expect, it } from "vitest";
import { mergeScanRisks, type MergeScanInput } from "@/lib/domain/risk-lifecycle";
import type { DetectedRisk, Risk } from "@/types/aegis";
import { definition, LATER, risk, rule } from "./fixtures";

const detected = (fingerprint: string, overrides: Partial<DetectedRisk> = {}): DetectedRisk => ({
  targetId: "tgt_a",
  fingerprint,
  definition: definition({ title: `Finding ${fingerprint}` }),
  ...overrides,
});

function merge(overrides: Partial<MergeScanInput>) {
  let n = 0;
  return mergeScanRisks({
    workspaceId: "ws_default",
    scanId: "scn_2",
    scanType: "SURFACE",
    at: LATER,
    scannedTargetIds: ["tgt_a"],
    existing: [],
    detected: [],
    rules: [],
    targets: [{ id: "tgt_a", tags: ["web"] }],
    createId: () => `rsk_new${++n}`,
    ...overrides,
  });
}

describe("mergeScanRisks", () => {
  it("opens new risks for first-time findings", () => {
    const result = merge({ detected: [detected("hsts"), detected("csp")] });
    expect(result.counts).toEqual({ newOpen: 2, stillOpen: 0, closed: 0 });
    expect(result.newOpen[0]).toMatchObject({
      id: "rsk_new1",
      status: "OPEN",
      firstDetectedAt: LATER,
      lastDetectedAt: LATER,
      lastScanId: "scn_2",
      isAccepted: false,
    });
    expect(result.changed).toHaveLength(2);
  });

  it("refreshes risks that are still open, keeping identity and first detection", () => {
    const stored = risk({ id: "rsk_old", fingerprint: "hsts" });
    const result = merge({
      existing: [stored],
      detected: [detected("hsts", { definition: definition({ title: "Updated title" }) })],
    });
    expect(result.counts).toEqual({ newOpen: 0, stillOpen: 1, closed: 0 });
    expect(result.stillOpen[0]).toMatchObject({
      id: "rsk_old",
      firstDetectedAt: stored.firstDetectedAt,
      lastDetectedAt: LATER,
      lastScanId: "scn_2",
      definition: { title: "Updated title" },
    });
    expect(stored.lastDetectedAt).not.toBe(LATER);
  });

  it("reopens a closed risk and counts it as new open", () => {
    const closed = risk({ id: "rsk_old", fingerprint: "hsts", status: "CLOSED", closedAt: "2026-11-02T12:00:00.000Z" });
    const result = merge({ existing: [closed], detected: [detected("hsts")] });
    expect(result.counts).toEqual({ newOpen: 1, stillOpen: 0, closed: 0 });
    expect(result.reopened).toEqual([expect.objectContaining({ id: "rsk_old", status: "OPEN", closedAt: null })]);
  });

  it("closes open risks the scan no longer detects", () => {
    const stored = risk({ id: "rsk_old", fingerprint: "hsts" });
    const result = merge({ existing: [stored], detected: [] });
    expect(result.counts).toEqual({ newOpen: 0, stillOpen: 0, closed: 1 });
    expect(result.closed[0]).toMatchObject({ id: "rsk_old", status: "CLOSED", closedAt: LATER, lastScanId: "scn_2" });
  });

  it("leaves risks from other scanners, skipped targets and already-closed risks alone", () => {
    const otherScanner = risk({ id: "rsk_n", fingerprint: "cve", definition: definition({ scanType: "NUCLEI" }) });
    const skippedTarget = risk({ id: "rsk_b", targetId: "tgt_b", fingerprint: "hsts" });
    const alreadyClosed = risk({ id: "rsk_c", fingerprint: "old", status: "CLOSED", closedAt: "x" });
    const result = merge({ existing: [otherScanner, skippedTarget, alreadyClosed], detected: [] });
    expect(result.changed).toEqual([]);
    expect(result.counts).toEqual({ newOpen: 0, stillOpen: 0, closed: 0 });
  });

  it("counts a finding reported twice in one scan once", () => {
    const result = merge({ detected: [detected("hsts"), detected("hsts")] });
    expect(result.counts.newOpen).toBe(1);
  });

  it("applies acceptance rules to new and still-open risks but keeps manual decisions", () => {
    const accept = rule({ targetTags: ["web"] }, { id: "rul_web", note: "Accepted for web" });
    const manual = risk({ id: "rsk_m", fingerprint: "manual", isAccepted: true, acceptedBy: "manual", acceptedReason: "Mine" });
    const result = merge({
      rules: [accept],
      existing: [manual],
      detected: [detected("hsts"), detected("manual")],
    });
    expect(result.newOpen[0]).toMatchObject({ isAccepted: true, acceptedBy: "rul_web" });
    expect(result.stillOpen[0]).toMatchObject({ isAccepted: true, acceptedBy: "manual", acceptedReason: "Mine" });
  });

  it("does not mutate its inputs", () => {
    const stored: Risk = risk({ id: "rsk_old", fingerprint: "hsts" });
    const existing = Object.freeze([Object.freeze(stored)]);
    const found = Object.freeze([Object.freeze(detected("hsts"))]);
    expect(() => merge({ existing, detected: found })).not.toThrow();
    expect(stored.lastScanId).toBe("scn_0");
  });
});
