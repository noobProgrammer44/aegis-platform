import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  addScanResult,
  getScanResultContent,
  listScanResults,
} from "@/lib/db/repos/scan-results";
import {
  createScan,
  deleteScan,
  getScan,
  listScans,
  listScansInStates,
  updateScan,
  type ScanPatch,
} from "@/lib/db/repos/scans";
import { createWorkspace } from "@/lib/db/repos/workspaces";
import { useMemoryDb, WS } from "./helpers";

describe("scans repository", () => {
  const db = useMemoryDb();

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-02T09:00:00.000Z"));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const advance = (ms: number) => vi.setSystemTime(new Date(Date.now() + ms));

  it("creates a queued scan with empty counts", () => {
    const scan = createScan(db(), WS, {
      type: "SURFACE",
      targetIds: ["tgt_1"],
      targets: ["example.com"],
    });
    expect(scan).toMatchObject({
      state: "QUEUED",
      progress: 0,
      risks: { newOpen: 0, stillOpen: 0, closed: 0 },
      skippedTargets: [],
      scheduledBy: null,
      createdAt: "2026-11-02T09:00:00.000Z",
    });
    expect(getScan(db(), WS, scan.id)).toEqual(scan);
  });

  it("applies a patch without clobbering fields passed as undefined", () => {
    const scan = createScan(db(), WS, { type: "NUCLEI", targetIds: [], targets: [] });
    const running = updateScan(db(), WS, scan.id, {
      state: "RUNNING",
      startedAt: "2026-11-02T09:00:01.000Z",
      progress: 40,
      progressMessage: "Running templates",
    });
    const patch: ScanPatch = { progress: 80, progressMessage: undefined };
    const later = updateScan(db(), WS, scan.id, patch);

    expect(running?.state).toBe("RUNNING");
    expect(later).toMatchObject({
      state: "RUNNING",
      progress: 80,
      progressMessage: "Running templates",
      startedAt: "2026-11-02T09:00:01.000Z",
    });
    expect(getScan(db(), WS, scan.id)).toEqual(later);
  });

  it("ignores id or workspace keys smuggled into a patch at runtime", () => {
    const a = createScan(db(), WS, { type: "SURFACE", targetIds: [], targets: [] });
    const b = createScan(db(), WS, { type: "SURFACE", targetIds: [], targets: [] });
    const smuggled = { id: b.id, workspaceId: "ws_other", state: "FAILED" } as ScanPatch;
    const updated = updateScan(db(), WS, a.id, smuggled);

    expect(updated).toMatchObject({ id: a.id, workspaceId: WS, state: "FAILED" });
    expect(getScan(db(), WS, b.id)?.state).toBe("QUEUED");
  });

  it("stores skipped targets and risk counts", () => {
    const scan = createScan(db(), WS, { type: "NMAP", targetIds: [], targets: ["x.test"] });
    const done = updateScan(db(), WS, scan.id, {
      state: "SUCCEEDED",
      skippedTargets: [{ target: "x.test", reason: "not authorized" }],
      risks: { newOpen: 2, stillOpen: 1, closed: 3 },
    });
    expect(getScan(db(), WS, scan.id)).toEqual(done);
    expect(done?.risks).toEqual({ newOpen: 2, stillOpen: 1, closed: 3 });
  });

  it("lists newest first, filters by state and honours the limit", () => {
    const first = createScan(db(), WS, { type: "SURFACE", targetIds: [], targets: [] });
    advance(1000);
    const second = createScan(db(), WS, { type: "NUCLEI", targetIds: [], targets: [] });
    advance(1000);
    const third = createScan(db(), WS, { type: "TLS", targetIds: [], targets: [] });
    updateScan(db(), WS, second.id, { state: "RUNNING" });

    expect(listScans(db(), WS).map((s) => s.id)).toEqual([third.id, second.id, first.id]);
    expect(listScans(db(), WS, { states: ["RUNNING"] }).map((s) => s.id)).toEqual([second.id]);
    expect(listScans(db(), WS, { limit: 1 }).map((s) => s.id)).toEqual([third.id]);
  });

  it("finds queued and running scans across workspaces for the runner", () => {
    const other = createWorkspace(db(), "Client B");
    const a = createScan(db(), WS, { type: "SURFACE", targetIds: [], targets: [] });
    advance(1000);
    const b = createScan(db(), other.id, { type: "SURFACE", targetIds: [], targets: [] });
    advance(1000);
    const c = createScan(db(), WS, { type: "SURFACE", targetIds: [], targets: [] });
    updateScan(db(), WS, c.id, { state: "SUCCEEDED" });

    expect(listScansInStates(db(), ["QUEUED", "RUNNING"]).map((s) => s.id)).toEqual([a.id, b.id]);
    expect(listScansInStates(db(), [])).toEqual([]);
    expect(listScans(db(), other.id).map((s) => s.id)).toEqual([b.id]);
    expect(getScan(db(), other.id, a.id)).toBeNull();
  });

  it("stores raw result files and serves them only within the workspace", () => {
    const scan = createScan(db(), WS, { type: "NUCLEI", targetIds: [], targets: [] });
    const file = addScanResult(db(), {
      scanId: scan.id,
      targetId: null,
      filename: "nuclei.jsonl",
      contentType: "application/x-ndjson",
      content: '{"template-id":"tech-detect"}\n',
    });
    expect(file.size).toBe(Buffer.byteLength('{"template-id":"tech-detect"}\n'));
    expect(listScanResults(db(), WS, scan.id)).toEqual([file]);

    const download = getScanResultContent(db(), WS, file.id);
    expect(download?.file).toEqual(file);
    expect(download?.content.toString()).toBe('{"template-id":"tech-detect"}\n');

    const other = createWorkspace(db(), "Client B");
    expect(listScanResults(db(), other.id, scan.id)).toEqual([]);
    expect(getScanResultContent(db(), other.id, file.id)).toBeNull();
  });

  it("deletes a scan with its result files", () => {
    const scan = createScan(db(), WS, { type: "NUCLEI", targetIds: [], targets: [] });
    const file = addScanResult(db(), {
      scanId: scan.id,
      targetId: null,
      filename: "out.txt",
      contentType: "text/plain",
      content: Buffer.from("ok"),
    });
    expect(deleteScan(db(), WS, scan.id)).toBe(true);
    expect(getScanResultContent(db(), WS, file.id)).toBeNull();
    expect(deleteScan(db(), WS, scan.id)).toBe(false);
  });
});
