import { getDb, nowIso, type DB } from "@/lib/db/client";
import { getScan, listScansInStates, updateScan } from "@/lib/db/repos/scans";
import type { Scan } from "@/types/aegis";
import { executeScan } from "./execute";
import { SCANNERS } from "./scanners";

/**
 * In-process scan queue. The database is the queue: QUEUED scans are picked oldest
 * first, at most CONCURRENCY at a time. State lives on globalThis so Next.js dev-mode
 * module reloads don't start a second runner.
 */

const CONCURRENCY = 2;

interface RunnerState {
  running: Map<string, AbortController>;
  recovered: boolean;
}

const globalForRunner = globalThis as unknown as { __aegisRunner?: RunnerState };

function state(): RunnerState {
  globalForRunner.__aegisRunner ??= { running: new Map(), recovered: false };
  return globalForRunner.__aegisRunner;
}

/** After a restart nothing is actually running: fail what was mid-flight. Runs once. */
function recover(db: DB): void {
  const runner = state();
  if (runner.recovered) return;
  runner.recovered = true;
  for (const scan of listScansInStates(db, ["RUNNING", "STOPPING"])) {
    updateScan(db, scan.workspaceId, scan.id, {
      state: scan.state === "STOPPING" ? "STOPPED" : "FAILED",
      error: scan.state === "STOPPING" ? null : "Interrupted because Aegis restarted.",
      finishedAt: nowIso(),
    });
  }
}

function start(db: DB, scan: Scan): void {
  const runner = state();
  const controller = new AbortController();
  runner.running.set(scan.id, controller);
  executeScan(db, scan, controller.signal, SCANNERS)
    .catch((err: unknown) => {
      updateScan(db, scan.workspaceId, scan.id, {
        state: "FAILED",
        error: err instanceof Error ? err.message : "Scan failed.",
        finishedAt: nowIso(),
      });
    })
    .finally(() => {
      runner.running.delete(scan.id);
      pumpQueue(db);
    });
}

/** Starts queued scans while there is capacity. Safe to call any time. */
export function pumpQueue(db: DB = getDb()): void {
  recover(db);
  const runner = state();
  const free = CONCURRENCY - runner.running.size;
  if (free <= 0) return;
  listScansInStates(db, ["QUEUED"])
    .filter((scan) => !runner.running.has(scan.id))
    .slice(0, free)
    .forEach((scan) => start(db, scan));
}

/**
 * Stops a scan: a queued one is cancelled straight away, a running one is aborted and
 * finishes as STOPPED once its current step returns.
 */
export function stopScan(workspaceId: string, scanId: string, db: DB = getDb()): Scan | null {
  const scan = getScan(db, workspaceId, scanId);
  if (!scan) return null;
  if (scan.state === "QUEUED") {
    return updateScan(db, workspaceId, scanId, { state: "STOPPED", finishedAt: nowIso() });
  }
  const controller = state().running.get(scanId);
  if (scan.state === "RUNNING" && controller) {
    controller.abort();
    return updateScan(db, workspaceId, scanId, { state: "STOPPING", progressMessage: "Stopping" });
  }
  return scan;
}

export function isRunning(scanId: string): boolean {
  return state().running.has(scanId);
}
