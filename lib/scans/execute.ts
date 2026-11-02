import { nowIso, type DB } from "@/lib/db/client";
import { listAcceptanceRules } from "@/lib/db/repos/acceptance-rules";
import { appendAudit } from "@/lib/db/repos/audit-log";
import { upsertDiscoveredDomain } from "@/lib/db/repos/discovered-domains";
import { listRisks, saveRisks } from "@/lib/db/repos/risks";
import { addScanResult } from "@/lib/db/repos/scan-results";
import { getScan, updateScan } from "@/lib/db/repos/scans";
import { getTarget } from "@/lib/db/repos/targets";
import { mergeScanRisks } from "@/lib/domain/risk-lifecycle";
import type { ScanIntensity } from "@/lib/recon/intensity";
import type { DetectedRisk, Scan, ScanType, Target } from "@/types/aegis";
import { activeScanAllowed } from "./gate";
import { newRiskId, recomputeHealth } from "./health";
import type { Scanner, ScannerOutput } from "./scanners";

/**
 * Runs one queued scan to completion: gate each target, run the scanner, store raw
 * results, merge findings into risks, recompute health. A stopped scan merges nothing,
 * because partial results would wrongly close risks that simply weren't checked.
 */

const ACTOR = "scanner";

type TargetOutcome =
  | { target: Target; output: ScannerOutput }
  | { target: Target | null; label: string; skipped: string; blocked: boolean };

async function runTarget(
  scanner: Scanner,
  target: Target,
  intensity: ScanIntensity,
  signal: AbortSignal,
  progress: (message: string) => void,
): Promise<TargetOutcome> {
  if (scanner.mode === "active") {
    const gate = activeScanAllowed(target);
    if (!gate.allowed) return { target, label: target.target, skipped: gate.reason ?? "Not authorized.", blocked: true };
  }
  try {
    const output = await scanner.run({ target, intensity, signal, progress });
    return output.skipped
      ? { target, label: target.target, skipped: output.skipped, blocked: false }
      : { target, output };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Scanner failed.";
    return { target, label: target.target, skipped: message, blocked: false };
  }
}

export async function executeScan(
  db: DB,
  queued: Scan,
  signal: AbortSignal,
  scanners: Partial<Record<ScanType, Scanner>>,
): Promise<Scan | null> {
  const ws = queued.workspaceId;
  const update = (patch: Parameters<typeof updateScan>[3]) => updateScan(db, ws, queued.id, patch);
  const scanner = scanners[queued.type];
  if (!scanner) {
    return update({ state: "FAILED", error: `The ${queued.type} scanner isn't available yet.`, finishedAt: nowIso() });
  }

  update({ state: "RUNNING", startedAt: nowIso(), progress: 0, progressMessage: "Starting" });
  appendAudit(db, ws, { actor: ACTOR, action: "scan.started", subject: queued.id, details: { type: queued.type, targets: queued.targets } });

  const outcomes: TargetOutcome[] = [];
  for (const [index, targetId] of queued.targetIds.entries()) {
    if (signal.aborted) break;
    const target = getTarget(db, ws, targetId);
    const step = (message: string) =>
      update({ progress: Math.round((index / queued.targetIds.length) * 90), progressMessage: `${target?.target ?? targetId}: ${message}` });
    outcomes.push(
      target
        ? await runTarget(scanner, target, queued.intensity, signal, step)
        : { target: null, label: queued.targets[index] ?? targetId, skipped: "Target was deleted.", blocked: false },
    );
  }

  if (signal.aborted) {
    appendAudit(db, ws, { actor: ACTOR, action: "scan.stopped", subject: queued.id });
    return update({ state: "STOPPED", progressMessage: "Stopped before finishing", finishedAt: nowIso() });
  }
  return finishScan(db, queued, outcomes);
}

function finishScan(db: DB, scan: Scan, outcomes: TargetOutcome[]): Scan | null {
  const ws = scan.workspaceId;
  const at = nowIso();
  const done = outcomes.flatMap((o) => ("output" in o ? [o] : []));
  const skipped = outcomes.flatMap((o) => ("output" in o ? [] : [o]));

  addScanResult(db, {
    scanId: scan.id,
    targetId: null,
    filename: `${scan.type.toLowerCase()}-results.json`,
    contentType: "application/json",
    content: JSON.stringify(
      {
        scan: { id: scan.id, type: scan.type, finishedAt: at },
        targets: done.map((o) => ({ target: o.target.target, raw: o.output.raw })),
        skipped: skipped.map((o) => ({ target: o.label, reason: o.skipped })),
      },
      null,
      2,
    ),
  });

  for (const o of done) {
    for (const domain of o.output.discovered) upsertDiscoveredDomain(db, ws, domain, at);
  }

  const scannedIds = done.map((o) => o.target.id);
  const detected: DetectedRisk[] = done.flatMap((o) => o.output.risks);
  const merge = mergeScanRisks({
    workspaceId: ws,
    scanId: scan.id,
    scanType: scan.type,
    at,
    scannedTargetIds: scannedIds,
    existing: scannedIds.length > 0 ? listRisks(db, ws, { targetIds: scannedIds }) : [],
    detected,
    rules: listAcceptanceRules(db, ws, { enabledOnly: true }),
    targets: done.map((o) => o.target),
    createId: newRiskId,
  });
  saveRisks(db, merge.changed);
  if (scannedIds.length > 0) recomputeHealth(db, ws, scannedIds, at);

  const allBlocked = done.length === 0 && skipped.length > 0 && skipped.every((o) => o.blocked);
  const allFailed = done.length === 0 && skipped.length > 0;
  const state = allBlocked ? "BLOCKED" : allFailed ? "FAILED" : "SUCCEEDED";
  appendAudit(db, ws, {
    actor: ACTOR,
    action: state === "BLOCKED" ? "scan.blocked" : "scan.finished",
    subject: scan.id,
    details: { state, ...merge.counts, skipped: skipped.length },
  });
  updateScan(db, ws, scan.id, {
    state,
    progress: 100,
    progressMessage: null,
    risks: merge.counts,
    skippedTargets: skipped.map((o) => ({ target: o.label, reason: o.skipped })),
    error: allFailed ? skipped[0].skipped : null,
    finishedAt: at,
  });
  return getScan(db, ws, scan.id);
}
