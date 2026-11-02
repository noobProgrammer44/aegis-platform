import type {
  AcceptanceRule,
  DetectedRisk,
  Risk,
  ScanRiskCounts,
  ScanType,
  Target,
} from "@/types/aegis";
import { applyAcceptanceRules } from "./acceptance";

/**
 * Merges one finished scan's findings into the stored risks.
 *
 * - detected, never seen before       -> new risk, OPEN          (counted as new open)
 * - detected, stored as CLOSED        -> reopened, OPEN again    (counted as new open)
 * - detected, stored as OPEN          -> still open, refreshed   (counted as still open)
 * - not detected, stored as OPEN, same scanner, target was scanned -> CLOSED
 *
 * Risks on targets the scan skipped, or from other scanners, are never closed: a
 * nuclei scan says nothing about a header finding. Acceptance rules are re-applied to
 * every risk the scan saw. Pure: the caller loads the inputs and saves `changed`.
 */

export interface MergeScanInput {
  workspaceId: string;
  scanId: string;
  scanType: ScanType;
  /** When the scan finished (ISO string); used as the detection / close time. */
  at: string;
  /** Targets the scan actually covered. */
  scannedTargetIds: readonly string[];
  /** Stored risks on the scanned targets, any status. */
  existing: readonly Risk[];
  detected: readonly DetectedRisk[];
  rules: readonly AcceptanceRule[];
  targets: readonly Pick<Target, "id" | "tags">[];
  createId: () => string;
}

export interface MergeScanResult {
  /** Every risk that must be saved: new, reopened, refreshed and closed. */
  changed: Risk[];
  counts: ScanRiskCounts;
  newOpen: Risk[];
  reopened: Risk[];
  stillOpen: Risk[];
  closed: Risk[];
}

const keyOf = (risk: { targetId: string; fingerprint: string }) =>
  `${risk.targetId}\u0000${risk.fingerprint}`;

function dedupeDetected(detected: readonly DetectedRisk[]): DetectedRisk[] {
  const byKey = new Map(detected.map((d) => [keyOf(d), d] as const));
  return [...byKey.values()];
}

export function mergeScanRisks(input: MergeScanInput): MergeScanResult {
  const { at, scanId } = input;
  const existingByKey = new Map(input.existing.map((risk) => [keyOf(risk), risk] as const));
  const targetsById = new Map(input.targets.map((target) => [target.id, target] as const));
  const withRules = (risk: Risk) =>
    applyAcceptanceRules(risk, input.rules, targetsById.get(risk.targetId) ?? null, at);

  const detected = dedupeDetected(input.detected);
  const detectedKeys = new Set(detected.map(keyOf));

  const seen = detected.map((finding) => {
    const stored = existingByKey.get(keyOf(finding));
    if (!stored) return { outcome: "new" as const, risk: withRules(newRisk(input, finding)) };
    const refreshed: Risk = {
      ...stored,
      definition: { ...finding.definition },
      status: "OPEN",
      closedAt: null,
      lastDetectedAt: at,
      lastScanId: scanId,
      updatedAt: at,
    };
    const outcome = stored.status === "CLOSED" ? ("reopened" as const) : ("still" as const);
    return { outcome, risk: withRules(refreshed) };
  });
  const byOutcome = (outcome: (typeof seen)[number]["outcome"]) =>
    seen.filter((entry) => entry.outcome === outcome).map((entry) => entry.risk);
  const newOpen = byOutcome("new");
  const reopened = byOutcome("reopened");
  const stillOpen = byOutcome("still");

  const scanned = new Set(input.scannedTargetIds);
  const closed: Risk[] = input.existing
    .filter(
      (risk) =>
        risk.status === "OPEN" &&
        risk.definition.scanType === input.scanType &&
        scanned.has(risk.targetId) &&
        !detectedKeys.has(keyOf(risk)),
    )
    .map((risk) => ({ ...risk, status: "CLOSED", closedAt: at, lastScanId: scanId, updatedAt: at }));

  return {
    changed: [...newOpen, ...reopened, ...stillOpen, ...closed],
    counts: {
      newOpen: newOpen.length + reopened.length,
      stillOpen: stillOpen.length,
      closed: closed.length,
    },
    newOpen,
    reopened,
    stillOpen,
    closed,
  };
}

function newRisk(input: MergeScanInput, finding: DetectedRisk): Risk {
  return {
    id: input.createId(),
    workspaceId: input.workspaceId,
    targetId: finding.targetId,
    fingerprint: finding.fingerprint,
    definition: { ...finding.definition },
    status: "OPEN",
    isAccepted: false,
    acceptedReason: null,
    acceptedBy: null,
    firstDetectedAt: input.at,
    lastDetectedAt: input.at,
    closedAt: null,
    lastScanId: input.scanId,
    createdAt: input.at,
    updatedAt: input.at,
  };
}
