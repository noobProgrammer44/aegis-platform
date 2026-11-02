import type { Risk, RiskDefinition, RiskStatus, ScanType, ThreatLevel } from "@/types/aegis";
import { newId, nowIso, parseJson, toBool, toJson, type DB } from "../client";
import { insertOrDuplicate } from "../errors";
import { placeholders } from "../sql";

/**
 * Stored risks. The lifecycle (new / still open / closed / reopened) is decided by
 * pure domain code; this module only reads rows and persists the Risk objects it returns.
 */

interface RiskRow {
  id: string;
  workspace_id: string;
  target_id: string;
  fingerprint: string;
  scan_type: ScanType;
  title: string;
  threat_level: ThreatLevel;
  description: string;
  solution: string;
  refs: string;
  cvss: string | null;
  additional_info: string;
  status: RiskStatus;
  is_accepted: number;
  accepted_reason: string | null;
  accepted_by: string | null;
  first_detected_at: string;
  last_detected_at: string;
  closed_at: string | null;
  last_scan_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface NewRisk {
  targetId: string;
  fingerprint: string;
  definition: RiskDefinition;
  lastScanId: string | null;
  detectedAt?: string;
}

export interface RiskFilter {
  status?: RiskStatus;
  isAccepted?: boolean;
  targetIds?: string[];
  scanTypes?: ScanType[];
  threatLevels?: ThreatLevel[];
}

const toRisk = (row: RiskRow): Risk => ({
  id: row.id,
  workspaceId: row.workspace_id,
  targetId: row.target_id,
  fingerprint: row.fingerprint,
  definition: {
    scanType: row.scan_type,
    title: row.title,
    threatLevel: row.threat_level,
    description: row.description,
    solution: row.solution,
    references: parseJson<string[]>(row.refs, []),
    cvss: row.cvss,
    additionalInfo: parseJson<Record<string, unknown>>(row.additional_info, {}),
  },
  status: row.status,
  isAccepted: toBool(row.is_accepted),
  acceptedReason: row.accepted_reason,
  acceptedBy: row.accepted_by,
  firstDetectedAt: row.first_detected_at,
  lastDetectedAt: row.last_detected_at,
  closedAt: row.closed_at,
  lastScanId: row.last_scan_id,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
});

const toParams = (r: Risk) => ({
  id: r.id,
  workspace_id: r.workspaceId,
  target_id: r.targetId,
  fingerprint: r.fingerprint,
  scan_type: r.definition.scanType,
  title: r.definition.title,
  threat_level: r.definition.threatLevel,
  description: r.definition.description,
  solution: r.definition.solution,
  refs: toJson(r.definition.references),
  cvss: r.definition.cvss,
  additional_info: toJson(r.definition.additionalInfo),
  status: r.status,
  is_accepted: r.isAccepted ? 1 : 0,
  accepted_reason: r.acceptedReason,
  accepted_by: r.acceptedBy,
  first_detected_at: r.firstDetectedAt,
  last_detected_at: r.lastDetectedAt,
  closed_at: r.closedAt,
  last_scan_id: r.lastScanId,
  created_at: r.createdAt,
  updated_at: r.updatedAt,
});

const UPSERT_SQL = `INSERT INTO risks (id, workspace_id, target_id, fingerprint, scan_type, title,
    threat_level, description, solution, refs, cvss, additional_info, status, is_accepted,
    accepted_reason, accepted_by, first_detected_at, last_detected_at, closed_at, last_scan_id,
    created_at, updated_at)
  VALUES (@id, @workspace_id, @target_id, @fingerprint, @scan_type, @title, @threat_level,
    @description, @solution, @refs, @cvss, @additional_info, @status, @is_accepted,
    @accepted_reason, @accepted_by, @first_detected_at, @last_detected_at, @closed_at,
    @last_scan_id, @created_at, @updated_at)
  ON CONFLICT (id) DO UPDATE SET scan_type = excluded.scan_type, title = excluded.title,
    threat_level = excluded.threat_level, description = excluded.description,
    solution = excluded.solution, refs = excluded.refs, cvss = excluded.cvss,
    additional_info = excluded.additional_info, status = excluded.status,
    is_accepted = excluded.is_accepted, accepted_reason = excluded.accepted_reason,
    accepted_by = excluded.accepted_by, last_detected_at = excluded.last_detected_at,
    closed_at = excluded.closed_at, last_scan_id = excluded.last_scan_id,
    updated_at = excluded.updated_at`;

/** Builds (without saving) a newly detected, open, unaccepted risk. */
export function buildRisk(workspaceId: string, input: NewRisk): Risk {
  const at = input.detectedAt ?? nowIso();
  return {
    id: newId("rsk"),
    workspaceId,
    targetId: input.targetId,
    fingerprint: input.fingerprint,
    definition: { ...input.definition },
    status: "OPEN",
    isAccepted: false,
    acceptedReason: null,
    acceptedBy: null,
    firstDetectedAt: at,
    lastDetectedAt: at,
    closedAt: null,
    lastScanId: input.lastScanId,
    createdAt: at,
    updatedAt: at,
  };
}

export function createRisk(db: DB, workspaceId: string, input: NewRisk): Risk {
  return saveRisk(db, buildRisk(workspaceId, input));
}

/** Insert or update by id. A second risk with the same target + fingerprint is a DuplicateError. */
export function saveRisk(db: DB, risk: Risk): Risk {
  insertOrDuplicate(
    () => db.prepare(UPSERT_SQL).run(toParams(risk)),
    `Risk ${risk.fingerprint} already exists on target ${risk.targetId}`,
  );
  return risk;
}

/** Saves all risks in one transaction (a scan's merge result lands all-or-nothing). */
export function saveRisks(db: DB, risks: readonly Risk[]): Risk[] {
  return db.transaction(() => risks.map((risk) => saveRisk(db, risk)))();
}

export function getRisk(db: DB, workspaceId: string, id: string): Risk | null {
  const row = db
    .prepare("SELECT * FROM risks WHERE workspace_id = ? AND id = ?")
    .get(workspaceId, id) as RiskRow | undefined;
  return row ? toRisk(row) : null;
}

export function findRisk(
  db: DB,
  workspaceId: string,
  targetId: string,
  fingerprint: string,
): Risk | null {
  const row = db
    .prepare("SELECT * FROM risks WHERE workspace_id = ? AND target_id = ? AND fingerprint = ?")
    .get(workspaceId, targetId, fingerprint) as RiskRow | undefined;
  return row ? toRisk(row) : null;
}

/** Most recently detected first. Empty filter arrays match everything. */
export function listRisks(db: DB, workspaceId: string, filter: RiskFilter = {}): Risk[] {
  const clauses = ["workspace_id = ?"];
  const params: unknown[] = [workspaceId];
  if (filter.status) {
    clauses.push("status = ?");
    params.push(filter.status);
  }
  if (filter.isAccepted !== undefined) {
    clauses.push("is_accepted = ?");
    params.push(filter.isAccepted ? 1 : 0);
  }
  const inFilters: [string, readonly string[] | undefined][] = [
    ["target_id", filter.targetIds],
    ["scan_type", filter.scanTypes],
    ["threat_level", filter.threatLevels],
  ];
  for (const [column, values] of inFilters) {
    if (values && values.length > 0) {
      clauses.push(`${column} IN (${placeholders(values.length)})`);
      params.push(...values);
    }
  }
  const rows = db
    .prepare(
      `SELECT * FROM risks WHERE ${clauses.join(" AND ")} ORDER BY last_detected_at DESC, id`,
    )
    .all(...params) as RiskRow[];
  return rows.map(toRisk);
}

/** Accept (suppress) or un-accept a risk. `by` is "manual" or an acceptance rule id. */
export function setRiskAcceptance(
  db: DB,
  workspaceId: string,
  id: string,
  acceptance: { accepted: boolean; reason: string | null; by: string | null },
): Risk | null {
  const current = getRisk(db, workspaceId, id);
  if (!current) return null;
  return saveRisk(db, {
    ...current,
    isAccepted: acceptance.accepted,
    acceptedReason: acceptance.accepted ? acceptance.reason : null,
    acceptedBy: acceptance.accepted ? acceptance.by : null,
    updatedAt: nowIso(),
  });
}
