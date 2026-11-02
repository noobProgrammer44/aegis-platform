/**
 * Domain types for the Aegis platform layer (targets, scans, risks, reports).
 * The recon pipeline's own types live in `types/recon.ts`.
 */

export type ThreatLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const THREAT_LEVELS: readonly ThreatLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export type HealthGrade = "A" | "B" | "C" | "D" | "F";

export interface HealthScore {
  /** 0-1000, lower is better. */
  score: number;
  grade: HealthGrade;
}

export type TargetKind = "domain" | "url" | "ipv4" | "cidr" | "host";
export type TargetSource = "manual" | "discovered" | "import" | "api";

export interface Target {
  id: string;
  workspaceId: string;
  /** Normalized target string: domain, URL, IPv4, CIDR or host:port. */
  target: string;
  kind: TargetKind;
  label: string;
  tags: string[];
  source: TargetSource;
  health: HealthScore;
  lastScannedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type ScanType =
  | "SURFACE"
  | "DISCOVERY"
  | "NUCLEI"
  | "NMAP"
  | "TLS"
  | "EMAIL"
  | "TAKEOVER"
  | "JS_SECRETS"
  | "ZAP_PASSIVE"
  | "ZAP_ACTIVE";

export type ScanState =
  | "QUEUED"
  | "RUNNING"
  | "SUCCEEDED"
  | "FAILED"
  | "BLOCKED"
  | "STOPPING"
  | "STOPPED";

export const TERMINAL_SCAN_STATES: readonly ScanState[] = [
  "SUCCEEDED",
  "FAILED",
  "BLOCKED",
  "STOPPED",
];

export interface ScanRiskCounts {
  newOpen: number;
  stillOpen: number;
  closed: number;
}

export interface Scan {
  id: string;
  workspaceId: string;
  type: ScanType;
  state: ScanState;
  progress: number;
  progressMessage: string | null;
  targetIds: string[];
  /** Target strings as requested, for display even after a target is deleted. */
  targets: string[];
  skippedTargets: { target: string; reason: string }[];
  risks: ScanRiskCounts;
  scheduledBy: string | null;
  error: string | null;
  aiSummary: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface ScanResultFile {
  id: string;
  scanId: string;
  targetId: string | null;
  filename: string;
  contentType: string;
  size: number;
  createdAt: string;
}

export type RiskStatus = "OPEN" | "CLOSED";

export interface RiskDefinition {
  scanType: ScanType;
  title: string;
  threatLevel: ThreatLevel;
  description: string;
  solution: string;
  references: string[];
  cvss: string | null;
  /** Scanner evidence: matched URL, port, header, CVE ids, etc. */
  additionalInfo: Record<string, unknown>;
}

export interface Risk {
  id: string;
  workspaceId: string;
  targetId: string;
  /** Stable identity of the finding on this target across scans. */
  fingerprint: string;
  definition: RiskDefinition;
  status: RiskStatus;
  isAccepted: boolean;
  acceptedReason: string | null;
  /** "manual" or the id of the acceptance rule that matched. */
  acceptedBy: string | null;
  firstDetectedAt: string;
  lastDetectedAt: string;
  closedAt: string | null;
  lastScanId: string | null;
  createdAt: string;
  updatedAt: string;
}

/** A finding as produced by a scanner, before it is merged into stored risks. */
export interface DetectedRisk {
  targetId: string;
  fingerprint: string;
  definition: RiskDefinition;
}

export type Schedule = "ONCE" | "DAILY" | "WEEKLY" | "MONTHLY" | "QUARTERLY" | "CUSTOM";
export type NotifyPolicy = "NEVER" | "ON_CHANGES" | "ALWAYS";

export interface TargetsFilter {
  targetIds: string[];
  tags: string[];
}

export interface ScheduledScan {
  id: string;
  workspaceId: string;
  name: string;
  schedule: Schedule;
  /** Only for CUSTOM: repeat every N days. */
  intervalDays: number | null;
  scanTypes: ScanType[];
  targetsFilter: TargetsFilter;
  notifyEmails: string[];
  notifyPolicy: NotifyPolicy;
  startAt: string;
  nextRun: string | null;
  lastRan: string | null;
  enabled: boolean;
  createdAt: string;
}

/** Field conditions an acceptance rule can match on. Empty arrays match anything. */
export interface AcceptanceQuery {
  scanTypes: ScanType[];
  threatLevels: ThreatLevel[];
  targetTags: string[];
  targetIds: string[];
  /** Case-insensitive regular expression tested against the risk title. */
  titlePattern: string | null;
  /** Ports from `additionalInfo.port`. */
  ports: number[];
}

export interface AcceptanceRule {
  id: string;
  workspaceId: string;
  name: string;
  query: AcceptanceQuery;
  note: string;
  enabled: boolean;
  createdAt: string;
}

export type AuthorizationMethod = "local" | "attested" | "dns";
export type AuthorizationTier = 0 | 1 | 2;

export interface Authorization {
  id: string;
  workspaceId: string;
  /** Domain, IPv4 or CIDR the authorization covers (subdomains inherit). */
  scope: string;
  method: AuthorizationMethod;
  /** DNS verification token (method "dns"). */
  token: string | null;
  verified: boolean;
  attestedBy: string | null;
  note: string | null;
  createdAt: string;
  verifiedAt: string | null;
}

export interface AuditEntry {
  id: string;
  workspaceId: string;
  at: string;
  actor: string;
  action: string;
  subject: string;
  details: Record<string, unknown>;
}

export interface DiscoveredDomain {
  id: string;
  workspaceId: string;
  name: string;
  viaTargetId: string | null;
  viaTarget: string | null;
  resolves: boolean;
  records: Record<string, string[]>;
  firstSeen: string;
  lastSeen: string;
  promotedTargetId: string | null;
}

export type ReportFormat = "HTML" | "JSON" | "CSV";

export type ReportSection =
  | "executive_summary"
  | "ai_summary"
  | "coverage"
  | "target_breakdown"
  | "risk_details"
  | "accepted_risks";

export interface ReportFilters {
  targets: TargetsFilter;
  threatLevels: ThreatLevel[];
  includeAccepted: boolean;
  includeClosed: boolean;
}

export interface Report {
  id: string;
  workspaceId: string;
  name: string;
  format: ReportFormat;
  filters: ReportFilters;
  sections: ReportSection[];
  scheduledReportId: string | null;
  aiSummary: string | null;
  createdAt: string;
}

export interface ScheduledReport {
  id: string;
  workspaceId: string;
  name: string;
  format: ReportFormat;
  filters: ReportFilters;
  sections: ReportSection[];
  schedule: Schedule;
  intervalDays: number | null;
  emails: string[];
  startAt: string;
  nextRun: string | null;
  lastRan: string | null;
  enabled: boolean;
  createdAt: string;
}

export type WebhookKind = "generic" | "slack";
export type WebhookEvent =
  | "scan.succeeded"
  | "scan.failed"
  | "risk.new_open"
  | "risk.closed"
  | "report.created";

export interface Webhook {
  id: string;
  workspaceId: string;
  name: string;
  kind: WebhookKind;
  url: string;
  /** HMAC-SHA256 signing secret (generic webhooks). */
  secret: string;
  events: WebhookEvent[];
  enabled: boolean;
  createdAt: string;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  event: WebhookEvent;
  ok: boolean;
  statusCode: number | null;
  error: string | null;
  at: string;
}

export interface ApiKey {
  id: string;
  workspaceId: string;
  name: string;
  /** First characters of the key, shown so users can tell keys apart. */
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export type NotificationStatus = "sent" | "outbox" | "failed";

export interface Notification {
  id: string;
  workspaceId: string;
  channel: "email";
  to: string[];
  subject: string;
  body: string;
  status: NotificationStatus;
  error: string | null;
  createdAt: string;
}

export interface Workspace {
  id: string;
  name: string;
  createdAt: string;
}

export interface HealthSnapshot {
  workspaceId: string;
  targetId: string | null;
  day: string;
  score: number;
  grade: HealthGrade;
  counts: Record<ThreatLevel, number>;
  assets: number;
}
