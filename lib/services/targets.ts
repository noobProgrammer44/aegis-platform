import type { DB } from "@/lib/db/client";
import { listAuthorizations } from "@/lib/db/repos/authorizations";
import { listDiscoveredDomains } from "@/lib/db/repos/discovered-domains";
import { listRisks } from "@/lib/db/repos/risks";
import { listScans } from "@/lib/db/repos/scans";
import { listTargets } from "@/lib/db/repos/targets";
import { DNS_TOKEN_PREFIX, targetAuthorization, type Tier } from "@/lib/domain/authorization";
import { countScoredRisks } from "@/lib/domain/health-score";
import type { TargetRow } from "@/lib/domain/target-table";
import {
  THREAT_LEVELS,
  type DiscoveredDomain,
  type RiskStatus,
  type ScanState,
  type ScanType,
  type ThreatLevel,
} from "@/types/aegis";

/** Data for the Targets page: table rows plus the compact detail each drawer shows. */

export interface RiskSummary {
  id: string;
  title: string;
  threatLevel: ThreatLevel;
  scanType: ScanType;
  status: RiskStatus;
  isAccepted: boolean;
  firstDetectedAt: string;
  lastDetectedAt: string;
}

export interface ScanSummary {
  id: string;
  type: ScanType;
  state: ScanState;
  createdAt: string;
}

export interface TargetDetail {
  risks: RiskSummary[];
  scans: ScanSummary[];
}

/** What the target drawer's authorization panel shows. */
export interface TargetAuthView {
  tier: Tier;
  method: "local" | "attested" | "dns" | null;
  scope: string;
  dnsVerifiable: boolean;
  /** Record that grants the current tier (for revoking); null when local or none. */
  recordId: string | null;
  /** Covered through a parent domain's authorization (e.g. example.com for app.example.com). */
  inheritedFrom: string | null;
  note: string | null;
  /** TXT value waiting to be published, when a DNS check is in progress. */
  pendingDnsValue: string | null;
}

export interface TargetsPageData {
  rows: TargetRow[];
  discovered: DiscoveredDomain[];
  details: Record<string, TargetDetail>;
  auth: Record<string, TargetAuthView>;
}

const SCANS_PER_TARGET = 10;

export function loadTargetsPage(db: DB, workspaceId: string): TargetsPageData {
  const targets = listTargets(db, workspaceId);
  const risks = listRisks(db, workspaceId);
  const scans = listScans(db, workspaceId, { limit: 500 });
  const discovered = listDiscoveredDomains(db, workspaceId);
  const records = listAuthorizations(db, workspaceId);
  const verified = records.filter((r) => r.verified);

  const rows: TargetRow[] = targets.map((target) => {
    const own = risks.filter((r) => r.targetId === target.id);
    const counts = countScoredRisks(own);
    return {
      target,
      counts,
      openTotal: THREAT_LEVELS.reduce((sum, level) => sum + counts[level], 0),
      closedTotal: own.filter((r) => r.status === "CLOSED").length,
      discoveredCount: discovered.filter((d) => d.viaTargetId === target.id).length,
    };
  });

  const details = Object.fromEntries(
    targets.map((target) => [
      target.id,
      {
        risks: risks
          .filter((r) => r.targetId === target.id)
          .map((r) => ({
            id: r.id,
            title: r.definition.title,
            threatLevel: r.definition.threatLevel,
            scanType: r.definition.scanType,
            status: r.status,
            isAccepted: r.isAccepted,
            firstDetectedAt: r.firstDetectedAt,
            lastDetectedAt: r.lastDetectedAt,
          })),
        scans: scans
          .filter((s) => s.targetIds.includes(target.id))
          .slice(0, SCANS_PER_TARGET)
          .map((s) => ({ id: s.id, type: s.type, state: s.state, createdAt: s.createdAt })),
      },
    ]),
  );

  const auth = Object.fromEntries(
    targets.map((target) => {
      const a = targetAuthorization(target, verified);
      const pending = records.find((r) => r.method === "dns" && !r.verified && r.scope === a.scope && r.token);
      const view: TargetAuthView = {
        tier: a.tier,
        method: a.method,
        scope: a.scope,
        dnsVerifiable: a.dnsVerifiable,
        recordId: a.record?.id ?? null,
        inheritedFrom: a.record && a.record.scope !== a.scope ? a.record.scope : null,
        note: a.record?.note ?? null,
        pendingDnsValue: a.tier < 2 && pending?.token ? `${DNS_TOKEN_PREFIX}${pending.token}` : null,
      };
      return [target.id, view];
    }),
  );

  return { rows, discovered, details, auth };
}
