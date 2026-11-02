import { createHash } from "node:crypto";
import type { DetectedRisk, ScanType, ThreatLevel } from "@/types/aegis";
import type { Finding } from "@/types/recon";

/**
 * Turns recon-pipeline findings into risks the lifecycle can track across scans.
 *
 * INFO findings are not risks, except open ports: those become LOW so they show up and
 * can be accepted per port (e.g. 80/443 on web servers). Other INFO findings stay in
 * the scan's raw results only.
 */

const LEVELS: Record<Exclude<Finding["severity"], "INFO">, ThreatLevel> = {
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
};

export function threatLevelFor(finding: Finding): ThreatLevel | null {
  if (finding.severity === "INFO") return finding.port !== undefined ? "LOW" : null;
  return LEVELS[finding.severity];
}

/**
 * Stable identity of a finding on a target. Numbers in the title are masked so a
 * finding like "TLS certificate expires in 9 days" stays the same risk as the count
 * changes, instead of closing and reopening every day.
 */
export function riskFingerprint(scanType: ScanType, finding: Finding): string {
  const stableTitle = finding.title.toLowerCase().replace(/\d+/g, "#");
  return createHash("sha256")
    .update(JSON.stringify([scanType, stableTitle, finding.host.toLowerCase(), finding.port ?? null]))
    .digest("hex")
    .slice(0, 24);
}

export function toDetectedRisks(
  scanType: ScanType,
  targetId: string,
  findings: readonly Finding[],
): DetectedRisk[] {
  return findings.flatMap((finding) => {
    const threatLevel = threatLevelFor(finding);
    if (!threatLevel) return [];
    const additionalInfo: Record<string, unknown> = {
      host: finding.host,
      ...(finding.port !== undefined ? { port: finding.port } : {}),
      ...(finding.service ? { service: finding.service } : {}),
      ...(finding.details ?? {}),
    };
    return [
      {
        targetId,
        fingerprint: riskFingerprint(scanType, finding),
        definition: {
          scanType,
          title: finding.title,
          threatLevel,
          description: finding.description,
          solution: finding.recommendation,
          references: [...(finding.references ?? [])],
          cvss: null,
          additionalInfo,
        },
      },
    ];
  });
}
