import type { Finding, Severity } from "@/types/recon";

/** Risk weight per severity. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

/** Weighted risk score across all findings. */
export function riskScore(findings: Finding[]): number {
  return findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
}

/** Weighted risk score grouped by host. */
export function riskScoreByHost(findings: Finding[]): Record<string, number> {
  const scores: Record<string, number> = {};
  for (const f of findings) {
    scores[f.host] = (scores[f.host] ?? 0) + (SEVERITY_WEIGHT[f.severity] ?? 0);
  }
  return scores;
}

/** Count of findings per severity. */
export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/** Findings sorted most-severe first. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}

/** Drop duplicate findings (same host + severity + title). */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.host}|${f.severity}|${f.title}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

export type RiskTone = "critical" | "high" | "elevated" | "low" | "clean";

/** A qualitative risk label derived from the most-severe finding present. */
export function riskLevel(findings: Finding[]): { label: string; tone: RiskTone } {
  const counts = severityCounts(findings);
  if (counts.CRITICAL > 0) return { label: "Critical", tone: "critical" };
  if (counts.HIGH > 0) return { label: "High", tone: "high" };
  if (counts.MEDIUM > 0) return { label: "Elevated", tone: "elevated" };
  if (counts.LOW > 0) return { label: "Low", tone: "low" };
  return { label: "Clean", tone: "clean" };
}
