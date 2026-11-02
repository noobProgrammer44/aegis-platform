import {
  THREAT_LEVELS,
  type HealthGrade,
  type HealthScore,
  type Risk,
  type ThreatLevel,
} from "@/types/aegis";

/**
 * Health score, 0-1000 where lower is better (model from docs/hostedscan-reference).
 *
 * The highest open severity picks a tier and the score starts at that tier's floor.
 * More findings of that severity climb toward the tier's ceiling with diminishing
 * returns (up to 80% of the tier); lower severities add a smaller, capped lift (up to
 * 20%), so no number of lower findings can push the score into the next tier.
 * Only open, non-accepted risks count.
 */

export type SeverityCounts = Record<ThreatLevel, number>;

export const EMPTY_COUNTS: SeverityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

const TIERS: Record<ThreatLevel, { floor: number; ceiling: number }> = {
  LOW: { floor: 10, ceiling: 149 },
  MEDIUM: { floor: 150, ceiling: 349 },
  HIGH: { floor: 350, ceiling: 699 },
  CRITICAL: { floor: 700, ceiling: 1000 },
};

const TOP_SHARE = 0.8;
/** Each further top-severity finding closes 30% of the remaining gap. */
const TOP_DECAY = 0.7;
const LOWER_SHARE = 0.2;
const LOWER_DECAY = 0.8;
/** How much a lower finding weighs: one level below the top, two below, three below. */
const LOWER_WEIGHT_BY_DISTANCE = [1, 0.3, 0.1];

const GRADE_CEILINGS: readonly [HealthGrade, number][] = [
  ["A", 200],
  ["B", 400],
  ["C", 600],
  ["D", 800],
  ["F", 1000],
];

export const GRADE_LABEL: Record<HealthGrade, string> = {
  A: "Excellent",
  B: "Good",
  C: "Fair",
  D: "Poor",
  F: "Critical",
};

export function gradeFor(score: number): HealthGrade {
  return GRADE_CEILINGS.find(([, ceiling]) => score <= ceiling)?.[0] ?? "F";
}

const safeCount = (value: number): number =>
  Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;

export function healthFromCounts(counts: SeverityCounts): HealthScore {
  const clean: SeverityCounts = {
    CRITICAL: safeCount(counts.CRITICAL),
    HIGH: safeCount(counts.HIGH),
    MEDIUM: safeCount(counts.MEDIUM),
    LOW: safeCount(counts.LOW),
  };
  // THREAT_LEVELS is ordered most severe first.
  const topIndex = THREAT_LEVELS.findIndex((level) => clean[level] > 0);
  if (topIndex === -1) return { score: 0, grade: "A" };

  const top = THREAT_LEVELS[topIndex];
  const { floor, ceiling } = TIERS[top];
  const span = ceiling - floor;
  const topLift = TOP_SHARE * span * (1 - TOP_DECAY ** (clean[top] - 1));
  const lowerWeight = THREAT_LEVELS.slice(topIndex + 1).reduce(
    (sum, level, distance) => sum + clean[level] * LOWER_WEIGHT_BY_DISTANCE[distance],
    0,
  );
  const lowerLift = LOWER_SHARE * span * (1 - LOWER_DECAY ** lowerWeight);
  const score = Math.min(ceiling, Math.round(floor + topLift + lowerLift));
  return { score, grade: gradeFor(score) };
}

type ScoredRisk = Pick<Risk, "status" | "isAccepted"> & {
  definition: Pick<Risk["definition"], "threatLevel">;
};

/** Open, non-accepted risks per severity: what the score is computed from. */
export function countScoredRisks(risks: readonly ScoredRisk[]): SeverityCounts {
  return risks
    .filter((risk) => risk.status === "OPEN" && !risk.isAccepted)
    .reduce(
      (counts, risk) => ({
        ...counts,
        [risk.definition.threatLevel]: counts[risk.definition.threatLevel] + 1,
      }),
      EMPTY_COUNTS,
    );
}

export function healthFromRisks(risks: readonly ScoredRisk[]): HealthScore {
  return healthFromCounts(countScoredRisks(risks));
}
