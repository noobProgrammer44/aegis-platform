import { describe, expect, it } from "vitest";
import {
  countScoredRisks,
  EMPTY_COUNTS,
  gradeFor,
  healthFromCounts,
  healthFromRisks,
  type SeverityCounts,
} from "@/lib/domain/health-score";
import type { ThreatLevel } from "@/types/aegis";

const counts = (partial: Partial<SeverityCounts>): SeverityCounts => ({ ...EMPTY_COUNTS, ...partial });
const score = (partial: Partial<SeverityCounts>) => healthFromCounts(counts(partial)).score;

describe("health score", () => {
  it("is 0 / A with nothing open", () => {
    expect(healthFromCounts(EMPTY_COUNTS)).toEqual({ score: 0, grade: "A" });
  });

  it("starts at the tier floor of the highest open severity", () => {
    expect(score({ LOW: 1 })).toBe(10);
    expect(score({ MEDIUM: 1 })).toBe(150);
    expect(score({ HIGH: 1 })).toBe(350);
    expect(score({ CRITICAL: 1 })).toBe(700);
  });

  it("climbs with more findings of the top severity, with diminishing returns", () => {
    const steps = [1, 2, 3, 4, 10, 50].map((n) => score({ HIGH: n }));
    for (let i = 1; i < steps.length; i++) expect(steps[i]).toBeGreaterThan(steps[i - 1]);
    expect(steps[1] - steps[0]).toBeGreaterThan(steps[2] - steps[1]);
    expect(steps[2] - steps[1]).toBeGreaterThan(steps[3] - steps[2]);
  });

  it("never leaves the tier, however many findings there are", () => {
    expect(score({ HIGH: 10_000, MEDIUM: 10_000, LOW: 10_000 })).toBeLessThanOrEqual(699);
    expect(score({ MEDIUM: 10_000, LOW: 10_000 })).toBeLessThanOrEqual(349);
    expect(score({ LOW: 10_000 })).toBeLessThanOrEqual(149);
    expect(score({ CRITICAL: 10_000, HIGH: 10_000 })).toBeLessThanOrEqual(1000);
  });

  it("lets lower severities lift the score inside the tier, nearer ones more", () => {
    const base = score({ HIGH: 1 });
    expect(score({ HIGH: 1, MEDIUM: 3 })).toBeGreaterThan(base);
    expect(score({ HIGH: 1, MEDIUM: 3 })).toBeGreaterThan(score({ HIGH: 1, LOW: 3 }));
    // Lower findings add less than one more top-severity finding.
    expect(score({ HIGH: 1, MEDIUM: 1 }) - base).toBeLessThan(score({ HIGH: 2 }) - base);
  });

  it("ranks any critical above any number of highs", () => {
    expect(score({ CRITICAL: 1 })).toBeGreaterThan(score({ HIGH: 10_000, MEDIUM: 10_000 }));
  });

  it("ignores negative or fractional counts", () => {
    expect(score({ HIGH: -3, LOW: 1.7 })).toBe(10);
  });

  it("maps scores to grades on the 200-point bands", () => {
    const cases: [number, string][] = [
      [0, "A"], [200, "A"], [201, "B"], [400, "B"], [401, "C"], [600, "C"], [601, "D"], [800, "D"], [801, "F"], [1000, "F"],
    ];
    for (const [value, grade] of cases) expect(gradeFor(value)).toBe(grade);
  });
});

describe("scoring from risks", () => {
  const risk = (threatLevel: ThreatLevel, status: "OPEN" | "CLOSED" = "OPEN", isAccepted = false) => ({
    status,
    isAccepted,
    definition: { threatLevel },
  });

  it("counts only open, non-accepted risks", () => {
    const risks = [risk("CRITICAL", "CLOSED"), risk("CRITICAL", "OPEN", true), risk("HIGH"), risk("LOW"), risk("LOW")];
    expect(countScoredRisks(risks)).toEqual({ CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 2 });
    expect(healthFromRisks(risks).score).toBe(score({ HIGH: 1, LOW: 2 }));
    expect(healthFromRisks([risk("CRITICAL", "CLOSED")])).toEqual({ score: 0, grade: "A" });
  });
});
