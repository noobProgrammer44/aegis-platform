/**
 * Geometry for the semicircle health gauge. Score 0 sits at the left end of the arc,
 * 1000 at the right; the arc bulges upward from a centre on the baseline.
 */

export const GAUGE_MAX = 1000;

export interface Point {
  x: number;
  y: number;
}

const clampScore = (score: number): number =>
  Number.isFinite(score) ? Math.min(GAUGE_MAX, Math.max(0, score)) : 0;

/** Point on the arc of radius `r` around (cx, cy) for a score. */
export function arcPoint(cx: number, cy: number, r: number, score: number): Point {
  const theta = Math.PI * (1 - clampScore(score) / GAUGE_MAX);
  return { x: round(cx + r * Math.cos(theta)), y: round(cy - r * Math.sin(theta)) };
}

/** SVG path for the arc between two scores (a band of the gauge). */
export function arcPath(cx: number, cy: number, r: number, from: number, to: number): string {
  const start = arcPoint(cx, cy, r, from);
  const end = arcPoint(cx, cy, r, to);
  return `M ${start.x} ${start.y} A ${r} ${r} 0 0 1 ${end.x} ${end.y}`;
}

const round = (value: number): number => Math.round(value * 100) / 100;
