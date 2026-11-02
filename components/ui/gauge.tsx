import { GRADE_LABEL } from "@/lib/domain/health-score";
import { arcPath, arcPoint } from "@/lib/ui/gauge";
import { cx } from "@/lib/ui/cx";
import { GRADE_COLOR_VAR, GRADE_TONE } from "@/lib/ui/severity";
import type { HealthGrade } from "@/types/aegis";

/** Grade bands along the arc, matching the 200-point grade boundaries. */
const BANDS: readonly [HealthGrade, number, number][] = [
  ["A", 0, 200],
  ["B", 200, 400],
  ["C", 400, 600],
  ["D", 600, 800],
  ["F", 800, 1000],
];

const WIDTH = 220;
const CX = WIDTH / 2;
const CY = 112;
const RADIUS = 92;
const STROKE = 16;
/** Small gap between bands so each grade reads as its own segment. */
const GAP = 6;

/** Semicircle health gauge: coloured grade bands, a needle at the score, grade below. */
export function HealthGauge({
  score,
  grade,
  className,
}: {
  score: number;
  grade: HealthGrade;
  className?: string;
}) {
  const tip = arcPoint(CX, CY, RADIUS - STROKE - 6, score);
  return (
    <div className={cx("flex flex-col items-center", className)}>
      <svg
        viewBox={`0 0 ${WIDTH} ${CY + 12}`}
        className="w-full max-w-[240px]"
        role="img"
        aria-label={`Health score ${score} of 1000, grade ${grade}`}
      >
        {BANDS.map(([band, from, to]) => (
          <path
            key={band}
            d={arcPath(CX, CY, RADIUS, from + (from === 0 ? 0 : GAP), to - (to === 1000 ? 0 : GAP))}
            fill="none"
            stroke={GRADE_COLOR_VAR[band]}
            strokeWidth={STROKE}
            strokeLinecap="butt"
            opacity={band === grade ? 1 : 0.28}
          />
        ))}
        <line
          x1={CX}
          y1={CY}
          x2={tip.x}
          y2={tip.y}
          stroke="var(--text)"
          strokeWidth={3}
          strokeLinecap="round"
        />
        <circle cx={CX} cy={CY} r={6} fill="var(--text)" />
      </svg>
      <div className="-mt-1 flex items-baseline gap-2">
        <span className="font-mono text-3xl font-semibold tabular-nums">{score}</span>
        <span className="text-xs text-text-faint">/ 1000</span>
      </div>
      <span className={cx("mt-1 text-sm font-medium", GRADE_TONE[grade].text)}>
        {grade} · {GRADE_LABEL[grade]} health
      </span>
    </div>
  );
}
