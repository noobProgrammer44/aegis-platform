import { SEVERITY_ACCENT } from "@/lib/ui/severity";
import { THREAT_LEVELS, type ThreatLevel } from "@/types/aegis";

/**
 * Severity donut from Jay's quick-scan redesign, for platform risk counts: one glowing
 * arc per severity, the total in the middle.
 */
export function SeverityDonut({
  counts,
  label = "open risks",
  size = "h-36 w-36",
}: {
  counts: Record<ThreatLevel, number>;
  label?: string;
  size?: string;
}) {
  const R = 52;
  const C = 2 * Math.PI * R;
  const total = THREAT_LEVELS.reduce((sum, level) => sum + counts[level], 0);
  const gap = total > 1 ? 3 : 0;
  const arcs = THREAT_LEVELS.filter((level) => counts[level] > 0).map((level, i, shown) => {
    const before = shown.slice(0, i).reduce((sum, l) => sum + counts[l], 0);
    return { level, length: (counts[level] / total) * C, offset: (before / total) * C };
  });
  return (
    <div className={`relative shrink-0 ${size}`}>
      <svg
        viewBox="0 0 140 140"
        className="h-full w-full -rotate-90"
        role="img"
        aria-label={THREAT_LEVELS.map((level) => `${counts[level]} ${level.toLowerCase()}`).join(", ")}
      >
        <circle cx="70" cy="70" r={R} fill="none" stroke="var(--surface-raised)" strokeWidth="14" />
        {arcs.map(({ level, length, offset }) => (
          <circle
            key={level}
            cx="70"
            cy="70"
            r={R}
            fill="none"
            stroke={SEVERITY_ACCENT[level].stroke}
            strokeWidth="14"
            strokeDasharray={`${Math.max(length - gap, 1)} ${C}`}
            strokeDashoffset={-offset}
            style={{ filter: `drop-shadow(0 0 6px ${SEVERITY_ACCENT[level].stroke})` }}
          />
        ))}
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <p className="font-mono text-[28px] font-semibold leading-none tabular-nums text-text">{total}</p>
          <p className="mt-1 text-[11px] text-text-faint">{label}</p>
        </div>
      </div>
    </div>
  );
}
