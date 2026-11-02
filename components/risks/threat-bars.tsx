import { cx } from "@/lib/ui/cx";
import { SEVERITY_TONE } from "@/lib/ui/severity";
import type { ThreatLevel } from "@/types/aegis";

const FILLED: Record<ThreatLevel, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/** Four vertical bars, filled up to the severity (1 = low ... 4 = critical). */
export function ThreatBars({ level, className }: { level: ThreatLevel; className?: string }) {
  const filled = FILLED[level];
  return (
    <span className={cx("inline-flex items-end gap-[3px]", className)} role="img" aria-label={`${SEVERITY_TONE[level].label} severity`}>
      {[0, 1, 2, 3].map((i) => (
        <span
          key={i}
          className={cx(
            "h-5 w-[5px] rounded-sm border",
            i < filled ? cx(SEVERITY_TONE[level].dot, "border-transparent") : "border-border-strong bg-transparent",
          )}
        />
      ))}
    </span>
  );
}
