import type { ReactNode } from "react";
import { GRADE_LABEL } from "@/lib/domain/health-score";
import { cx } from "@/lib/ui/cx";
import { GRADE_TONE, SEVERITY_TONE } from "@/lib/ui/severity";
import type { HealthGrade, ThreatLevel } from "@/types/aegis";

/** Tag chip (targets, filters, email recipients). */
export function Chip({
  children,
  tone = "neutral",
  className,
}: {
  children: ReactNode;
  tone?: "neutral" | "accent";
  className?: string;
}) {
  return (
    <span
      className={cx(
        "inline-flex h-6 items-center gap-1 rounded-md border px-2 text-xs",
        tone === "accent"
          ? "border-accent/30 bg-accent/10 text-accent"
          : "border-border bg-white/[0.04] text-text-dim",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ level }: { level: ThreatLevel }) {
  const tone = SEVERITY_TONE[level];
  return (
    <span
      className={cx(
        "inline-flex h-6 items-center gap-1.5 rounded-md border px-2 text-xs font-medium",
        tone.bg,
        tone.border,
        tone.text,
      )}
    >
      <span className={cx("h-1.5 w-1.5 rounded-full", tone.dot)} aria-hidden="true" />
      {tone.label}
    </span>
  );
}

export function SeverityDot({ level }: { level: ThreatLevel }) {
  return (
    <span
      className={cx("inline-block h-2 w-2 shrink-0 rounded-full", SEVERITY_TONE[level].dot)}
      title={SEVERITY_TONE[level].label}
    />
  );
}

/** Letter grade chip; `withLabel` adds "Good", "Poor", etc. */
export function GradeBadge({
  grade,
  withLabel = false,
  size = "md",
}: {
  grade: HealthGrade;
  withLabel?: boolean;
  size?: "md" | "lg";
}) {
  const tone = GRADE_TONE[grade];
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-md border font-semibold",
        size === "lg" ? "h-8 px-2.5 text-sm" : "h-6 px-2 text-xs",
        tone.bg,
        tone.border,
        tone.text,
      )}
    >
      {grade}
      {withLabel && <span className="font-medium">{GRADE_LABEL[grade]}</span>}
    </span>
  );
}
