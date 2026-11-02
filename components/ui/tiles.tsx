import Link from "next/link";
import { cx } from "@/lib/ui/cx";
import { SEVERITY_TONE } from "@/lib/ui/severity";
import type { ThreatLevel } from "@/types/aegis";

/** Tall tinted tile with a big count, one per severity (dashboard "Risks detected"). */
export function SeverityTile({
  level,
  count,
  href,
}: {
  level: ThreatLevel;
  count: number;
  href?: string;
}) {
  const tone = SEVERITY_TONE[level];
  const body = (
    <>
      <span className={cx("text-xs font-medium uppercase tracking-[0.12em]", tone.text)}>
        {tone.label}
      </span>
      <span className="mt-6 font-mono text-4xl font-semibold tabular-nums leading-none text-text">
        {count}
      </span>
    </>
  );
  const className = cx(
    "flex min-h-32 flex-col justify-between rounded-xl border p-4 transition-colors",
    tone.bg,
    tone.border,
    href && "hover:brightness-125",
  );
  return href ? (
    <Link href={href} className={className}>
      {body}
    </Link>
  ) : (
    <div className={className}>{body}</div>
  );
}

const BAR_TONE = {
  accepted: { text: "text-signal-live", bg: "bg-signal-live/10", border: "border-signal-live/30" },
  closed: { text: "text-signal-closed", bg: "bg-signal-closed/10", border: "border-signal-closed/30" },
} as const;

/** Slim count bar under the tiles (Accepted, Closed). */
export function StatBar({
  label,
  count,
  tone,
  href,
}: {
  label: string;
  count: number;
  tone: keyof typeof BAR_TONE;
  href?: string;
}) {
  const style = BAR_TONE[tone];
  const className = cx(
    "flex h-10 items-center justify-between rounded-lg border px-4 text-sm",
    style.bg,
    style.border,
    href && "hover:brightness-125",
  );
  const body = (
    <>
      <span className={cx("font-medium", style.text)}>{label}</span>
      <span className="font-mono tabular-nums">{count}</span>
    </>
  );
  return href ? (
    <Link href={href} className={className}>
      {body}
    </Link>
  ) : (
    <div className={className}>{body}</div>
  );
}
