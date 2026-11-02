import { cx } from "@/lib/ui/cx";
import type { Risk } from "@/types/aegis";

/** OPEN / CLOSED / ACCEPTED pill. */
export function StatusPill({ risk }: { risk: Pick<Risk, "status" | "isAccepted"> }) {
  const [label, tone] =
    risk.status === "CLOSED"
      ? ["Closed", "border-signal-closed/40 bg-signal-closed/10 text-signal-closed"]
      : risk.isAccepted
        ? ["Accepted", "border-signal-live/35 bg-signal-live/[0.08] text-signal-live"]
        : ["Open", "border-accent/35 bg-accent/[0.08] text-accent"];
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.08em]", tone)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label}
    </span>
  );
}
