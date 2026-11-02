import { cx } from "@/lib/ui/cx";
import { SCAN_STATE_LABEL } from "@/lib/ui/format";
import type { Scan, ScanState } from "@/types/aegis";

const TONE: Record<ScanState, string> = {
  QUEUED: "text-text-dim",
  RUNNING: "text-accent",
  STOPPING: "text-text-dim",
  SUCCEEDED: "text-signal-live",
  FAILED: "text-signal-critical",
  BLOCKED: "text-caution",
  STOPPED: "text-text-dim",
};

/** State label, with a progress bar while the scan runs and a note when results are partial. */
export function ScanStateBadge({ scan }: { scan: Pick<Scan, "state" | "progress" | "progressMessage"> }) {
  const running = scan.state === "RUNNING" || scan.state === "STOPPING";
  return (
    <div className="min-w-32">
      <span className={cx("text-xs font-medium", TONE[scan.state])}>
        {SCAN_STATE_LABEL[scan.state]}
        {running && ` · ${scan.progress}%`}
      </span>
      {running && (
        <>
          <div className="mt-1 h-1 overflow-hidden rounded-full bg-white/[0.06]">
            <div className="h-full rounded-full bg-accent transition-[width]" style={{ width: `${Math.max(4, scan.progress)}%` }} />
          </div>
          {scan.progressMessage && (
            <p className="mt-1 max-w-56 truncate text-[11px] text-text-faint" title={scan.progressMessage}>
              {scan.progressMessage}
            </p>
          )}
        </>
      )}
      {!running && scan.state === "SUCCEEDED" && scan.progressMessage && (
        <p className="mt-1 max-w-56 truncate text-[11px] text-caution" title={scan.progressMessage}>
          Partial: some checks were blocked
        </p>
      )}
    </div>
  );
}
