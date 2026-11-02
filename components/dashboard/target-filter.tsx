"use client";

import { Crosshair } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";
import { cx } from "@/lib/ui/cx";
import type { Target } from "@/types/aegis";

/** Narrows the whole dashboard to one target; the choice lives in the URL. */
export function TargetFilter({
  targets,
  selected,
  period,
}: {
  targets: readonly Target[];
  selected: string | null;
  period: string;
}) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const choose = (targetId: string) => {
    const params = new URLSearchParams({ period });
    if (targetId) params.set("target", targetId);
    start(() => router.push(`/dashboard?${params.toString()}`));
  };
  return (
    <label className={cx("relative flex h-9 items-center", pending && "opacity-60")}>
      <span className="sr-only">Target</span>
      <Crosshair aria-hidden className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-text-faint" />
      <select
        value={selected ?? ""}
        onChange={(e) => choose(e.target.value)}
        className={cx(
          "h-9 max-w-64 rounded-lg border bg-control pl-8 pr-2.5 text-sm focus:border-accent/60 focus:outline-none",
          selected ? "border-accent/50 text-text" : "border-border text-text-dim",
        )}
      >
        <option value="">All targets</option>
        {targets.map((t) => (
          <option key={t.id} value={t.id}>{t.label || t.target}</option>
        ))}
      </select>
    </label>
  );
}
