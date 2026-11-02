import Link from "next/link";
import { cx } from "@/lib/ui/cx";

/** Jay's segmented-control look, shared by radio groups and link groups. */
export const SEGMENT_FRAME = "flex rounded-lg border border-border bg-control p-0.5";
export const segmentClass = (active: boolean, caution = false) =>
  cx(
    "flex h-8 cursor-pointer items-center rounded-md px-3 text-[12px] font-medium transition-colors duration-150",
    "has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-accent-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring",
    active
      ? caution
        ? "bg-caution/15 text-caution shadow-[0_0_0_1px_var(--caution-border)]"
        : "bg-surface-raised text-text shadow-[0_0_0_1px_var(--border-strong)]"
      : "text-text-faint hover:text-text-dim",
  );

/** Segmented links (filters that live in the URL, like the dashboard period). */
export function SegmentedLinks({
  items,
  active,
  label,
}: {
  items: readonly { value: string; label: string; href: string }[];
  active: string;
  label: string;
}) {
  return (
    <nav aria-label={label} className={cx(SEGMENT_FRAME, "w-fit")}>
      {items.map((item) => (
        <Link
          key={item.value}
          href={item.href}
          aria-current={item.value === active ? "true" : undefined}
          className={segmentClass(item.value === active)}
        >
          {item.label}
        </Link>
      ))}
    </nav>
  );
}
