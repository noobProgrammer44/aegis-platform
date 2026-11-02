"use client";

import { Crosshair, Plus } from "lucide-react";
import Link from "next/link";
import { useCallback, useState } from "react";
import { Button } from "@/components/ui/button";
import { EmptyState, PageHeader } from "@/components/ui/card";
import type { TargetsPageData } from "@/lib/services/targets";
import { cx } from "@/lib/ui/cx";
import { AddTargetModal } from "./add-target-modal";
import { DiscoveredTable } from "./discovered-table";
import { TargetDrawer } from "./target-drawer";
import { TargetsTable } from "./targets-table";

export type TargetsTab = "targets" | "discovered";

export function TargetsView({ data, tab }: { data: TargetsPageData; tab: TargetsTab }) {
  const [adding, setAdding] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const closeAdd = useCallback(() => setAdding(false), []);
  const closeDrawer = useCallback(() => setSelectedId(null), []);
  const selected = data.rows.find((r) => r.target.id === selectedId) ?? null;
  const pending = data.discovered.filter((d) => !d.promotedTargetId).length;

  const tabs: [TargetsTab, string, number][] = [
    ["targets", "Targets", data.rows.length],
    ["discovered", "Discovered domains", pending],
  ];

  return (
    <div className="px-8 py-8">
      <PageHeader
        title="Targets"
        description="Domains, URLs, IP addresses and ranges you track. Click a target for its risks and health."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <Plus className="h-4 w-4" /> Add targets
          </Button>
        }
      />

      <nav className="mb-4 flex gap-1 border-b border-border-soft" aria-label="Target views">
        {tabs.map(([value, label, count]) => (
          <Link
            key={value}
            href={value === "targets" ? "/targets" : "/targets?tab=discovered"}
            aria-current={tab === value ? "page" : undefined}
            className={cx(
              "-mb-px flex items-center gap-2 border-b-2 px-3 py-2 text-sm",
              tab === value ? "border-accent text-text" : "border-transparent text-text-faint hover:text-text",
            )}
          >
            {label}
            <span className="rounded bg-white/[0.06] px-1.5 font-mono text-[11px]">{count}</span>
          </Link>
        ))}
      </nav>

      {tab === "discovered" ? (
        <DiscoveredTable domains={data.discovered} />
      ) : data.rows.length === 0 ? (
        <EmptyState
          icon={<Crosshair className="h-6 w-6" />}
          title="No targets yet"
          description="Add the domains, URLs or IP ranges you own. Aegis tracks their risks and health over time."
          action={<Button variant="primary" onClick={() => setAdding(true)}><Plus className="h-4 w-4" /> Add targets</Button>}
        />
      ) : (
        <TargetsTable rows={data.rows} auth={data.auth} onOpen={setSelectedId} />
      )}

      <AddTargetModal open={adding} onClose={closeAdd} />
      <TargetDrawer
        key={selectedId ?? "none"}
        row={selected}
        detail={selectedId ? data.details[selectedId] : undefined}
        auth={selectedId ? data.auth[selectedId] : undefined}
        onClose={closeDrawer}
      />
    </div>
  );
}
