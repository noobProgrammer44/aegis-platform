"use client";

import { Bug, Download } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { buttonClass } from "@/components/ui/button";
import { EmptyState, PageHeader } from "@/components/ui/card";
import { SeverityDonut } from "@/components/ui/severity-donut";
import { countScoredRisks } from "@/lib/domain/health-score";
import { filterRisks, groupRisks, type RiskFilters, type RiskGrouping } from "@/lib/domain/risk-table";
import { cx } from "@/lib/ui/cx";
import type { AcceptanceRule, Risk, ScanType, Target } from "@/types/aegis";
import { RiskDrawer } from "./risk-drawer";
import { RiskGroups, RiskToolbar } from "./risk-list";
import { RulesPanel } from "./rules-panel";

type Tab = "risks" | "rules";

function exportHref(filters: RiskFilters): string {
  const params = new URLSearchParams();
  if (filters.levels.length > 0) params.set("level", filters.levels.join(","));
  if (filters.status !== "OPEN") params.set("status", filters.status);
  if (filters.accepted !== "all") params.set("accepted", filters.accepted === "accepted" ? "1" : "0");
  if (filters.targetId) params.set("target", filters.targetId);
  if (filters.tag) params.set("tag", filters.tag);
  if (filters.search) params.set("q", filters.search);
  const query = params.toString();
  return `/api/risks/export${query ? `?${query}` : ""}`;
}

export function RisksView({
  risks,
  targets,
  rules,
  scanTypes,
  initialFilters,
}: {
  risks: Risk[];
  targets: Target[];
  rules: AcceptanceRule[];
  scanTypes: ScanType[];
  initialFilters: RiskFilters;
}) {
  const [tab, setTab] = useState<Tab>("risks");
  const [filters, setFilters] = useState<RiskFilters>(initialFilters);
  const [grouping, setGrouping] = useState<RiskGrouping>("none");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const close = useCallback(() => setSelectedId(null), []);

  const targetMap = useMemo(() => new Map(targets.map((t) => [t.id, t] as const)), [targets]);
  const tags = useMemo(() => [...new Set(targets.flatMap((t) => t.tags))].sort(), [targets]);
  const filtered = useMemo(() => filterRisks(risks, targetMap, filters), [risks, targetMap, filters]);
  const groups = useMemo(() => groupRisks(filtered, grouping, targetMap), [filtered, grouping, targetMap]);
  const targetName = useCallback((id: string) => {
    const t = targetMap.get(id);
    return t ? t.label || t.target : "Deleted target";
  }, [targetMap]);
  const selected = risks.find((r) => r.id === selectedId) ?? null;
  const scored = countScoredRisks(risks);

  return (
    <div className="px-8 py-8">
      <PageHeader
        title="Risks"
        description="Every finding across your targets. Accept the ones that are fine; closed risks are ones the latest scan no longer finds."
        actions={
          <a href={exportHref(filters)} className={buttonClass("secondary")}>
            <Download className="h-4 w-4" /> Export CSV
          </a>
        }
      />

      <nav className="mb-5 flex gap-1 border-b border-border-soft" aria-label="Risk views">
        {([["risks", `Risks (${filtered.length})`], ["rules", `Acceptance rules (${rules.length})`]] as const).map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-current={tab === value ? "page" : undefined}
            onClick={() => setTab(value)}
            className={cx("-mb-px border-b-2 px-3 py-2 text-sm", tab === value ? "border-accent text-text" : "border-transparent text-text-faint hover:text-text")}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === "rules" ? (
        <RulesPanel rules={rules} scanTypes={scanTypes} />
      ) : risks.length === 0 ? (
        <EmptyState
          icon={<Bug className="h-6 w-6" />}
          title="No risks yet"
          description="Run a scan of your targets. Its findings show up here as risks you can track, accept and export."
        />
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1fr_200px]">
          <div className="min-w-0 space-y-4">
            <RiskToolbar
              filters={filters}
              onChange={setFilters}
              grouping={grouping}
              onGrouping={setGrouping}
              targets={targets}
              tags={tags}
              scanTypes={scanTypes}
            />
            {filtered.length === 0 ? (
              <p className="rounded-2xl border border-dashed border-border-strong py-10 text-center text-sm text-text-faint">
                No risks match these filters.
              </p>
            ) : (
              <RiskGroups groups={groups} grouping={grouping} targetName={targetName} onOpen={setSelectedId} />
            )}
          </div>
          <aside className="hidden xl:block">
            <div className="sticky top-8 flex flex-col items-center gap-2 rounded-2xl border border-border bg-surface/90 p-5">
              <SeverityDonut counts={scored} label="scored risks" />
              <p className="text-center text-xs text-text-faint">Open and not accepted: what the health score counts.</p>
            </div>
          </aside>
        </div>
      )}

      <RiskDrawer key={selectedId ?? "none"} risk={selected} targetName={selected ? targetName(selected.targetId) : ""} onClose={close} />
    </div>
  );
}
