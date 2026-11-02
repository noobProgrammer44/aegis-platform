"use client";

import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Chip, GradeBadge, SeverityDot } from "@/components/ui/badges";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import {
  allTags,
  filterTargets,
  groupTargets,
  sortTargets,
  type TargetGrouping,
  type TargetRow,
  type TargetSort,
} from "@/lib/domain/target-table";
import type { TargetAuthView } from "@/lib/services/targets";
import { timeAgo } from "@/lib/ui/format";
import { AuthBadge } from "./authorization-panel";
import { THREAT_LEVELS, type HealthGrade } from "@/types/aegis";

const SELECT =
  "h-9 rounded-lg border border-border bg-control px-2.5 text-sm text-text focus:border-accent/60 focus:outline-none";
const GRADES: HealthGrade[] = ["A", "B", "C", "D", "F"];

function RiskCounts({ row }: { row: TargetRow }) {
  if (row.openTotal === 0) return <span className="text-xs text-text-faint">None open</span>;
  return (
    <span className="flex items-center gap-3">
      {THREAT_LEVELS.filter((level) => row.counts[level] > 0).map((level) => (
        <span key={level} className="flex items-center gap-1 font-mono text-xs tabular-nums">
          <SeverityDot level={level} />
          {row.counts[level]}
        </span>
      ))}
    </span>
  );
}

function Row({ row, auth, onOpen }: { row: TargetRow; auth: TargetAuthView | undefined; onOpen: (id: string) => void }) {
  const t = row.target;
  return (
    <TR className="cursor-pointer" onClick={() => onOpen(t.id)}>
      <TD>
        <button type="button" className="text-left" onClick={() => onOpen(t.id)}>
          <span className="block font-medium">{t.label || t.target}</span>
          {t.label && <span className="block font-mono text-xs text-text-faint">{t.target}</span>}
        </button>
        {t.tags.length > 0 && (
          <span className="mt-1.5 flex flex-wrap gap-1">
            {t.tags.map((tag) => (
              <Chip key={tag}>{tag}</Chip>
            ))}
          </span>
        )}
      </TD>
      <TD>
        {t.lastScannedAt ? (
          <span className="flex items-center gap-2">
            <GradeBadge grade={t.health.grade} />
            <span className="font-mono text-xs text-text-faint">{t.health.score}</span>
          </span>
        ) : (
          <span className="text-xs text-text-faint">Not scanned</span>
        )}
      </TD>
      <TD><RiskCounts row={row} /></TD>
      <TD>{auth && <AuthBadge auth={auth} />}</TD>
      <TD>{row.discoveredCount > 0 ? <Chip tone="accent">{row.discoveredCount}</Chip> : <span className="text-text-faint">0</span>}</TD>
      <TD className="capitalize text-text-dim">{t.source}</TD>
      <TD className="whitespace-nowrap text-text-dim">{t.lastScannedAt ? timeAgo(t.lastScannedAt) : "Never"}</TD>
    </TR>
  );
}

export function TargetsTable({
  rows,
  auth,
  onOpen,
}: {
  rows: TargetRow[];
  auth: Record<string, TargetAuthView>;
  onOpen: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<TargetSort>("health");
  const [grouping, setGrouping] = useState<TargetGrouping>("none");
  const [grade, setGrade] = useState<HealthGrade | "">("");
  const [tag, setTag] = useState("");

  const groups = useMemo(() => {
    const filtered = filterTargets(rows, { search, grades: grade ? [grade] : [], tag: tag || null });
    return groupTargets(sortTargets(filtered, sort), grouping);
  }, [rows, search, sort, grouping, grade, tag]);
  const tags = useMemo(() => allTags(rows), [rows]);
  const shown = groups.reduce((sum, g) => sum + g.rows.length, 0);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative min-w-56 flex-1">
          <span className="sr-only">Search targets</span>
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-faint" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search targets, labels, tags"
            className={`${SELECT} w-full pl-9`}
          />
        </label>
        <select aria-label="Group by" value={grouping} onChange={(e) => setGrouping(e.target.value as TargetGrouping)} className={SELECT}>
          <option value="none">No grouping</option>
          <option value="tag">Group by tag</option>
        </select>
        <select aria-label="Sort by" value={sort} onChange={(e) => setSort(e.target.value as TargetSort)} className={SELECT}>
          <option value="health">Sort: worst health</option>
          <option value="name">Sort: name</option>
          <option value="lastScanned">Sort: last scanned</option>
          <option value="added">Sort: recently added</option>
        </select>
        <select aria-label="Filter by grade" value={grade} onChange={(e) => setGrade(e.target.value as HealthGrade | "")} className={SELECT}>
          <option value="">Any grade</option>
          {GRADES.map((g) => <option key={g} value={g}>Grade {g}</option>)}
        </select>
        <select aria-label="Filter by tag" value={tag} onChange={(e) => setTag(e.target.value)} className={SELECT}>
          <option value="">Any tag</option>
          {tags.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {shown === 0 ? (
        <p className="rounded-xl border border-dashed border-border-strong py-10 text-center text-sm text-text-faint">
          No targets match these filters.
        </p>
      ) : (
        groups.map((group) => (
          <div key={group.key}>
            {grouping !== "none" && (
              <h3 className="mb-2 mt-4 font-mono text-[11px] uppercase tracking-[0.14em] text-text-faint">
                {group.label} · {group.rows.length}
              </h3>
            )}
            <Table>
              <THead>
                <tr>
                  <TH>Target</TH>
                  <TH>Health</TH>
                  <TH>Open risks</TH>
                  <TH>Authorization</TH>
                  <TH>Discovered</TH>
                  <TH>Source</TH>
                  <TH>Last scanned</TH>
                </tr>
              </THead>
              <TBody>
                {group.rows.map((row) => <Row key={row.target.id} row={row} auth={auth[row.target.id]} onOpen={onOpen} />)}
              </TBody>
            </Table>
          </div>
        ))
      )}
    </div>
  );
}
