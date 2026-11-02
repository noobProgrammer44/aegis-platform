"use client";

import { ChevronDown, ChevronRight, Search } from "lucide-react";
import { Chip, SeverityBadge, SeverityDot } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { SEGMENT_FRAME, segmentClass } from "@/components/ui/segmented";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import type { RiskFilters, RiskGroup, RiskGrouping, StatusFilter } from "@/lib/domain/risk-table";
import { cx } from "@/lib/ui/cx";
import { SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import { readEvidence } from "@/lib/domain/evidence";
import { THREAT_LEVELS, type Risk, type ScanType, type Target, type ThreatLevel } from "@/types/aegis";
import { RiskDetail } from "./risk-detail";
import { StatusPill } from "./status-pill";
import { ThreatBars } from "./threat-bars";

const SELECT =
  "h-9 rounded-lg border border-border bg-control px-2.5 text-sm text-text focus:border-accent/60 focus:outline-none";

export function RiskToolbar({
  filters,
  onChange,
  grouping,
  onGrouping,
  targets,
  tags,
  scanTypes,
}: {
  filters: RiskFilters;
  onChange: (next: RiskFilters) => void;
  grouping: RiskGrouping;
  onGrouping: (g: RiskGrouping) => void;
  targets: Target[];
  tags: string[];
  scanTypes: ScanType[];
}) {
  const set = <K extends keyof RiskFilters>(key: K, value: RiskFilters[K]) => onChange({ ...filters, [key]: value });
  const toggleLevel = (level: ThreatLevel) =>
    set("levels", filters.levels.includes(level) ? filters.levels.filter((l) => l !== level) : [...filters.levels, level]);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="relative min-w-56 flex-1">
          <span className="sr-only">Search risks</span>
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-faint" />
          <input
            value={filters.search}
            onChange={(e) => set("search", e.target.value)}
            placeholder="Search titles, descriptions, targets"
            className={`${SELECT} w-full pl-9`}
          />
        </label>
        <div className={SEGMENT_FRAME} role="radiogroup" aria-label="Status">
          {(["OPEN", "CLOSED", "ALL"] as StatusFilter[]).map((s) => (
            <button key={s} type="button" role="radio" aria-checked={filters.status === s} className={segmentClass(filters.status === s)} onClick={() => set("status", s)}>
              {s === "OPEN" ? "Open" : s === "CLOSED" ? "Closed" : "All"}
            </button>
          ))}
        </div>
        <select aria-label="Accepted" value={filters.accepted} onChange={(e) => set("accepted", e.target.value as RiskFilters["accepted"])} className={SELECT}>
          <option value="all">Accepted or not</option>
          <option value="unaccepted">Not accepted</option>
          <option value="accepted">Accepted only</option>
        </select>
        <select aria-label="Scanner" value={filters.scanTypes[0] ?? ""} onChange={(e) => set("scanTypes", e.target.value ? [e.target.value as ScanType] : [])} className={SELECT}>
          <option value="">Any scanner</option>
          {scanTypes.map((t) => <option key={t} value={t}>{SCAN_TYPE_LABEL[t]}</option>)}
        </select>
        <select aria-label="Target" value={filters.targetId ?? ""} onChange={(e) => set("targetId", e.target.value || null)} className={SELECT}>
          <option value="">Any target</option>
          {targets.map((t) => <option key={t.id} value={t.id}>{t.label || t.target}</option>)}
        </select>
        {tags.length > 0 && (
          <select aria-label="Tag" value={filters.tag ?? ""} onChange={(e) => set("tag", e.target.value || null)} className={SELECT}>
            <option value="">Any tag</option>
            {tags.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        )}
        <select aria-label="Group by" value={grouping} onChange={(e) => onGrouping(e.target.value as RiskGrouping)} className={SELECT}>
          <option value="none">No grouping</option>
          <option value="title">Group by risk</option>
          <option value="target">Group by target</option>
        </select>
      </div>
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Severity">
        {THREAT_LEVELS.map((level) => (
          <button
            key={level}
            type="button"
            aria-pressed={filters.levels.includes(level)}
            onClick={() => toggleLevel(level)}
            className={cx("rounded-md transition-opacity", filters.levels.length > 0 && !filters.levels.includes(level) && "opacity-40 hover:opacity-80")}
          >
            <SeverityBadge level={level} />
          </button>
        ))}
      </div>
    </div>
  );
}

function RiskRow({
  risk,
  targetName,
  showTarget,
  expanded,
  onToggle,
  onAccept,
}: {
  risk: Risk;
  targetName: string;
  showTarget: boolean;
  expanded: boolean;
  onToggle: () => void;
  onAccept: () => void;
}) {
  const d = risk.definition;
  const ev = readEvidence(d.additionalInfo);
  return (
    <>
      <TR className={cx("cursor-pointer", expanded && "bg-row-hover")} onClick={onToggle}>
        <TD className="w-10">
          <button type="button" aria-expanded={expanded} aria-label={expanded ? "Collapse risk" : "Expand risk"} onClick={(e) => { e.stopPropagation(); onToggle(); }} className="rounded p-1 text-text-faint hover:text-text">
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        </TD>
        <TD className="w-16"><ThreatBars level={d.threatLevel} /></TD>
        <TD>
          <span className="block text-xs text-text-faint">{SCAN_TYPE_LABEL[d.scanType]}</span>
          <span className={cx("block font-medium", risk.status === "CLOSED" && "text-text-faint line-through")}>{d.title}</span>
          <span className="mt-1 flex flex-wrap items-center gap-1.5">
            {ev.owasp && <Chip tone="accent">OWASP Top 10</Chip>}
            {d.cvss && <span className="text-[11px] text-text-faint">CVSS {d.cvss}</span>}
            {ev.confidence && <span className="text-[11px] text-text-faint">Confidence {ev.confidence}</span>}
          </span>
        </TD>
        {showTarget && <TD className="max-w-56 truncate text-text-dim">{targetName}</TD>}
        <TD className="whitespace-nowrap text-xs text-text-dim">
          <span className="block"><span className="text-text-faint">First:</span> {timeAgo(risk.firstDetectedAt)}</span>
          <span className="block"><span className="text-text-faint">Last:</span> {timeAgo(risk.lastDetectedAt)}</span>
        </TD>
        <TD><StatusPill risk={risk} /></TD>
        <TD className="text-right">
          {risk.status === "OPEN" && !risk.isAccepted && (
            <Button size="sm" onClick={(e) => { e.stopPropagation(); onAccept(); }}>Accept Risk</Button>
          )}
        </TD>
      </TR>
      {expanded && (
        <tr className="bg-surface-raised/40">
          {/* max-w-0 keeps long evidence from widening the table; the content wraps instead. */}
          <td colSpan={showTarget ? 7 : 6} className="max-w-0 border-b border-border-soft p-0">
            <RiskDetail risk={risk} targetName={targetName} />
          </td>
        </tr>
      )}
    </>
  );
}

export function RiskGroups({
  groups,
  grouping,
  targetName,
  expandedId,
  onToggle,
  onAccept,
}: {
  groups: RiskGroup[];
  grouping: RiskGrouping;
  targetName: (id: string) => string;
  expandedId: string | null;
  onToggle: (id: string) => void;
  onAccept: (id: string) => void;
}) {
  return (
    <div className="space-y-5">
      {groups.map((group) => (
        <div key={group.key}>
          {grouping !== "none" && (
            <h3 className="mb-2 flex items-center gap-2 text-sm font-medium">
              <SeverityDot level={group.worst} />
              <span className="truncate">{group.label}</span>
              <Chip>{group.risks.length}</Chip>
            </h3>
          )}
          <Table>
            <THead>
              <tr>
                <TH className="w-10"><span className="sr-only">Expand</span></TH>
                <TH>Threat</TH>
                <TH>Vulnerability</TH>
                {grouping !== "target" && <TH>Target</TH>}
                <TH>Detected</TH>
                <TH>Status</TH>
                <TH><span className="sr-only">Actions</span></TH>
              </tr>
            </THead>
            <TBody>
              {group.risks.map((risk) => (
                <RiskRow
                  key={risk.id}
                  risk={risk}
                  targetName={targetName(risk.targetId)}
                  showTarget={grouping !== "target"}
                  expanded={expandedId === risk.id}
                  onToggle={() => onToggle(risk.id)}
                  onAccept={() => onAccept(risk.id)}
                />
              ))}
            </TBody>
          </Table>
        </div>
      ))}
    </div>
  );
}
