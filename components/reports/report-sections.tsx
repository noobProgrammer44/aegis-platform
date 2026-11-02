import { GradeBadge, SeverityBadge, SeverityDot } from "@/components/ui/badges";
import { HealthGauge } from "@/components/ui/gauge";
import { SeverityDonut } from "@/components/ui/severity-donut";
import { SeverityTile } from "@/components/ui/tiles";
import type { ReportSnapshot } from "@/lib/domain/report";
import { pluralize, SCAN_TYPE_LABEL } from "@/lib/ui/format";
import { SEVERITY_ACCENT } from "@/lib/ui/severity";
import { THREAT_LEVELS } from "@/types/aegis";

/** Numbered sections of a report document. Server components; print-friendly. */

const date = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) : "Never";

export function Section({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section className="break-inside-avoid-page border-t border-border-soft py-8">
      <h2 className="mb-5 flex items-baseline gap-3 text-xl font-semibold tracking-tight">
        <span className="font-mono text-sm text-accent">{n}.0</span>
        {title}
      </h2>
      {children}
    </section>
  );
}

export function ExecutiveSummary({ s }: { s: ReportSnapshot }) {
  const total = s.totals.included;
  return (
    <div className="space-y-6">
      <div className="grid items-center gap-6 md:grid-cols-[220px_1fr]">
        <HealthGauge score={s.health.score} grade={s.health.grade} />
        <p className="text-sm leading-relaxed text-text-dim">
          This report covers {pluralize(s.coverage.targets, "target")} in {s.workspaceName}.{" "}
          {total === 0
            ? "No risks matched the report's filters."
            : `It lists ${pluralize(total, "risk")}, ${s.totals.byLevel.CRITICAL} critical and ${s.totals.byLevel.HIGH} high.`}{" "}
          {s.totals.accepted > 0 && `${pluralize(s.totals.accepted, "risk")} accepted by your team ${s.totals.accepted === 1 ? "is" : "are"} excluded from the score. `}
          {s.totals.closed > 0 && `${pluralize(s.totals.closed, "risk")} found earlier ${s.totals.closed === 1 ? "is" : "are"} no longer detected.`}
        </p>
      </div>
      <div className="flex flex-col items-center gap-5 sm:flex-row">
        <SeverityDonut counts={s.totals.byLevel} label="in report" />
        <div className="grid w-full flex-1 grid-cols-2 gap-3 sm:grid-cols-4">
          {THREAT_LEVELS.map((l) => <SeverityTile key={l} level={l} count={s.totals.byLevel[l]} />)}
        </div>
      </div>
      {total > 0 && (
        <div className="flex h-2.5 overflow-hidden rounded-full bg-surface-raised" aria-hidden="true">
          {THREAT_LEVELS.map((l) => (
            <div key={l} style={{ width: `${(s.totals.byLevel[l] / total) * 100}%`, background: SEVERITY_ACCENT[l].stroke }} />
          ))}
        </div>
      )}
      {s.topIssues.length > 0 && (
        <div>
          <h3 className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-text-faint">Top issues</h3>
          <ol className="space-y-1.5 text-sm">
            {s.topIssues.map((i) => (
              <li key={`${i.scanType}-${i.title}`} className="flex items-center gap-2.5">
                <SeverityDot level={i.threatLevel} />
                <span className="flex-1">{i.title}</span>
                <span className="text-xs text-text-faint">{pluralize(i.targetCount, "target")}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

export function Coverage({ s }: { s: ReportSnapshot }) {
  const stats: [string, number | string][] = [
    ["Targets in scope", s.coverage.targets],
    ["Targets scanned", s.coverage.scannedTargets],
    ["Scans run", s.coverage.scans],
    ["Last scan", date(s.coverage.lastScanAt)],
  ];
  return (
    <div className="space-y-5">
      <dl className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {stats.map(([label, value]) => (
          <div key={label} className="rounded-xl border border-border p-4">
            <dt className="text-xs text-text-faint">{label}</dt>
            <dd className="mt-1 font-mono text-2xl font-semibold">{value}</dd>
          </div>
        ))}
      </dl>
      {s.coverage.byScanType.length > 0 && (
        <ul className="flex flex-wrap gap-2 text-sm">
          {s.coverage.byScanType.map((b) => (
            <li key={b.type} className="rounded-lg border border-border px-3 py-1.5">
              {SCAN_TYPE_LABEL[b.type]} <span className="ml-1 font-mono text-text-faint">×{b.count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function TargetBreakdown({ s }: { s: ReportSnapshot }) {
  return (
    <table className="w-full border-collapse text-[13px]">
      <thead>
        <tr className="border-b border-border-soft text-left font-mono text-[11px] uppercase tracking-[0.16em] text-text-faint">
          <th className="py-2 pr-3">Target</th>
          <th className="py-2 pr-3">Health</th>
          {THREAT_LEVELS.map((l) => <th key={l} className="py-2 pr-3 text-right">{l.slice(0, 4)}</th>)}
          <th className="py-2 text-right">Last scanned</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-border-soft">
        {s.targets.map((t) => (
          <tr key={t.id} className="break-inside-avoid">
            <td className="py-2.5 pr-3">
              <span className="block font-medium">{t.name}</span>
              {t.name !== t.target && <span className="font-mono text-xs text-text-faint">{t.target}</span>}
            </td>
            <td className="py-2.5 pr-3">{t.lastScannedAt ? <GradeBadge grade={t.health.grade} /> : <span className="text-xs text-text-faint">Not scanned</span>}</td>
            {THREAT_LEVELS.map((l) => <td key={l} className="py-2.5 pr-3 text-right font-mono tabular-nums">{t.counts[l]}</td>)}
            <td className="py-2.5 text-right text-text-dim">{date(t.lastScannedAt)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function RiskDetails({ risks }: { risks: ReportSnapshot["risks"] }) {
  if (risks.length === 0) return <p className="text-sm text-text-faint">No risks in this section.</p>;
  return (
    <ol className="space-y-4">
      {risks.map((r, i) => (
        <li key={r.id} className={`break-inside-avoid rounded-xl border border-border p-4 ${SEVERITY_ACCENT[r.threatLevel].row}`}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-text-faint">{i + 1}.</span>
            <SeverityBadge level={r.threatLevel} />
            <h3 className="font-medium">{r.title}</h3>
          </div>
          <p className="mt-1 text-xs text-text-faint">
            {r.target}
            {r.host && r.host !== r.target && ` · ${r.host}`}
            {r.port !== null && ` · port ${r.port}`} · {SCAN_TYPE_LABEL[r.scanType]} · first seen {date(r.firstDetectedAt)} · last seen {date(r.lastDetectedAt)}
            {r.status === "CLOSED" && " · no longer found"}
          </p>
          {r.isAccepted && <p className="mt-2 text-sm text-signal-live">Accepted: {r.acceptedReason ?? "no reason given"}</p>}
          {r.description && <p className="mt-3 text-sm leading-relaxed text-text-dim">{r.description}</p>}
          {r.solution && (
            <p className="mt-2 text-sm leading-relaxed">
              <span className="font-medium">Solution: </span>
              <span className="text-text-dim">{r.solution}</span>
            </p>
          )}
          {r.references.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-xs">
              {r.references.map((ref) => <li key={ref} className="break-all text-accent">{ref}</li>)}
            </ul>
          )}
        </li>
      ))}
    </ol>
  );
}
