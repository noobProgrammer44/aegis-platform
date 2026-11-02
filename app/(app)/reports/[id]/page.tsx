import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { ShieldMark } from "@/components/brand/shield-mark";
import { ReportToolbar } from "@/components/reports/report-toolbar";
import { Coverage, ExecutiveSummary, RiskDetails, Section, TargetBreakdown } from "@/components/reports/report-sections";
import { GradeBadge } from "@/components/ui/badges";
import { getDb } from "@/lib/db/client";
import { GRADE_LABEL } from "@/lib/domain/health-score";
import { loadReport } from "@/lib/services/reports";
import { currentWorkspaceId } from "@/lib/workspace";
import type { ReportSection } from "@/types/aegis";

export const metadata: Metadata = { title: "Report" };

const longDate = (iso: string) =>
  new Date(iso).toLocaleString("en-GB", { dateStyle: "long", timeStyle: "short" });

export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const loaded = loadReport(getDb(), currentWorkspaceId(), id);
  if (!loaded) notFound();
  const { report, snapshot: s } = loaded;
  const has = (section: ReportSection) => report.sections.includes(section);
  const accepted = s.risks.filter((r) => r.isAccepted);
  const scored = s.risks.filter((r) => !r.isAccepted);
  const scope =
    s.filters.targets.targetIds.length === 0 && s.filters.targets.tags.length === 0
      ? "All targets"
      : [
          s.filters.targets.targetIds.length > 0 && `${s.filters.targets.targetIds.length} selected target(s)`,
          s.filters.targets.tags.length > 0 && `tags ${s.filters.targets.tags.join(", ")}`,
        ]
          .filter(Boolean)
          .join(" + ");

  const sections = [
    has("executive_summary") && { title: "Executive summary", body: <ExecutiveSummary s={s} /> },
    has("coverage") && { title: "Report coverage", body: <Coverage s={s} /> },
    has("target_breakdown") && { title: "Target breakdown", body: <TargetBreakdown s={s} /> },
    has("risk_details") && { title: "Risk details", body: <RiskDetails risks={scored} /> },
    has("accepted_risks") && accepted.length > 0 && { title: "Accepted risks", body: <RiskDetails risks={accepted} /> },
  ].filter((x): x is { title: string; body: React.ReactElement } => Boolean(x));

  return (
    <div className="mx-auto max-w-4xl px-8 py-8 print:max-w-none print:p-0">
      <ReportToolbar id={report.id} />
      <article className="rounded-2xl border border-border bg-surface/90 px-10 py-10 print:rounded-none print:border-0 print:bg-transparent print:p-0">
        <header className="pb-10">
          <div className="flex items-center gap-2.5">
            <ShieldMark className="h-6 w-6 text-accent" />
            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-text-dim">Aegis security report</span>
          </div>
          <h1 className="mt-10 w-fit bg-[linear-gradient(100deg,var(--text)_35%,var(--accent)_80%,var(--accent-2))] bg-clip-text pb-1 text-[40px] font-semibold leading-tight tracking-[-0.035em] text-transparent print:bg-none print:text-text">
            {report.name}
          </h1>
          <dl className="mt-6 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
            <div><dt className="text-text-faint">Workspace</dt><dd>{s.workspaceName}</dd></div>
            <div><dt className="text-text-faint">Generated</dt><dd>{longDate(s.generatedAt)}</dd></div>
            <div><dt className="text-text-faint">Scope</dt><dd>{scope}</dd></div>
            <div>
              <dt className="text-text-faint">Overall health</dt>
              <dd className="mt-0.5 flex items-center gap-2">
                <GradeBadge grade={s.health.grade} withLabel />
                <span className="font-mono text-text-dim">{s.health.score} / 1000</span>
              </dd>
            </div>
          </dl>
          <p className="mt-6 text-xs text-text-faint">
            Severity filter: {s.filters.threatLevels.length > 0 ? s.filters.threatLevels.join(", ") : "all"} ·
            accepted risks {s.filters.includeAccepted ? "included" : "excluded"} · closed risks{" "}
            {s.filters.includeClosed ? "included" : "excluded"}. {GRADE_LABEL[s.health.grade]} health means
            a score of {s.health.score} on a 0 (best) to 1000 (worst) scale.
          </p>
        </header>
        {sections.map((section, i) => (
          <Section key={section.title} n={i + 1} title={section.title}>{section.body}</Section>
        ))}
      </article>
    </div>
  );
}
