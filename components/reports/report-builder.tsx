"use client";

import { FileText } from "lucide-react";
import { useActionState, useState, useTransition } from "react";
import { createReportAction } from "@/app/(app)/reports/actions";
import { SeverityBadge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { SEGMENT_FRAME, segmentClass } from "@/components/ui/segmented";
import { INITIAL_RESULT } from "@/lib/actions/result";
import { REPORT_SECTIONS } from "@/lib/domain/report";
import { THREAT_LEVELS, type ReportFormat, type Target } from "@/types/aegis";

const FIELD = "w-full rounded-lg border border-border bg-control px-3 py-2 text-sm focus:border-accent/60 focus:outline-none";
const LABEL = "mb-1.5 block text-sm font-medium";
const FORMATS: { value: ReportFormat; label: string; hint: string }[] = [
  { value: "HTML", label: "Report (PDF)", hint: "Printable report; save as PDF from the print dialog." },
  { value: "JSON", label: "JSON", hint: "Machine-readable data for other tools." },
  { value: "CSV", label: "CSV", hint: "Risk list for spreadsheets." },
];

export function ReportBuilder({ targets, preselected }: { targets: Target[]; preselected: string | null }) {
  const [result, formAction, pending] = useActionState(createReportAction, INITIAL_RESULT);
  const [, startSubmit] = useTransition();
  const [format, setFormat] = useState<ReportFormat>("HTML");
  const [scope, setScope] = useState<"all" | "pick">(preselected ? "pick" : "all");
  const today = new Date().toISOString().slice(0, 10);
  const defaultName = preselected
    ? `${targets.find((t) => t.id === preselected)?.target ?? "Target"} security report ${today}`
    : `Security report ${today}`;

  return (
    <Card title="Create a report">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const data = new FormData(e.currentTarget);
          startSubmit(() => formAction(data));
        }}
        className="space-y-5"
      >
        <label className="block">
          <span className={LABEL}>Name</span>
          <input name="name" required maxLength={100} defaultValue={defaultName} className={FIELD} />
        </label>

        <div>
          <span id="format-label" className={LABEL}>Format</span>
          <div role="radiogroup" aria-labelledby="format-label" className={SEGMENT_FRAME + " w-fit"}>
            {FORMATS.map((f) => (
              <label key={f.value} className={segmentClass(format === f.value)}>
                <input type="radio" name="format" value={f.value} checked={format === f.value} onChange={() => setFormat(f.value)} className="sr-only" />
                {f.label}
              </label>
            ))}
          </div>
          <p className="mt-1.5 text-xs text-text-faint">{FORMATS.find((f) => f.value === format)?.hint}</p>
        </div>

        <fieldset>
          <legend className={LABEL}>Which targets?</legend>
          <div className="flex gap-4 text-sm">
            <label className="flex items-center gap-1.5"><input type="radio" checked={scope === "all"} onChange={() => setScope("all")} /> All targets</label>
            <label className="flex items-center gap-1.5"><input type="radio" checked={scope === "pick"} onChange={() => setScope("pick")} /> Choose targets or tags</label>
          </div>
          {scope === "pick" && (
            <div className="mt-3 space-y-3">
              <div className="max-h-40 space-y-1 overflow-y-auto rounded-lg border border-border p-2">
                {targets.length === 0 && <p className="px-2 py-1 text-sm text-text-faint">No targets yet.</p>}
                {targets.map((t) => (
                  <label key={t.id} className="flex items-center gap-2.5 rounded px-2 py-1.5 text-sm hover:bg-row-hover">
                    <input type="checkbox" name="targetIds" value={t.id} defaultChecked={t.id === preselected} />
                    <span className="truncate">{t.label || t.target}</span>
                  </label>
                ))}
              </div>
              <input name="tags" placeholder="…or tags: web, prod" className={FIELD} />
            </div>
          )}
        </fieldset>

        <fieldset>
          <legend className={LABEL}>Which risks?</legend>
          <div className="flex flex-wrap gap-3 text-sm">
            {THREAT_LEVELS.map((l) => (
              <label key={l} className="flex items-center gap-1.5"><input type="checkbox" name="threatLevels" value={l} /> <SeverityBadge level={l} /></label>
            ))}
          </div>
          <p className="mt-1.5 text-xs text-text-faint">Leave all unticked for every severity.</p>
          <div className="mt-3 flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-1.5"><input type="checkbox" name="includeAccepted" /> Include accepted risks</label>
            <label className="flex items-center gap-1.5"><input type="checkbox" name="includeClosed" /> Include closed risks</label>
          </div>
        </fieldset>

        <fieldset>
          <legend className={LABEL}>Sections</legend>
          <div className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
            {REPORT_SECTIONS.map((s) => (
              <label key={s.value} className="flex items-center gap-1.5">
                <input type="checkbox" name="sections" value={s.value} defaultChecked={s.value !== "accepted_risks"} /> {s.label}
              </label>
            ))}
          </div>
        </fieldset>

        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" disabled={pending}>
            <FileText className="h-4 w-4" /> {pending ? "Generating…" : "Generate report"}
          </Button>
          {result.message && !result.ok && <span role="alert" className="text-xs text-signal-critical">{result.message}</span>}
        </div>
      </form>
    </Card>
  );
}
