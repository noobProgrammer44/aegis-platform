"use client";

import { AlertTriangle } from "lucide-react";
import { Chip } from "@/components/ui/badges";
import { SEGMENT_FRAME, segmentClass } from "@/components/ui/segmented";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { SCHEDULE_LABEL } from "@/lib/domain/schedule";
import { INTENSITY_PROFILES } from "@/lib/recon/intensity";
import { AVAILABLE_SCANNERS, SCANNER_CATALOG } from "@/lib/scans/catalog";
import { cx } from "@/lib/ui/cx";
import { timeAgo } from "@/lib/ui/format";
import type { Schedule, ScanIntensityLevel, Target } from "@/types/aegis";
import { selectedTypes, type WizardState } from "./wizard-state";

type Update = (patch: Partial<WizardState>) => void;
const toggle = (list: string[], value: string) => (list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);
const CARD = "rounded-xl border px-5 py-4 transition-colors";
const FIELD = "rounded-lg border border-border bg-control px-3 py-2 text-sm focus:border-accent/60 focus:outline-none";

function Tags({ tags }: { tags: readonly string[] }) {
  return <span className="flex flex-wrap gap-1">{tags.map((t) => <Chip key={t}>{t}</Chip>)}</span>;
}

export function StepScans({ state, update, unavailable }: { state: WizardState; update: Update; unavailable: Record<string, string> }) {
  const cards = AVAILABLE_SCANNERS.filter((s) => s.type !== "ZAP_PASSIVE" && s.type !== "ZAP_ACTIVE");
  const zapDown = unavailable.ZAP_PASSIVE;
  return (
    <div className="space-y-3">
      <div className={cx(CARD, state.zap ? "border-accent/50 bg-accent/[0.05]" : "border-border", zapDown && "opacity-50")}>
        <label className="flex items-start gap-3">
          <input type="checkbox" className="mt-1.5" disabled={Boolean(zapDown)} checked={state.zap !== null} onChange={() => update({ zap: state.zap ? null : "passive" })} />
          <span className="flex-1">
            <span className="block font-mono text-[11px] uppercase tracking-[0.14em] text-text-faint">OWASP ZAP</span>
            <span className="block text-lg font-semibold">Web Application Scan</span>
          </span>
          <Tags tags={SCANNER_CATALOG.ZAP_ACTIVE.tags} />
        </label>
        {zapDown && <p className="mt-2 text-xs text-caution">Unavailable: {zapDown}</p>}
        {state.zap && (
          <div className="mt-3 space-y-2 pl-7">
            {(["passive", "active"] as const).map((mode) => (
              <label key={mode} className={cx("flex items-start gap-3 rounded-lg border px-4 py-3", state.zap === mode ? "border-accent/50" : "border-border")}>
                <input type="radio" name="zap-mode" className="mt-1" checked={state.zap === mode} onChange={() => update({ zap: mode })} />
                <span>
                  <span className="block font-medium">{mode === "passive" ? "ZAP Passive" : "ZAP Active + Passive"}</span>
                  <span className="block text-sm text-text-dim">{mode === "passive" ? SCANNER_CATALOG.ZAP_PASSIVE.description : SCANNER_CATALOG.ZAP_ACTIVE.description}</span>
                  {mode === "active" && (
                    <span className="mt-1 flex items-center gap-1.5 text-xs text-caution">
                      <AlertTriangle className="h-3.5 w-3.5" /> Submits forms and attack requests. Only for targets you are authorized to test.
                    </span>
                  )}
                </span>
              </label>
            ))}
          </div>
        )}
      </div>
      {cards.map((s) => {
        const down = unavailable[s.type];
        const on = state.types.includes(s.type);
        return (
          <label key={s.type} className={cx(CARD, "flex items-start gap-3", on ? "border-accent/50 bg-accent/[0.05]" : "border-border hover:bg-row-hover", down ? "cursor-not-allowed opacity-50" : "cursor-pointer")}>
            <input type="checkbox" className="mt-1.5" disabled={Boolean(down)} checked={on} onChange={() => update({ types: toggle(state.types, s.type) })} />
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-text-faint">
                {s.mode}
              </span>
              <span className="block text-lg font-semibold">{s.label}</span>
              <span className="mt-0.5 block text-sm text-text-dim">{s.description}</span>
              {down && <span className="mt-1 block text-xs text-caution">Unavailable: {down}</span>}
            </span>
            <Tags tags={s.tags} />
          </label>
        );
      })}
    </div>
  );
}

export function StepTargets({ state, update, targets, authorizedIds }: { state: WizardState; update: Update; targets: Target[]; authorizedIds: string[] }) {
  const tags = [...new Set(targets.flatMap((t) => t.tags))].sort();
  const modes: [WizardState["targetMode"], string][] = [["selected", "Choose targets"], ["tags", "By tag"], ["all", "All targets"]];
  const blocked = targets.filter((t) => !authorizedIds.includes(t.id));
  return (
    <div className="space-y-4">
      <div className={SEGMENT_FRAME + " w-fit"} role="radiogroup" aria-label="Which targets">
        {modes.map(([mode, label]) => (
          <button key={mode} type="button" role="radio" aria-checked={state.targetMode === mode} className={segmentClass(state.targetMode === mode)} onClick={() => update({ targetMode: mode })}>{label}</button>
        ))}
      </div>
      {state.targetMode === "tags" && (
        tags.length === 0 ? <p className="text-sm text-text-faint">No targets have tags yet.</p> : (
          <div className="flex flex-wrap gap-2">
            {tags.map((tag) => (
              <button key={tag} type="button" aria-pressed={state.tags.includes(tag)} onClick={() => update({ tags: toggle(state.tags, tag) })}
                className={cx("rounded-md border px-2.5 py-1 font-mono text-xs", state.tags.includes(tag) ? "border-accent/50 bg-accent/10 text-accent" : "border-border text-text-dim hover:text-text")}>
                {tag}
              </button>
            ))}
          </div>
        )
      )}
      {state.targetMode === "all" && <p className="text-sm text-text-dim">Every target, including ones you add later when this runs on a schedule.</p>}
      {state.targetMode === "selected" && (
        <Table>
          <THead>
            <tr>
              <TH className="w-10">
                <input type="checkbox" aria-label="Select all" checked={targets.length > 0 && state.targetIds.length === targets.length} onChange={() => update({ targetIds: state.targetIds.length === targets.length ? [] : targets.map((t) => t.id) })} />
              </TH>
              <TH>Target</TH><TH>Label</TH><TH>Tags</TH><TH>Created</TH>
            </tr>
          </THead>
          <TBody>
            {targets.map((t) => (
              <TR key={t.id} className="cursor-pointer" onClick={() => update({ targetIds: toggle(state.targetIds, t.id) })}>
                <TD><input type="checkbox" aria-label={`Select ${t.target}`} checked={state.targetIds.includes(t.id)} onChange={() => update({ targetIds: toggle(state.targetIds, t.id) })} onClick={(e) => e.stopPropagation()} /></TD>
                <TD className="font-mono">{t.target}</TD>
                <TD className="text-text-dim">{t.label}</TD>
                <TD><span className="flex flex-wrap gap-1">{t.tags.map((tag) => <Chip key={tag}>{tag}</Chip>)}</span></TD>
                <TD className="text-text-dim">{timeAgo(t.createdAt)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
      {blocked.length > 0 && (
        <p className="rounded-lg border border-caution-border bg-caution-bg px-3 py-2 text-xs text-caution">
          Active scanners skip targets that aren&apos;t authorized yet: {blocked.map((t) => t.target).join(", ")}. Authorize them from the target&apos;s panel on the Targets page.
        </p>
      )}
    </div>
  );
}

const SCHEDULES: Schedule[] = ["ONCE", "DAILY", "WEEKLY", "MONTHLY", "QUARTERLY", "CUSTOM"];
const INTENSITY: ScanIntensityLevel[] = ["polite", "normal", "aggressive"];

export function StepConfigure({ state, update }: { state: WizardState; update: Update }) {
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <section className="rounded-xl border border-border p-5">
        <h3 className="font-semibold">Schedule</h3>
        <p className="mb-3 text-sm text-text-dim">Run the scan once, or on a recurring schedule.</p>
        <div className="space-y-2.5 text-sm">
          {SCHEDULES.map((s) => (
            <div key={s}>
              <label className="flex items-center gap-2">
                <input type="radio" name="schedule" checked={state.schedule === s} onChange={() => update({ schedule: s })} /> {SCHEDULE_LABEL[s]}
              </label>
              {state.schedule === s && s === "ONCE" && (
                <div className="mt-2 flex flex-wrap items-center gap-2 pl-6">
                  <select aria-label="When" value={state.when} onChange={(e) => update({ when: e.target.value as WizardState["when"] })} className={FIELD}>
                    <option value="now">Now</option>
                    <option value="later">At a later time</option>
                  </select>
                  {state.when === "later" && <input type="datetime-local" aria-label="Run at" value={state.runAtLocal} onChange={(e) => update({ runAtLocal: e.target.value })} className={FIELD} />}
                </div>
              )}
              {state.schedule === s && s !== "ONCE" && (
                <div className="mt-2 flex flex-wrap items-center gap-2 pl-6 text-text-dim">
                  {s === "CUSTOM" && (
                    <>Every <input type="number" min={1} max={365} aria-label="Days between runs" value={state.intervalDays} onChange={(e) => update({ intervalDays: Number(e.target.value) })} className={cx(FIELD, "w-20")} /> days, </>
                  )}
                  starting <input type="datetime-local" aria-label="First run" value={state.runAtLocal} onChange={(e) => update({ runAtLocal: e.target.value })} className={FIELD} />
                  <span className="text-xs">(empty = now)</span>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
      <div className="space-y-5">
        <section className="rounded-xl border border-border p-5">
          <h3 className="font-semibold">Email notification</h3>
          <p className="mb-3 text-sm text-text-dim">Addresses are saved with the schedule. Sending starts once email is connected under Integrations.</p>
          <div className="space-y-2.5 text-sm">
            {([["ALWAYS", "Email results after every scan"], ["ON_CHANGES", "Email results when risks change"], ["NEVER", "Do not email results"]] as const).map(([policy, label]) => (
              <label key={policy} className="flex items-center gap-2"><input type="radio" name="notify" checked={state.notifyPolicy === policy} onChange={() => update({ notifyPolicy: policy })} /> {label}</label>
            ))}
            {state.notifyPolicy !== "NEVER" && (
              <input value={state.emails} onChange={(e) => update({ emails: e.target.value })} placeholder="security@yourcompany.com, cto@yourcompany.com" className={cx(FIELD, "w-full")} />
            )}
          </div>
        </section>
        <section className="rounded-xl border border-border p-5">
          <h3 className="font-semibold">Intensity</h3>
          <p className="mb-3 text-sm text-text-dim">How hard active scanners hit the target.</p>
          <div className={SEGMENT_FRAME + " w-fit"} role="radiogroup" aria-label="Intensity">
            {INTENSITY.map((i) => (
              <button key={i} type="button" role="radio" aria-checked={state.intensity === i} className={segmentClass(state.intensity === i, i === "aggressive")} onClick={() => update({ intensity: i })}>{INTENSITY_PROFILES[i].label}</button>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

export function StepReview({ state, targets }: { state: WizardState; targets: Target[] }) {
  const names = selectedTypes(state).map((t) => AVAILABLE_SCANNERS.find((s) => s.type === t)?.label ?? t);
  const scope =
    state.targetMode === "all" ? "All targets" : state.targetMode === "tags" ? `Targets tagged ${state.tags.join(", ")}` : targets.filter((t) => state.targetIds.includes(t.id)).map((t) => t.target).join(", ");
  const when =
    state.schedule === "ONCE"
      ? state.when === "now" ? "Once, now" : `Once, at ${new Date(state.runAtLocal).toLocaleString()}`
      : `${SCHEDULE_LABEL[state.schedule]}${state.schedule === "CUSTOM" ? ` (every ${state.intervalDays} days)` : ""}, starting ${state.runAtLocal ? new Date(state.runAtLocal).toLocaleString() : "now"}`;
  const rows: [string, string][] = [
    ["Scanners", names.join(", ")],
    ["Targets", scope],
    ["When", when],
    ["Intensity", INTENSITY_PROFILES[state.intensity].label],
    ["Email", state.notifyPolicy === "NEVER" ? "Don't email results" : `${state.notifyPolicy === "ALWAYS" ? "After every scan" : "When risks change"}: ${state.emails}`],
  ];
  return (
    <dl className="divide-y divide-border-soft rounded-xl border border-border">
      {rows.map(([k, v]) => (
        <div key={k} className="grid gap-1 px-5 py-3 sm:grid-cols-[140px_1fr]">
          <dt className="text-sm text-text-faint">{k}</dt>
          <dd className="text-sm">{v}</dd>
        </div>
      ))}
    </dl>
  );
}
