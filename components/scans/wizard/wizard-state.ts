import type { ScanRequest } from "@/lib/validation/scan-request";
import type { NotifyPolicy, Schedule, ScanIntensityLevel } from "@/types/aegis";

/** Wizard form state and its conversion to the request the server validates. Pure. */

export type ZapMode = "passive" | "active";
export type TargetMode = ScanRequest["targetMode"];

export interface WizardState {
  /** Scanner types except ZAP, which is one card with a passive / active choice. */
  types: string[];
  zap: ZapMode | null;
  targetMode: TargetMode;
  targetIds: string[];
  tags: string[];
  intensity: ScanIntensityLevel;
  schedule: Schedule;
  /** "now" only applies to one-time scans. */
  when: "now" | "later";
  /** Value of a datetime-local input (browser local time). */
  runAtLocal: string;
  intervalDays: number;
  notifyPolicy: NotifyPolicy;
  emails: string;
}

export const initialWizard = (preselected: string[]): WizardState => ({
  types: ["SURFACE"],
  zap: null,
  targetMode: "selected",
  targetIds: preselected,
  tags: [],
  intensity: "polite",
  schedule: "ONCE",
  when: "now",
  runAtLocal: "",
  intervalDays: 14,
  notifyPolicy: "NEVER",
  emails: "",
});

export function selectedTypes(state: WizardState): string[] {
  const zap = state.zap === "passive" ? ["ZAP_PASSIVE"] : state.zap === "active" ? ["ZAP_ACTIVE"] : [];
  return [...state.types, ...zap];
}

export function toRequest(state: WizardState): ScanRequest {
  const runNow = state.schedule === "ONCE" && state.when === "now";
  const runAt = runNow || !state.runAtLocal ? null : new Date(state.runAtLocal).toISOString();
  return {
    scanTypes: selectedTypes(state),
    targetMode: state.targetMode,
    targetIds: state.targetMode === "selected" ? state.targetIds : [],
    tags: state.targetMode === "tags" ? state.tags : [],
    intensity: state.intensity,
    schedule: state.schedule,
    runAt,
    intervalDays: state.schedule === "CUSTOM" ? state.intervalDays : null,
    notifyPolicy: state.notifyPolicy,
    notifyEmails: state.notifyPolicy === "NEVER" ? [] : state.emails.split(/[\s,;]+/).filter(Boolean),
  };
}

/** Why the user can't move past a step yet, or null. */
export function stepProblem(step: number, state: WizardState): string | null {
  if (step === 0 && selectedTypes(state).length === 0) return "Pick at least one scanner.";
  if (step === 1 && state.targetMode === "selected" && state.targetIds.length === 0) return "Pick at least one target.";
  if (step === 1 && state.targetMode === "tags" && state.tags.length === 0) return "Pick at least one tag.";
  if (step === 2 && state.schedule === "ONCE" && state.when === "later" && !state.runAtLocal) return "Choose when to run the scan.";
  if (step === 2 && state.notifyPolicy !== "NEVER" && !state.emails.trim()) return "Add an email address, or choose not to email results.";
  return null;
}
