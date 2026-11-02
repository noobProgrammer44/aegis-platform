"use client";

import { ArrowLeft, ArrowRight, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState, useTransition } from "react";
import { submitScanRequestAction } from "@/app/(app)/scans/actions";
import { AddTargetModal } from "@/components/targets/add-target-modal";
import { Button } from "@/components/ui/button";
import { cx } from "@/lib/ui/cx";
import type { Target } from "@/types/aegis";
import { initialWizard, stepProblem, toRequest, type WizardState } from "./wizard-state";
import { StepConfigure, StepReview, StepScans, StepTargets } from "./wizard-steps";

const STEPS = ["Select Scans", "Select Targets", "Configure", "Review"];

export function ScanWizard({
  targets,
  authorizedIds,
  unavailable,
  preselected,
}: {
  targets: Target[];
  authorizedIds: string[];
  unavailable: Record<string, string>;
  preselected: string[];
}) {
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [state, setState] = useState<WizardState>(() => initialWizard(preselected));
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [pending, start] = useTransition();
  const update = useCallback((patch: Partial<WizardState>) => {
    setState((s) => ({ ...s, ...patch }));
    setError(null);
  }, []);
  const closeAdd = useCallback(() => {
    setAdding(false);
    router.refresh();
  }, [router]);

  const next = () => {
    const problem = stepProblem(step, state);
    if (problem) return setError(problem);
    setStep(step + 1);
  };
  const submit = () =>
    start(async () => {
      const result = await submitScanRequestAction(toRequest(state));
      if (!result.ok) return setError(result.message);
      router.push(result.kind === "scheduled" ? "/scans?tab=scheduled" : "/scans");
    });
  const recurring = state.schedule !== "ONCE" || state.when === "later";

  return (
    <div className="px-8 py-8">
      <Link href="/scans" className="mb-4 inline-flex items-center gap-1.5 text-sm text-text-faint hover:text-text">
        <ArrowLeft className="h-4 w-4" /> Back
      </Link>
      <div className="mb-8 flex flex-wrap items-center justify-between gap-6">
        <h1 className="w-fit bg-[linear-gradient(100deg,var(--text)_35%,var(--accent)_80%,var(--accent-2))] bg-clip-text text-[30px] font-semibold leading-none tracking-[-0.035em] text-transparent">New Scan</h1>
        <ol className="flex flex-wrap items-center gap-3 text-sm">
          {STEPS.map((label, i) => (
            <li key={label} className="flex items-center gap-3">
              <span className={cx("flex items-center gap-2", i === step ? "text-text" : i < step ? "text-text-dim" : "text-text-faint")}>
                <span className={cx("h-2 w-2 rounded-full", i === step ? "bg-signal-live" : i < step ? "bg-text-dim" : "bg-border-strong")} />
                {i + 1}. {label}
              </span>
              {i < STEPS.length - 1 && <span className="h-px w-8 bg-border-strong" />}
            </li>
          ))}
        </ol>
      </div>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-semibold">{["Select scans to run", "Select targets", "Configure", "Review"][step]}</h2>
        {step === 1 && (
          <Button size="sm" onClick={() => setAdding(true)}><Plus className="h-3.5 w-3.5" /> Create target</Button>
        )}
      </div>

      {step === 0 && <StepScans state={state} update={update} unavailable={unavailable} />}
      {step === 1 && <StepTargets state={state} update={update} targets={targets} authorizedIds={authorizedIds} />}
      {step === 2 && <StepConfigure state={state} update={update} />}
      {step === 3 && <StepReview state={state} targets={targets} />}

      <div className="mt-6 flex items-center justify-end gap-3">
        {error && <p role="alert" className="mr-auto text-sm text-signal-critical">{error}</p>}
        {step > 0 && (
          <Button variant="ghost" onClick={() => setStep(step - 1)} aria-label="Previous step"><ArrowLeft className="h-4 w-4" /></Button>
        )}
        {step < 3 ? (
          <Button variant="primary" onClick={next}>Next <ArrowRight className="h-4 w-4" /></Button>
        ) : (
          <Button variant="primary" onClick={submit} disabled={pending}>{pending ? "Saving…" : recurring ? "Create schedule" : "Start scan"}</Button>
        )}
      </div>

      <AddTargetModal open={adding} onClose={closeAdd} />
    </div>
  );
}
