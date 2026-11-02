"use client";

import { useActionState, useEffect, useMemo, useState } from "react";
import { startScanAction } from "@/app/(app)/scans/actions";
import { Chip } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/overlays";
import { INITIAL_RESULT } from "@/lib/actions/result";
import { parseTarget } from "@/lib/domain/targets";
import { INTENSITY_PROFILES } from "@/lib/recon/intensity";
import { AVAILABLE_SCANNERS } from "@/lib/scans/catalog";
import { cx } from "@/lib/ui/cx";
import type { Target } from "@/types/aegis";

const isLocal = (t: Target) => {
  const parsed = parseTarget(t.target);
  return parsed.ok && parsed.target.isLocal;
};

export function NewScanModal({
  open,
  onClose,
  targets,
  preselected,
}: {
  open: boolean;
  onClose: () => void;
  targets: Target[];
  preselected: string[];
}) {
  const [result, formAction, pending] = useActionState(startScanAction, INITIAL_RESULT);
  const [types, setTypes] = useState<string[]>(["SURFACE"]);
  const [selected, setSelected] = useState<string[]>(preselected);

  useEffect(() => {
    if (result.ok) onClose();
  }, [result, onClose]);

  const toggle = (list: string[], value: string) =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
  const anyActive = AVAILABLE_SCANNERS.some((s) => s.mode === "active" && types.includes(s.type));
  const blocked = useMemo(
    () => targets.filter((t) => selected.includes(t.id) && !isLocal(t)),
    [targets, selected],
  );

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New scan"
      width="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="new-scan" disabled={pending || types.length === 0 || selected.length === 0}>
            {pending ? "Queuing…" : "Run scan"}
          </Button>
        </>
      }
    >
      <form id="new-scan" action={formAction} className="space-y-5">
        <fieldset>
          <legend className="mb-2 text-sm font-medium">Scanners</legend>
          <div className="space-y-2">
            {AVAILABLE_SCANNERS.map((s) => (
              <label
                key={s.type}
                className={cx(
                  "flex cursor-pointer items-start gap-3 rounded-lg border px-4 py-3",
                  types.includes(s.type) ? "border-accent/50 bg-accent/[0.06]" : "border-border hover:bg-white/[0.02]",
                )}
              >
                <input
                  type="checkbox"
                  name="scanTypes"
                  value={s.type}
                  checked={types.includes(s.type)}
                  onChange={() => setTypes(toggle(types, s.type))}
                  className="mt-1"
                />
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2 text-sm font-medium">
                    {s.label}
                    <Chip tone={s.mode === "passive" ? "accent" : "neutral"}>{s.mode}</Chip>
                  </span>
                  <span className="mt-0.5 block text-xs text-text-dim">{s.description}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <fieldset>
          <legend className="mb-2 flex w-full items-center justify-between text-sm font-medium">
            Targets
            <button
              type="button"
              className="text-xs font-normal text-accent hover:text-accent-hover"
              onClick={() => setSelected(selected.length === targets.length ? [] : targets.map((t) => t.id))}
            >
              {selected.length === targets.length ? "Clear" : "Select all"}
            </button>
          </legend>
          {targets.length === 0 ? (
            <p className="text-sm text-text-faint">Add a target first on the Targets page.</p>
          ) : (
            <div className="max-h-48 space-y-1 overflow-y-auto rounded-lg border border-border p-2">
              {targets.map((t) => (
                <label key={t.id} className="flex items-center gap-2.5 rounded px-2 py-1.5 text-sm hover:bg-white/[0.03]">
                  <input
                    type="checkbox"
                    name="targetIds"
                    value={t.id}
                    checked={selected.includes(t.id)}
                    onChange={() => setSelected(toggle(selected, t.id))}
                  />
                  <span className="truncate">{t.label || t.target}</span>
                  {t.label && <span className="truncate font-mono text-xs text-text-faint">{t.target}</span>}
                </label>
              ))}
            </div>
          )}
          {anyActive && blocked.length > 0 && (
            <p className="mt-2 rounded-lg border border-caution-border bg-caution-bg px-3 py-2 text-xs text-caution">
              Active scanners will skip {blocked.map((t) => t.target).join(", ")}. For now they only run on
              local and private-network targets.
            </p>
          )}
        </fieldset>

        <label className="flex items-center justify-between gap-4 text-sm">
          <span>
            <span className="font-medium">Intensity</span>
            <span className="block text-xs text-text-dim">How hard active scanners hit the target.</span>
          </span>
          <select name="intensity" defaultValue="polite" className="h-9 rounded-lg border border-border bg-control px-2.5 text-sm">
            {Object.entries(INTENSITY_PROFILES).map(([value, profile]) => (
              <option key={value} value={value}>{profile.label}</option>
            ))}
          </select>
        </label>

        {result.message && !result.ok && (
          <p role="alert" className="text-sm text-signal-critical">{result.message}</p>
        )}
      </form>
    </Modal>
  );
}
