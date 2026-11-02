"use client";

import { useActionState, useEffect } from "react";
import { addTargetsAction } from "@/app/(app)/targets/actions";
import { INITIAL_RESULT } from "@/app/(app)/targets/action-result";
import { Button } from "@/components/ui/button";
import { Modal } from "@/components/ui/overlays";
import { MAX_TAGS } from "@/lib/validation/limits";

const FIELD =
  "w-full rounded-lg border border-border bg-control px-3 py-2 text-sm text-text placeholder:text-text-faint " +
  "focus:border-accent/60 focus:outline-none focus:ring-2 focus:ring-accent-ring";

export function AddTargetModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [result, formAction, pending] = useActionState(addTargetsAction, INITIAL_RESULT);

  // Close once everything was added; keep the dialog open to show skipped entries.
  useEffect(() => {
    if (result.ok && result.errors.length === 0) onClose();
  }, [result, onClose]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add targets"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="add-targets" disabled={pending}>
            {pending ? "Adding…" : "Add targets"}
          </Button>
        </>
      }
    >
      <form id="add-targets" action={formAction} className="space-y-4">
        <div>
          <label htmlFor="targets" className="mb-1.5 block text-sm font-medium">
            Targets
          </label>
          <textarea
            id="targets"
            name="targets"
            rows={4}
            required
            autoFocus
            placeholder={"example.com\nhttps://app.example.com/login\n203.0.113.0/28"}
            className={`${FIELD} font-mono`}
          />
          <p className="mt-1.5 text-xs text-text-faint">
            Domain, URL, IPv4 address or CIDR range up to /24. Paste several, one per line.
          </p>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="tags" className="mb-1.5 block text-sm font-medium">
              Tags
            </label>
            <input id="tags" name="tags" placeholder="web, prod" className={FIELD} />
            <p className="mt-1.5 text-xs text-text-faint">Up to {MAX_TAGS}, comma separated.</p>
          </div>
          <div>
            <label htmlFor="label" className="mb-1.5 block text-sm font-medium">
              Label
            </label>
            <input id="label" name="label" placeholder="Customer app" className={FIELD} />
            <p className="mt-1.5 text-xs text-text-faint">Used when adding a single target.</p>
          </div>
        </div>

        {result.message && (
          <div
            role="status"
            className={
              result.ok
                ? "rounded-lg border border-signal-live/30 bg-signal-live/10 px-3 py-2 text-sm text-signal-live"
                : "rounded-lg border border-signal-critical/30 bg-signal-critical/10 px-3 py-2 text-sm text-signal-critical"
            }
          >
            {result.message}
            {result.errors.length > 0 && (
              <ul className="mt-1.5 space-y-0.5 text-xs text-text-dim">
                {result.errors.map((e) => (
                  <li key={`${e.input}-${e.error}`}>
                    <span className="font-mono">{e.input || "Paste"}</span>: {e.error}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </form>
    </Modal>
  );
}
