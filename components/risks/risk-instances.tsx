"use client";

import { ChevronDown, ChevronRight, CornerDownRight } from "lucide-react";
import { useState } from "react";
import type { RiskInstance } from "@/lib/domain/evidence";
import { cx } from "@/lib/ui/cx";

const BLOCK = "max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border-soft bg-control p-3 font-mono text-[11px] leading-relaxed text-text-dim";

function Block({ title, text }: { title: string; text?: string }) {
  if (!text) return null;
  return (
    <div>
      <p className="mb-1 text-xs text-text-faint">{title}</p>
      <pre className={BLOCK}>{text}</pre>
    </div>
  );
}

function Field({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div className="flex gap-2 text-xs">
      <span className="w-20 shrink-0 text-text-faint">{label}</span>
      <span className="break-all font-mono">{value}</span>
    </div>
  );
}

function Instance({ instance, defaultOpen }: { instance: RiskInstance; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const hasDetail = Boolean(
    instance.method || instance.param || instance.attack || instance.evidence || instance.otherInfo ||
      instance.requestHeader || instance.responseHeader || instance.responseBody,
  );
  return (
    <li className="border-b border-border-soft last:border-0">
      <button
        type="button"
        onClick={() => hasDetail && setOpen(!open)}
        aria-expanded={hasDetail ? open : undefined}
        className={cx("flex w-full items-center gap-2 px-4 py-2.5 text-left text-sm", hasDetail ? "hover:bg-row-hover" : "cursor-default")}
      >
        {hasDetail ? (open ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-text-faint" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-text-faint" />) : <span className="w-3.5" />}
        {instance.method && <span className="font-mono text-[11px] text-text-faint">{instance.method}</span>}
        <span className="break-all font-mono text-[13px]">{instance.uri}</span>
      </button>
      {open && hasDetail && (
        <div className="space-y-3 px-4 pb-4 pl-10">
          <div className="space-y-1">
            <Field label="Parameter" value={instance.param} />
            <Field label="Attack" value={instance.attack} />
            <Field label="Evidence" value={instance.evidence} />
            <Field label="Other info" value={instance.otherInfo} />
          </div>
          {(instance.requestHeader || instance.responseHeader) && (
            <div className="flex gap-2">
              <CornerDownRight className="mt-1 h-3.5 w-3.5 shrink-0 text-text-faint" />
              <div className="min-w-0 flex-1 space-y-3">
                <Block title="Request header" text={instance.requestHeader} />
                <Block title="Request body" text={instance.requestBody} />
                <Block title="Response header" text={instance.responseHeader} />
                <Block title="Response body" text={instance.responseBody} />
              </div>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

const PAGE = 10;

/** Every place a risk was seen; each expands to the evidence and HTTP exchange. */
export function RiskInstances({ instances }: { instances: RiskInstance[] }) {
  const [shown, setShown] = useState(PAGE);
  if (instances.length === 0) return <p className="text-sm text-text-faint">The scanner didn&apos;t record individual instances.</p>;
  return (
    <div className="overflow-hidden rounded-xl border border-border">
      <p className="border-b border-border-soft px-4 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-text-faint">URI</p>
      <ul>
        {instances.slice(0, shown).map((instance, i) => (
          <Instance key={`${instance.uri}-${i}`} instance={instance} defaultOpen={i === 0} />
        ))}
      </ul>
      {instances.length > shown && (
        <button type="button" onClick={() => setShown(shown + PAGE)} className="w-full border-t border-border-soft py-2 text-xs text-accent hover:bg-row-hover">
          Show {Math.min(PAGE, instances.length - shown)} more of {instances.length - shown}
        </button>
      )}
    </div>
  );
}
