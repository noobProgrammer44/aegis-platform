"use client";

import { Trash2 } from "lucide-react";
import { useActionState, useEffect, useState, useTransition } from "react";
import { createRuleAction, deleteRuleAction, toggleRuleAction } from "@/app/(app)/risks/actions";
import { Chip, SeverityBadge } from "@/components/ui/badges";
import { Button } from "@/components/ui/button";
import { Card, EmptyState } from "@/components/ui/card";
import { INITIAL_RESULT } from "@/lib/actions/result";
import { SCAN_TYPE_LABEL } from "@/lib/ui/format";
import { THREAT_LEVELS, type AcceptanceRule, type ScanType } from "@/types/aegis";

const FIELD = "w-full rounded-lg border border-border bg-control px-3 py-2 text-sm focus:border-accent/60 focus:outline-none";

function Conditions({ rule }: { rule: AcceptanceRule }) {
  const q = rule.query;
  return (
    <span className="flex flex-wrap items-center gap-1.5 text-xs text-text-dim">
      {q.threatLevels.map((l) => <SeverityBadge key={l} level={l} />)}
      {q.scanTypes.map((t) => <Chip key={t}>{SCAN_TYPE_LABEL[t]}</Chip>)}
      {q.targetTags.map((t) => <Chip key={t} tone="accent">tag:{t}</Chip>)}
      {q.ports.length > 0 && <Chip>ports {q.ports.join(", ")}</Chip>}
      {q.titlePattern && <Chip>title ~ /{q.titlePattern}/i</Chip>}
    </span>
  );
}

function RuleRow({ rule }: { rule: AcceptanceRule }) {
  const [pending, start] = useTransition();
  return (
    <li className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5">
      <div className="min-w-0">
        <p className="text-sm font-medium">
          {rule.name} {!rule.enabled && <span className="ml-1 text-xs font-normal text-text-faint">(disabled)</span>}
        </p>
        <div className="mt-1.5"><Conditions rule={rule} /></div>
        {rule.note && <p className="mt-1 text-xs text-text-faint">{rule.note}</p>}
      </div>
      <span className="flex items-center gap-1">
        <Button size="sm" variant="ghost" disabled={pending} onClick={() => start(async () => void (await toggleRuleAction(rule.id, !rule.enabled)))}>
          {rule.enabled ? "Disable" : "Enable"}
        </Button>
        <Button size="sm" variant="ghost" aria-label={`Delete rule ${rule.name}`} disabled={pending} onClick={() => start(async () => void (await deleteRuleAction(rule.id)))}>
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </span>
    </li>
  );
}

export function RulesPanel({ rules, scanTypes }: { rules: AcceptanceRule[]; scanTypes: ScanType[] }) {
  const [result, formAction, pending] = useActionState(createRuleAction, INITIAL_RESULT);
  const [formKey, setFormKey] = useState(0);
  const [, startSubmit] = useTransition();
  // Clear the form only after a successful save; on an error the user's input stays.
  useEffect(() => {
    if (result.ok) setFormKey((k) => k + 1);
  }, [result]);
  return (
    <div className="grid gap-5 xl:grid-cols-[1fr_420px]">
      <Card title={`Acceptance rules (${rules.length})`} bodyClassName="p-0">
        {rules.length === 0 ? (
          <div className="p-5">
            <EmptyState
              title="No rules yet"
              description="Rules accept matching risks automatically, now and in every future scan. For example: accept ports 80 and 443 on targets tagged web."
            />
          </div>
        ) : (
          <ul className="divide-y divide-border-soft">{rules.map((r) => <RuleRow key={r.id} rule={r} />)}</ul>
        )}
      </Card>

      <Card title="New rule">
        <form
          key={formKey}
          onSubmit={(e) => {
            e.preventDefault();
            const data = new FormData(e.currentTarget);
            startSubmit(() => formAction(data));
          }}
          className="space-y-4"
        >
          <label className="block text-sm">
            <span className="mb-1.5 block font-medium">Name</span>
            <input name="name" required maxLength={80} placeholder="Web ports on web servers" className={FIELD} />
          </label>
          <fieldset>
            <legend className="mb-1.5 text-sm font-medium">Severity</legend>
            <div className="flex flex-wrap gap-3 text-sm">
              {THREAT_LEVELS.map((l) => (
                <label key={l} className="flex items-center gap-1.5"><input type="checkbox" name="threatLevels" value={l} /> <SeverityBadge level={l} /></label>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend className="mb-1.5 text-sm font-medium">Scanner</legend>
            <div className="flex flex-wrap gap-3 text-sm">
              {scanTypes.map((t) => (
                <label key={t} className="flex items-center gap-1.5"><input type="checkbox" name="scanTypes" value={t} /> {SCAN_TYPE_LABEL[t]}</label>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block text-sm">
              <span className="mb-1.5 block font-medium">Target tags</span>
              <input name="tags" placeholder="web, prod" className={FIELD} />
            </label>
            <label className="block text-sm">
              <span className="mb-1.5 block font-medium">Ports</span>
              <input name="ports" placeholder="80, 443" className={FIELD} />
            </label>
          </div>
          <label className="block text-sm">
            <span className="mb-1.5 block font-medium">Title matches (regex)</span>
            <input name="titlePattern" maxLength={200} placeholder="referrer-policy" className={`${FIELD} font-mono`} />
          </label>
          <label className="block text-sm">
            <span className="mb-1.5 block font-medium">Reason</span>
            <input name="note" maxLength={500} placeholder="Expected on public web servers" className={FIELD} />
          </label>
          <p className="text-xs text-text-faint">All filled conditions must match. Leave a condition empty to ignore it.</p>
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" disabled={pending}>{pending ? "Saving…" : "Save rule"}</Button>
            {result.message && (
              <span className={result.ok ? "text-xs text-signal-live" : "text-xs text-signal-critical"}>{result.message}</span>
            )}
          </div>
        </form>
      </Card>
    </div>
  );
}
