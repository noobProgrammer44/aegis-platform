"use client";

import { Copy, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState, useTransition } from "react";
import {
  attestAction,
  checkDnsAction,
  revokeAuthorizationAction,
  startDnsAction,
} from "@/app/(app)/targets/authorization-actions";
import { Button } from "@/components/ui/button";
import { TIER_LABEL } from "@/lib/domain/authorization";
import type { TargetAuthView } from "@/lib/services/targets";
import { cx } from "@/lib/ui/cx";

const METHOD_TEXT = {
  local: "On your own machine or private network, so it's authorized automatically.",
  attested: "You confirmed you're authorized to test it.",
  dns: "Ownership proven with a DNS TXT record.",
} as const;

export function AuthBadge({ auth }: { auth: TargetAuthView }) {
  const tone =
    auth.tier === 2
      ? "border-signal-live/35 bg-signal-live/[0.08] text-signal-live"
      : auth.tier === 1
        ? "border-accent/35 bg-accent/[0.08] text-accent"
        : "border-caution-border bg-caution-bg text-caution";
  return (
    <span className={cx("inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em]", tone)}>
      {auth.tier === 0 ? <ShieldAlert className="h-3 w-3" /> : <ShieldCheck className="h-3 w-3" />}
      {auth.method === "local" ? "Local" : TIER_LABEL[auth.tier]}
    </span>
  );
}

function DnsSteps({ targetId, auth, onMessage }: { targetId: string; auth: TargetAuthView; onMessage: (m: string, ok: boolean) => void }) {
  const [value, setValue] = useState<string | null>(auth.pendingDnsValue);
  const [pending, start] = useTransition();
  const [copied, setCopied] = useState(false);

  if (!value) {
    return (
      <Button size="sm" disabled={pending} onClick={() => start(async () => {
        const result = await startDnsAction(targetId);
        if (result.record) setValue(result.record.value);
        onMessage(result.message, result.ok);
      })}>
        Verify ownership with DNS
      </Button>
    );
  }
  return (
    <div className="space-y-2 text-sm">
      <p className="text-text-dim">Add this TXT record to <span className="font-mono text-text">{auth.scope}</span>, then check:</p>
      <div className="flex items-center gap-2 rounded-lg border border-border bg-control px-3 py-2">
        <code className="flex-1 break-all font-mono text-xs">{value}</code>
        <button
          type="button"
          aria-label="Copy TXT value"
          className="rounded p-1 text-text-faint hover:text-text"
          onClick={() => {
            navigator.clipboard?.writeText(value).then(() => setCopied(true), () => setCopied(false));
          }}
        >
          <Copy className="h-3.5 w-3.5" />
        </button>
      </div>
      {copied && <p className="text-xs text-text-faint">Copied.</p>}
      <Button size="sm" variant="primary" disabled={pending} onClick={() => start(async () => {
        const result = await checkDnsAction(targetId);
        onMessage(result.message, result.ok);
      })}>
        {pending ? "Checking…" : "Check DNS now"}
      </Button>
    </div>
  );
}

export function AuthorizationPanel({ targetId, auth }: { targetId: string; auth: TargetAuthView }) {
  const [confirmed, setConfirmed] = useState(false);
  const [note, setNote] = useState("");
  const [message, setMessage] = useState<{ text: string; ok: boolean } | null>(null);
  const [pending, start] = useTransition();
  const show = (text: string, ok: boolean) => setMessage({ text, ok });

  return (
    <section className="rounded-xl border border-border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-mono text-[11px] uppercase tracking-[0.16em] text-text-faint">Authorization</h3>
        <AuthBadge auth={auth} />
      </div>

      {auth.tier > 0 ? (
        <div className="mt-2 space-y-2 text-sm">
          <p className="text-text-dim">
            {auth.method ? METHOD_TEXT[auth.method] : null}
            {auth.inheritedFrom && <> Covered by the authorization for <span className="font-mono">{auth.inheritedFrom}</span>.</>}
          </p>
          {auth.note && <p className="text-xs text-text-faint">Note: {auth.note}</p>}
          {auth.tier === 1 && auth.dnsVerifiable && <DnsSteps targetId={targetId} auth={auth} onMessage={show} />}
          {auth.recordId && (
            <Button size="sm" variant="ghost" disabled={pending} onClick={() => start(async () => {
              const result = await revokeAuthorizationAction(auth.recordId as string);
              show(result.message, result.ok);
            })}>
              Remove authorization
            </Button>
          )}
        </div>
      ) : (
        <div className="mt-2 space-y-3 text-sm">
          <p className="text-text-dim">
            Passive checks work now. Active scans (probing, ports, nuclei) stay blocked until you
            confirm you&apos;re authorized{auth.dnsVerifiable ? " or prove ownership with DNS" : ""}.
          </p>
          <label className="flex items-start gap-2">
            <input type="checkbox" className="mt-1" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            <span>I own <span className="font-mono">{auth.scope}</span> or have written permission to test it.</span>
          </label>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={300}
            placeholder="Optional: who authorized it, or a contract reference"
            className="w-full rounded-lg border border-border bg-control px-3 py-2 text-sm focus:border-accent/60 focus:outline-none"
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="primary" disabled={!confirmed || pending} onClick={() => start(async () => {
              const result = await attestAction(targetId, confirmed, note);
              show(result.message, result.ok);
            })}>
              Confirm authorization
            </Button>
            {auth.dnsVerifiable && <span className="text-xs text-text-faint">or</span>}
          </div>
          {auth.dnsVerifiable && <DnsSteps targetId={targetId} auth={auth} onMessage={show} />}
        </div>
      )}
      {message && <p role="status" className={cx("mt-3 text-xs", message.ok ? "text-signal-live" : "text-signal-critical")}>{message.text}</p>}
      <p className="mt-3 text-[11px] text-text-faint">Every change here is recorded in the audit log.</p>
    </section>
  );
}
