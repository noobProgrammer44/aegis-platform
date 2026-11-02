"use client";

import { Check, Plus } from "lucide-react";
import { useState, useTransition } from "react";
import { promoteDomainAction } from "@/app/(app)/targets/actions";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { timeAgo } from "@/lib/ui/format";
import type { DiscoveredDomain } from "@/types/aegis";

function AddButton({ domain }: { domain: DiscoveredDomain }) {
  const [pending, start] = useTransition();
  const [message, setMessage] = useState<string | null>(null);
  if (domain.promotedTargetId) {
    return (
      <span className="flex items-center gap-1 text-xs text-signal-live">
        <Check className="h-3.5 w-3.5" /> Target
      </span>
    );
  }
  return (
    <span className="flex items-center gap-2">
      <Button
        size="sm"
        disabled={pending}
        onClick={() =>
          start(async () => {
            const result = await promoteDomainAction(domain.id);
            setMessage(result.ok ? null : result.message);
          })
        }
      >
        <Plus className="h-3.5 w-3.5" />
        {pending ? "Adding…" : "Add as target"}
      </Button>
      {message && <span className="text-xs text-signal-critical">{message}</span>}
    </span>
  );
}

export function DiscoveredTable({ domains }: { domains: DiscoveredDomain[] }) {
  if (domains.length === 0) {
    return (
      <EmptyState
        title="No discovered domains yet"
        description="Subdomain discovery scans list the hosts they find here, so you can start tracking the ones that matter."
      />
    );
  }
  return (
    <Table>
      <THead>
        <tr>
          <TH>Domain</TH>
          <TH>Found via</TH>
          <TH>Resolves</TH>
          <TH>First seen</TH>
          <TH>Last seen</TH>
          <TH className="text-right">Action</TH>
        </tr>
      </THead>
      <TBody>
        {domains.map((d) => (
          <TR key={d.id}>
            <TD className="font-mono">{d.name}</TD>
            <TD className="text-text-dim">{d.viaTarget ?? "Unknown"}</TD>
            <TD>
              {d.resolves ? (
                <span className="font-mono text-xs text-text-dim">{(d.records.A ?? []).join(", ") || "Yes"}</span>
              ) : (
                <span className="text-xs text-text-faint">No</span>
              )}
            </TD>
            <TD className="whitespace-nowrap text-text-dim">{timeAgo(d.firstSeen)}</TD>
            <TD className="whitespace-nowrap text-text-dim">{timeAgo(d.lastSeen)}</TD>
            <TD className="text-right"><AddButton domain={d} /></TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}
