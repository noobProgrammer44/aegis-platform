import { ScrollText } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { getDb } from "@/lib/db/client";
import { listAudit } from "@/lib/db/repos/audit-log";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Audit log" };

const formatTime = (iso: string) =>
  new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });

export default function AuditLogPage() {
  const entries = listAudit(getDb(), currentWorkspaceId(), { limit: 200 });
  return (
    <div className="px-8 py-8">
      <PageHeader
        title="Audit log"
        description="A permanent record of authorizations, scans and changes in this workspace. Entries can't be edited or removed."
      />
      {entries.length === 0 ? (
        <EmptyState
          icon={<ScrollText className="h-6 w-6" />}
          title="No activity recorded yet"
          description="Authorizations, scans and setting changes are logged here as they happen."
        />
      ) : (
        <Table>
          <THead>
            <tr>
              <TH>Time (UTC)</TH>
              <TH>Action</TH>
              <TH>Subject</TH>
              <TH>Actor</TH>
            </tr>
          </THead>
          <TBody>
            {entries.map((entry) => (
              <TR key={entry.id}>
                <TD className="whitespace-nowrap text-text-dim">{formatTime(entry.at)}</TD>
                <TD className="font-mono text-xs">{entry.action}</TD>
                <TD className="font-mono text-xs">{entry.subject}</TD>
                <TD className="text-text-dim">{entry.actor}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </div>
  );
}
