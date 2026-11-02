import { FileText } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { ReportBuilder } from "@/components/reports/report-builder";
import { Chip } from "@/components/ui/badges";
import { Card, PageHeader } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { getDb } from "@/lib/db/client";
import { listReports } from "@/lib/db/repos/reports";
import { listTargets } from "@/lib/db/repos/targets";
import { timeAgo } from "@/lib/ui/format";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Reports" };

const FORMAT_LABEL = { HTML: "Report", JSON: "JSON", CSV: "CSV" } as const;

export default async function ReportsPage({ searchParams }: { searchParams: Promise<{ target?: string }> }) {
  const { target } = await searchParams;
  const db = getDb();
  const ws = currentWorkspaceId();
  const targets = listTargets(db, ws);
  const reports = listReports(db, ws, 100);
  const preselected = targets.some((t) => t.id === target) ? (target ?? null) : null;

  return (
    <div className="px-8 py-8">
      <PageHeader
        title="Reports"
        description="Branded reports of your risks and coverage. Each report freezes the data at the moment it was generated."
      />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <ReportBuilder targets={targets} preselected={preselected} />
        <Card title={`Report history (${reports.length})`} bodyClassName="p-0">
          {reports.length === 0 ? (
            <div className="flex flex-col items-center px-6 py-14 text-center">
              <FileText className="mb-3 h-6 w-6 text-text-faint" />
              <p className="text-sm font-medium">No reports yet</p>
              <p className="mt-1.5 max-w-sm text-sm text-text-dim">Generated reports are kept here to open, print or download later.</p>
            </div>
          ) : (
            <Table className="rounded-none border-0 bg-transparent">
              <THead>
                <tr>
                  <TH>Name</TH>
                  <TH>Format</TH>
                  <TH>Created</TH>
                </tr>
              </THead>
              <TBody>
                {reports.map((r) => (
                  <TR key={r.id}>
                    <TD>
                      <Link href={`/reports/${r.id}`} className="font-medium hover:text-accent">{r.name}</Link>
                    </TD>
                    <TD><Chip>{FORMAT_LABEL[r.format]}</Chip></TD>
                    <TD className="whitespace-nowrap text-text-dim">{timeAgo(r.createdAt)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
      </div>
    </div>
  );
}
