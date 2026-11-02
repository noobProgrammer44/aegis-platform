import { ArrowLeft, Download } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ScanStateBadge } from "@/components/scans/scan-state";
import { SeverityDot } from "@/components/ui/badges";
import { AutoRefresh } from "@/components/ui/auto-refresh";
import { Card, PageHeader } from "@/components/ui/card";
import { getDb } from "@/lib/db/client";
import { listRisks } from "@/lib/db/repos/risks";
import { listScanResults } from "@/lib/db/repos/scan-results";
import { getScan } from "@/lib/db/repos/scans";
import { INTENSITY_PROFILES } from "@/lib/recon/intensity";
import { SCAN_TYPE_LABEL, timeAgo } from "@/lib/ui/format";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Scan" };

const formatSize = (bytes: number) => (bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`);

export default async function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const db = getDb();
  const ws = currentWorkspaceId();
  const scan = getScan(db, ws, id);
  if (!scan) notFound();
  const files = listScanResults(db, ws, scan.id);
  const risks = listRisks(db, ws, { targetIds: scan.targetIds }).filter((r) => r.lastScanId === scan.id && r.status === "OPEN");
  const live = ["QUEUED", "RUNNING", "STOPPING"].includes(scan.state);

  return (
    <div className="max-w-5xl px-8 py-8">
      <AutoRefresh active={live} />
      <Link href="/scans" className="mb-4 inline-flex items-center gap-1.5 text-xs text-text-faint hover:text-text">
        <ArrowLeft className="h-3.5 w-3.5" /> All scans
      </Link>
      <PageHeader
        title={SCAN_TYPE_LABEL[scan.type]}
        description={`${INTENSITY_PROFILES[scan.intensity].label} intensity · queued ${timeAgo(scan.createdAt)}`}
      />

      <div className="grid gap-5 lg:grid-cols-3">
        <Card title="Status">
          <ScanStateBadge scan={scan} />
          {scan.error && <p className="mt-3 text-sm text-signal-critical">{scan.error}</p>}
          <dl className="mt-4 grid grid-cols-3 gap-2 text-center">
            {[
              ["New", scan.risks.newOpen],
              ["Still open", scan.risks.stillOpen],
              ["Closed", scan.risks.closed],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-border-soft py-2">
                <dt className="text-[11px] text-text-faint">{label}</dt>
                <dd className="font-mono text-lg font-semibold">{value}</dd>
              </div>
            ))}
          </dl>
        </Card>

        <Card title="Targets" className="lg:col-span-2">
          <ul className="space-y-1.5 text-sm">
            {scan.targets.map((t) => {
              const skip = scan.skippedTargets.find((s) => s.target === t);
              return (
                <li key={t} className="flex flex-wrap items-baseline gap-x-3">
                  <span className="font-mono">{t}</span>
                  {skip && <span className="text-xs text-caution">Skipped: {skip.reason}</span>}
                </li>
              );
            })}
          </ul>
        </Card>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <Card title={`Open risks from this scan (${risks.length})`} className="lg:col-span-2" bodyClassName="p-0">
          {risks.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-text-faint">
              {live ? "Findings appear when the scan finishes." : "This scan found no open risks."}
            </p>
          ) : (
            <ul className="divide-y divide-border-soft">
              {risks.map((r) => (
                <li key={r.id} className="flex items-start gap-3 px-5 py-3">
                  <span className="mt-1.5"><SeverityDot level={r.definition.threatLevel} /></span>
                  <div className="min-w-0">
                    <p className="text-sm">{r.definition.title}</p>
                    <p className="truncate text-xs text-text-faint">{String(r.definition.additionalInfo.host ?? "")}</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Raw results">
          {files.length === 0 ? (
            <p className="text-sm text-text-faint">Saved when the scan finishes.</p>
          ) : (
            <ul className="space-y-2">
              {files.map((f) => (
                <li key={f.id}>
                  <a
                    href={`/api/scans/${scan.id}/results/${f.id}`}
                    className="flex items-center gap-2 text-sm text-accent hover:text-accent-hover"
                  >
                    <Download className="h-4 w-4" /> {f.filename}
                    <span className="text-xs text-text-faint">{formatSize(f.size)}</span>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
