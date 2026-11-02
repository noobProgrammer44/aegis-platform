"use client";

import { ArrowLeft, Download, Printer, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import { deleteReportAction } from "@/app/(app)/reports/actions";
import { Button, buttonClass } from "@/components/ui/button";

/** Actions above a report; hidden when printing. */
export function ReportToolbar({ id }: { id: string }) {
  const router = useRouter();
  const [confirming, setConfirming] = useState(false);
  const [pending, start] = useTransition();
  return (
    <div className="mb-6 flex flex-wrap items-center justify-between gap-3 print:hidden">
      <Link href="/reports" className="inline-flex items-center gap-1.5 text-xs text-text-faint hover:text-text">
        <ArrowLeft className="h-3.5 w-3.5" /> All reports
      </Link>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" onClick={() => window.print()}>
          <Printer className="h-4 w-4" /> Print / save as PDF
        </Button>
        <a href={`/api/reports/${id}/download?format=json`} className={buttonClass("secondary")}>
          <Download className="h-4 w-4" /> JSON
        </a>
        <a href={`/api/reports/${id}/download?format=csv`} className={buttonClass("secondary")}>
          <Download className="h-4 w-4" /> CSV
        </a>
        {confirming ? (
          <>
            <Button
              variant="danger"
              disabled={pending}
              onClick={() =>
                start(async () => {
                  const result = await deleteReportAction(id);
                  if (result.ok) router.push("/reports");
                })
              }
            >
              {pending ? "Deleting…" : "Delete report"}
            </Button>
            <Button variant="ghost" onClick={() => setConfirming(false)}>Cancel</Button>
          </>
        ) : (
          <Button variant="ghost" aria-label="Delete report" onClick={() => setConfirming(true)}>
            <Trash2 className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  );
}
