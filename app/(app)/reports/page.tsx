import { FileText } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "Reports" };

export default function ReportsPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader title="Reports" description="Branded reports of your risks and coverage, on demand or on a schedule." />
      <EmptyState
        icon={<FileText className="h-6 w-6" />}
        title="No reports yet"
        description="Reports you generate are kept here so you can open or share them later."
      />
    </div>
  );
}
