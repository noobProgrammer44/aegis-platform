import { Bug } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "Risks" };

export default function RisksPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader title="Risks" description="Every finding across your targets, open or closed." />
      <EmptyState
        icon={<Bug className="h-6 w-6" />}
        title="No risks found"
        description="Findings from your scans collect here, where you can filter, accept or export them."
      />
    </div>
  );
}
