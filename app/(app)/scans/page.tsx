import { Radar } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "Scans" };

export default function ScansPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader title="Scans" description="Running, finished and scheduled scans of your targets." />
      <EmptyState
        icon={<Radar className="h-6 w-6" />}
        title="No scans yet"
        description="Scans you run or schedule show up here with their progress and results."
      />
    </div>
  );
}
