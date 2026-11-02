import { Crosshair } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "Targets" };

export default function TargetsPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader title="Targets" description="Domains, URLs, IP addresses and ranges you track and scan." />
      <EmptyState
        icon={<Crosshair className="h-6 w-6" />}
        title="No targets yet"
        description="Targets you add, and subdomains Aegis discovers, are listed here with their health grade."
      />
    </div>
  );
}
