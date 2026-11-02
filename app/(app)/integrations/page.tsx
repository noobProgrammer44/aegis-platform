import { Plug } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "Integrations" };

export default function IntegrationsPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader title="Integrations" description="Send scan results to Slack, email or your own systems." />
      <EmptyState
        icon={<Plug className="h-6 w-6" />}
        title="No integrations set up"
        description="Webhooks, Slack and email alerts are configured here."
      />
    </div>
  );
}
