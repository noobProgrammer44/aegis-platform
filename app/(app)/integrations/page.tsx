import type { Metadata } from "next";
import { IntegrationsPreview } from "@/components/integrations/integrations-preview";
import { PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "Integrations" };

export default function IntegrationsPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader
        title="Integrations"
        description="Send scan results and new risks to the tools your team already uses, and import targets from your cloud accounts."
      />
      <IntegrationsPreview />
    </div>
  );
}
