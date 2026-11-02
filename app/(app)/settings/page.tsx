import { Settings } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "Settings" };

export default function SettingsPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader title="Settings" description="Workspace settings, API keys, branding and scanner status." />
      <EmptyState
        icon={<Settings className="h-6 w-6" />}
        title="Nothing to configure yet"
        description="API keys, report branding and the health threshold are managed here."
      />
    </div>
  );
}
