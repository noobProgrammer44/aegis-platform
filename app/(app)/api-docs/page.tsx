import { BookOpen } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState, PageHeader } from "@/components/ui/card";

export const metadata: Metadata = { title: "API docs" };

export default function ApiDocsPage() {
  return (
    <div className="px-8 py-8">
      <PageHeader title="API docs" description="Use Aegis from scripts and CI with the REST API." />
      <EmptyState
        icon={<BookOpen className="h-6 w-6" />}
        title="The REST API isn't enabled yet"
        description="Once API keys are available in Settings, the endpoints and examples are documented here."
      />
    </div>
  );
}
