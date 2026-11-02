import type { ReactNode } from "react";
import { Sidebar } from "@/components/shell/sidebar";
import { getDb } from "@/lib/db/client";
import { getWorkspace } from "@/lib/db/repos/workspaces";
import { currentWorkspaceId } from "@/lib/workspace";

// Every page reads the local database, so nothing here is prerendered at build time.
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export default function AppLayout({ children }: { children: ReactNode }) {
  const workspace = getWorkspace(getDb(), currentWorkspaceId());
  return (
    <div className="flex min-h-screen">
      <Sidebar workspaceName={workspace?.name ?? "Workspace"} />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
