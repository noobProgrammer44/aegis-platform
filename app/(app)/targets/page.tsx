import type { Metadata } from "next";
import { TargetsView } from "@/components/targets/targets-view";
import { getDb } from "@/lib/db/client";
import { loadTargetsPage } from "@/lib/services/targets";
import { currentWorkspaceId } from "@/lib/workspace";

export const metadata: Metadata = { title: "Targets" };

export default async function TargetsPage({
  searchParams,
}: {
  searchParams: Promise<{ tab?: string }>;
}) {
  const { tab } = await searchParams;
  const data = loadTargetsPage(getDb(), currentWorkspaceId());
  return <TargetsView data={data} tab={tab === "discovered" ? "discovered" : "targets"} />;
}
