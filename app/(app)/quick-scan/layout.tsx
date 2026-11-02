import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = { title: "Quick scan" };

export default function QuickScanLayout({ children }: { children: ReactNode }) {
  return children;
}
