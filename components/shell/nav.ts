import {
  BookOpen,
  Bug,
  Crosshair,
  FileText,
  LayoutDashboard,
  LifeBuoy,
  Plug,
  Radar,
  ScrollText,
  Settings,
  Zap,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

export const MAIN_NAV: readonly NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/quick-scan", label: "Quick scan", icon: Zap },
  { href: "/targets", label: "Targets", icon: Crosshair },
  { href: "/scans", label: "Scans", icon: Radar },
  { href: "/risks", label: "Risks", icon: Bug },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/integrations", label: "Integrations", icon: Plug },
  { href: "/settings", label: "Settings", icon: Settings },
  { href: "/audit-log", label: "Audit log", icon: ScrollText },
];

export const FOOTER_NAV: readonly NavItem[] = [
  { href: "/api-docs", label: "API docs", icon: BookOpen },
  { href: "/help", label: "Help", icon: LifeBuoy },
];

/** Active when the path is the item's page or one of its sub-pages. */
export function isActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}
