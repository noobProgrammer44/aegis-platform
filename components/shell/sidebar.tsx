"use client";

import { ChevronsLeft, ChevronsRight } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { ShieldMark } from "@/components/brand/shield-mark";
import { cx } from "@/lib/ui/cx";
import { FOOTER_NAV, isActive, MAIN_NAV, type NavItem } from "./nav";

const COLLAPSED_KEY = "aegis.sidebar.collapsed";

function readCollapsed(): boolean {
  try {
    return window.localStorage.getItem(COLLAPSED_KEY) === "1";
  } catch {
    return false;
  }
}

function writeCollapsed(collapsed: boolean): void {
  try {
    window.localStorage.setItem(COLLAPSED_KEY, collapsed ? "1" : "0");
  } catch {
    /* storage unavailable (private window): the choice just isn't remembered */
  }
}

function NavLink({ item, active, collapsed }: { item: NavItem; active: boolean; collapsed: boolean }) {
  const Icon = item.icon;
  return (
    <Link
      href={item.href}
      title={collapsed ? item.label : undefined}
      aria-current={active ? "page" : undefined}
      className={cx(
        "flex h-9 items-center gap-3 rounded-lg px-2.5 text-sm transition-colors",
        active
          ? "bg-accent/12 font-medium text-text"
          : "text-text-dim hover:bg-white/[0.04] hover:text-text",
        collapsed && "justify-center px-0",
      )}
    >
      <Icon className={cx("h-4 w-4 shrink-0", active ? "text-accent" : "text-text-faint")} />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Link>
  );
}

export function Sidebar({ workspaceName }: { workspaceName: string }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  // Read after mount: localStorage doesn't exist during server rendering.
  useEffect(() => setCollapsed(readCollapsed()), []);

  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    writeCollapsed(next);
  };

  return (
    <aside
      className={cx(
        "sticky top-0 flex h-screen shrink-0 flex-col border-r border-border-soft bg-surface/60 transition-[width]",
        collapsed ? "w-16" : "w-60",
      )}
    >
      <div className={cx("flex h-14 items-center gap-2.5 px-4", collapsed && "justify-center px-0")}>
        <ShieldMark className="h-5 w-5 shrink-0 text-accent" />
        {!collapsed && (
          <span className="font-mono text-sm font-semibold tracking-tight">aegis</span>
        )}
      </div>

      {!collapsed && (
        <div className="mx-3 mb-3 rounded-lg border border-border-soft px-3 py-2">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-text-faint">
            Workspace
          </p>
          <p className="truncate text-sm">{workspaceName}</p>
        </div>
      )}

      <nav className="flex flex-1 flex-col gap-0.5 px-3" aria-label="Main">
        {MAIN_NAV.map((item) => (
          <NavLink key={item.href} item={item} active={isActive(pathname, item.href)} collapsed={collapsed} />
        ))}
      </nav>

      <nav className="flex flex-col gap-0.5 border-t border-border-soft px-3 py-3" aria-label="Tools">
        {FOOTER_NAV.map((item) => (
          <NavLink key={item.href} item={item} active={isActive(pathname, item.href)} collapsed={collapsed} />
        ))}
        <button
          type="button"
          onClick={toggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className={cx(
            "mt-1 flex h-9 items-center gap-3 rounded-lg px-2.5 text-sm text-text-faint hover:bg-white/[0.04] hover:text-text",
            collapsed && "justify-center px-0",
          )}
        >
          {collapsed ? <ChevronsRight className="h-4 w-4" /> : <ChevronsLeft className="h-4 w-4" />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </nav>
    </aside>
  );
}
