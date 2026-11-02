"use client";

import { X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";
import { cx } from "@/lib/ui/cx";

/** Closes on Escape and moves focus into the panel when it opens. */
function useOverlay(open: boolean, onClose: () => void) {
  const panelRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    panelRef.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  return panelRef;
}

function CloseButton({ onClose }: { onClose: () => void }) {
  return (
    <button
      type="button"
      onClick={onClose}
      aria-label="Close"
      className="rounded-md p-1.5 text-text-faint hover:bg-white/[0.06] hover:text-text"
    >
      <X className="h-4 w-4" />
    </button>
  );
}

/** Right-hand side panel (target overview, risk detail). */
export function Drawer({
  open,
  onClose,
  title,
  children,
  width = "max-w-2xl",
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  width?: string;
}) {
  const panelRef = useOverlay(open, onClose);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        className={cx(
          "relative flex h-full w-full flex-col border-l border-border bg-surface shadow-2xl outline-none",
          width,
        )}
      >
        <header className="flex items-center justify-between gap-3 border-b border-border-soft px-6 py-4">
          <div className="min-w-0 text-base font-semibold tracking-tight">{title}</div>
          <CloseButton onClose={onClose} />
        </header>
        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>
      </div>
    </div>
  );
}

/** Centred dialog (new scan, add target, confirmations). */
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  width = "max-w-lg",
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  const panelRef = useOverlay(open, onClose);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 pt-[10vh]">
      <div className="fixed inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        className={cx(
          "relative w-full rounded-xl border border-border bg-surface shadow-2xl outline-none",
          width,
        )}
      >
        <header className="flex items-center justify-between gap-3 border-b border-border-soft px-5 py-3.5">
          <div className="text-sm font-semibold tracking-tight">{title}</div>
          <CloseButton onClose={onClose} />
        </header>
        <div className="px-5 py-4">{children}</div>
        {footer && (
          <footer className="flex justify-end gap-2 border-t border-border-soft px-5 py-3">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
