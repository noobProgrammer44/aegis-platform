import type { HealthGrade, ThreatLevel } from "@/types/aegis";

/** Tailwind classes per severity and grade. Full class strings so Tailwind can see them. */

export interface ToneClasses {
  label: string;
  text: string;
  bg: string;
  border: string;
  dot: string;
}

/** Jay's severity accents: left edge bar, soft glow, SVG stroke. */
export const SEVERITY_ACCENT: Record<ThreatLevel, { edge: string; glow: string; stroke: string }> = {
  CRITICAL: {
    edge: "shadow-[inset_3px_0_0_var(--signal-critical),0_18px_48px_-30px_var(--signal-critical)]",
    glow: "drop-shadow-[0_0_6px_var(--signal-critical)]",
    stroke: "var(--signal-critical)",
  },
  HIGH: {
    edge: "shadow-[inset_3px_0_0_var(--signal-high),0_18px_48px_-30px_var(--signal-high)]",
    glow: "drop-shadow-[0_0_6px_var(--signal-high)]",
    stroke: "var(--signal-high)",
  },
  MEDIUM: {
    edge: "shadow-[inset_3px_0_0_var(--signal-medium),0_18px_48px_-30px_var(--signal-medium)]",
    glow: "drop-shadow-[0_0_6px_var(--signal-medium)]",
    stroke: "var(--signal-medium)",
  },
  LOW: {
    edge: "shadow-[inset_3px_0_0_var(--signal-low),0_18px_48px_-30px_var(--signal-low)]",
    glow: "drop-shadow-[0_0_6px_var(--signal-low)]",
    stroke: "var(--signal-low)",
  },
};

export const SEVERITY_TONE: Record<ThreatLevel, ToneClasses> = {
  CRITICAL: {
    label: "Critical",
    text: "text-signal-critical",
    bg: "bg-signal-critical/[0.08]",
    border: "border-signal-critical/35",
    dot: "bg-signal-critical",
  },
  HIGH: {
    label: "High",
    text: "text-signal-high",
    bg: "bg-signal-high/[0.08]",
    border: "border-signal-high/35",
    dot: "bg-signal-high",
  },
  MEDIUM: {
    label: "Medium",
    text: "text-signal-medium",
    bg: "bg-signal-medium/[0.08]",
    border: "border-signal-medium/35",
    dot: "bg-signal-medium",
  },
  LOW: {
    label: "Low",
    text: "text-signal-low",
    bg: "bg-signal-low/[0.08]",
    border: "border-signal-low/35",
    dot: "bg-signal-low",
  },
};

export const GRADE_TONE: Record<HealthGrade, Omit<ToneClasses, "label">> = {
  A: { text: "text-grade-a", bg: "bg-grade-a/12", border: "border-grade-a/35", dot: "bg-grade-a" },
  B: { text: "text-grade-b", bg: "bg-grade-b/12", border: "border-grade-b/35", dot: "bg-grade-b" },
  C: { text: "text-grade-c", bg: "bg-grade-c/12", border: "border-grade-c/35", dot: "bg-grade-c" },
  D: { text: "text-grade-d", bg: "bg-grade-d/12", border: "border-grade-d/35", dot: "bg-grade-d" },
  F: { text: "text-grade-f", bg: "bg-grade-f/12", border: "border-grade-f/35", dot: "bg-grade-f" },
};

/** CSS variable per grade, for SVG fills (the gauge bands). */
export const GRADE_COLOR_VAR: Record<HealthGrade, string> = {
  A: "var(--grade-a)",
  B: "var(--grade-b)",
  C: "var(--grade-c)",
  D: "var(--grade-d)",
  F: "var(--grade-f)",
};
