"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import type { ActionResult } from "@/lib/actions/result";
import { getDb } from "@/lib/db/client";
import { appendAudit } from "@/lib/db/repos/audit-log";
import { deleteReport, getReport } from "@/lib/db/repos/reports";
import { REPORT_SECTIONS } from "@/lib/domain/report";
import { generateReport } from "@/lib/services/reports";
import { currentWorkspaceId } from "@/lib/workspace";
import { THREAT_LEVELS, type ReportFormat, type ReportSection, type ThreatLevel } from "@/types/aegis";

const ACTOR = "local user";
const FORMATS: readonly ReportFormat[] = ["HTML", "JSON", "CSV"];
const fail = (message: string): ActionResult => ({ ok: false, message, errors: [] });

const pick = <T extends string>(values: FormDataEntryValue[], allowed: readonly T[]): T[] =>
  [...new Set(values.map(String))].filter((v): v is T => (allowed as readonly string[]).includes(v));

export async function createReportAction(_prev: ActionResult, form: FormData): Promise<ActionResult> {
  const name = String(form.get("name") ?? "").trim().slice(0, 100);
  if (!name) return fail("Give the report a name.");
  const format = String(form.get("format"));
  if (!(FORMATS as readonly string[]).includes(format)) return fail("Pick a format.");
  const sections = pick<ReportSection>(form.getAll("sections"), REPORT_SECTIONS.map((s) => s.value));
  if (sections.length === 0) return fail("Include at least one section.");
  const targetIds = [...new Set(form.getAll("targetIds").map(String))].filter((id) => id.length > 0 && id.length <= 64);
  const tags = String(form.get("tags") ?? "").split(/[\s,]+/).map((t) => t.trim().toLowerCase()).filter(Boolean).slice(0, 10);

  const db = getDb();
  const ws = currentWorkspaceId();
  const report = generateReport(db, ws, {
    name,
    format: format as ReportFormat,
    sections,
    actor: ACTOR,
    filters: {
      targets: { targetIds, tags },
      threatLevels: pick<ThreatLevel>(form.getAll("threatLevels"), THREAT_LEVELS),
      includeAccepted: form.get("includeAccepted") === "on",
      includeClosed: form.get("includeClosed") === "on",
    },
  });
  revalidatePath("/reports");
  redirect(`/reports/${report.id}`);
}

export async function deleteReportAction(id: string): Promise<ActionResult> {
  if (typeof id !== "string" || id.length === 0 || id.length > 64) return fail("Unknown report.");
  const db = getDb();
  const ws = currentWorkspaceId();
  const report = getReport(db, ws, id);
  if (!report || !deleteReport(db, ws, id)) return fail("That report no longer exists.");
  appendAudit(db, ws, { actor: ACTOR, action: "report.deleted", subject: id, details: { name: report.name } });
  revalidatePath("/reports");
  return { ok: true, message: "Deleted.", errors: [] };
}
