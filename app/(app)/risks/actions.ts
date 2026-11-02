"use server";

import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/lib/actions/result";
import { getDb, nowIso } from "@/lib/db/client";
import {
  createAcceptanceRule,
  deleteAcceptanceRule,
  getAcceptanceRule,
  normalizeQuery,
  updateAcceptanceRule,
} from "@/lib/db/repos/acceptance-rules";
import { appendAudit, listAudit } from "@/lib/db/repos/audit-log";
import { getRisk, setRiskAcceptance } from "@/lib/db/repos/risks";
import { MANUAL_ACCEPTANCE, validateAcceptanceQuery } from "@/lib/domain/acceptance";
import { recomputeHealth } from "@/lib/scans/health";
import { reapplyAcceptanceRules } from "@/lib/services/acceptance";
import { currentWorkspaceId } from "@/lib/workspace";
import { THREAT_LEVELS, type AuditEntry, type ScanType, type ThreatLevel } from "@/types/aegis";

/** Server actions for the Risks page. Inputs are re-validated here, never trusted. */

const ACTOR = "local user";
const MAX_ID = 64;
const MAX_REASON = 500;
const MAX_NAME = 80;
const SCAN_TYPES: readonly ScanType[] = ["SURFACE", "DISCOVERY", "NUCLEI", "NMAP", "TLS", "EMAIL", "TAKEOVER", "JS_SECRETS", "ZAP_PASSIVE", "ZAP_ACTIVE"];

const fail = (message: string): ActionResult => ({ ok: false, message, errors: [] });
const ok = (message: string): ActionResult => ({ ok: true, message, errors: [] });
const validId = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_ID;

function refresh(): void {
  revalidatePath("/risks");
  revalidatePath("/dashboard");
  revalidatePath("/targets");
}

export async function setAcceptanceAction(id: string, accepted: boolean, reason: string): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown risk.");
  const trimmed = String(reason ?? "").trim().slice(0, MAX_REASON);
  if (accepted && !trimmed) return fail("Say why this risk is accepted.");
  const db = getDb();
  const ws = currentWorkspaceId();
  const risk = getRisk(db, ws, id);
  if (!risk) return fail("That risk no longer exists.");

  setRiskAcceptance(db, ws, id, { accepted, reason: accepted ? trimmed : null, by: accepted ? MANUAL_ACCEPTANCE : null });
  recomputeHealth(db, ws, [risk.targetId], nowIso());
  appendAudit(db, ws, {
    actor: ACTOR,
    action: accepted ? "risk.accepted" : "risk.unaccepted",
    subject: id,
    details: { title: risk.definition.title, ...(accepted ? { reason: trimmed } : {}) },
  });
  // Un-accepting hands the risk back to the rules, which may accept it again.
  if (!accepted) reapplyAcceptanceRules(db, ws);
  refresh();
  return ok(accepted ? "Accepted." : "No longer accepted.");
}

const pick = <T extends string>(values: FormDataEntryValue[], allowed: readonly T[]): T[] =>
  [...new Set(values.map(String))].filter((v): v is T => (allowed as readonly string[]).includes(v));

export async function createRuleAction(_prev: ActionResult, form: FormData): Promise<ActionResult> {
  const name = String(form.get("name") ?? "").trim().slice(0, MAX_NAME);
  if (!name) return fail("Give the rule a name.");
  const ports = String(form.get("ports") ?? "")
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(Number);
  const tags = String(form.get("tags") ?? "")
    .split(/[\s,]+/)
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
  const titlePattern = String(form.get("titlePattern") ?? "").trim() || null;
  const query = normalizeQuery({
    threatLevels: pick<ThreatLevel>(form.getAll("threatLevels"), THREAT_LEVELS),
    scanTypes: pick<ScanType>(form.getAll("scanTypes"), SCAN_TYPES),
    targetTags: tags,
    ports,
    titlePattern,
  });
  const errors = validateAcceptanceQuery(query);
  if (errors.length > 0) return fail(errors[0]);

  const db = getDb();
  const ws = currentWorkspaceId();
  const rule = createAcceptanceRule(db, ws, { name, query, note: String(form.get("note") ?? "").trim().slice(0, MAX_REASON) });
  appendAudit(db, ws, { actor: ACTOR, action: "rule.created", subject: rule.id, details: { name, query } });
  const changed = reapplyAcceptanceRules(db, ws);
  refresh();
  return ok(`Rule saved. It accepted ${changed} open risk${changed === 1 ? "" : "s"}.`);
}

export async function toggleRuleAction(id: string, enabled: boolean): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown rule.");
  const db = getDb();
  const ws = currentWorkspaceId();
  if (!updateAcceptanceRule(db, ws, id, { enabled })) return fail("That rule no longer exists.");
  appendAudit(db, ws, { actor: ACTOR, action: enabled ? "rule.enabled" : "rule.disabled", subject: id });
  reapplyAcceptanceRules(db, ws);
  refresh();
  return ok(enabled ? "Rule enabled." : "Rule disabled.");
}

export async function deleteRuleAction(id: string): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown rule.");
  const db = getDb();
  const ws = currentWorkspaceId();
  const rule = getAcceptanceRule(db, ws, id);
  if (!rule || !deleteAcceptanceRule(db, ws, id)) return fail("That rule no longer exists.");
  appendAudit(db, ws, { actor: ACTOR, action: "rule.deleted", subject: id, details: { name: rule.name } });
  reapplyAcceptanceRules(db, ws);
  refresh();
  return ok("Rule deleted. Risks it accepted are open again.");
}

/** Audit entries about one risk, newest first (for the drawer's history). */
export async function riskHistoryAction(id: string): Promise<AuditEntry[]> {
  if (!validId(id)) return [];
  return listAudit(getDb(), currentWorkspaceId(), { subject: id, limit: 50 });
}
