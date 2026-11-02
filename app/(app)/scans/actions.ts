"use server";

import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/lib/actions/result";
import { getDb } from "@/lib/db/client";
import { appendAudit } from "@/lib/db/repos/audit-log";
import { deleteScan, getScan } from "@/lib/db/repos/scans";
import { deleteScheduledScan, getScheduledScan, updateScheduledScan } from "@/lib/db/repos/scheduled-scans";
import { listTargetsMatching } from "@/lib/db/repos/targets";
import { isAvailableScanType } from "@/lib/scans/catalog";
import { pumpQueue, stopScan } from "@/lib/scans/runner";
import { queueScans, submitScanRequest } from "@/lib/services/scan-requests";
import { parseScanRequest } from "@/lib/validation/scan-request";
import { currentWorkspaceId } from "@/lib/workspace";

/** Server actions for the Scans page. The browser only sends ids; everything else is checked here. */

const ACTOR = "local user";
const MAX_ID_LENGTH = 64;

const fail = (message: string): ActionResult => ({ ok: false, message, errors: [] });
const validId = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= MAX_ID_LENGTH;

function refresh(): void {
  revalidatePath("/scans");
  revalidatePath("/scans/new");
  revalidatePath("/dashboard");
  revalidatePath("/targets");
}

/** The New Scan wizard's submit: queue now, or create a schedule. */
export async function submitScanRequestAction(payload: unknown): Promise<ActionResult & { kind?: "queued" | "scheduled" }> {
  const parsed = parseScanRequest(payload);
  if (!parsed.ok) return fail(parsed.error);
  const db = getDb();
  const outcome = submitScanRequest(db, currentWorkspaceId(), parsed.value, new Date(), ACTOR);
  if (outcome.kind === "error") return fail(outcome.message);
  if (outcome.kind === "queued") pumpQueue(db);
  refresh();
  return outcome.kind === "queued"
    ? { ok: true, kind: "queued", message: `Started ${outcome.scans.length} scan${outcome.scans.length === 1 ? "" : "s"}.`, errors: [] }
    : { ok: true, kind: "scheduled", message: `Scheduled "${outcome.schedule.name}".`, errors: [] };
}

export async function toggleScheduleAction(id: string, enabled: boolean): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown schedule.");
  const db = getDb();
  const ws = currentWorkspaceId();
  if (!updateScheduledScan(db, ws, id, { enabled })) return fail("That schedule no longer exists.");
  appendAudit(db, ws, { actor: ACTOR, action: enabled ? "schedule.resumed" : "schedule.paused", subject: id });
  refresh();
  return { ok: true, message: enabled ? "Resumed." : "Paused.", errors: [] };
}

export async function deleteScheduleAction(id: string): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown schedule.");
  const db = getDb();
  const ws = currentWorkspaceId();
  if (!deleteScheduledScan(db, ws, id)) return fail("That schedule no longer exists.");
  appendAudit(db, ws, { actor: ACTOR, action: "schedule.deleted", subject: id });
  refresh();
  return { ok: true, message: "Deleted.", errors: [] };
}

/** Runs a schedule's scans now without changing its next run. */
export async function runScheduleNowAction(id: string): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown schedule.");
  const db = getDb();
  const ws = currentWorkspaceId();
  const schedule = getScheduledScan(db, ws, id);
  if (!schedule) return fail("That schedule no longer exists.");
  const targets = listTargetsMatching(db, ws, schedule.targetsFilter);
  if (targets.length === 0) return fail("No targets match this schedule.");
  const types = schedule.scanTypes.filter(isAvailableScanType);
  queueScans(db, ws, { types, targets, intensity: schedule.intensity, actor: ACTOR, scheduledBy: schedule.id });
  pumpQueue(db);
  refresh();
  return { ok: true, message: `Started ${types.length} scan${types.length === 1 ? "" : "s"}.`, errors: [] };
}

export async function stopScanAction(id: string): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown scan.");
  const ws = currentWorkspaceId();
  const scan = stopScan(ws, id);
  if (!scan) return fail("That scan no longer exists.");
  appendAudit(getDb(), ws, { actor: ACTOR, action: "scan.stop_requested", subject: id });
  refresh();
  return { ok: true, message: "Stopping.", errors: [] };
}

export async function deleteScanAction(id: string): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown scan.");
  const db = getDb();
  const ws = currentWorkspaceId();
  const scan = getScan(db, ws, id);
  if (!scan) return fail("That scan no longer exists.");
  if (["QUEUED", "RUNNING", "STOPPING"].includes(scan.state)) return fail("Stop the scan before deleting it.");
  deleteScan(db, ws, id);
  appendAudit(db, ws, { actor: ACTOR, action: "scan.deleted", subject: id, details: { type: scan.type } });
  refresh();
  return { ok: true, message: "Deleted.", errors: [] };
}
