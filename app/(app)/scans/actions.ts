"use server";

import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/lib/actions/result";
import { getDb } from "@/lib/db/client";
import { appendAudit } from "@/lib/db/repos/audit-log";
import { createScan, deleteScan, getScan } from "@/lib/db/repos/scans";
import { getTarget } from "@/lib/db/repos/targets";
import { resolveIntensity } from "@/lib/recon/intensity";
import { isAvailableScanType, SCANNER_CATALOG } from "@/lib/scans/catalog";
import { pumpQueue, stopScan } from "@/lib/scans/runner";
import { currentWorkspaceId } from "@/lib/workspace";
import type { Target } from "@/types/aegis";

/** Server actions for the Scans page. The browser only sends ids; everything else is checked here. */

const ACTOR = "local user";
const MAX_ID_LENGTH = 64;
const MAX_TARGETS_PER_SCAN = 100;

const fail = (message: string): ActionResult => ({ ok: false, message, errors: [] });
const validId = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= MAX_ID_LENGTH;

function refresh(): void {
  revalidatePath("/scans");
  revalidatePath("/dashboard");
  revalidatePath("/targets");
}

export async function startScanAction(_prev: ActionResult, form: FormData): Promise<ActionResult> {
  const types = [...new Set(form.getAll("scanTypes").map(String))].filter(isAvailableScanType);
  if (types.length === 0) return fail("Pick at least one scanner.");
  const ids = [...new Set(form.getAll("targetIds").map(String))].filter(validId);
  if (ids.length === 0) return fail("Pick at least one target.");
  if (ids.length > MAX_TARGETS_PER_SCAN) return fail(`Scan at most ${MAX_TARGETS_PER_SCAN} targets at a time.`);

  const db = getDb();
  const ws = currentWorkspaceId();
  const targets = ids.map((id) => getTarget(db, ws, id)).filter((t): t is Target => t !== null);
  if (targets.length === 0) return fail("Those targets no longer exist.");
  const intensity = resolveIntensity(form.get("intensity"));

  for (const type of types) {
    const scan = createScan(db, ws, {
      type,
      intensity,
      targetIds: targets.map((t) => t.id),
      targets: targets.map((t) => t.target),
    });
    appendAudit(db, ws, {
      actor: ACTOR,
      action: "scan.requested",
      subject: scan.id,
      details: { type, intensity, targets: scan.targets },
    });
  }
  pumpQueue(db);
  refresh();
  const names = types.map((t) => SCANNER_CATALOG[t].label).join(", ");
  return { ok: true, message: `Queued ${names} for ${targets.length} target${targets.length === 1 ? "" : "s"}.`, errors: [] };
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
