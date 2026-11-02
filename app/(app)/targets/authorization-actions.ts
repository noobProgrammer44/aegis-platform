"use server";

import { revalidatePath } from "next/cache";
import type { ActionResult } from "@/lib/actions/result";
import { getDb } from "@/lib/db/client";
import { getTarget } from "@/lib/db/repos/targets";
import {
  attestTarget,
  checkDnsVerification,
  revokeAuthorization,
  startDnsVerification,
} from "@/lib/services/authorization";
import { currentWorkspaceId } from "@/lib/workspace";

/** Authorization actions from the target drawer. All checks happen here, server-side. */

const ACTOR = "local user";
const MAX_NOTE = 300;
const fail = (message: string): ActionResult => ({ ok: false, message, errors: [] });
const ok = (message: string): ActionResult => ({ ok: true, message, errors: [] });
const validId = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= 64;

function refresh(): void {
  revalidatePath("/targets");
  revalidatePath("/scans");
  revalidatePath("/audit-log");
}

function loadTarget(id: unknown) {
  if (!validId(id)) return null;
  return getTarget(getDb(), currentWorkspaceId(), id);
}

export async function attestAction(targetId: string, confirmed: boolean, note: string): Promise<ActionResult> {
  const target = loadTarget(targetId);
  if (!target) return fail("That target no longer exists.");
  if (confirmed !== true) return fail("Tick the box to confirm you're authorized.");
  const trimmed = String(note ?? "").trim().slice(0, MAX_NOTE) || null;
  attestTarget(getDb(), currentWorkspaceId(), target, ACTOR, trimmed);
  refresh();
  return ok("Recorded. Active scans can now run on this target.");
}

export async function startDnsAction(targetId: string): Promise<ActionResult & { record?: { domain: string; value: string } }> {
  const target = loadTarget(targetId);
  if (!target) return fail("That target no longer exists.");
  try {
    const record = startDnsVerification(getDb(), currentWorkspaceId(), target, ACTOR);
    refresh();
    return { ...ok("Add this TXT record, then check."), record };
  } catch (err) {
    return fail(err instanceof Error ? err.message : "Couldn't start verification.");
  }
}

export async function checkDnsAction(targetId: string): Promise<ActionResult> {
  const target = loadTarget(targetId);
  if (!target) return fail("That target no longer exists.");
  const result = await checkDnsVerification(getDb(), currentWorkspaceId(), target, ACTOR);
  refresh();
  return result.ok ? ok("Ownership verified.") : fail(result.reason);
}

export async function revokeAuthorizationAction(authorizationId: string): Promise<ActionResult> {
  if (!validId(authorizationId)) return fail("Unknown authorization.");
  const removed = revokeAuthorization(getDb(), currentWorkspaceId(), authorizationId, ACTOR);
  refresh();
  return removed ? ok("Authorization removed.") : fail("That authorization no longer exists.");
}
