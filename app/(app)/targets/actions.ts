"use server";

import { revalidatePath } from "next/cache";
import { getDb } from "@/lib/db/client";
import { DuplicateError } from "@/lib/db/errors";
import { appendAudit } from "@/lib/db/repos/audit-log";
import { getDiscoveredDomain, markDomainPromoted } from "@/lib/db/repos/discovered-domains";
import {
  createTarget,
  deleteTarget,
  findTargetByValue,
  getTarget,
  updateTarget,
} from "@/lib/db/repos/targets";
import { parseTarget, parseTargetList } from "@/lib/domain/targets";
import { parseLabel, parseTags } from "@/lib/validation/targets";
import { currentWorkspaceId } from "@/lib/workspace";
import type { ActionResult } from "./action-result";

/** Server actions for the Targets page. Every input is validated here, not in the browser. */

const ACTOR = "local user";
const MAX_ID_LENGTH = 64;

const fail = (message: string, errors: ActionResult["errors"] = []): ActionResult => ({
  ok: false,
  message,
  errors,
});

const validId = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= MAX_ID_LENGTH;

function refresh(): void {
  revalidatePath("/targets");
  revalidatePath("/dashboard");
}

export async function addTargetsAction(_prev: ActionResult, form: FormData): Promise<ActionResult> {
  const tags = parseTags(String(form.get("tags") ?? ""));
  if (!tags.ok) return fail(tags.error);
  const label = parseLabel(String(form.get("label") ?? ""));
  if (!label.ok) return fail(label.error);

  const parsed = parseTargetList(String(form.get("targets") ?? ""));
  if (parsed.targets.length === 0) {
    return fail(parsed.errors.length > 0 ? "None of these could be added." : "Enter at least one target.", parsed.errors);
  }

  const db = getDb();
  const ws = currentWorkspaceId();
  // A label only makes sense for a single target.
  const singleLabel = parsed.targets.length === 1 ? label.label : "";
  const outcomes = parsed.targets.map((t) => {
    try {
      createTarget(db, ws, { target: t.target, kind: t.kind, label: singleLabel, tags: tags.tags });
      appendAudit(db, ws, { actor: ACTOR, action: "target.added", subject: t.target, details: { kind: t.kind } });
      return null;
    } catch (err) {
      if (err instanceof DuplicateError) return { input: t.target, error: "Already a target." };
      throw err;
    }
  });
  const skipped = outcomes.filter((o): o is { input: string; error: string } => o !== null);
  const added = parsed.targets.length - skipped.length;
  refresh();

  const errors = [...parsed.errors, ...skipped];
  if (added === 0) return fail("Nothing new to add.", errors);
  return { ok: true, message: `Added ${added} target${added === 1 ? "" : "s"}.`, errors };
}

export async function updateTargetAction(_prev: ActionResult, form: FormData): Promise<ActionResult> {
  const id = form.get("id");
  if (!validId(id)) return fail("Unknown target.");
  const tags = parseTags(String(form.get("tags") ?? ""));
  if (!tags.ok) return fail(tags.error);
  const label = parseLabel(String(form.get("label") ?? ""));
  if (!label.ok) return fail(label.error);

  const db = getDb();
  const ws = currentWorkspaceId();
  const updated = updateTarget(db, ws, id, { label: label.label, tags: tags.tags });
  if (!updated) return fail("That target no longer exists.");
  appendAudit(db, ws, { actor: ACTOR, action: "target.updated", subject: updated.target });
  refresh();
  return { ok: true, message: "Saved.", errors: [] };
}

export async function deleteTargetAction(id: string): Promise<ActionResult> {
  if (!validId(id)) return fail("Unknown target.");
  const db = getDb();
  const ws = currentWorkspaceId();
  const target = getTarget(db, ws, id);
  if (!target || !deleteTarget(db, ws, id)) return fail("That target no longer exists.");
  appendAudit(db, ws, { actor: ACTOR, action: "target.deleted", subject: target.target });
  refresh();
  return { ok: true, message: `Deleted ${target.target}.`, errors: [] };
}

/** Adds a discovered subdomain as a target and links the two. */
export async function promoteDomainAction(domainId: string): Promise<ActionResult> {
  if (!validId(domainId)) return fail("Unknown domain.");
  const db = getDb();
  const ws = currentWorkspaceId();
  const domain = getDiscoveredDomain(db, ws, domainId);
  if (!domain) return fail("That domain is no longer listed.");
  const parsed = parseTarget(domain.name);
  if (!parsed.ok) return fail(parsed.error);

  try {
    const target = db.transaction(() => {
      const created = createTarget(db, ws, {
        target: parsed.target.target,
        kind: parsed.target.kind,
        source: "discovered",
        tags: [],
      });
      markDomainPromoted(db, ws, domain.id, created.id);
      return created;
    })();
    appendAudit(db, ws, { actor: ACTOR, action: "target.added", subject: target.target, details: { source: "discovered", via: domain.viaTarget } });
  } catch (err) {
    if (!(err instanceof DuplicateError)) throw err;
    // Already tracked (added by hand earlier): just link the sighting to it.
    const existing = findTargetByValue(db, ws, parsed.target.target);
    if (existing) markDomainPromoted(db, ws, domain.id, existing.id);
    refresh();
    return { ok: true, message: `${domain.name} was already a target; linked it.`, errors: [] };
  }
  refresh();
  return { ok: true, message: `Added ${domain.name}.`, errors: [] };
}
