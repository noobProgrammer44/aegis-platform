import { z } from "zod";
import { tagSchema } from "./targets";

/** What the New Scan wizard submits. Validated on the server before anything is queued. */

export const scanRequestSchema = z
  .object({
    scanTypes: z.array(z.string().max(32)).min(1, "Pick at least one scanner.").max(12),
    targetMode: z.enum(["selected", "all", "tags"]),
    targetIds: z.array(z.string().min(1).max(64)).max(200).default([]),
    tags: z.array(tagSchema).max(5).default([]),
    intensity: z.enum(["polite", "normal", "aggressive"]),
    schedule: z.enum(["ONCE", "DAILY", "WEEKLY", "MONTHLY", "QUARTERLY", "CUSTOM"]),
    /** ISO start time; null runs a one-time scan now (or starts a recurring one now). */
    runAt: z.string().datetime({ offset: true }).nullable(),
    intervalDays: z.number().int().min(1).max(365).nullable(),
    notifyPolicy: z.enum(["NEVER", "ON_CHANGES", "ALWAYS"]),
    notifyEmails: z.array(z.string().email().max(200)).max(10).default([]),
    name: z.string().trim().max(100).optional(),
  })
  .superRefine((req, ctx) => {
    if (req.targetMode === "selected" && req.targetIds.length === 0) {
      ctx.addIssue({ code: "custom", message: "Pick at least one target.", path: ["targetIds"] });
    }
    if (req.targetMode === "tags" && req.tags.length === 0) {
      ctx.addIssue({ code: "custom", message: "Pick at least one tag.", path: ["tags"] });
    }
    if (req.schedule === "CUSTOM" && req.intervalDays === null) {
      ctx.addIssue({ code: "custom", message: "Say how many days between runs.", path: ["intervalDays"] });
    }
    if (req.notifyPolicy !== "NEVER" && req.notifyEmails.length === 0) {
      ctx.addIssue({ code: "custom", message: "Add an email address, or choose not to email results.", path: ["notifyEmails"] });
    }
  });

export type ScanRequest = z.infer<typeof scanRequestSchema>;

export function parseScanRequest(input: unknown): { ok: true; value: ScanRequest } | { ok: false; error: string } {
  const result = scanRequestSchema.safeParse(input);
  return result.success ? { ok: true, value: result.data } : { ok: false, error: result.error.issues[0].message };
}
