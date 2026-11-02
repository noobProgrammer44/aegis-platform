import { z } from "zod";

/** Validation for target labels and tags (shared by the UI actions and, later, the REST API). */

import { MAX_LABEL_LENGTH, MAX_TAG_LENGTH, MAX_TAGS } from "./limits";

export { MAX_LABEL_LENGTH, MAX_TAG_LENGTH, MAX_TAGS };

const TAG_RE = /^[a-z0-9][a-z0-9._-]*$/;

export const tagSchema = z
  .string()
  .min(1)
  .max(MAX_TAG_LENGTH, `Tags can be at most ${MAX_TAG_LENGTH} characters.`)
  .regex(TAG_RE, "Tags use lowercase letters, numbers, dots, dashes and underscores.");

export const labelSchema = z
  .string()
  .trim()
  .max(MAX_LABEL_LENGTH, `Labels can be at most ${MAX_LABEL_LENGTH} characters.`);

export type ParsedTags = { ok: true; tags: string[] } | { ok: false; error: string };

/** Parses "web, Prod  api" into ["web", "prod", "api"]: lowercased, deduped, max five. */
export function parseTags(raw: string): ParsedTags {
  const tags = [
    ...new Set(
      raw
        .split(/[\s,]+/)
        .map((tag) => tag.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
  if (tags.length > MAX_TAGS) return { ok: false, error: `Use at most ${MAX_TAGS} tags.` };
  for (const tag of tags) {
    const result = tagSchema.safeParse(tag);
    if (!result.success) return { ok: false, error: `"${tag}": ${result.error.issues[0].message}` };
  }
  return { ok: true, tags };
}

export function parseLabel(raw: string): { ok: true; label: string } | { ok: false; error: string } {
  const result = labelSchema.safeParse(raw);
  return result.success
    ? { ok: true, label: result.data }
    : { ok: false, error: result.error.issues[0].message };
}
