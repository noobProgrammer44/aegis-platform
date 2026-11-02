import { DEFAULT_WORKSPACE_ID } from "@/lib/db/client";

/**
 * The workspace the current request works in. Single-workspace for now; the workspace
 * switcher replaces this with the user's selection.
 */
export function currentWorkspaceId(): string {
  return DEFAULT_WORKSPACE_ID;
}
