/** Result shape shared by the Targets server actions and the forms that call them. */
export interface ActionResult {
  ok: boolean;
  message: string;
  /** Per-entry problems for bulk adds. */
  errors: { input: string; error: string }[];
}

export const INITIAL_RESULT: ActionResult = { ok: false, message: "", errors: [] };
