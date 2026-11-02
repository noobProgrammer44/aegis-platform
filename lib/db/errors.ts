/** Thrown when an insert would break a UNIQUE constraint, e.g. adding the same target twice. */
export class DuplicateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DuplicateError";
  }
}

export function isUniqueViolation(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return code === "SQLITE_CONSTRAINT_UNIQUE" || code === "SQLITE_CONSTRAINT_PRIMARYKEY";
}

/** Run a write and turn a UNIQUE violation into a `DuplicateError` with a readable message. */
export function insertOrDuplicate<T>(run: () => T, message: string): T {
  try {
    return run();
  } catch (err) {
    if (isUniqueViolation(err)) throw new DuplicateError(message);
    throw err;
  }
}
