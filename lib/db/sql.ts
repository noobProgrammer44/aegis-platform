/** `?, ?, ?` placeholders for an `IN (...)` clause; the values are still bound as parameters. */
export function placeholders(count: number): string {
  return Array.from({ length: count }, () => "?").join(", ");
}

/**
 * Copy of a patch without keys whose value is `undefined`, so `{ ...current, ...patch }`
 * never overwrites a stored field with `undefined` (an explicit `null` still clears it).
 */
export function definedOnly<T extends object>(patch: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(patch).filter(([, value]) => value !== undefined),
  ) as Partial<T>;
}
