import { afterEach, beforeEach } from "vitest";
import { DEFAULT_WORKSPACE_ID, openDb, type DB } from "@/lib/db/client";
import type { RiskDefinition } from "@/types/aegis";

export const WS = DEFAULT_WORKSPACE_ID;

/** Fresh in-memory database per test; call inside a `describe` and read it with `db()`. */
export function useMemoryDb(): () => DB {
  let db: DB | undefined;
  beforeEach(() => {
    db = openDb(":memory:");
  });
  afterEach(() => {
    db?.close();
    db = undefined;
  });
  return () => {
    if (!db) throw new Error("useMemoryDb: database is only available inside a test");
    return db;
  };
}

export function riskDefinition(overrides: Partial<RiskDefinition> = {}): RiskDefinition {
  return {
    scanType: "SURFACE",
    title: "Missing Content-Security-Policy header",
    threatLevel: "MEDIUM",
    description: "No CSP header was returned.",
    solution: "Send a Content-Security-Policy header.",
    references: ["https://owasp.org/www-project-secure-headers/"],
    cvss: null,
    additionalInfo: { header: "content-security-policy" },
    ...overrides,
  };
}
