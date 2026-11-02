import type { AcceptanceQuery, AcceptanceRule, Risk, RiskDefinition } from "@/types/aegis";

export const AT = "2026-11-02T10:00:00.000Z";
export const LATER = "2026-11-03T10:00:00.000Z";

export function definition(overrides: Partial<RiskDefinition> = {}): RiskDefinition {
  return {
    scanType: "SURFACE",
    title: "Missing HSTS header",
    threatLevel: "MEDIUM",
    description: "",
    solution: "",
    references: [],
    cvss: null,
    additionalInfo: {},
    ...overrides,
  };
}

export function risk(overrides: Partial<Risk> = {}): Risk {
  return {
    id: "rsk_1",
    workspaceId: "ws_default",
    targetId: "tgt_a",
    fingerprint: "hsts",
    definition: definition(),
    status: "OPEN",
    isAccepted: false,
    acceptedReason: null,
    acceptedBy: null,
    firstDetectedAt: AT,
    lastDetectedAt: AT,
    closedAt: null,
    lastScanId: "scn_0",
    createdAt: AT,
    updatedAt: AT,
    ...overrides,
  };
}

export function rule(query: Partial<AcceptanceQuery>, overrides: Partial<AcceptanceRule> = {}): AcceptanceRule {
  return {
    id: "rul_1",
    workspaceId: "ws_default",
    name: "Rule",
    query: {
      scanTypes: [],
      threatLevels: [],
      targetTags: [],
      targetIds: [],
      titlePattern: null,
      ports: [],
      ...query,
    },
    note: "",
    enabled: true,
    createdAt: AT,
    ...overrides,
  };
}
