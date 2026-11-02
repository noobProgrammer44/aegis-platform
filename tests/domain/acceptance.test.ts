import { describe, expect, it } from "vitest";
import {
  applyAcceptanceRules,
  findMatchingRule,
  MANUAL_ACCEPTANCE,
  matchesQuery,
  validateAcceptanceQuery,
} from "@/lib/domain/acceptance";
import { AT, definition, LATER, risk, rule } from "./fixtures";

const webserver = { id: "tgt_a", tags: ["webserver", "prod"] };
const database = { id: "tgt_b", tags: ["db"] };
const portRisk = (port: unknown) =>
  risk({ definition: definition({ scanType: "NMAP", title: "Open port", threatLevel: "LOW", additionalInfo: { port } }) });

describe("matchesQuery", () => {
  it("matches nothing when the query is empty", () => {
    expect(matchesQuery(rule({}).query, risk(), webserver)).toBe(false);
  });

  it("accepts web ports on targets tagged webserver (HostedScan's example)", () => {
    const query = rule({ targetTags: ["webserver"], ports: [80, 443] }).query;
    expect(matchesQuery(query, portRisk(443), webserver)).toBe(true);
    expect(matchesQuery(query, portRisk("80"), webserver)).toBe(true);
    expect(matchesQuery(query, portRisk(22), webserver)).toBe(false);
    expect(matchesQuery(query, { ...portRisk(443), targetId: "tgt_b" }, database)).toBe(false);
    expect(matchesQuery(query, risk(), webserver)).toBe(false);
  });

  it("ANDs conditions and ORs values within one condition", () => {
    const query = rule({ scanTypes: ["SURFACE", "TLS"], threatLevels: ["LOW", "MEDIUM"] }).query;
    expect(matchesQuery(query, risk(), null)).toBe(true);
    expect(matchesQuery(query, risk({ definition: definition({ threatLevel: "HIGH" }) }), null)).toBe(false);
    expect(matchesQuery(query, risk({ definition: definition({ scanType: "NUCLEI" }) }), null)).toBe(false);
  });

  it("matches titles case-insensitively and target ids exactly", () => {
    expect(matchesQuery(rule({ titlePattern: "^missing hs" }).query, risk(), null)).toBe(true);
    expect(matchesQuery(rule({ titlePattern: "csp" }).query, risk(), null)).toBe(false);
    expect(matchesQuery(rule({ titlePattern: "([" }).query, risk(), null)).toBe(false);
    expect(matchesQuery(rule({ targetIds: ["tgt_a"] }).query, risk(), null)).toBe(true);
    expect(matchesQuery(rule({ targetTags: ["prod"] }).query, risk(), null)).toBe(false);
  });
});

describe("validateAcceptanceQuery", () => {
  it("rejects empty queries, bad patterns and bad ports", () => {
    expect(validateAcceptanceQuery(rule({}).query)).toEqual(["Add at least one condition."]);
    expect(validateAcceptanceQuery(rule({ titlePattern: "([" }).query)).toEqual([
      "Title pattern is not a valid regular expression.",
    ]);
    expect(validateAcceptanceQuery(rule({ titlePattern: "a".repeat(201) }).query)[0]).toMatch(/at most 200/);
    expect(validateAcceptanceQuery(rule({ ports: [0, 443] }).query)[0]).toMatch(/1 to 65535/);
    expect(validateAcceptanceQuery(rule({ threatLevels: ["LOW"] }).query)).toEqual([]);
  });
});

describe("rule application", () => {
  const lowRule = rule({ threatLevels: ["MEDIUM"] }, { id: "rul_low", name: "Medium noise", note: "Tracked in JIRA-1" });

  it("picks the first enabled matching rule", () => {
    const disabled = rule({ threatLevels: ["MEDIUM"] }, { id: "rul_off", enabled: false });
    expect(findMatchingRule([disabled, lowRule], risk(), webserver)?.id).toBe("rul_low");
    expect(findMatchingRule([disabled], risk(), webserver)).toBeNull();
  });

  it("accepts a matching risk with the rule's note as the reason", () => {
    const original = risk();
    const accepted = applyAcceptanceRules(original, [lowRule], webserver, LATER);
    expect(accepted).toMatchObject({
      isAccepted: true,
      acceptedBy: "rul_low",
      acceptedReason: "Tracked in JIRA-1",
      updatedAt: LATER,
    });
    expect(original.isAccepted).toBe(false);
    expect(applyAcceptanceRules(accepted, [lowRule], webserver, AT)).toBe(accepted);
  });

  it("un-accepts when the accepting rule no longer matches", () => {
    const byRule = risk({ isAccepted: true, acceptedBy: "rul_gone", acceptedReason: "old" });
    expect(applyAcceptanceRules(byRule, [], webserver, LATER)).toMatchObject({
      isAccepted: false,
      acceptedBy: null,
      acceptedReason: null,
    });
  });

  it("never touches a risk a person accepted", () => {
    const manual = risk({ isAccepted: true, acceptedBy: MANUAL_ACCEPTANCE, acceptedReason: "Known" });
    const legacy = risk({ isAccepted: true, acceptedBy: null, acceptedReason: "Known" });
    expect(applyAcceptanceRules(manual, [], webserver, LATER)).toBe(manual);
    expect(applyAcceptanceRules(legacy, [lowRule], webserver, LATER)).toBe(legacy);
  });

  it("returns the same object when an unaccepted risk matches no rule", () => {
    const original = risk({ definition: definition({ threatLevel: "HIGH" }) });
    expect(applyAcceptanceRules(original, [lowRule], webserver, LATER)).toBe(original);
  });
});
