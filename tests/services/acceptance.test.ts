import { describe, expect, it } from "vitest";
import { createAcceptanceRule, deleteAcceptanceRule } from "@/lib/db/repos/acceptance-rules";
import { createRisk, getRisk, setRiskAcceptance } from "@/lib/db/repos/risks";
import { createTarget, getTarget } from "@/lib/db/repos/targets";
import { reapplyAcceptanceRules } from "@/lib/services/acceptance";
import { recomputeHealth } from "@/lib/scans/health";
import { riskDefinition, useMemoryDb, WS } from "../db/helpers";

describe("reapplyAcceptanceRules", () => {
  const db = useMemoryDb();

  it("accepts matching open risks, refreshes health, and reverts when the rule goes", () => {
    const web = createTarget(db(), WS, { target: "localhost:3100", kind: "host", tags: ["web"] });
    const port80 = createRisk(db(), WS, {
      targetId: web.id,
      fingerprint: "p80",
      definition: riskDefinition({ scanType: "NMAP", title: "Open port 80", threatLevel: "HIGH", additionalInfo: { port: 80 } }),
      lastScanId: null,
    });
    const manual = createRisk(db(), WS, { targetId: web.id, fingerprint: "m", definition: riskDefinition({ threatLevel: "LOW" }), lastScanId: null });
    setRiskAcceptance(db(), WS, manual.id, { accepted: true, reason: "mine", by: "manual" });
    recomputeHealth(db(), WS, [web.id], "2026-11-02T00:00:00.000Z");
    expect(getTarget(db(), WS, web.id)?.health.grade).toBe("B");

    const rule = createAcceptanceRule(db(), WS, { name: "web ports", query: { targetTags: ["web"], ports: [80, 443] } });
    expect(reapplyAcceptanceRules(db(), WS)).toBe(1);
    expect(getRisk(db(), WS, port80.id)).toMatchObject({ isAccepted: true, acceptedBy: rule.id });
    expect(getTarget(db(), WS, web.id)?.health).toEqual({ score: 0, grade: "A" });

    deleteAcceptanceRule(db(), WS, rule.id);
    expect(reapplyAcceptanceRules(db(), WS)).toBe(1);
    expect(getRisk(db(), WS, port80.id)?.isAccepted).toBe(false);
    expect(getRisk(db(), WS, manual.id)).toMatchObject({ isAccepted: true, acceptedBy: "manual" });
    expect(reapplyAcceptanceRules(db(), WS)).toBe(0);
  });
});
