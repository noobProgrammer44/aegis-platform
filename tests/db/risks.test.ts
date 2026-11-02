import { describe, expect, it } from "vitest";
import { DuplicateError } from "@/lib/db/errors";
import {
  createAcceptanceRule,
  deleteAcceptanceRule,
  getAcceptanceRule,
  listAcceptanceRules,
  updateAcceptanceRule,
} from "@/lib/db/repos/acceptance-rules";
import {
  buildRisk,
  createRisk,
  findRisk,
  getRisk,
  listRisks,
  saveRisk,
  saveRisks,
  setRiskAcceptance,
} from "@/lib/db/repos/risks";
import { createTarget } from "@/lib/db/repos/targets";
import { createWorkspace } from "@/lib/db/repos/workspaces";
import { riskDefinition, useMemoryDb, WS } from "./helpers";

describe("risks repository", () => {
  const db = useMemoryDb();
  const target = (value = "example.com") => createTarget(db(), WS, { target: value, kind: "domain" });

  it("creates an open, unaccepted risk and round-trips its definition", () => {
    const t = target();
    const definition = riskDefinition({
      cvss: "5.3",
      additionalInfo: { url: "https://example.com", port: 443 },
    });
    const risk = createRisk(db(), WS, {
      targetId: t.id,
      fingerprint: "csp-missing",
      definition,
      lastScanId: "scn_1",
      detectedAt: "2026-11-01T00:00:00.000Z",
    });
    expect(risk).toMatchObject({
      status: "OPEN",
      isAccepted: false,
      firstDetectedAt: "2026-11-01T00:00:00.000Z",
      lastDetectedAt: "2026-11-01T00:00:00.000Z",
      closedAt: null,
      lastScanId: "scn_1",
    });
    expect(getRisk(db(), WS, risk.id)).toEqual(risk);
    expect(findRisk(db(), WS, t.id, "csp-missing")).toEqual(risk);
  });

  it("saves an updated copy by id (closing a risk)", () => {
    const t = target();
    const risk = createRisk(db(), WS, {
      targetId: t.id,
      fingerprint: "csp-missing",
      definition: riskDefinition(),
      lastScanId: null,
    });
    const closed = saveRisk(db(), {
      ...risk,
      status: "CLOSED",
      closedAt: "2026-11-02T00:00:00.000Z",
      updatedAt: "2026-11-02T00:00:00.000Z",
    });
    expect(risk.status).toBe("OPEN");
    expect(getRisk(db(), WS, risk.id)).toEqual(closed);
    expect(listRisks(db(), WS)).toHaveLength(1);
  });

  it("rejects a second risk with the same fingerprint on the same target", () => {
    const t = target();
    const input = { targetId: t.id, fingerprint: "dup", definition: riskDefinition(), lastScanId: null };
    createRisk(db(), WS, input);
    expect(() => createRisk(db(), WS, input)).toThrow(DuplicateError);
  });

  it("saves a batch all-or-nothing", () => {
    const t = target();
    const input = { targetId: t.id, fingerprint: "same", definition: riskDefinition(), lastScanId: null };
    const ok = buildRisk(WS, { ...input, fingerprint: "other" });
    expect(() => saveRisks(db(), [ok, buildRisk(WS, input), buildRisk(WS, input)])).toThrow(
      DuplicateError,
    );
    expect(listRisks(db(), WS)).toEqual([]);
    expect(saveRisks(db(), [ok])).toEqual([ok]);
  });

  it("filters by status, acceptance, target, scanner and threat level", () => {
    const a = target("a.test");
    const b = target("b.test");
    const high = createRisk(db(), WS, {
      targetId: a.id,
      fingerprint: "nuclei:cve",
      definition: riskDefinition({ scanType: "NUCLEI", threatLevel: "HIGH", title: "CVE" }),
      lastScanId: null,
    });
    const low = createRisk(db(), WS, {
      targetId: b.id,
      fingerprint: "hdr",
      definition: riskDefinition({ threatLevel: "LOW" }),
      lastScanId: null,
    });
    saveRisk(db(), { ...low, status: "CLOSED" });
    setRiskAcceptance(db(), WS, high.id, { accepted: true, reason: "False positive", by: "manual" });
    const ids = (filter: Parameters<typeof listRisks>[2]) =>
      listRisks(db(), WS, filter).map((r) => r.id);

    expect(ids({ status: "OPEN" })).toEqual([high.id]);
    expect(ids({ status: "CLOSED" })).toEqual([low.id]);
    expect(ids({ isAccepted: true })).toEqual([high.id]);
    expect(ids({ isAccepted: false })).toEqual([low.id]);
    expect(ids({ targetIds: [b.id] })).toEqual([low.id]);
    expect(ids({ scanTypes: ["NUCLEI"] })).toEqual([high.id]);
    expect(ids({ threatLevels: ["LOW", "MEDIUM"] })).toEqual([low.id]);
    expect(ids({ targetIds: [] })).toHaveLength(2);
  });

  it("accepts and un-accepts, clearing the reason on un-accept", () => {
    const t = target();
    const risk = createRisk(db(), WS, {
      targetId: t.id,
      fingerprint: "port-22",
      definition: riskDefinition(),
      lastScanId: null,
    });
    const accepted = setRiskAcceptance(db(), WS, risk.id, {
      accepted: true,
      reason: "Bastion host",
      by: "rul_1",
    });
    expect(accepted).toMatchObject({ isAccepted: true, acceptedReason: "Bastion host", acceptedBy: "rul_1" });
    const reopened = setRiskAcceptance(db(), WS, risk.id, { accepted: false, reason: "ignored", by: "x" });
    expect(reopened).toMatchObject({ isAccepted: false, acceptedReason: null, acceptedBy: null });

    const other = createWorkspace(db(), "Client B");
    expect(setRiskAcceptance(db(), other.id, risk.id, { accepted: true, reason: null, by: null })).toBeNull();
    expect(listRisks(db(), other.id)).toEqual([]);
  });
});

describe("acceptance rules repository", () => {
  const db = useMemoryDb();

  it("fills missing query fields on create and read", () => {
    const rule = createAcceptanceRule(db(), WS, {
      name: "Web ports on webservers",
      query: { targetTags: ["webserver"], ports: [80, 443] },
    });
    expect(rule.query).toEqual({
      scanTypes: [],
      threatLevels: [],
      targetTags: ["webserver"],
      targetIds: [],
      titlePattern: null,
      ports: [80, 443],
    });
    expect(rule).toMatchObject({ note: "", enabled: true });
    expect(getAcceptanceRule(db(), WS, rule.id)).toEqual(rule);
  });

  it("updates, lists enabled-only and deletes", () => {
    const a = createAcceptanceRule(db(), WS, { name: "A", query: {} });
    const b = createAcceptanceRule(db(), WS, { name: "B", query: { threatLevels: ["LOW"] } });
    const disabled = updateAcceptanceRule(db(), WS, a.id, { enabled: false, note: "paused" });

    expect(disabled).toMatchObject({ name: "A", enabled: false, note: "paused" });
    expect(listAcceptanceRules(db(), WS, { enabledOnly: true }).map((r) => r.id)).toEqual([b.id]);
    expect(listAcceptanceRules(db(), WS)).toHaveLength(2);
    expect(deleteAcceptanceRule(db(), WS, a.id)).toBe(true);
    expect(getAcceptanceRule(db(), WS, a.id)).toBeNull();
    expect(updateAcceptanceRule(db(), WS, a.id, { name: "gone" })).toBeNull();
  });
});
