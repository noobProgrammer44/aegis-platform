import { describe, expect, it } from "vitest";
import {
  csvCell,
  DEFAULT_RISK_FILTERS,
  filterRisks,
  filtersFromParams,
  groupRisks,
  risksToCsv,
  sortRisks,
} from "@/lib/domain/risk-table";
import { definition, risk } from "./fixtures";

const targets = new Map([
  ["tgt_a", { id: "tgt_a", target: "app.example.com", label: "Customer app", tags: ["web", "prod"] }],
  ["tgt_b", { id: "tgt_b", target: "10.0.0.5", label: "", tags: ["db"] }],
]);

const risks = [
  risk({ id: "1", targetId: "tgt_a", definition: definition({ title: "Missing CSP", threatLevel: "MEDIUM" }), lastDetectedAt: "2026-11-01T00:00:00.000Z" }),
  risk({ id: "2", targetId: "tgt_b", definition: definition({ title: "Redis exposed", threatLevel: "CRITICAL", scanType: "NMAP", additionalInfo: { host: "10.0.0.5", port: 6379 } }) }),
  risk({ id: "3", targetId: "tgt_a", definition: definition({ title: "Missing CSP", threatLevel: "MEDIUM" }), status: "CLOSED", closedAt: "2026-11-02T00:00:00.000Z" }),
  risk({ id: "4", targetId: "tgt_b", definition: definition({ title: "Missing CSP", threatLevel: "MEDIUM" }), isAccepted: true, acceptedBy: "manual", acceptedReason: "Internal only", lastDetectedAt: "2026-11-02T00:00:00.000Z" }),
];
const ids = (list: { id: string }[]) => list.map((r) => r.id);

describe("filterRisks", () => {
  it("shows open risks by default and supports every filter", () => {
    expect(ids(filterRisks(risks, targets, DEFAULT_RISK_FILTERS))).toEqual(["1", "2", "4"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, status: "CLOSED" }))).toEqual(["3"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, status: "ALL" }))).toHaveLength(4);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, accepted: "accepted" }))).toEqual(["4"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, accepted: "unaccepted" }))).toEqual(["1", "2"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, levels: ["CRITICAL"] }))).toEqual(["2"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, scanTypes: ["NMAP"] }))).toEqual(["2"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, targetId: "tgt_a" }))).toEqual(["1"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, tag: "db" }))).toEqual(["2", "4"]);
  });

  it("searches titles, descriptions, targets and labels", () => {
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, search: "redis" }))).toEqual(["2"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, search: "customer" }))).toEqual(["1"]);
    expect(ids(filterRisks(risks, targets, { ...DEFAULT_RISK_FILTERS, search: "10.0.0" }))).toEqual(["2", "4"]);
  });
});

describe("sorting and grouping", () => {
  it("sorts worst first, then most recently detected", () => {
    expect(ids(sortRisks(risks))).toEqual(["2", "3", "4", "1"]);
  });

  it("groups by title or target with the worst severity first", () => {
    const open = filterRisks(risks, targets, DEFAULT_RISK_FILTERS);
    expect(groupRisks(open, "title", targets).map((g) => [g.label, g.worst, ids(g.risks)])).toEqual([
      ["Redis exposed", "CRITICAL", ["2"]],
      ["Missing CSP", "MEDIUM", ["4", "1"]],
    ]);
    expect(groupRisks(open, "target", targets).map((g) => g.label)).toEqual(["10.0.0.5", "Customer app"]);
    expect(groupRisks(open, "none", targets)[0].risks).toHaveLength(3);
  });
});

describe("filters from the URL", () => {
  it("reads the dashboard links", () => {
    expect(filtersFromParams({ level: "CRITICAL" }).levels).toEqual(["CRITICAL"]);
    expect(filtersFromParams({ accepted: "1" }).accepted).toBe("accepted");
    expect(filtersFromParams({ status: "CLOSED" }).status).toBe("CLOSED");
    expect(filtersFromParams({ level: "BOGUS", status: "nope" })).toEqual(DEFAULT_RISK_FILTERS);
  });
});

describe("CSV export", () => {
  it("quotes cells and defuses spreadsheet formulas", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell('say "hi", ok')).toBe('"say ""hi"", ok"');
    expect(csvCell("=HYPERLINK(\"x\")")).toBe('"\'=HYPERLINK(""x"")"');
    expect(csvCell("+1")).toBe("\"'+1\"");
    expect(csvCell("-cmd")).toBe("\"'-cmd\"");
    expect(csvCell("@sum")).toBe("\"'@sum\"");
    expect(csvCell(null)).toBe("");
    expect(csvCell(6379)).toBe("6379");
  });

  it("writes a header and one row per risk, worst first", () => {
    const csv = risksToCsv(risks.slice(0, 2), targets);
    const lines = csv.trim().split("\r\n");
    expect(lines[0]).toBe("Title,Severity,Status,Accepted,Accepted reason,Scanner,Target,Host,Port,First detected,Last detected,Closed,Description,Solution");
    expect(lines[1]).toMatch(/^Redis exposed,CRITICAL,OPEN,no,,NMAP,10\.0\.0\.5,10\.0\.0\.5,6379,/);
    expect(lines).toHaveLength(3);
  });
});
