import { describe, expect, it } from "vitest";
import { FOOTER_NAV, isActive, MAIN_NAV } from "@/components/shell/nav";
import { arcPath, arcPoint } from "@/lib/ui/gauge";

describe("gauge geometry", () => {
  it("puts 0 at the left end, 500 at the top and 1000 at the right end", () => {
    expect(arcPoint(100, 100, 50, 0)).toEqual({ x: 50, y: 100 });
    expect(arcPoint(100, 100, 50, 500)).toEqual({ x: 100, y: 50 });
    expect(arcPoint(100, 100, 50, 1000)).toEqual({ x: 150, y: 100 });
  });

  it("clamps out-of-range and invalid scores", () => {
    expect(arcPoint(100, 100, 50, -20)).toEqual(arcPoint(100, 100, 50, 0));
    expect(arcPoint(100, 100, 50, 5000)).toEqual(arcPoint(100, 100, 50, 1000));
    expect(arcPoint(100, 100, 50, Number.NaN)).toEqual(arcPoint(100, 100, 50, 0));
  });

  it("draws a clockwise arc between two scores", () => {
    expect(arcPath(100, 100, 50, 0, 500)).toBe("M 50 100 A 50 50 0 0 1 100 50");
  });
});

describe("navigation", () => {
  it("marks a section active on its page and sub-pages only", () => {
    expect(isActive("/targets", "/targets")).toBe(true);
    expect(isActive("/targets/tgt_1", "/targets")).toBe(true);
    expect(isActive("/targets-archive", "/targets")).toBe(false);
    expect(isActive("/dashboard", "/targets")).toBe(false);
  });

  it("has a unique route for every link", () => {
    const hrefs = [...MAIN_NAV, ...FOOTER_NAV].map((item) => item.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });
});
