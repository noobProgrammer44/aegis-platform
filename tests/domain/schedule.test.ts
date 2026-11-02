import { describe, expect, it } from "vitest";
import { nextRunAfter, validateSchedule, type ScheduleSpec } from "@/lib/domain/schedule";

const spec = (schedule: ScheduleSpec["schedule"], startAt: string, intervalDays: number | null = null): ScheduleSpec => ({
  schedule,
  startAt,
  intervalDays,
});

describe("validateSchedule", () => {
  it("needs a valid start and, for custom schedules, 1-365 days", () => {
    expect(validateSchedule(spec("DAILY", "2026-11-02T09:00:00.000Z"))).toBeNull();
    expect(validateSchedule(spec("DAILY", "not a date"))).toMatch(/valid date/);
    expect(validateSchedule(spec("CUSTOM", "2026-11-02T09:00:00.000Z", null))).toMatch(/1 to 365/);
    expect(validateSchedule(spec("CUSTOM", "2026-11-02T09:00:00.000Z", 0))).toMatch(/1 to 365/);
    expect(validateSchedule(spec("CUSTOM", "2026-11-02T09:00:00.000Z", 2.5))).toMatch(/1 to 365/);
    expect(validateSchedule(spec("CUSTOM", "2026-11-02T09:00:00.000Z", 10))).toBeNull();
  });
});

describe("nextRunAfter", () => {
  const start = "2026-11-02T09:00:00.000Z";

  it("returns the start time while it is still in the future", () => {
    expect(nextRunAfter(spec("WEEKLY", start), "2026-11-01T00:00:00.000Z")).toBe(start);
    expect(nextRunAfter(spec("ONCE", start), "2026-11-01T00:00:00.000Z")).toBe(start);
  });

  it("has no next run for a one-time schedule that has passed", () => {
    expect(nextRunAfter(spec("ONCE", start), start)).toBeNull();
  });

  it("steps daily, weekly and custom periods from the start, strictly after the given time", () => {
    expect(nextRunAfter(spec("DAILY", start), start)).toBe("2026-11-03T09:00:00.000Z");
    expect(nextRunAfter(spec("DAILY", start), "2026-11-03T08:59:59.999Z")).toBe("2026-11-03T09:00:00.000Z");
    expect(nextRunAfter(spec("WEEKLY", start), "2026-11-09T09:00:00.000Z")).toBe("2026-11-16T09:00:00.000Z");
    expect(nextRunAfter(spec("CUSTOM", start, 10), "2026-11-05T00:00:00.000Z")).toBe("2026-11-12T09:00:00.000Z");
  });

  it("skips runs missed while the scheduler was off instead of replaying them", () => {
    expect(nextRunAfter(spec("DAILY", start), "2026-11-20T12:00:00.000Z")).toBe("2026-11-21T09:00:00.000Z");
  });

  it("keeps the day of month for monthly runs, clamping short months", () => {
    const endOfMonth = spec("MONTHLY", "2026-01-31T09:00:00.000Z");
    expect(nextRunAfter(endOfMonth, "2026-01-31T09:00:00.000Z")).toBe("2026-02-28T09:00:00.000Z");
    expect(nextRunAfter(endOfMonth, "2026-02-28T09:00:00.000Z")).toBe("2026-03-31T09:00:00.000Z");
    expect(nextRunAfter(endOfMonth, "2026-04-15T00:00:00.000Z")).toBe("2026-04-30T09:00:00.000Z");
    expect(nextRunAfter(spec("MONTHLY", "2026-11-02T09:00:00.000Z"), "2027-03-10T00:00:00.000Z")).toBe(
      "2027-04-02T09:00:00.000Z",
    );
  });

  it("runs quarterly every three months, across year ends", () => {
    const quarterly = spec("QUARTERLY", "2026-11-15T09:00:00.000Z");
    expect(nextRunAfter(quarterly, "2026-11-15T09:00:00.000Z")).toBe("2027-02-15T09:00:00.000Z");
    expect(nextRunAfter(quarterly, "2027-06-01T00:00:00.000Z")).toBe("2027-08-15T09:00:00.000Z");
  });

  it("returns null for invalid input", () => {
    expect(nextRunAfter(spec("CUSTOM", start, null), start)).toBeNull();
    expect(nextRunAfter(spec("DAILY", start), "garbage")).toBeNull();
  });
});
