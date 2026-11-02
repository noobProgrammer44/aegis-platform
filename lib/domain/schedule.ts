import type { Schedule } from "@/types/aegis";

/**
 * Next-run calculation for scheduled scans and reports. Runs are anchored to `startAt`
 * (occurrence k = startAt + k periods), so the time of day never drifts and a scheduler
 * that was offline skips missed runs instead of replaying them. Calendar maths is in UTC.
 */

export interface ScheduleSpec {
  schedule: Schedule;
  /** First run (ISO string). */
  startAt: string;
  /** CUSTOM only: repeat every N days. */
  intervalDays: number | null;
}

export const MAX_INTERVAL_DAYS = 365;

const DAY_MS = 86_400_000;
const DAYS_PER_PERIOD: Partial<Record<Schedule, number>> = { DAILY: 1, WEEKLY: 7 };
const MONTHS_PER_PERIOD: Partial<Record<Schedule, number>> = { MONTHLY: 1, QUARTERLY: 3 };

export const SCHEDULE_LABEL: Record<Schedule, string> = {
  ONCE: "One time",
  DAILY: "Daily",
  WEEKLY: "Weekly",
  MONTHLY: "Monthly",
  QUARTERLY: "Quarterly",
  CUSTOM: "Custom",
};

/** Problem with the spec, or null when it is valid. */
export function validateSchedule(spec: ScheduleSpec): string | null {
  if (Number.isNaN(Date.parse(spec.startAt))) return "Start time is not a valid date.";
  if (spec.schedule !== "CUSTOM") return null;
  const days = spec.intervalDays;
  if (days === null || !Number.isInteger(days) || days < 1 || days > MAX_INTERVAL_DAYS) {
    return `Custom schedules repeat every 1 to ${MAX_INTERVAL_DAYS} days.`;
  }
  return null;
}

/** `date` plus `months` calendar months, keeping the day of month where it exists (Jan 31 -> Feb 28). */
function addMonths(date: Date, months: number): Date {
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth() + months;
  const lastDay = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  return new Date(
    Date.UTC(
      year,
      month,
      Math.min(date.getUTCDate(), lastDay),
      date.getUTCHours(),
      date.getUTCMinutes(),
      date.getUTCSeconds(),
      date.getUTCMilliseconds(),
    ),
  );
}

function nextByDays(start: Date, after: Date, days: number): Date {
  const period = days * DAY_MS;
  const k = Math.floor((after.getTime() - start.getTime()) / period) + 1;
  return new Date(start.getTime() + k * period);
}

function nextByMonths(start: Date, after: Date, months: number): Date {
  const monthsApart =
    (after.getUTCFullYear() - start.getUTCFullYear()) * 12 +
    (after.getUTCMonth() - start.getUTCMonth());
  // Start one period early so the clamped day can't make us skip an occurrence.
  let k = Math.max(1, Math.floor(monthsApart / months) - 1);
  while (addMonths(start, k * months).getTime() <= after.getTime()) k += 1;
  return addMonths(start, k * months);
}

/**
 * The first occurrence strictly after `after`: `startAt` itself while it is still in
 * the future, otherwise the next slot. Null when a one-time schedule has passed or the
 * spec is invalid.
 */
export function nextRunAfter(spec: ScheduleSpec, after: string | Date): string | null {
  if (validateSchedule(spec)) return null;
  const start = new Date(spec.startAt);
  const afterDate = typeof after === "string" ? new Date(after) : after;
  if (Number.isNaN(afterDate.getTime())) return null;
  if (start.getTime() > afterDate.getTime()) return start.toISOString();
  if (spec.schedule === "ONCE") return null;

  const days = spec.schedule === "CUSTOM" ? spec.intervalDays : DAYS_PER_PERIOD[spec.schedule];
  if (days) return nextByDays(start, afterDate, days).toISOString();
  const months = MONTHS_PER_PERIOD[spec.schedule];
  return months ? nextByMonths(start, afterDate, months).toISOString() : null;
}
