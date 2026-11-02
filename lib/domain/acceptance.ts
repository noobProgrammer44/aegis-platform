import type { AcceptanceQuery, AcceptanceRule, Risk, Target } from "@/types/aegis";

/**
 * Acceptance rules: saved queries that mark matching risks as accepted (suppressed
 * from the health score). Every non-empty condition must match (AND); within one
 * condition any listed value matches (OR). A rule with no conditions matches nothing,
 * so an empty rule can never silently accept every risk.
 */

/** `acceptedBy` value for a risk a person accepted by hand (rules never override it). */
export const MANUAL_ACCEPTANCE = "manual";

const MAX_TITLE_PATTERN_LENGTH = 200;

type MatchableRisk = Pick<Risk, "targetId" | "definition">;
type MatchableTarget = Pick<Target, "id" | "tags">;

export function isEmptyQuery(query: AcceptanceQuery): boolean {
  return (
    query.scanTypes.length === 0 &&
    query.threatLevels.length === 0 &&
    query.targetTags.length === 0 &&
    query.targetIds.length === 0 &&
    query.ports.length === 0 &&
    !query.titlePattern
  );
}

function compileTitlePattern(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern, "i");
  } catch {
    return null;
  }
}

/** Problems that should stop a rule from being saved; empty when the query is fine. */
export function validateAcceptanceQuery(query: AcceptanceQuery): string[] {
  const errors: string[] = [];
  if (isEmptyQuery(query)) errors.push("Add at least one condition.");
  if (query.titlePattern) {
    if (query.titlePattern.length > MAX_TITLE_PATTERN_LENGTH) {
      errors.push(`Title pattern must be at most ${MAX_TITLE_PATTERN_LENGTH} characters.`);
    } else if (!compileTitlePattern(query.titlePattern)) {
      errors.push("Title pattern is not a valid regular expression.");
    }
  }
  if (query.ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
    errors.push("Ports must be whole numbers from 1 to 65535.");
  }
  return errors;
}

function riskPort(risk: MatchableRisk): number | null {
  const raw = risk.definition.additionalInfo.port;
  const port = typeof raw === "string" ? Number(raw) : raw;
  return typeof port === "number" && Number.isInteger(port) ? port : null;
}

export function matchesQuery(
  query: AcceptanceQuery,
  risk: MatchableRisk,
  target: MatchableTarget | null,
): boolean {
  if (isEmptyQuery(query)) return false;
  const { definition } = risk;
  const anyOrAll = <T>(values: readonly T[], test: (value: T) => boolean) =>
    values.length === 0 || values.some(test);

  const port = riskPort(risk);
  const pattern = query.titlePattern ? compileTitlePattern(query.titlePattern) : null;
  return (
    anyOrAll(query.scanTypes, (type) => type === definition.scanType) &&
    anyOrAll(query.threatLevels, (level) => level === definition.threatLevel) &&
    anyOrAll(query.targetIds, (id) => id === risk.targetId) &&
    anyOrAll(query.targetTags, (tag) => target?.tags.includes(tag) ?? false) &&
    anyOrAll(query.ports, (p) => p === port) &&
    (!query.titlePattern || (pattern?.test(definition.title) ?? false))
  );
}

/** First enabled rule that matches, in the order given. */
export function findMatchingRule(
  rules: readonly AcceptanceRule[],
  risk: MatchableRisk,
  target: MatchableTarget | null,
): AcceptanceRule | null {
  return rules.find((rule) => rule.enabled && matchesQuery(rule.query, risk, target)) ?? null;
}

/**
 * Re-evaluates a risk against the rules. Manual acceptances are kept as they are. A risk
 * accepted by a rule that no longer matches (deleted, disabled or edited) is un-accepted.
 * Returns the same object when nothing changes.
 */
export function applyAcceptanceRules(
  risk: Risk,
  rules: readonly AcceptanceRule[],
  target: MatchableTarget | null,
  at: string,
): Risk {
  // Anything not provably accepted by a rule is treated as a person's decision.
  const acceptedByPerson =
    risk.isAccepted && (risk.acceptedBy === null || risk.acceptedBy === MANUAL_ACCEPTANCE);
  if (acceptedByPerson) return risk;
  const rule = findMatchingRule(rules, risk, target);
  if (rule) {
    if (risk.isAccepted && risk.acceptedBy === rule.id) return risk;
    return {
      ...risk,
      isAccepted: true,
      acceptedBy: rule.id,
      acceptedReason: rule.note || `Accepted by rule "${rule.name}"`,
      updatedAt: at,
    };
  }
  if (!risk.isAccepted) return risk;
  return { ...risk, isAccepted: false, acceptedBy: null, acceptedReason: null, updatedAt: at };
}
