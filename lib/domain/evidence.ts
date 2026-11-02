import type { OwaspCategory } from "./owasp";

/**
 * Structured evidence scanners attach to a risk (stored in definition.additionalInfo):
 * classification (CWE, WASC, OWASP Top 10), confidence, and the individual instances
 * where the issue was seen, with the HTTP exchange when the scanner captured it.
 */

export interface RiskInstance {
  uri: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  otherInfo?: string;
  requestHeader?: string;
  requestBody?: string;
  responseHeader?: string;
  responseBody?: string;
}

export interface RiskEvidence {
  cweId?: string;
  wascId?: string;
  owasp?: OwaspCategory;
  confidence?: string;
  pluginId?: string;
  instances?: RiskInstance[];
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : typeof v === "number" ? String(v) : undefined);

function readInstance(raw: unknown): RiskInstance | null {
  const r = (raw ?? {}) as Record<string, unknown>;
  const uri = str(r.uri);
  if (!uri) return null;
  return {
    uri,
    method: str(r.method),
    param: str(r.param),
    attack: str(r.attack),
    evidence: str(r.evidence),
    otherInfo: str(r.otherInfo),
    requestHeader: str(r.requestHeader),
    requestBody: str(r.requestBody),
    responseHeader: str(r.responseHeader),
    responseBody: str(r.responseBody),
  };
}

/** Reads evidence fields back out of stored additionalInfo, ignoring anything malformed. */
export function readEvidence(info: Record<string, unknown>): RiskEvidence {
  const owasp = info.owasp as Partial<OwaspCategory> | undefined;
  const instances = Array.isArray(info.instances)
    ? info.instances.map(readInstance).filter((i): i is RiskInstance => i !== null)
    : undefined;
  return {
    cweId: str(info.cweId),
    wascId: str(info.wascId),
    owasp: owasp?.code && owasp.name && owasp.url ? { code: owasp.code, name: owasp.name, url: owasp.url } : undefined,
    confidence: str(info.confidence),
    pluginId: str(info.pluginId),
    instances,
  };
}

/** Keys rendered by the evidence views; the rest of additionalInfo shows as plain key / values. */
export const EVIDENCE_KEYS = new Set(["cweId", "wascId", "owasp", "confidence", "pluginId", "instances"]);
