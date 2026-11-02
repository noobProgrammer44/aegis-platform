import { promises as dns } from "node:dns";
import type { Finding } from "@/types/recon";

/**
 * Email security (passive, DNS only): SPF and DMARC records that let others send
 * mail as the domain. DKIM selectors can't be enumerated from outside, so DKIM isn't
 * checked.
 */

export interface EmailDns {
  mx: string[];
  /** TXT records on the domain, each as its chunks. */
  txt: string[][];
  /** TXT records on _dmarc.<domain>. */
  dmarc: string[][];
}

export interface DnsLookup {
  resolveMx(domain: string): Promise<{ exchange: string }[]>;
  resolveTxt(domain: string): Promise<string[][]>;
}

const NO_RECORD_CODES = new Set(["ENODATA", "ENOTFOUND"]);

async function orEmpty<T>(lookup: () => Promise<T[]>): Promise<T[]> {
  try {
    return await lookup();
  } catch (err) {
    if (NO_RECORD_CODES.has((err as { code?: string }).code ?? "")) return [];
    throw err;
  }
}

export async function lookupEmailDns(domain: string, lookup: DnsLookup = dns): Promise<EmailDns> {
  const [mx, txt, dmarc] = await Promise.all([
    orEmpty(() => lookup.resolveMx(domain)),
    orEmpty(() => lookup.resolveTxt(domain)),
    orEmpty(() => lookup.resolveTxt(`_dmarc.${domain}`)),
  ]);
  return { mx: mx.map((r) => r.exchange), txt, dmarc };
}

const joined = (records: string[][]) => records.map((chunks) => chunks.join("").trim());

const finding = (host: string, severity: Finding["severity"], title: string, description: string, recommendation: string): Finding => ({
  host,
  title,
  severity,
  description,
  recommendation,
  category: "email",
});

function spfFindings(domain: string, spf: string[], hasMail: boolean): Finding[] {
  if (spf.length === 0) {
    return [
      finding(
        domain,
        "MEDIUM",
        "No SPF record",
        hasMail
          ? `${domain} receives mail but publishes no SPF record, so receivers can't tell which servers may send as it.`
          : `${domain} has no SPF record. Even domains that never send mail can be spoofed without one.`,
        hasMail
          ? "Publish a TXT record listing your senders, ending in -all (e.g. v=spf1 include:_spf.google.com -all)."
          : 'Publish "v=spf1 -all" to declare that the domain sends no mail.',
      ),
    ];
  }
  if (spf.length > 1) {
    return [finding(domain, "MEDIUM", "Multiple SPF records", `${domain} publishes ${spf.length} SPF records. Receivers treat that as an error and ignore SPF.`, "Merge them into a single v=spf1 record.")];
  }
  const all = /(?:^|\s)([+?~-]?)all(?:\s|$)/i.exec(spf[0]);
  if (!all) {
    return [finding(domain, "LOW", "SPF record has no 'all' mechanism", `The SPF record for ${domain} doesn't say what to do with unlisted senders: ${spf[0]}`, "End the record with -all (or ~all while testing).")];
  }
  const qualifier = all[1] || "+";
  if (qualifier === "+") {
    return [finding(domain, "HIGH", "SPF allows any sender (+all)", `The SPF record for ${domain} authorizes every server on the internet to send as it: ${spf[0]}`, "Replace +all with -all.")];
  }
  if (qualifier === "?") {
    return [finding(domain, "LOW", "SPF policy is neutral (?all)", `The SPF record for ${domain} ends in ?all, which gives receivers no guidance.`, "Use -all (or ~all while testing).")];
  }
  return [];
}

function dmarcFindings(domain: string, dmarc: string[]): Finding[] {
  const records = dmarc.filter((r) => /^v=DMARC1/i.test(r));
  if (records.length === 0) {
    return [finding(domain, "MEDIUM", "No DMARC record", `_dmarc.${domain} has no DMARC policy, so receivers have no instruction for mail that fails SPF or DKIM.`, `Publish a TXT record at _dmarc.${domain}, starting with "v=DMARC1; p=none; rua=mailto:…" and moving to p=quarantine or p=reject.`)];
  }
  if (records.length > 1) {
    return [finding(domain, "MEDIUM", "Multiple DMARC records", `_dmarc.${domain} publishes ${records.length} DMARC records; receivers ignore DMARC when there's more than one.`, "Keep a single v=DMARC1 record.")];
  }
  const policy = /(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(records[0])?.[1]?.toLowerCase();
  if (!policy) {
    return [finding(domain, "MEDIUM", "DMARC record has no policy", `The DMARC record for ${domain} is missing the required p= tag: ${records[0]}`, "Add p=quarantine or p=reject.")];
  }
  if (policy === "none") {
    return [finding(domain, "LOW", "DMARC policy is p=none", `DMARC for ${domain} only monitors; spoofed mail is still delivered.`, "Once reports look clean, move to p=quarantine and then p=reject.")];
  }
  return [];
}

/** Findings for a domain's published email-authentication records. Pure. */
export function evaluateEmailSecurity(domain: string, records: EmailDns): Finding[] {
  const spf = joined(records.txt).filter((r) => /^v=spf1(\s|$)/i.test(r));
  return [...spfFindings(domain, spf, records.mx.length > 0), ...dmarcFindings(domain, joined(records.dmarc))];
}
