import tls from "node:tls";
import pLimit from "p-limit";
import type { Finding, Fingerprint, LiveHost, Severity } from "@/types/recon";

/**
 * Stage 4a — Surface analysis → findings (ACTIVE).
 *
 * Correlates probe output (captured headers) and fingerprint output
 * (technologies, exposed paths) into severity-ranked findings. Reads TLS
 * certificates for HTTPS hosts, so it is gated behind `activeAllowed`. Deep CVE
 * matching via nuclei lands in a later phase.
 */

const TLS_TIMEOUT_MS = 5_000;
const CERT_EXPIRY_WARN_DAYS = 14;
const HOST_CONCURRENCY = 10;

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

type SecurityHeaderCheck = {
  key: string;
  name: string;
  severity: Severity;
  httpsOnly?: boolean;
  protects: string;
  fix: string;
};

const SECURITY_HEADERS: SecurityHeaderCheck[] = [
  {
    key: "content-security-policy",
    name: "Content-Security-Policy",
    severity: "MEDIUM",
    protects:
      "A CSP mitigates cross-site scripting (XSS) and data injection by controlling which resources may load.",
    fix: "Add a Content-Security-Policy header with a restrictive policy, e.g. default-src 'self'.",
  },
  {
    key: "strict-transport-security",
    name: "Strict-Transport-Security",
    severity: "MEDIUM",
    httpsOnly: true,
    protects:
      "HSTS forces HTTPS for future requests, preventing SSL-stripping and protocol-downgrade attacks.",
    fix: "Add Strict-Transport-Security: max-age=63072000; includeSubDomains.",
  },
  {
    key: "x-frame-options",
    name: "X-Frame-Options",
    severity: "LOW",
    protects:
      "Prevents clickjacking by disallowing the page from being embedded in a frame.",
    fix: "Add X-Frame-Options: DENY, or a CSP frame-ancestors directive.",
  },
  {
    key: "x-content-type-options",
    name: "X-Content-Type-Options",
    severity: "LOW",
    protects:
      "Stops MIME-type sniffing that can turn benign uploads into executable content.",
    fix: "Add X-Content-Type-Options: nosniff.",
  },
  {
    key: "referrer-policy",
    name: "Referrer-Policy",
    severity: "LOW",
    protects:
      "Limits how much referrer information leaks to other origins on navigation.",
    fix: "Add Referrer-Policy: strict-origin-when-cross-origin.",
  },
];

export async function analyze(
  liveHosts: LiveHost[],
  fingerprints: Fingerprint[],
  activeAllowed: boolean,
): Promise<Finding[]> {
  if (!activeAllowed) {
    throw new Error(
      "Active scanning is not authorized. Enable 'Active scan' before surface analysis.",
    );
  }

  const fpByHost = new Map(fingerprints.map((fp) => [fp.host, fp]));
  const limit = pLimit(HOST_CONCURRENCY);

  const perHost = await Promise.all(
    liveHosts.map((host) =>
      limit(async () => {
        const fp = fpByHost.get(host.url);
        const findings: Finding[] = [];
        findings.push(...checkSecurityHeaders(host));
        const tls = await checkTls(host);
        if (tls) findings.push(tls);
        if (fp) {
          findings.push(...exposedPathFindings(host, fp));
          findings.push(...versionHintFindings(host, fp));
        }
        return findings;
      }),
    ),
  );

  return perHost
    .flat()
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

// --- 1. missing security headers ------------------------------------------

function checkSecurityHeaders(host: LiveHost): Finding[] {
  const headers = host.headers ?? {};
  const isHttps = host.url.startsWith("https:");
  const findings: Finding[] = [];

  for (const check of SECURITY_HEADERS) {
    if (check.httpsOnly && !isHttps) continue; // HSTS is meaningless over HTTP
    if (headers[check.key]) continue; // present

    findings.push({
      host: host.url,
      title: `Missing ${check.name} header`,
      severity: check.severity,
      description: `The ${check.name} response header is not set. ${check.protects}`,
      recommendation: check.fix,
    });
  }

  return findings;
}

// --- 2. TLS certificate check ---------------------------------------------

async function checkTls(host: LiveHost): Promise<Finding | null> {
  let url: URL;
  try {
    url = new URL(host.url);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;

  const port = url.port ? Number(url.port) : 443;
  const cert = await readCertificate(url.hostname, port);
  if (!cert?.valid_to) return null;

  return evaluateCertExpiry(host.url, url.hostname, new Date(cert.valid_to));
}

/** Pure expiry classifier — expired => CRITICAL, expiring soon => HIGH. */
export function evaluateCertExpiry(
  hostUrl: string,
  hostname: string,
  expiry: Date,
): Finding | null {
  const msLeft = expiry.getTime() - Date.now();
  const daysLeft = Math.floor(msLeft / 86_400_000);

  if (msLeft <= 0) {
    return {
      host: hostUrl,
      title: "TLS certificate expired",
      severity: "CRITICAL",
      description: `The TLS certificate for ${hostname} expired on ${expiry.toUTCString()}.`,
      recommendation: "Renew or replace the TLS certificate immediately.",
    };
  }
  if (daysLeft <= CERT_EXPIRY_WARN_DAYS) {
    return {
      host: hostUrl,
      title: "TLS certificate expiring soon",
      severity: "HIGH",
      description: `The TLS certificate for ${hostname} expires in ${daysLeft} day(s), on ${expiry.toUTCString()}.`,
      recommendation:
        "Renew the TLS certificate before it expires to avoid an outage or trust errors.",
    };
  }
  return null;
}

function readCertificate(
  host: string,
  port: number,
): Promise<tls.PeerCertificate | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: tls.PeerCertificate | null) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: TLS_TIMEOUT_MS },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        done(cert && Object.keys(cert).length > 0 ? cert : null);
      },
    );
    socket.on("error", () => done(null));
    socket.on("timeout", () => {
      socket.destroy();
      done(null);
    });
  });
}

// --- 3. exposed paths ------------------------------------------------------

function exposedPathFindings(host: LiveHost, fp: Fingerprint): Finding[] {
  return fp.exposedPaths.map((entry) => {
    const match = entry.match(/^(\S+)\s*(?:\((\d+)\))?/);
    const path = match ? match[1] : entry;
    const status = match?.[2] ?? "";
    const meta = classifyExposedPath(path);

    return {
      host: host.url,
      title: `Exposed path: ${path}`,
      severity: meta.severity,
      description: `${path} is reachable${status ? ` (HTTP ${status})` : ""}. ${meta.description}`,
      recommendation: meta.recommendation,
    };
  });
}

function classifyExposedPath(path: string): {
  severity: Severity;
  description: string;
  recommendation: string;
} {
  if (/^\/\.(git|env)/i.test(path)) {
    return {
      severity: "HIGH",
      description:
        "This can leak source code, configuration, or credentials to anyone.",
      recommendation:
        "Block access to this path immediately and rotate any secrets it may have exposed.",
    };
  }
  if (path === "/admin" || path === "/api-docs" || path === "/swagger") {
    return {
      severity: "MEDIUM",
      description:
        "Administrative or API-documentation endpoints enlarge the attack surface.",
      recommendation:
        "Require authentication, restrict by IP, or remove the endpoint from production.",
    };
  }
  if (path === "/robots.txt" || path === "/sitemap.xml") {
    return {
      severity: "INFO",
      description: "Informational; it may disclose additional paths worth reviewing.",
      recommendation: "Confirm it does not reveal sensitive or internal locations.",
    };
  }
  return {
    severity: "LOW",
    description: "An unexpected path is publicly reachable.",
    recommendation: "Verify this path is intended to be publicly accessible.",
  };
}

// --- 4. outdated-component hints -------------------------------------------

function versionHintFindings(host: LiveHost, fp: Fingerprint): Finding[] {
  return fp.technologies
    .filter((tech) => tech.version)
    .map((tech) => ({
      host: host.url,
      title: `${tech.name} ${tech.version} detected`,
      severity: "INFO" as Severity,
      description: `A specific ${tech.name} version (${tech.version}) is exposed and can be cross-referenced against public CVE databases.`,
      recommendation:
        "Confirm it is the latest patched release; deep CVE matching runs in the nuclei stage.",
    }));
}
