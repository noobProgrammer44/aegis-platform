import { isIP } from "node:net";
import tls, { type ConnectionOptions, type PeerCertificate } from "node:tls";
import type { Finding } from "@/types/recon";

/**
 * TLS / SSL check in pure Node, so it works without sslyze or Docker: certificate
 * validity, trust chain, hostname match, key size, and whether TLS 1.0 / 1.1 are still
 * accepted. One normal handshake plus one legacy-protocol attempt per host.
 */

export interface TlsCertInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  /** RSA modulus size; undefined for EC keys. */
  bits?: number;
  altNames: string[];
}

export interface TlsProbe {
  host: string;
  port: number;
  reachable: boolean;
  error?: string;
  protocol?: string;
  trusted?: boolean;
  trustError?: string;
  hostnameMatches?: boolean;
  cert?: TlsCertInfo;
  /** TLS 1.0 / 1.1 handshake succeeded. */
  legacyAccepted?: boolean;
}

const TIMEOUT_MS = 8_000;

function handshake(options: ConnectionOptions): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ ...options, rejectUnauthorized: false });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("timed out"));
    }, TIMEOUT_MS);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

const first = (value: string | string[] | undefined): string => (Array.isArray(value) ? (value[0] ?? "") : (value ?? ""));

const toInfo = (cert: PeerCertificate): TlsCertInfo => ({
  subject: first(cert.subject?.CN),
  issuer: first(cert.issuer?.O) || first(cert.issuer?.CN),
  validFrom: new Date(cert.valid_from).toISOString(),
  validTo: new Date(cert.valid_to).toISOString(),
  bits: typeof cert.bits === "number" ? cert.bits : undefined,
  altNames: (cert.subjectaltname ?? "").split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter(Boolean),
});

export async function probeTls(host: string, port: number): Promise<TlsProbe> {
  const servername = isIP(host) ? undefined : host;
  let socket: tls.TLSSocket;
  try {
    socket = await handshake({ host, port, servername });
  } catch (err) {
    return { host, port, reachable: false, error: err instanceof Error ? err.message : String(err) };
  }
  const peer = socket.getPeerCertificate();
  const probe: TlsProbe = {
    host,
    port,
    reachable: true,
    protocol: socket.getProtocol() ?? undefined,
    trusted: socket.authorized,
    trustError: socket.authorized ? undefined : String(socket.authorizationError ?? ""),
    hostnameMatches: servername && peer?.raw ? tls.checkServerIdentity(servername, peer) === undefined : undefined,
    cert: peer?.raw ? toInfo(peer) : undefined,
  };
  socket.end();

  let legacyAccepted = false;
  try {
    const old = await handshake({ host, port, servername, minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT@SECLEVEL=0" });
    legacyAccepted = true;
    old.end();
  } catch {
    legacyAccepted = false;
  }
  return { ...probe, legacyAccepted };
}

const DAY_MS = 86_400_000;
const SELF_SIGNED = new Set(["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN"]);

/** Findings for one TLS endpoint. Pure. */
export function evaluateTls(probe: TlsProbe, now: Date): Finding[] {
  if (!probe.reachable || !probe.cert) return [];
  const where = `${probe.host}:${probe.port}`;
  const make = (severity: Finding["severity"], title: string, description: string, recommendation: string): Finding => ({
    host: where,
    port: probe.port,
    title,
    severity,
    description,
    recommendation,
    category: "tls",
  });
  const out: Finding[] = [];
  const daysLeft = Math.floor((Date.parse(probe.cert.validTo) - now.getTime()) / DAY_MS);
  if (daysLeft < 0) {
    out.push(make("HIGH", "TLS certificate has expired", `The certificate on ${where} expired on ${probe.cert.validTo.slice(0, 10)}. Browsers show a full-page warning.`, "Renew the certificate and set up automatic renewal (e.g. Let's Encrypt)."));
  } else if (daysLeft <= 14) {
    out.push(make("MEDIUM", "TLS certificate expires within 14 days", `The certificate on ${where} expires on ${probe.cert.validTo.slice(0, 10)}.`, "Renew it now and check that automatic renewal works."));
  } else if (daysLeft <= 30) {
    out.push(make("LOW", "TLS certificate expires within 30 days", `The certificate on ${where} expires on ${probe.cert.validTo.slice(0, 10)}.`, "Make sure renewal is scheduled."));
  }
  if (probe.trusted === false && probe.trustError !== "CERT_HAS_EXPIRED") {
    out.push(
      SELF_SIGNED.has(probe.trustError ?? "")
        ? make("MEDIUM", "Self-signed TLS certificate", `${where} presents a self-signed certificate, so clients can't verify they're talking to the real server.`, "Use a certificate from a public CA.")
        : make("MEDIUM", "TLS certificate is not trusted", `The certificate chain on ${where} doesn't verify (${probe.trustError}). This is often a missing intermediate certificate.`, "Serve the full certificate chain from a public CA."),
    );
  }
  if (probe.hostnameMatches === false) {
    out.push(make("MEDIUM", "TLS certificate doesn't match the hostname", `The certificate on ${where} is for ${probe.cert.subject || probe.cert.altNames.slice(0, 3).join(", ")}, not ${probe.host}.`, "Issue a certificate that covers this hostname."));
  }
  if (probe.legacyAccepted) {
    out.push(make("MEDIUM", "Legacy TLS 1.0 / 1.1 enabled", `${where} still accepts TLS 1.0 or 1.1, which are deprecated and have known weaknesses.`, "Allow only TLS 1.2 and 1.3."));
  }
  if (probe.cert.bits !== undefined && probe.cert.bits < 2048) {
    out.push(make("MEDIUM", "Weak TLS key", `The certificate on ${where} uses a ${probe.cert.bits}-bit RSA key.`, "Reissue the certificate with a 2048-bit (or larger) RSA key or an EC key."));
  }
  return out;
}
