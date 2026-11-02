import { describe, expect, it } from "vitest";
import { evaluateEmailSecurity, lookupEmailDns } from "@/lib/scans/checks/email";
import { evaluateJsExposure, findSecrets, firstPartyScripts, maskSecret, sourceMapRef } from "@/lib/scans/checks/js-secrets";
import { checkCname, evaluateTakeover, hostedService } from "@/lib/scans/checks/takeover";
import { evaluateTls, type TlsProbe } from "@/lib/scans/checks/tls";
import { parseZapReport } from "@/lib/scans/checks/zap";
import { forDocker } from "@/lib/scans/tools";

// Fake credentials are assembled at runtime so no secret-shaped literal lives in the repo.
const fake = (...parts: string[]) => parts.join("");
const titles = (findings: { title: string }[]) => findings.map((f) => f.title);
const dnsError = (code: string) => Object.assign(new Error(code), { code });

describe("email security", () => {
  const records = (txt: string[], dmarc: string[], mx: string[] = ["mx.example.com"]) => ({
    mx,
    txt: txt.map((t) => [t]),
    dmarc: dmarc.map((d) => [d]),
  });

  it("is quiet for a strict SPF and an enforcing DMARC", () => {
    expect(evaluateEmailSecurity("example.com", records(["v=spf1 include:_spf.google.com -all"], ["v=DMARC1; p=reject"]))).toEqual([]);
  });

  it("flags missing, duplicated and permissive SPF", () => {
    expect(titles(evaluateEmailSecurity("example.com", records([], ["v=DMARC1; p=reject"])))).toEqual(["No SPF record"]);
    expect(titles(evaluateEmailSecurity("example.com", records(["v=spf1 -all", "v=spf1 ~all"], ["v=DMARC1; p=reject"])))).toEqual(["Multiple SPF records"]);
    const plusAll = evaluateEmailSecurity("example.com", records(["v=spf1 +all"], ["v=DMARC1; p=reject"]));
    expect(plusAll).toMatchObject([{ title: "SPF allows any sender (+all)", severity: "HIGH" }]);
    expect(titles(evaluateEmailSecurity("example.com", records(["v=spf1 a mx"], ["v=DMARC1; p=reject"])))).toEqual(["SPF record has no 'all' mechanism"]);
    expect(titles(evaluateEmailSecurity("example.com", records(["v=spf1 ?all"], ["v=DMARC1; p=reject"])))).toEqual(["SPF policy is neutral (?all)"]);
  });

  it("flags missing, monitoring-only and broken DMARC", () => {
    expect(titles(evaluateEmailSecurity("example.com", records(["v=spf1 -all"], [])))).toEqual(["No DMARC record"]);
    expect(evaluateEmailSecurity("example.com", records(["v=spf1 -all"], ["v=DMARC1; p=none; rua=mailto:x@example.com"]))).toMatchObject([{ title: "DMARC policy is p=none", severity: "LOW" }]);
    expect(titles(evaluateEmailSecurity("example.com", records(["v=spf1 -all"], ["v=DMARC1; rua=mailto:x@example.com"])))).toEqual(["DMARC record has no policy"]);
  });

  it("joins split TXT chunks and treats missing records as empty", async () => {
    const lookup = {
      resolveMx: async () => Promise.reject(dnsError("ENODATA")),
      resolveTxt: async (d: string) => (d.startsWith("_dmarc.") ? Promise.reject(dnsError("ENOTFOUND")) : [["v=spf1 ", "-all"]]),
    };
    const dns = await lookupEmailDns("example.com", lookup);
    expect(dns).toEqual({ mx: [], txt: [["v=spf1 ", "-all"]], dmarc: [] });
    expect(titles(evaluateEmailSecurity("example.com", dns))).toEqual(["No DMARC record"]);
    await expect(lookupEmailDns("example.com", { ...lookup, resolveMx: async () => Promise.reject(dnsError("ETIMEOUT")) })).rejects.toThrow();
  });
});

describe("domain takeover", () => {
  it("recognises hosted services by CNAME suffix", () => {
    expect(hostedService("old-site.github.io.")).toBe("GitHub Pages");
    expect(hostedService("assets.s3.amazonaws.com")).toBe("AWS S3");
    expect(hostedService("shop.example.com")).toBeNull();
    expect(hostedService("notgithub.io")).toBeNull();
  });

  it("flags a CNAME to a hosted service that no longer exists", async () => {
    const lookup = {
      resolveCname: async () => ["old-site.herokuapp.com"],
      resolve4: async () => Promise.reject(dnsError("ENOTFOUND")),
      resolve6: async () => Promise.reject(dnsError("ENOTFOUND")),
    };
    const check = await checkCname("promo.example.com", lookup);
    expect(check).toEqual({ host: "promo.example.com", cname: "old-site.herokuapp.com", targetExists: false });
    expect(evaluateTakeover(check)).toMatchObject({ title: "Possible subdomain takeover via Heroku", severity: "HIGH" });
  });

  it("stays quiet when the CNAME target resolves or there is no CNAME", async () => {
    const live = { resolveCname: async () => ["site.netlify.app"], resolve4: async () => ["1.2.3.4"], resolve6: async () => Promise.reject(dnsError("ENODATA")) };
    expect(evaluateTakeover(await checkCname("www.example.com", live))).toBeNull();
    const none = { resolveCname: async () => Promise.reject(dnsError("ENODATA")), resolve4: async () => [], resolve6: async () => [] };
    expect(evaluateTakeover(await checkCname("example.com", none))).toBeNull();
    expect(evaluateTakeover({ host: "a.example.com", cname: "gone.example.net", targetExists: false })).toMatchObject({ title: "Dangling CNAME record", severity: "MEDIUM" });
  });
});

describe("TLS", () => {
  const NOW = new Date("2026-11-03T00:00:00.000Z");
  const probe = (overrides: Partial<TlsProbe> = {}, validTo = "2027-06-01T00:00:00.000Z"): TlsProbe => ({
    host: "app.example.com",
    port: 443,
    reachable: true,
    protocol: "TLSv1.3",
    trusted: true,
    hostnameMatches: true,
    legacyAccepted: false,
    cert: { subject: "app.example.com", issuer: "Let's Encrypt", validFrom: "2026-09-01T00:00:00.000Z", validTo, bits: 2048, altNames: ["app.example.com"] },
    ...overrides,
  });

  it("is quiet for a healthy endpoint and for unreachable ones", () => {
    expect(evaluateTls(probe(), NOW)).toEqual([]);
    expect(evaluateTls({ host: "x", port: 443, reachable: false, error: "ECONNREFUSED" }, NOW)).toEqual([]);
  });

  it("grades expiry", () => {
    expect(evaluateTls(probe({}, "2026-10-01T00:00:00.000Z"), NOW)).toMatchObject([{ title: "TLS certificate has expired", severity: "HIGH" }]);
    expect(titles(evaluateTls(probe({}, "2026-11-10T00:00:00.000Z"), NOW))).toEqual(["TLS certificate expires within 14 days"]);
    expect(titles(evaluateTls(probe({}, "2026-11-25T00:00:00.000Z"), NOW))).toEqual(["TLS certificate expires within 30 days"]);
  });

  it("flags trust, hostname, legacy protocols and weak keys", () => {
    const bad = probe({ trusted: false, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT", hostnameMatches: false, legacyAccepted: true, cert: { ...probe().cert!, bits: 1024 } });
    expect(titles(evaluateTls(bad, NOW))).toEqual([
      "Self-signed TLS certificate",
      "TLS certificate doesn't match the hostname",
      "Legacy TLS 1.0 / 1.1 enabled",
      "Weak TLS key",
    ]);
    expect(titles(evaluateTls(probe({ trusted: false, trustError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }), NOW))).toEqual(["TLS certificate is not trusted"]);
    expect(evaluateTls(probe({}, "2026-10-01T00:00:00.000Z"), NOW)[0].port).toBe(443);
  });
});

describe("JS secrets and source maps", () => {
  const stripe = fake("sk_", "live_", "a1B2c3D4e5F6g7H8i9J0k1L2");
  const aws = fake("AKIA", "ABCDEFGHIJKLMNOP");
  const header = Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url");
  const jwt = (role: string) => `${header}.${Buffer.from(JSON.stringify({ role })).toString("base64url")}.${"s".repeat(20)}`;

  it("masks secrets", () => {
    expect(maskSecret(stripe)).toBe(`${stripe.slice(0, 4)}…${stripe.slice(-4)}`);
    expect(maskSecret("short")).toBe("****");
  });

  it("finds known key formats, once each, and never returns the full value", () => {
    const source = `const s="${stripe}"; const k='${aws}'; const again="${stripe}";`;
    const hits = findSecrets(source, "https://app.example.com/main.js");
    expect(hits.map((h) => h.patternId)).toEqual(["stripe-secret", "aws-access-key"]);
    expect(JSON.stringify(hits)).not.toContain(stripe);
  });

  it("only reports Supabase JWTs that carry the service_role", () => {
    expect(findSecrets(`k="${jwt("service_role")}"`, "x").map((h) => h.patternId)).toEqual(["supabase-service-role"]);
    expect(findSecrets(`k="${jwt("anon")}"`, "x")).toEqual([]);
  });

  it("reads sourceMappingURL comments and first-party script tags", () => {
    expect(sourceMapRef("console.log(1)\n//# sourceMappingURL=main.js.map\n")).toBe("main.js.map");
    expect(sourceMapRef("console.log(1)")).toBeNull();
    const html = '<script src="/main.js"></script><script src="https://cdn.example.com/a.js"></script><script src="https://www.googletagmanager.com/gtm.js"></script><script src="/main.js"></script>';
    expect(firstPartyScripts(html, "https://www.example.com/")).toEqual(["https://www.example.com/main.js", "https://cdn.example.com/a.js"]);
  });

  it("turns hits into one finding per key type, plus one for source maps", () => {
    const hits = findSecrets(`"${stripe}" "${aws}"`, "https://app.example.com/main.js");
    const findings = evaluateJsExposure("app.example.com", hits, ["https://app.example.com/main.js.map"]);
    expect(findings.map((f) => [f.title, f.severity])).toEqual([
      ["Stripe secret key exposed in public JavaScript", "CRITICAL"],
      ["AWS access key ID exposed in public JavaScript", "HIGH"],
      ["JavaScript source maps are publicly downloadable", "MEDIUM"],
    ]);
    expect(findings[0].description).not.toContain(stripe);
  });
});

describe("ZAP report parsing", () => {
  it("maps risk codes, skips informational alerts and strips HTML", () => {
    const report = {
      site: [
        {
          "@host": "host.docker.internal",
          alerts: [
            { name: "Content Security Policy (CSP) Header Not Set", riskcode: "2", desc: "<p>CSP is missing.</p>", solution: "<p>Set it.</p>", reference: "<p>https://developer.mozilla.org/csp</p>", cweid: "693", instances: [{ uri: "http://host.docker.internal:3100/" }] },
            { name: "Modern Web Application", riskcode: "0", desc: "info" },
            { name: "Cookie No HttpOnly Flag", riskcode: "1", desc: "<p>Cookie.</p>", solution: "", instances: [] },
          ],
        },
      ],
    };
    const findings = parseZapReport(report, "localhost:3100");
    expect(findings.map((f) => [f.title, f.severity, f.host])).toEqual([
      ["Content Security Policy (CSP) Header Not Set", "MEDIUM", "localhost:3100"],
      ["Cookie No HttpOnly Flag", "LOW", "localhost:3100"],
    ]);
    expect(findings[0].description).toBe("CSP is missing. Seen at http://host.docker.internal:3100/. CWE-693.");
    expect(findings[0].recommendation).toBe("Set it. See https://developer.mozilla.org/csp");
    expect(parseZapReport({ site: "nope" }, "x")).toEqual([]);
    expect(parseZapReport(null, "x")).toEqual([]);
  });

  it("points containers at the host for local targets only", () => {
    expect(forDocker("http://localhost:3100/")).toBe("http://host.docker.internal:3100/");
    expect(forDocker("https://app.example.com/")).toBe("https://app.example.com/");
  });
});
