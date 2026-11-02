import { describe, expect, it } from "vitest";
import { evaluateEmailSecurity, lookupEmailDns } from "@/lib/scans/checks/email";
import { evaluateJsExposure, findSecrets, firstPartyScripts, maskSecret, sourceMapRef } from "@/lib/scans/checks/js-secrets";
import { checkCname, evaluateTakeover, hostedService } from "@/lib/scans/checks/takeover";
import { evaluateTls, type TlsProbe } from "@/lib/scans/checks/tls";
import { parseZapReport, zapPlan } from "@/lib/scans/checks/zap";
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
  const report = {
    site: [
      {
        alerts: [
          {
            name: "Missing Anti-clickjacking Header",
            pluginid: "10020",
            riskcode: "2",
            confidence: "2",
            desc: "<p>The response does not protect against ClickJacking.</p>",
            solution: "<p>Set X-Frame-Options.</p>",
            reference: "<p>https://developer.mozilla.org/x-frame-options</p><p>https://owasp.org/clickjacking</p>",
            cweid: "1021",
            wascid: "15",
            tags: [
              { tag: "OWASP_2021_A05", link: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
              { tag: "CWE-1021", link: "https://cwe.mitre.org/data/definitions/1021.html" },
            ],
            instances: [
              {
                uri: "http://host.docker.internal:3100/",
                method: "GET",
                param: "x-frame-options",
                "request-header": "GET http://host.docker.internal:3100/ HTTP/1.1\r\nhost: host.docker.internal:3100",
                "response-header": "HTTP/1.1 200 OK\r\nContent-Type: text/html",
                "response-body": "x".repeat(5000),
              },
              { method: "GET" },
            ],
          },
          { name: "Modern Web Application", riskcode: "0", desc: "info" },
        ],
      },
    ],
  };

  it("keeps ZAP's classification, references and instances", () => {
    const [f] = parseZapReport(report, "localhost:3100", "host.docker.internal:3100");
    expect(f).toMatchObject({
      title: "Missing Anti-clickjacking Header",
      severity: "MEDIUM",
      host: "localhost:3100",
      description: "The response does not protect against ClickJacking.",
      recommendation: "Set X-Frame-Options.",
      references: ["https://developer.mozilla.org/x-frame-options", "https://owasp.org/clickjacking"],
      details: {
        pluginId: "10020",
        cweId: "1021",
        wascId: "15",
        confidence: "Medium",
        owasp: { code: "A05:2021", name: "Security Misconfiguration" },
      },
    });
    const instances = (f.details as { instances: { uri: string; requestHeader?: string; responseBody?: string }[] }).instances;
    expect(instances).toHaveLength(1);
    expect(instances[0].uri).toBe("http://localhost:3100/");
    expect(instances[0].requestHeader).toContain("GET http://localhost:3100/");
    expect(instances[0].responseBody).toMatch(/more characters\)$/);
  });

  it("skips informational alerts and tolerates junk", () => {
    expect(parseZapReport(report, "x")).toHaveLength(1);
    expect(parseZapReport({ site: "nope" }, "x")).toEqual([]);
    expect(parseZapReport(null, "x")).toEqual([]);
  });

  it("builds an automation plan with the URL safely quoted", () => {
    const plan = zapPlan('http://host.docker.internal:3100/"evil', "baseline");
    expect(plan).toContain('- "http://host.docker.internal:3100/\\"evil"');
    expect(plan).toContain("template: traditional-json-plus");
    expect(plan).not.toContain("activeScan");
    expect(zapPlan("https://a.test/", "full")).toContain("type: activeScan");
  });

  it("points containers at the host for local targets only", () => {
    expect(forDocker("http://localhost:3100/")).toBe("http://host.docker.internal:3100/");
    expect(forDocker("https://app.example.com/")).toBe("https://app.example.com/");
  });
});

describe("stored evidence", () => {
  it("reads instances and classification back defensively", async () => {
    const { readEvidence } = await import("@/lib/domain/evidence");
    expect(
      readEvidence({
        cweId: "798",
        owasp: { code: "A07:2021", name: "Identification and Authentication Failures", url: "https://owasp.org/x" },
        instances: [{ uri: "https://a.test/main.js", evidence: "AKIA…0000" }, { nope: true }, null],
      }),
    ).toEqual({
      cweId: "798",
      wascId: undefined,
      owasp: { code: "A07:2021", name: "Identification and Authentication Failures", url: "https://owasp.org/x" },
      confidence: undefined,
      pluginId: undefined,
      instances: [expect.objectContaining({ uri: "https://a.test/main.js", evidence: "AKIA…0000" })],
    });
    expect(readEvidence({ owasp: { code: "x" }, instances: "nope" })).toMatchObject({ owasp: undefined, instances: undefined });
  });

  it("attaches CWE, OWASP and instances to TLS and JS findings", () => {
    const tlsFinding = evaluateTls(
      { host: "a.test", port: 443, reachable: true, trusted: true, hostnameMatches: true, legacyAccepted: true, cert: { subject: "a.test", issuer: "CA", validFrom: "2026-01-01T00:00:00.000Z", validTo: "2027-01-01T00:00:00.000Z", altNames: [] } },
      new Date("2026-11-03T00:00:00.000Z"),
    )[0];
    expect(tlsFinding.details).toMatchObject({ cweId: "327", owasp: { code: "A02:2021" }, instances: [{ uri: "https://a.test:443" }] });
    const js = evaluateJsExposure("a.test", [], ["https://a.test/main.js.map"])[0];
    expect(js.details).toMatchObject({ cweId: "540", owasp: { code: "A01:2021" }, instances: [{ uri: "https://a.test/main.js.map" }] });
  });
});
