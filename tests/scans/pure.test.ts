import { describe, expect, it } from "vitest";
import { riskFingerprint, threatLevelFor, toDetectedRisks } from "@/lib/scans/findings";
import { activeScanAllowed } from "@/lib/scans/gate";
import { discoveryDomain, hostsForTarget, toSubdomains } from "@/lib/scans/target-hosts";
import type { Finding } from "@/types/recon";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  host: "localhost:3100",
  title: "Missing Content-Security-Policy header",
  severity: "MEDIUM",
  description: "No CSP.",
  recommendation: "Add a CSP.",
  ...overrides,
});

describe("finding to risk mapping", () => {
  it("maps severities, keeping open ports as LOW and dropping other INFO", () => {
    expect(threatLevelFor(finding({ severity: "CRITICAL" }))).toBe("CRITICAL");
    expect(threatLevelFor(finding({ severity: "INFO", port: 22 }))).toBe("LOW");
    expect(threatLevelFor(finding({ severity: "INFO" }))).toBeNull();
  });

  it("builds detected risks with evidence and drops informational findings", () => {
    const risks = toDetectedRisks("NMAP", "tgt_1", [
      finding({ severity: "INFO", title: "Open port 22 (ssh)", port: 22, service: "ssh" }),
      finding({ severity: "INFO", title: "Exposed path: /robots.txt" }),
    ]);
    expect(risks).toHaveLength(1);
    expect(risks[0]).toMatchObject({
      targetId: "tgt_1",
      definition: {
        scanType: "NMAP",
        threatLevel: "LOW",
        solution: "Add a CSP.",
        additionalInfo: { host: "localhost:3100", port: 22, service: "ssh" },
      },
    });
  });

  it("keeps the fingerprint stable when only numbers in the title change", () => {
    const a = riskFingerprint("TLS", finding({ title: "TLS certificate expires in 9 days" }));
    const b = riskFingerprint("TLS", finding({ title: "TLS certificate expires in 8 days" }));
    expect(a).toBe(b);
    expect(riskFingerprint("TLS", finding({ title: "x" }))).not.toBe(riskFingerprint("SURFACE", finding({ title: "x" })));
    expect(riskFingerprint("NMAP", finding({ port: 22 }))).not.toBe(riskFingerprint("NMAP", finding({ port: 23 })));
    expect(riskFingerprint("SURFACE", finding({ host: "a.test" }))).not.toBe(riskFingerprint("SURFACE", finding({ host: "b.test" })));
  });
});

describe("hosts for a target", () => {
  it("uses host:port for URLs and the value itself for hosts and domains", () => {
    expect(hostsForTarget({ target: "http://localhost:3100/login", kind: "url" })).toEqual(["localhost:3100"]);
    expect(hostsForTarget({ target: "example.com", kind: "domain" })).toEqual(["example.com"]);
    expect(hostsForTarget({ target: "10.0.0.5:8080", kind: "host" })).toEqual(["10.0.0.5:8080"]);
  });

  it("expands CIDR ranges without network and broadcast addresses", () => {
    expect(hostsForTarget({ target: "192.168.1.0/30", kind: "cidr" })).toEqual(["192.168.1.1", "192.168.1.2"]);
    expect(hostsForTarget({ target: "192.168.1.7/32", kind: "cidr" })).toEqual(["192.168.1.7"]);
    expect(hostsForTarget({ target: "10.0.0.0/24", kind: "cidr" })).toHaveLength(254);
  });

  it("wraps hosts as resolved names for the probe", () => {
    expect(toSubdomains(["a.test"])).toEqual([{ name: "a.test", resolves: true, records: {} }]);
  });

  it("only enumerates subdomains of real domains", () => {
    expect(discoveryDomain({ target: "example.com", kind: "domain" })).toBe("example.com");
    expect(discoveryDomain({ target: "https://app.example.com/x", kind: "url" })).toBe("app.example.com");
    expect(discoveryDomain({ target: "http://localhost:3100", kind: "url" })).toBeNull();
    expect(discoveryDomain({ target: "http://10.0.0.1", kind: "url" })).toBeNull();
    expect(discoveryDomain({ target: "10.0.0.0/24", kind: "cidr" })).toBeNull();
  });
});

describe("active scan gate", () => {
  it("allows only local and private-network targets for now", () => {
    expect(activeScanAllowed({ target: "localhost:3100" }).allowed).toBe(true);
    expect(activeScanAllowed({ target: "http://127.0.0.1:3100" }).allowed).toBe(true);
    expect(activeScanAllowed({ target: "192.168.1.0/28" }).allowed).toBe(true);
    const external = activeScanAllowed({ target: "example.com" });
    expect(external.allowed).toBe(false);
    expect(external.reason).toMatch(/local and private-network/);
  });
});
