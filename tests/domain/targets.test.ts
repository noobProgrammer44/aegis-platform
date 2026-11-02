import { describe, expect, it } from "vitest";
import {
  formatIPv4,
  isLocalCidr,
  isLocalHostname,
  isLocalIPv4,
  parseCidr,
  parseIPv4,
} from "@/lib/domain/network";
import { MAX_TARGETS_PER_PASTE, parseTarget, parseTargetList } from "@/lib/domain/targets";

const parsed = (raw: string) => {
  const result = parseTarget(raw);
  if (!result.ok) throw new Error(`expected ${raw} to parse: ${result.error}`);
  return result.target;
};
const errorOf = (raw: string) => {
  const result = parseTarget(raw);
  if (result.ok) throw new Error(`expected ${raw} to be rejected`);
  return result.error;
};

describe("network helpers", () => {
  it("parses and formats IPv4 without leading zeros", () => {
    expect(parseIPv4("192.168.1.10")).toBe(3232235786);
    expect(formatIPv4(3232235786)).toBe("192.168.1.10");
    expect(formatIPv4(parseIPv4("255.255.255.255") as number)).toBe("255.255.255.255");
    expect(parseIPv4("256.1.1.1")).toBeNull();
    expect(parseIPv4("010.1.1.1")).toBeNull();
    expect(parseIPv4("1.2.3")).toBeNull();
  });

  it("normalizes a CIDR to its network address", () => {
    expect(parseCidr("10.0.0.77/24")).toEqual({ network: parseIPv4("10.0.0.0"), prefix: 24, size: 256 });
    expect(parseCidr("10.0.0.0/33")).toBeNull();
  });

  it("recognizes loopback, private and link-local ranges", () => {
    for (const ip of ["127.0.0.1", "10.4.5.6", "172.16.0.1", "172.31.255.255", "192.168.0.1", "169.254.1.1"]) {
      expect(isLocalIPv4(parseIPv4(ip) as number)).toBe(true);
    }
    for (const ip of ["8.8.8.8", "172.32.0.1", "100.64.0.1", "193.168.0.1"]) {
      expect(isLocalIPv4(parseIPv4(ip) as number)).toBe(false);
    }
    expect(isLocalCidr(parseCidr("192.168.1.0/24")!)).toBe(true);
    expect(isLocalCidr(parseCidr("172.31.255.0/24")!)).toBe(true);
    expect(isLocalCidr(parseCidr("203.0.113.0/24")!)).toBe(false);
    expect(isLocalHostname("LOCALHOST")).toBe(true);
    expect(isLocalHostname("app.localhost")).toBe(true);
    expect(isLocalHostname("printer.local")).toBe(true);
    expect(isLocalHostname("localhost.example.com")).toBe(false);
  });
});

describe("parseTarget", () => {
  it("parses domains, lowercased and without a trailing dot", () => {
    expect(parsed(" Example.COM. ")).toEqual({
      target: "example.com",
      kind: "domain",
      host: "example.com",
      port: null,
      isLocal: false,
    });
    expect(parsed("xn--bcher-kva.example").kind).toBe("domain");
  });

  it("parses URLs, keeping path and query but dropping the fragment", () => {
    expect(parsed("HTTPS://Example.com/Login?next=/a#top")).toEqual({
      target: "https://example.com/Login?next=/a",
      kind: "url",
      host: "example.com",
      port: 443,
      isLocal: false,
    });
    expect(parsed("http://localhost:3100/")).toMatchObject({
      target: "http://localhost:3100",
      port: 3100,
      isLocal: true,
    });
    expect(parsed("example.com/admin")).toMatchObject({ target: "https://example.com/admin", kind: "url" });
  });

  it("parses IPv4 addresses and host:port", () => {
    expect(parsed("203.0.113.9")).toMatchObject({ kind: "ipv4", port: null, isLocal: false });
    expect(parsed("10.0.0.5:8080")).toMatchObject({ target: "10.0.0.5:8080", kind: "host", port: 8080, isLocal: true });
    expect(parsed("example.com:8443")).toMatchObject({ target: "example.com:8443", kind: "host", host: "example.com" });
    expect(parsed("localhost")).toMatchObject({ target: "localhost", kind: "host", isLocal: true });
    expect(parsed("juiceshop:3000")).toMatchObject({ kind: "host", isLocal: true });
  });

  it("parses CIDR ranges up to /24", () => {
    expect(parsed("192.168.1.99/24")).toEqual({
      target: "192.168.1.0/24",
      kind: "cidr",
      host: "192.168.1.0/24",
      port: null,
      isLocal: true,
    });
    expect(parsed("203.0.113.8/30").isLocal).toBe(false);
    expect(errorOf("10.0.0.0/16")).toMatch(/at most 256 addresses/);
    expect(errorOf("10.0.0.0/40")).toMatch(/not a valid CIDR/);
  });

  it("rejects input it can't scan, with a reason", () => {
    expect(errorOf("   ")).toMatch(/Enter a target/);
    expect(errorOf("ftp://example.com")).toMatch(/Only http/);
    expect(errorOf("https://user:pass@example.com")).toMatch(/credentials/);
    expect(errorOf("::1")).toMatch(/IPv6/);
    expect(errorOf("[2001:db8::1]:443")).toMatch(/IPv6/);
    expect(errorOf("*.example.com")).toMatch(/Wildcards/);
    expect(errorOf("999.1.1.1")).toMatch(/not a valid IPv4/);
    expect(errorOf("example.com:99999")).toMatch(/out of range/);
    expect(errorOf("exa mple.com")).toMatch(/not a valid/);
    expect(errorOf("-bad-.com")).toMatch(/not a valid/);
    expect(errorOf("a".repeat(3000))).toMatch(/too long/);
  });
});

describe("parseTargetList", () => {
  it("splits on lines, commas and spaces, dedupes and reports bad entries", () => {
    const result = parseTargetList("example.com\nEXAMPLE.com, 10.0.0.1 ; bad..name\n\nhttps://a.test");
    expect(result.targets.map((t) => t.target)).toEqual(["example.com", "10.0.0.1", "https://a.test"]);
    expect(result.errors).toEqual([{ input: "bad..name", error: expect.stringMatching(/not a valid/) }]);
  });

  it("refuses pastes that are too large", () => {
    const text = Array.from({ length: MAX_TARGETS_PER_PASTE + 1 }, (_, i) => `h${i}.example.com`).join("\n");
    const result = parseTargetList(text);
    expect(result.targets).toEqual([]);
    expect(result.errors[0].error).toMatch(/at most/);
  });
});
