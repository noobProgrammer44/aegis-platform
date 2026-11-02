import { describe, expect, it } from "vitest";
import {
  hostAuthorization,
  scopeCovers,
  scopeFor,
  targetAuthorization,
  txtRecordsContainToken,
} from "@/lib/domain/authorization";
import type { Authorization, AuthorizationMethod } from "@/types/aegis";

const record = (scope: string, method: AuthorizationMethod, verified = true): Authorization => ({
  id: `aut_${scope}_${method}`,
  workspaceId: "ws_default",
  scope,
  method,
  token: method === "dns" ? "tok" : null,
  verified,
  attestedBy: method === "attested" ? "local user" : null,
  note: null,
  createdAt: "2026-11-03T00:00:00.000Z",
  verifiedAt: verified ? "2026-11-03T00:00:00.000Z" : null,
});

describe("scopes", () => {
  it("records authorizations under the bare host, IP or range", () => {
    expect(scopeFor({ target: "https://App.Example.com:8443/login" })).toBe("app.example.com");
    expect(scopeFor({ target: "example.com" })).toBe("example.com");
    expect(scopeFor({ target: "203.0.113.9:8080" })).toBe("203.0.113.9");
    expect(scopeFor({ target: "203.0.113.0/28" })).toBe("203.0.113.0/28");
  });

  it("lets a domain cover its subdomains but not look-alikes", () => {
    expect(scopeCovers("example.com", "example.com")).toBe(true);
    expect(scopeCovers("example.com", "api.dev.example.com")).toBe(true);
    expect(scopeCovers("example.com", "notexample.com")).toBe(false);
    expect(scopeCovers("example.com", "example.com.evil.test")).toBe(false);
    expect(scopeCovers("app.example.com", "example.com")).toBe(false);
  });

  it("matches IPs exactly and ranges by containment", () => {
    expect(scopeCovers("203.0.113.9", "203.0.113.9")).toBe(true);
    expect(scopeCovers("203.0.113.9", "203.0.113.10")).toBe(false);
    expect(scopeCovers("203.0.113.0/28", "203.0.113.14")).toBe(true);
    expect(scopeCovers("203.0.113.0/28", "203.0.113.16")).toBe(false);
    expect(scopeCovers("203.0.113.0/24", "203.0.113.0/28")).toBe(true);
    expect(scopeCovers("203.0.113.0/28", "203.0.113.0/24")).toBe(false);
  });
});

describe("tiers", () => {
  it("authorizes local targets automatically", () => {
    expect(targetAuthorization({ target: "localhost:3100" }, [])).toMatchObject({ tier: 2, method: "local", dnsVerifiable: false });
    expect(targetAuthorization({ target: "192.168.1.0/28" }, [])).toMatchObject({ tier: 2, method: "local" });
  });

  it("starts external targets at tier 0, with DNS checks only for domains", () => {
    expect(targetAuthorization({ target: "example.com" }, [])).toMatchObject({ tier: 0, method: null, dnsVerifiable: true });
    expect(targetAuthorization({ target: "203.0.113.9" }, [])).toMatchObject({ tier: 0, dnsVerifiable: false });
  });

  it("uses the strongest verified record and ignores pending ones", () => {
    const records = [record("example.com", "attested"), record("example.com", "dns", false)];
    expect(targetAuthorization({ target: "https://app.example.com" }, records)).toMatchObject({ tier: 1, method: "attested" });
    const verified = [record("example.com", "attested"), record("example.com", "dns")];
    expect(targetAuthorization({ target: "app.example.com" }, verified)).toMatchObject({ tier: 2, method: "dns" });
    expect(targetAuthorization({ target: "other.test" }, verified).tier).toBe(0);
  });

  it("checks raw hosts sent by the quick-scan routes", () => {
    const records = [record("example.com", "attested")];
    expect(hostAuthorization("shop.example.com:8443", records).tier).toBe(1);
    expect(hostAuthorization("http://localhost:3100/", []).tier).toBe(2);
    expect(hostAuthorization("evil.test", records).tier).toBe(0);
    expect(hostAuthorization("not a host", records).tier).toBe(0);
  });
});

describe("DNS token check", () => {
  it("accepts the exact token, including TXT records split into chunks", () => {
    expect(txtRecordsContainToken([["v=spf1 -all"], ["aegis-verify=abc123"]], "abc123")).toBe(true);
    expect(txtRecordsContainToken([["aegis-verify=", "abc123"]], "abc123")).toBe(true);
    expect(txtRecordsContainToken([["aegis-verify=abc1234"]], "abc123")).toBe(false);
    expect(txtRecordsContainToken([], "abc123")).toBe(false);
  });
});
