import { describe, expect, it } from "vitest";
import { listAudit } from "@/lib/db/repos/audit-log";
import { listAuthorizations } from "@/lib/db/repos/authorizations";
import { createTarget } from "@/lib/db/repos/targets";
import {
  attestTarget,
  authorizationForTarget,
  checkDnsVerification,
  revokeAuthorization,
  startDnsVerification,
  unauthorizedHosts,
} from "@/lib/services/authorization";
import { useMemoryDb, WS } from "../db/helpers";

describe("authorization service", () => {
  const db = useMemoryDb();
  const external = () => createTarget(db(), WS, { target: "https://app.example.com/login", kind: "url" });

  it("records an attestation for the target's host and logs it", () => {
    const t = external();
    expect(authorizationForTarget(db(), WS, t).tier).toBe(0);
    const auth = attestTarget(db(), WS, t, "local user", "Pentest contract #42");
    expect(auth).toMatchObject({ tier: 1, method: "attested", scope: "app.example.com" });
    expect(listAudit(db(), WS, { action: "authorization.attested" })[0]).toMatchObject({ subject: "app.example.com" });
  });

  it("verifies DNS ownership only when the published token matches", async () => {
    const t = external();
    await expect(checkDnsVerification(db(), WS, t, "local user", async () => [])).resolves.toMatchObject({ ok: false, reason: /Start DNS verification/ });

    const { domain, value } = startDnsVerification(db(), WS, t, "local user");
    expect(domain).toBe("app.example.com");
    expect(value).toMatch(/^aegis-verify=[0-9a-f]{32}$/);
    expect(startDnsVerification(db(), WS, t, "local user").value).toBe(value);

    const wrong = await checkDnsVerification(db(), WS, t, "local user", async () => [["aegis-verify=nope"]]);
    expect(wrong).toMatchObject({ ok: false, reason: /isn't visible yet/ });
    expect(authorizationForTarget(db(), WS, t).tier).toBe(0);

    let asked = "";
    const right = await checkDnsVerification(db(), WS, t, "local user", async (d) => {
      asked = d;
      return [["v=spf1 -all"], [value]];
    });
    expect(right).toEqual({ ok: true });
    expect(asked).toBe("app.example.com");
    expect(authorizationForTarget(db(), WS, t)).toMatchObject({ tier: 2, method: "dns" });
    expect(listAudit(db(), WS, { action: "authorization.dns_verified" })).toHaveLength(1);
  });

  it("treats a missing TXT record as not yet visible and other DNS errors as retryable", async () => {
    const t = external();
    startDnsVerification(db(), WS, t, "local user");
    const missing = await checkDnsVerification(db(), WS, t, "u", async () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" })));
    expect(missing).toMatchObject({ ok: false, reason: /isn't visible yet/ });
    const timeout = await checkDnsVerification(db(), WS, t, "u", async () => Promise.reject(Object.assign(new Error("x"), { code: "ETIMEOUT" })));
    expect(timeout).toMatchObject({ ok: false, reason: /ETIMEOUT/ });
  });

  it("refuses DNS verification for IP targets", () => {
    const ip = createTarget(db(), WS, { target: "203.0.113.9", kind: "ipv4" });
    expect(() => startDnsVerification(db(), WS, ip, "u")).toThrow(/domain targets/);
  });

  it("revokes and flags hosts nothing authorizes", () => {
    const t = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    attestTarget(db(), WS, t, "local user", null);
    expect(unauthorizedHosts(["shop.example.com:443", "localhost:3100", "evil.test"], WS, db())).toEqual(["evil.test"]);

    const [record] = listAuthorizations(db(), WS);
    expect(revokeAuthorization(db(), WS, record.id, "local user")).toBe(true);
    expect(unauthorizedHosts(["shop.example.com"], WS, db())).toEqual(["shop.example.com"]);
    expect(revokeAuthorization(db(), WS, record.id, "local user")).toBe(false);
  });
});
