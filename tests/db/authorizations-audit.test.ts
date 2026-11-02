import { describe, expect, it } from "vitest";
import { appendAudit, listAudit } from "@/lib/db/repos/audit-log";
import {
  deleteAuthorization,
  getAuthorization,
  getAuthorizationById,
  listAuthorizations,
  listVerifiedAuthorizations,
  markAuthorizationVerified,
  saveAuthorization,
} from "@/lib/db/repos/authorizations";
import { createWorkspace } from "@/lib/db/repos/workspaces";
import { useMemoryDb, WS } from "./helpers";

describe("authorizations repository", () => {
  const db = useMemoryDb();

  it("creates one record per scope and method", () => {
    const attested = saveAuthorization(db(), WS, {
      scope: "example.com",
      method: "attested",
      verified: true,
      attestedBy: "local user",
      verifiedAt: "2026-11-02T10:00:00.000Z",
    });
    const dns = saveAuthorization(db(), WS, {
      scope: "example.com",
      method: "dns",
      token: "tok-1",
      verified: false,
    });
    expect(attested.id).not.toBe(dns.id);
    expect(getAuthorization(db(), WS, "example.com", "attested")).toEqual(attested);
    expect(getAuthorization(db(), WS, "example.com", "dns")).toEqual(dns);
    expect(listAuthorizations(db(), WS)).toHaveLength(2);
  });

  it("replaces fields on re-save but keeps the id and creation time", () => {
    const first = saveAuthorization(db(), WS, {
      scope: "example.com",
      method: "dns",
      token: "tok-1",
      verified: false,
    });
    const second = saveAuthorization(db(), WS, {
      scope: "example.com",
      method: "dns",
      token: "tok-2",
      verified: false,
    });
    expect(second).toMatchObject({ id: first.id, createdAt: first.createdAt, token: "tok-2" });
    expect(getAuthorizationById(db(), WS, first.id)).toEqual(second);
    expect(listAuthorizations(db(), WS)).toHaveLength(1);
  });

  it("marks a DNS record verified and lists only verified records", () => {
    const pending = saveAuthorization(db(), WS, {
      scope: "example.com",
      method: "dns",
      token: "tok",
      verified: false,
    });
    expect(listVerifiedAuthorizations(db(), WS)).toEqual([]);
    const verified = markAuthorizationVerified(db(), WS, pending.id, "2026-11-02T11:00:00.000Z");
    expect(verified).toMatchObject({ verified: true, verifiedAt: "2026-11-02T11:00:00.000Z" });
    expect(listVerifiedAuthorizations(db(), WS)).toEqual([verified]);
  });

  it("keeps records isolated per workspace", () => {
    const record = saveAuthorization(db(), WS, { scope: "example.com", method: "attested", verified: true });
    const other = createWorkspace(db(), "Client B");
    expect(getAuthorization(db(), other.id, "example.com", "attested")).toBeNull();
    expect(markAuthorizationVerified(db(), other.id, record.id)).toBeNull();
    expect(deleteAuthorization(db(), other.id, record.id)).toBe(false);
    expect(deleteAuthorization(db(), WS, record.id)).toBe(true);
    expect(listAuthorizations(db(), WS)).toEqual([]);
  });
});

describe("audit log repository", () => {
  const db = useMemoryDb();

  it("appends entries and lists them newest first", () => {
    const first = appendAudit(db(), WS, {
      actor: "local user",
      action: "authorization.attested",
      subject: "example.com",
      details: { tier: 1 },
      at: "2026-11-02T10:00:00.000Z",
    });
    const second = appendAudit(db(), WS, {
      actor: "scheduler",
      action: "scan.started",
      subject: "example.com",
      at: "2026-11-02T10:05:00.000Z",
    });
    expect(second.details).toEqual({});
    expect(listAudit(db(), WS)).toEqual([second, first]);
  });

  it("keeps insertion order for entries with the same timestamp", () => {
    const at = "2026-11-02T10:00:00.000Z";
    const a = appendAudit(db(), WS, { actor: "u", action: "a", subject: "s", at });
    const b = appendAudit(db(), WS, { actor: "u", action: "b", subject: "s", at });
    expect(listAudit(db(), WS).map((e) => e.id)).toEqual([b.id, a.id]);
  });

  it("filters by subject and action and pages with limit and offset", () => {
    appendAudit(db(), WS, { actor: "u", action: "scan.started", subject: "a.test", at: "2026-11-02T01:00:00.000Z" });
    const b = appendAudit(db(), WS, { actor: "u", action: "scan.started", subject: "b.test", at: "2026-11-02T02:00:00.000Z" });
    const c = appendAudit(db(), WS, { actor: "u", action: "scan.blocked", subject: "b.test", at: "2026-11-02T03:00:00.000Z" });

    expect(listAudit(db(), WS, { subject: "b.test" }).map((e) => e.id)).toEqual([c.id, b.id]);
    expect(listAudit(db(), WS, { action: "scan.blocked" }).map((e) => e.id)).toEqual([c.id]);
    expect(listAudit(db(), WS, { limit: 1, offset: 1 }).map((e) => e.id)).toEqual([b.id]);

    const other = createWorkspace(db(), "Client B");
    expect(listAudit(db(), other.id)).toEqual([]);
  });
});
