import { describe, expect, it } from "vitest";
import { DEFAULT_WORKSPACE_ID } from "@/lib/db/client";
import { DuplicateError } from "@/lib/db/errors";
import {
  createApiKey,
  findActiveApiKeyByHash,
  listApiKeys,
  revokeApiKey,
  touchApiKey,
} from "@/lib/db/repos/api-keys";
import {
  listDiscoveredDomains,
  markDomainPromoted,
  upsertDiscoveredDomain,
} from "@/lib/db/repos/discovered-domains";
import { listHealthSnapshots, upsertHealthSnapshot } from "@/lib/db/repos/health-snapshots";
import {
  createNotification,
  listNotifications,
  setNotificationStatus,
} from "@/lib/db/repos/notifications";
import { deleteSetting, getSetting, listSettings, setSetting } from "@/lib/db/repos/settings";
import { createTarget, deleteTarget, listTargets } from "@/lib/db/repos/targets";
import {
  createWebhook,
  deleteWebhook,
  listWebhookDeliveries,
  listWebhooksForEvent,
  recordWebhookDelivery,
  updateWebhook,
} from "@/lib/db/repos/webhooks";
import {
  createWorkspace,
  deleteWorkspace,
  getWorkspace,
  listWorkspaces,
  renameWorkspace,
} from "@/lib/db/repos/workspaces";
import { useMemoryDb, WS } from "./helpers";

describe("webhooks repository", () => {
  const db = useMemoryDb();
  const hook = (events: Parameters<typeof createWebhook>[2]["events"]) =>
    createWebhook(db(), WS, { name: "SIEM", kind: "generic", url: "https://hooks.test/x", secret: "s3cret", events });

  it("finds enabled webhooks subscribed to an event", () => {
    const scans = hook(["scan.succeeded", "scan.failed"]);
    const risks = hook(["risk.new_open"]);
    updateWebhook(db(), WS, risks.id, { enabled: false });
    expect(listWebhooksForEvent(db(), WS, "scan.failed").map((w) => w.id)).toEqual([scans.id]);
    expect(listWebhooksForEvent(db(), WS, "risk.new_open")).toEqual([]);
  });

  it("logs deliveries newest first, hidden from other workspaces, removed with the hook", () => {
    const w = hook(["scan.succeeded"]);
    const ok = recordWebhookDelivery(db(), { webhookId: w.id, event: "scan.succeeded", ok: true, statusCode: 200, error: null, at: "2026-11-02T01:00:00.000Z" });
    const failed = recordWebhookDelivery(db(), { webhookId: w.id, event: "scan.succeeded", ok: false, statusCode: null, error: "timeout", at: "2026-11-02T02:00:00.000Z" });

    expect(listWebhookDeliveries(db(), WS, w.id)).toEqual([failed, ok]);
    const other = createWorkspace(db(), "Client B");
    expect(listWebhookDeliveries(db(), other.id, w.id)).toEqual([]);
    expect(deleteWebhook(db(), WS, w.id)).toBe(true);
    expect(listWebhookDeliveries(db(), WS, w.id)).toEqual([]);
  });
});

describe("api keys repository", () => {
  const db = useMemoryDb();

  it("finds active keys by hash only and never returns the hash", () => {
    const key = createApiKey(db(), WS, { name: "CI", prefix: "aeg_ab12", hash: "h1" });
    expect(key).not.toHaveProperty("hash");
    expect(findActiveApiKeyByHash(db(), "h1")).toEqual(key);
    expect(findActiveApiKeyByHash(db(), "nope")).toBeNull();
    expect(listApiKeys(db(), WS)).toEqual([key]);
  });

  it("records last use, revokes once, and rejects a duplicate hash", () => {
    const key = createApiKey(db(), WS, { name: "CI", prefix: "aeg_ab12", hash: "h1" });
    touchApiKey(db(), key.id, "2026-11-02T12:00:00.000Z");
    expect(findActiveApiKeyByHash(db(), "h1")?.lastUsedAt).toBe("2026-11-02T12:00:00.000Z");

    expect(revokeApiKey(db(), WS, key.id, "2026-11-02T13:00:00.000Z")).toBe(true);
    expect(revokeApiKey(db(), WS, key.id)).toBe(false);
    expect(findActiveApiKeyByHash(db(), "h1")).toBeNull();
    expect(listApiKeys(db(), WS)[0].revokedAt).toBe("2026-11-02T13:00:00.000Z");
    expect(() => createApiKey(db(), WS, { name: "again", prefix: "p", hash: "h1" })).toThrow(DuplicateError);
  });
});

describe("settings repository", () => {
  const db = useMemoryDb();

  it("returns the fallback, stores JSON values and keeps workspaces apart", () => {
    expect(getSetting(db(), WS, "health.threshold", 600)).toBe(600);
    setSetting(db(), WS, "health.threshold", 400);
    setSetting(db(), WS, "branding", { company: "Acme", accent: "#06b6d4" });
    setSetting(db(), WS, "health.threshold", 450);

    expect(getSetting(db(), WS, "health.threshold", 600)).toBe(450);
    expect(listSettings(db(), WS)).toEqual({
      branding: { company: "Acme", accent: "#06b6d4" },
      "health.threshold": 450,
    });
    const other = createWorkspace(db(), "Client B");
    expect(getSetting(db(), other.id, "health.threshold", 600)).toBe(600);
    expect(deleteSetting(db(), WS, "branding")).toBe(true);
    expect(Object.keys(listSettings(db(), WS))).toEqual(["health.threshold"]);
  });
});

describe("notifications repository", () => {
  const db = useMemoryDb();

  it("holds unsent mail in the outbox and updates its status", () => {
    const n = createNotification(db(), WS, { to: ["sec@example.com"], subject: "Scan done", body: "2 new risks", status: "outbox" });
    expect(n).toMatchObject({ channel: "email", error: null, to: ["sec@example.com"] });
    expect(listNotifications(db(), WS, { status: "outbox" })).toEqual([n]);

    const sent = setNotificationStatus(db(), WS, n.id, "sent");
    expect(sent?.status).toBe("sent");
    expect(listNotifications(db(), WS, { status: "outbox" })).toEqual([]);
    expect(listNotifications(db(), WS)).toEqual([sent]);
  });
});

describe("discovered domains repository", () => {
  const db = useMemoryDb();

  it("keeps id, first sighting and origin when a domain is seen again", () => {
    const root = createTarget(db(), WS, { target: "example.com", kind: "domain" });
    const first = upsertDiscoveredDomain(db(), WS, { name: "vpn.example.com", viaTargetId: root.id, viaTarget: "example.com", resolves: false, records: {} }, "2026-11-01T00:00:00.000Z");
    const again = upsertDiscoveredDomain(db(), WS, { name: "vpn.example.com", viaTargetId: null, viaTarget: null, resolves: true, records: { A: ["203.0.113.7"] } }, "2026-11-02T00:00:00.000Z");

    expect(again).toMatchObject({
      id: first.id,
      firstSeen: "2026-11-01T00:00:00.000Z",
      lastSeen: "2026-11-02T00:00:00.000Z",
      viaTargetId: root.id,
      viaTarget: "example.com",
      resolves: true,
      records: { A: ["203.0.113.7"] },
    });
    expect(listDiscoveredDomains(db(), WS)).toHaveLength(1);
  });

  it("tracks promotion and survives the promoted target being deleted", () => {
    const d = upsertDiscoveredDomain(db(), WS, { name: "api.example.com", viaTargetId: null, viaTarget: null, resolves: true, records: {} });
    const target = createTarget(db(), WS, { target: "api.example.com", kind: "domain", source: "discovered" });
    expect(markDomainPromoted(db(), WS, d.id, target.id)?.promotedTargetId).toBe(target.id);
    expect(listDiscoveredDomains(db(), WS, { unpromotedOnly: true })).toEqual([]);

    deleteTarget(db(), WS, target.id);
    expect(listDiscoveredDomains(db(), WS, { unpromotedOnly: true }).map((x) => x.id)).toEqual([d.id]);
  });
});

describe("health snapshots repository", () => {
  const db = useMemoryDb();
  const snapshot = (day: string, score: number, targetId: string | null = null) => ({
    workspaceId: WS,
    targetId,
    day,
    score,
    grade: "C" as const,
    counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 },
    assets: 4,
  });

  it("keeps one snapshot per day and separates workspace and target series", () => {
    upsertHealthSnapshot(db(), snapshot("2026-11-01", 300));
    upsertHealthSnapshot(db(), snapshot("2026-11-02", 500));
    upsertHealthSnapshot(db(), snapshot("2026-11-02", 450));
    upsertHealthSnapshot(db(), snapshot("2026-11-02", 900, "tgt_1"));

    expect(listHealthSnapshots(db(), WS, { targetId: null }).map((s) => [s.day, s.score])).toEqual([
      ["2026-11-01", 300],
      ["2026-11-02", 450],
    ]);
    expect(listHealthSnapshots(db(), WS, { targetId: "tgt_1" })).toEqual([snapshot("2026-11-02", 900, "tgt_1")]);
    expect(listHealthSnapshots(db(), WS, { targetId: null, sinceDay: "2026-11-02" })).toHaveLength(1);
    expect(listHealthSnapshots(db(), WS, { targetId: null, untilDay: "2026-11-01" })).toHaveLength(1);
  });
});

describe("workspaces repository", () => {
  const db = useMemoryDb();

  it("creates, renames and deletes a workspace with everything in it", () => {
    const ws = createWorkspace(db(), "Client B");
    createTarget(db(), ws.id, { target: "b.test", kind: "domain" });
    expect(listWorkspaces(db()).map((w) => w.id)).toEqual([DEFAULT_WORKSPACE_ID, ws.id]);
    expect(renameWorkspace(db(), ws.id, "Client B (prod)")?.name).toBe("Client B (prod)");
    expect(renameWorkspace(db(), "missing", "x")).toBeNull();

    expect(deleteWorkspace(db(), ws.id)).toBe(true);
    expect(getWorkspace(db(), ws.id)).toBeNull();
    expect(listTargets(db(), ws.id)).toEqual([]);
  });

  it("refuses to delete the default workspace", () => {
    expect(() => deleteWorkspace(db(), DEFAULT_WORKSPACE_ID)).toThrow(/default workspace/);
    expect(getWorkspace(db(), DEFAULT_WORKSPACE_ID)).not.toBeNull();
  });
});
