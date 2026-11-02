import { describe, expect, it } from "vitest";
import { CLOUDFLARE_PROXY_PORTS, isCloudflareResponse } from "@/lib/recon/cdn-edge";

describe("isCloudflareResponse", () => {
  it("spots Cloudflare by cf-ray or the server header, any case", () => {
    expect(isCloudflareResponse({ "CF-RAY": "a545c8709df6c87d-BOM" })).toBe(true);
    expect(isCloudflareResponse({ server: "cloudflare" })).toBe(true);
    expect(isCloudflareResponse({ server: "nginx", "x-cache": "HIT" })).toBe(false);
  });

  it("covers Cloudflare's proxied ports but not databases", () => {
    expect([2082, 2083, 8443, 8880].every((p) => CLOUDFLARE_PROXY_PORTS.has(p))).toBe(true);
    expect(CLOUDFLARE_PROXY_PORTS.has(3306)).toBe(false);
  });
});
