import { describe, expect, it } from "vitest";
import { isExposedResponse } from "@/lib/recon/exposed-paths";

const ROOT = "<!doctype html><html><body>app</body></html>";
const res = (status: number, body: string, contentType = "text/plain") => ({ status, body, contentType });

describe("isExposedResponse", () => {
  it("flags a real git config and env file", () => {
    expect(isExposedResponse("/.git/config", res(200, "[core]\n\trepositoryformatversion = 0\n"), ROOT)).toBe(true);
    expect(isExposedResponse("/.env", res(200, "DB_PASSWORD=hunter2\nAPI_KEY=abc\n"), ROOT)).toBe(true);
  });

  it("ignores WAF blocks and errors (Cloudflare 403 page)", () => {
    const blocked = res(403, "<!DOCTYPE html><html>Attention Required! | Cloudflare</html>", "text/html; charset=UTF-8");
    expect(isExposedResponse("/.git/config", blocked, ROOT)).toBe(false);
    expect(isExposedResponse("/admin", blocked, ROOT)).toBe(false);
    expect(isExposedResponse("/.env", res(401, "unauthorized"), ROOT)).toBe(false);
    expect(isExposedResponse("/.env", res(500, "DB=1"), ROOT)).toBe(false);
  });

  it("ignores catch-all pages and look-alike bodies", () => {
    expect(isExposedResponse("/admin", res(200, ROOT, "text/html"), ROOT)).toBe(false);
    expect(isExposedResponse("/.env", res(200, "<html>not found</html>", "text/html"), ROOT)).toBe(false);
    expect(isExposedResponse("/.env", res(200, "Not found"), ROOT)).toBe(false);
    expect(isExposedResponse("/.git/config", res(200, "hello"), ROOT)).toBe(false);
  });

  it("keeps real admin pages and plain-text robots.txt", () => {
    expect(isExposedResponse("/admin", res(200, "<html>Admin login</html>", "text/html"), ROOT)).toBe(true);
    expect(isExposedResponse("/robots.txt", res(200, "User-agent: *\nDisallow: /private"), ROOT)).toBe(true);
  });

  it("ignores pages that look like the site's catch-all (soft 404)", () => {
    const page = (n: number) => res(200, `<html>${"x".repeat(n)}</html>`, "text/html; charset=utf-8");
    const baseline = page(268_270);
    expect(isExposedResponse("/admin", page(268_186), ROOT, baseline)).toBe(false);
    expect(isExposedResponse("/swagger", page(268_210), ROOT, baseline)).toBe(false);
    // A clearly different page is still reported.
    expect(isExposedResponse("/admin", page(12_000), ROOT, baseline)).toBe(true);
    // A site with real 404s doesn't hide anything.
    expect(isExposedResponse("/admin", page(268_186), ROOT, res(404, "nope"))).toBe(true);
  });
});
