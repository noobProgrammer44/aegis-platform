import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required at runtime instead of bundled: simple-wappalyzer ships a ~3MB ruleset and
  // CJS deps; better-sqlite3 is a native addon; socks is used by the optional proxy.
  // undici is intentionally NOT external: a project-level version (for the proxy
  // dispatcher) differs from Next's internal one, so let Next bundle it.
  serverExternalPackages: ["simple-wappalyzer", "better-sqlite3", "socks"],
  // Keep the dev-only Next.js badge off the sidebar's bottom controls.
  devIndicators: { position: "bottom-right" },
};

export default nextConfig;
