import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required at runtime instead of bundled: simple-wappalyzer ships a ~3MB ruleset and
  // CJS deps; better-sqlite3 is a native addon.
  serverExternalPackages: ["simple-wappalyzer", "better-sqlite3"],
  // Keep the dev-only Next.js badge off the sidebar's bottom controls.
  devIndicators: { position: "bottom-right" },
};

export default nextConfig;
