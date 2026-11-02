import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required at runtime instead of bundled: simple-wappalyzer ships a ~3MB ruleset and
  // CJS deps; better-sqlite3 is a native addon.
  serverExternalPackages: ["simple-wappalyzer", "better-sqlite3"],
};

export default nextConfig;
