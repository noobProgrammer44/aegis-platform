import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // simple-wappalyzer ships a ~3MB ruleset and CJS deps; require it at runtime
  // instead of bundling it into the route.
  // undici is intentionally NOT external: a project-level version (for the proxy
  // dispatcher) differs from Next's internal one, so let Next bundle it.
  serverExternalPackages: ["simple-wappalyzer", "socks"],
};

export default nextConfig;
