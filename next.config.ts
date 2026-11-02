import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // simple-wappalyzer ships a ~3MB ruleset and CJS deps; require it at runtime
  // instead of bundling it into the route.
  serverExternalPackages: ["simple-wappalyzer"],
};

export default nextConfig;
