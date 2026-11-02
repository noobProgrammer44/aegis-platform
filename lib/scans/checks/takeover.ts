import { promises as dns } from "node:dns";
import type { Finding } from "@/types/recon";

/**
 * Subdomain takeover (passive, DNS only). A host whose CNAME points at a hosted
 * service (S3, GitHub Pages, Heroku, Azure, ...) whose name no longer exists can be
 * claimed by anyone on that service, who then serves content on the host.
 */

const SERVICES: readonly [suffix: string, service: string][] = [
  ["s3.amazonaws.com", "AWS S3"],
  ["s3-website", "AWS S3 website"],
  ["elasticbeanstalk.com", "AWS Elastic Beanstalk"],
  ["cloudfront.net", "AWS CloudFront"],
  ["github.io", "GitHub Pages"],
  ["herokuapp.com", "Heroku"],
  ["herokudns.com", "Heroku"],
  ["azurewebsites.net", "Azure App Service"],
  ["cloudapp.net", "Azure Cloud Services"],
  ["cloudapp.azure.com", "Azure"],
  ["trafficmanager.net", "Azure Traffic Manager"],
  ["blob.core.windows.net", "Azure Blob Storage"],
  ["azureedge.net", "Azure CDN"],
  ["netlify.app", "Netlify"],
  ["netlify.com", "Netlify"],
  ["vercel.app", "Vercel"],
  ["now.sh", "Vercel"],
  ["pantheonsite.io", "Pantheon"],
  ["ghost.io", "Ghost"],
  ["myshopify.com", "Shopify"],
  ["surge.sh", "Surge"],
  ["bitbucket.io", "Bitbucket"],
  ["zendesk.com", "Zendesk"],
  ["readme.io", "ReadMe"],
  ["wpengine.com", "WP Engine"],
  ["fly.dev", "Fly.io"],
];

export function hostedService(cname: string): string | null {
  const name = cname.toLowerCase().replace(/\.$/, "");
  const match = SERVICES.find(([suffix]) =>
    suffix.includes(".") ? name === suffix || name.endsWith(`.${suffix}`) : name.includes(suffix),
  );
  return match ? match[1] : null;
}

export interface CnameCheck {
  host: string;
  cname: string | null;
  /** False when the CNAME's target name does not exist (NXDOMAIN). */
  targetExists: boolean;
}

export interface CnameLookup {
  resolveCname(host: string): Promise<string[]>;
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
}

const code = (err: unknown) => (err as { code?: string }).code ?? "";

/** A host's CNAME, and whether that name still exists in DNS. */
export async function checkCname(host: string, lookup: CnameLookup = dns): Promise<CnameCheck> {
  let cname: string | null = null;
  try {
    cname = (await lookup.resolveCname(host))[0] ?? null;
  } catch {
    return { host, cname: null, targetExists: true };
  }
  if (!cname) return { host, cname: null, targetExists: true };
  const exists = async (resolve: (h: string) => Promise<string[]>) => {
    try {
      await resolve(cname as string);
      return true;
    } catch (err) {
      return code(err) !== "ENOTFOUND";
    }
  };
  const [v4, v6] = await Promise.all([exists((h) => lookup.resolve4(h)), exists((h) => lookup.resolve6(h))]);
  return { host, cname, targetExists: v4 || v6 };
}

/** Finding for one host's CNAME check, or null when it's fine. Pure. */
export function evaluateTakeover(check: CnameCheck): Finding | null {
  if (!check.cname || check.targetExists) return null;
  const service = hostedService(check.cname);
  if (service) {
    return {
      host: check.host,
      title: `Possible subdomain takeover via ${service}`,
      severity: "HIGH",
      description: `${check.host} is a CNAME for ${check.cname}, which no longer exists. Anyone who creates that name on ${service} can serve content, set cookies or phish on ${check.host}.`,
      recommendation: `Delete the CNAME for ${check.host}, or reclaim ${check.cname} on ${service}.`,
      category: "takeover",
    };
  }
  return {
    host: check.host,
    title: "Dangling CNAME record",
    severity: "MEDIUM",
    description: `${check.host} is a CNAME for ${check.cname}, which doesn't resolve. If that domain lapses, whoever registers it controls ${check.host}.`,
    recommendation: `Delete or fix the CNAME for ${check.host}.`,
    category: "takeover",
  };
}
