import { dockerAvailable, runCommand } from "@/lib/scans/tools";

/**
 * nuclei only finds things if its template library is present in the persistent
 * `aegis-nuclei` volume. Scans run with -disable-update-check, so on a fresh machine
 * the library is empty and every scan "completes" with 0 requests. This downloads it
 * once, before the first scan, and remembers that it's there.
 */

const IMAGE = "projectdiscovery/nuclei:latest";
const VOLUME = "aegis-nuclei";
const DOWNLOAD_TIMEOUT_MS = 10 * 60_000;

const globalForTemplates = globalThis as unknown as { __aegisNucleiTemplates?: Promise<TemplatesResult> };

export type TemplatesResult = { ok: true; downloaded: boolean } | { ok: false; message: string };

async function templatesPresent(): Promise<boolean> {
  const check = await runCommand(
    "docker",
    ["run", "--rm", "-v", `${VOLUME}:/root`, "--entrypoint", "sh", IMAGE, "-c", "test -d /root/nuclei-templates/http"],
    { timeoutMs: 60_000 },
  );
  return check.code === 0;
}

async function ensure(onProgress: (message: string) => void): Promise<TemplatesResult> {
  if (!(await dockerAvailable())) return { ok: false, message: "Docker isn't running, so nuclei can't start." };
  if (await templatesPresent()) return { ok: true, downloaded: false };
  onProgress("Downloading nuclei templates (first run only, about a minute)");
  const update = await runCommand("docker", ["run", "--rm", "-v", `${VOLUME}:/root`, IMAGE, "-update-templates", "-silent"], {
    timeoutMs: DOWNLOAD_TIMEOUT_MS,
  });
  if (await templatesPresent()) return { ok: true, downloaded: true };
  const detail = (update.stderr || update.stdout).trim().split("\n").slice(-2).join(" ");
  return { ok: false, message: `Couldn't download nuclei templates${detail ? `: ${detail}` : ""}.` };
}

/** Makes sure templates exist; concurrent scans share one download. */
export function ensureNucleiTemplates(onProgress: (message: string) => void): Promise<TemplatesResult> {
  const pending = globalForTemplates.__aegisNucleiTemplates;
  if (pending) return pending;
  const run = ensure(onProgress).then((result) => {
    // Only cache success; a failed download is retried by the next scan.
    if (!result.ok) globalForTemplates.__aegisNucleiTemplates = undefined;
    return result;
  });
  globalForTemplates.__aegisNucleiTemplates = run;
  return run;
}
