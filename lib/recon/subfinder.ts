import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { runCommand } from "@/lib/scans/tools";

/**
 * ProjectDiscovery subfinder (passive OSINT: dozens of sources) as a second
 * subdomain source next to crt.sh, so discovery still works when crt.sh is down.
 * Uses a local binary if installed (go install ... or Homebrew); otherwise it's
 * simply skipped. Passive: it never contacts the target.
 */

const TIMEOUT_MS = 90_000;

async function executable(file: string): Promise<boolean> {
  try {
    await access(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Prefer ~/go/bin (go install), then Homebrew and PATH. */
export async function findSubfinder(): Promise<string | null> {
  const name = process.platform === "win32" ? "subfinder.exe" : "subfinder";
  const dirs = [
    path.join(homedir(), "go", "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
    ...(process.env.PATH ?? "").split(path.delimiter),
  ];
  for (const dir of dirs.filter(Boolean)) {
    const file = path.join(dir, name);
    if (await executable(file)) return file;
  }
  return null;
}

/** In-scope names from subfinder's output (one per line), lowercased and deduped. */
export function parseSubfinderOutput(stdout: string, domain: string): string[] {
  const apex = domain.toLowerCase();
  const names = stdout
    .split(/\r?\n/)
    .map((line) => line.trim().toLowerCase().replace(/\.$/, ""))
    .filter((name) => /^[a-z0-9.-]+$/.test(name) && (name === apex || name.endsWith(`.${apex}`)));
  return [...new Set(names)].sort();
}

export type SubfinderResult = { status: "ok"; names: string[] } | { status: "unavailable" | "error"; message: string };

export async function runSubfinder(domain: string): Promise<SubfinderResult> {
  const binary = await findSubfinder();
  if (!binary) return { status: "unavailable", message: "subfinder isn't installed." };
  const result = await runCommand(binary, ["-d", domain, "-silent", "-all", "-timeout", "20", "-max-time", "1"], { timeoutMs: TIMEOUT_MS });
  if (result.code !== 0 && !result.stdout.trim()) {
    return { status: "error", message: result.stderr.trim().split("\n").slice(-1)[0] || "subfinder failed." };
  }
  return { status: "ok", names: parseSubfinderOutput(result.stdout, domain) };
}
