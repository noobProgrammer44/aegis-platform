import { spawn } from "node:child_process";

/**
 * External tools (Docker, images). Commands always run as an argument list with no
 * shell, so nothing from a target can be interpreted as shell syntax.
 */

export interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

const MAX_OUTPUT = 2_000_000;

export function runCommand(
  command: string,
  args: readonly string[],
  options: { timeoutMs: number; signal?: AbortSignal; onAbort?: () => void },
): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, [...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const append = (current: string, chunk: Buffer) => (current.length < MAX_OUTPUT ? current + chunk.toString() : current);
    child.stdout.on("data", (chunk: Buffer) => (stdout = append(stdout, chunk)));
    child.stderr.on("data", (chunk: Buffer) => (stderr = append(stderr, chunk)));
    const stop = () => {
      options.onAbort?.();
      child.kill("SIGTERM");
    };
    const timer = setTimeout(stop, options.timeoutMs);
    options.signal?.addEventListener("abort", stop, { once: true });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ code: null, stdout, stderr: stderr || err.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", stop);
      resolve({ code, stdout, stderr });
    });
  });
}

const CACHE_MS = 30_000;
const cache = new Map<string, { at: number; value: boolean }>();

async function cached(key: string, check: () => Promise<boolean>): Promise<boolean> {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.value;
  const value = await check();
  cache.set(key, { at: Date.now(), value });
  return value;
}

export function dockerAvailable(): Promise<boolean> {
  return cached("docker", async () => (await runCommand("docker", ["version", "--format", "{{.Server.Version}}"], { timeoutMs: 5_000 })).code === 0);
}

export function dockerImagePresent(image: string): Promise<boolean> {
  return cached(`image:${image}`, async () => (await runCommand("docker", ["image", "inspect", image], { timeoutMs: 5_000 })).code === 0);
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"]);

/** Containers can't reach the host's localhost; point them at host.docker.internal instead. */
export function forDocker(url: string): string {
  try {
    const parsed = new URL(url);
    if (!LOCAL_HOSTS.has(parsed.hostname) && !parsed.hostname.endsWith(".localhost")) return url;
    parsed.hostname = "host.docker.internal";
    return parsed.toString();
  } catch {
    return url;
  }
}
