import { spawn } from "node:child_process";
import readline from "node:readline";
import type { Finding, LiveHost, Severity } from "@/types/recon";

/**
 * Stage 4b — Deep vulnerability detection with nuclei (ACTIVE, streaming).
 *
 * Shells out to the nuclei Docker image. nuclei runs INSIDE the container, so it
 * can't reach the host's localhost — local targets are rewritten to
 * host.docker.internal before scanning, then mapped back for reporting. A named
 * volume persists the template set so it only downloads on the first ever run.
 *
 * Findings are streamed to the caller as nuclei discovers them (one JSONL line
 * per finding), rather than buffered, so the UI can show results live and a slow
 * scan never fails all-or-nothing. Gated behind `activeAllowed` at the route.
 * Any Docker/nuclei failure degrades gracefully via the returned status.
 */

const NUCLEI_IMAGE = "projectdiscovery/nuclei:latest";
const NUCLEI_VOLUME = "aegis-nuclei"; // persists templates across runs
const NUCLEI_TIMEOUT_MS = 600_000; // safety ceiling; partial findings are kept

const LOCAL_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "[::1]",
]);

interface NucleiLine {
  "template-id"?: string;
  "matched-at"?: string;
  host?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    remediation?: string;
    reference?: string[];
    classification?: { "cve-id"?: string[] | null };
  };
}

type StreamStatus = {
  status: "ok" | "partial" | "unavailable" | "error";
  message?: string;
};

export async function runNucleiStream(
  hosts: LiveHost[],
  callbacks: {
    onFinding: (finding: Finding) => void;
    onProgress: (message: string) => void;
  },
  options: { signal?: AbortSignal } = {},
): Promise<StreamStatus> {
  if (hosts.length === 0) return { status: "ok" };

  // Rewrite localhost targets for the container; keep a reverse map for reporting.
  const targets: string[] = [];
  const rewrittenToOriginal = new Map<string, string>();
  let allLocal = true;
  for (const host of hosts) {
    const { url, local } = rewriteForDocker(host.url);
    if (!local) allLocal = false;
    targets.push(url);
    try {
      rewrittenToOriginal.set(new URL(url).host, host.url);
    } catch {
      /* ignore unparseable */
    }
  }

  // Local single-instance targets (e.g. Juice Shop) crash under default nuclei
  // aggression, so scan them gently. Remote hosts tolerate more, but a managed
  // host/WAF will wall us off if we flood it — so stay moderate there too.
  const rateLimit = allLocal ? "40" : "60";
  const concurrency = allLocal ? "15" : "20";

  const args = [
    "run",
    "--rm",
    "-v",
    `${NUCLEI_VOLUME}:/root`,
    NUCLEI_IMAGE,
    "-u",
    targets.join(","),
    "-jsonl",
    "-severity",
    "low,medium,high,critical",
    "-rate-limit",
    rateLimit,
    "-concurrency",
    concurrency,
    "-timeout",
    "10",
    "-max-host-error",
    "100",
    "-stats",
    "-stats-interval",
    "5",
  ];

  const fallbackHost = hosts[0].url;

  return new Promise<StreamStatus>((resolve) => {
    let spawnError: NodeJS.ErrnoException | null = null;
    let timedOut = false;
    let hostSkipped = false;
    let lastProgress = "";

    const child = spawn("docker", args, { windowsHide: true });

    // Findings stream as JSONL on stdout, one per line.
    readline.createInterface({ input: child.stdout }).on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed.startsWith("{")) return;
      try {
        const obj = JSON.parse(trimmed) as NucleiLine;
        // Ignore any non-finding JSON (e.g. a stats object) that reaches stdout.
        if (!obj["template-id"] && !obj.info) return;
        callbacks.onFinding(toFinding(obj, rewrittenToOriginal, fallbackHost));
      } catch {
        /* skip malformed line */
      }
    });

    // Progress stats arrive on stderr; note if the target throttled us off.
    readline.createInterface({ input: child.stderr }).on("line", (line) => {
      if (/found unresponsive|Skipped .+ from target list/i.test(line)) {
        hostSkipped = true;
      }
      const message = parseProgress(line);
      // Collapse consecutive identical messages (e.g. repeated "host skipped").
      if (message && message !== lastProgress) {
        lastProgress = message;
        callbacks.onProgress(message);
      }
    });

    child.on("error", (err: NodeJS.ErrnoException) => {
      spawnError = err;
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, NUCLEI_TIMEOUT_MS);

    const onAbort = () => child.kill("SIGKILL");
    options.signal?.addEventListener("abort", onAbort);

    child.on("close", () => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);

      if (spawnError) {
        const reason =
          spawnError.code === "ENOENT"
            ? "the Docker CLI was not found on PATH"
            : spawnError.message;
        console.error("[nuclei] unavailable:", reason);
        resolve({
          status: "unavailable",
          message: `nuclei skipped — ${reason}. Showing header/path findings only.`,
        });
      } else if (timedOut) {
        resolve({
          status: "error",
          message:
            "nuclei hit the time limit. Partial results are shown — re-run or narrow the target.",
        });
      } else if (hostSkipped) {
        resolve({
          status: "partial",
          message:
            "Deep scan was cut short — the target throttled or blocked nuclei (common for a WAF, CDN, or managed host). Header, path, and TLS findings are unaffected.",
        });
      } else {
        resolve({ status: "ok" });
      }
    });
  });
}

/** Swap a localhost-family host for host.docker.internal so the container reaches it. */
function rewriteForDocker(rawUrl: string): { url: string; local: boolean } {
  try {
    const u = new URL(rawUrl);
    if (LOCAL_HOSTNAMES.has(u.hostname)) {
      u.hostname = "host.docker.internal";
      return { url: u.toString(), local: true };
    }
    return { url: u.toString(), local: false };
  } catch {
    return { url: rawUrl, local: false };
  }
}

/** Extract a concise progress message from a nuclei stderr line. */
function parseProgress(raw: string): string | null {
  const line = raw.replace(/\x1b\[[0-9;]*m/g, "").trim();
  if (!line) return null;

  // With -stats + -jsonl, nuclei emits progress as JSON objects on stderr.
  if (line.startsWith("{")) {
    try {
      const stats = JSON.parse(line) as {
        percent?: string;
        requests?: string;
        total?: string;
        rps?: string;
        matched?: string;
      };
      if (stats.percent !== undefined && stats.requests !== undefined) {
        const matched =
          stats.matched && stats.matched !== "0" ? ` · ${stats.matched} matched` : "";
        return `Scanning — ${stats.percent}% · ${stats.requests}/${stats.total ?? "?"} requests · ${stats.rps ?? "?"}/s${matched}`;
      }
    } catch {
      /* not a stats line */
    }
    return null;
  }

  const loaded = line.match(/Templates loaded for current scan:\s*(\d+)/i);
  if (loaded) return `Loaded ${loaded[1]} templates`;
  if (/nuclei-templates are not installed/i.test(line)) {
    return "Downloading nuclei templates (first run)…";
  }
  if (/Scan completed/i.test(line)) return "Scan completed";
  if (/unresponsive/i.test(line)) return "A host stopped responding and was skipped";
  return null;
}

function toFinding(
  line: NucleiLine,
  rewrittenToOriginal: Map<string, string>,
  fallbackHost: string,
): Finding {
  const info = line.info ?? {};
  const templateId = line["template-id"] ?? "unknown-template";
  const name = info.name ?? templateId;
  const matchedAt = line["matched-at"] ?? line.host ?? "";
  const cves = info.classification?.["cve-id"] ?? [];

  const descParts = [`nuclei template: ${templateId}`];
  if (info.description) descParts.push(info.description.trim());
  if (matchedAt) descParts.push(`Matched at ${matchedAt}`);

  const recommendation = info.remediation
    ? info.remediation.trim()
    : info.reference?.length
      ? `Review guidance: ${info.reference[0]}`
      : "Review the nuclei template and remediate the reported issue.";

  return {
    host: resolveHost(matchedAt, rewrittenToOriginal, fallbackHost),
    title: cves && cves.length ? `${name} (${cves.join(", ")})` : name,
    severity: mapSeverity(info.severity),
    description: descParts.join(" — "),
    recommendation,
  };
}

/** Map a nuclei-reported host back to the original (pre-rewrite) target URL. */
function resolveHost(
  reported: string,
  rewrittenToOriginal: Map<string, string>,
  fallbackHost: string,
): string {
  if (!reported) return fallbackHost;
  try {
    const hostPort = new URL(
      reported.includes("://") ? reported : `http://${reported}`,
    ).host;
    const original = rewrittenToOriginal.get(hostPort);
    if (original) return original;
  } catch {
    /* fall through */
  }
  return reported.replace("host.docker.internal", "localhost");
}

function mapSeverity(severity: string | undefined): Severity {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    case "low":
      return "LOW";
    default:
      return "INFO";
  }
}
