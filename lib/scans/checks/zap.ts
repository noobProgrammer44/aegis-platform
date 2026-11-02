import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "@/types/recon";
import { dockerAvailable, dockerImagePresent, forDocker, runCommand } from "../tools";

/**
 * OWASP ZAP in Docker. "baseline" spiders the site and applies ZAP's passive rules;
 * "full" adds the active scan (it sends attack payloads, so it only runs on authorized
 * targets and can take a long time). ZAP's JSON report is parsed into findings.
 */

export const ZAP_IMAGE = "zaproxy/zap-stable";
export type ZapMode = "baseline" | "full";

const SCRIPT: Record<ZapMode, string> = { baseline: "zap-baseline.py", full: "zap-full-scan.py" };
const MINUTES: Record<ZapMode, number> = { baseline: 5, full: 20 };

interface ZapAlert {
  name?: string;
  alert?: string;
  riskcode?: string;
  desc?: string;
  solution?: string;
  reference?: string;
  cweid?: string;
  count?: string;
  instances?: { uri?: string }[];
}

const RISK: Record<string, Finding["severity"] | null> = { "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": null };

const stripHtml = (html = "") => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

/** ZAP JSON report (-J) -> findings, skipping informational alerts. Pure. */
export function parseZapReport(report: unknown, displayHost: string): Finding[] {
  const sites = ((report as { site?: unknown })?.site ?? []) as { alerts?: ZapAlert[] }[];
  if (!Array.isArray(sites)) return [];
  return sites.flatMap((site) =>
    (site.alerts ?? []).flatMap((alert): Finding[] => {
      const severity = RISK[alert.riskcode ?? "0"];
      if (!severity) return [];
      const uris = [...new Set((alert.instances ?? []).map((i) => i.uri).filter(Boolean))];
      const refs = stripHtml(alert.reference).split(" ").filter((r) => r.startsWith("http")).slice(0, 3);
      return [
        {
          host: displayHost,
          title: alert.name ?? alert.alert ?? "ZAP alert",
          severity,
          description:
            stripHtml(alert.desc) +
            (uris.length > 0 ? ` Seen at ${uris.slice(0, 3).join(", ")}${uris.length > 3 ? ` and ${uris.length - 3} more` : ""}.` : "") +
            (alert.cweid && alert.cweid !== "-1" ? ` CWE-${alert.cweid}.` : ""),
          recommendation: stripHtml(alert.solution) + (refs.length > 0 ? ` See ${refs.join(", ")}` : ""),
          category: "zap",
        },
      ];
    }),
  );
}

export type ZapRun =
  | { status: "ok"; findings: Finding[]; report: unknown }
  | { status: "unavailable" | "error"; message: string };

export async function runZap(url: string, mode: ZapMode, signal: AbortSignal): Promise<ZapRun> {
  if (!(await dockerAvailable())) return { status: "unavailable", message: "Docker isn't running, so ZAP can't start." };
  if (!(await dockerImagePresent(ZAP_IMAGE))) {
    return { status: "unavailable", message: `The ${ZAP_IMAGE} image isn't installed. Run: docker pull ${ZAP_IMAGE}` };
  }
  // Inside the project (data/ is gitignored): Docker Desktop shares /Users and C:\Users by
  // default but not the OS temp folder, which would mount as an empty root-owned dir.
  const root = path.join(process.cwd(), "data", "zap-runs");
  await mkdir(root, { recursive: true });
  const workdir = await mkdtemp(path.join(root, "run-"));
  // ZAP runs as a non-root user inside the container and writes its report here.
  await chmod(workdir, 0o777);
  const name = `aegis-zap-${randomBytes(4).toString("hex")}`;
  try {
    const result = await runCommand(
      "docker",
      [
        "run", "--rm", "--name", name,
        "--add-host", "host.docker.internal:host-gateway",
        "-v", `${workdir}:/zap/wrk:rw`,
        ZAP_IMAGE, SCRIPT[mode],
        "-t", forDocker(url),
        "-J", "report.json",
        "-I",
        "-m", "1",
        "-T", String(MINUTES[mode]),
      ],
      {
        timeoutMs: (MINUTES[mode] + 3) * 60_000,
        signal,
        onAbort: () => void runCommand("docker", ["rm", "-f", name], { timeoutMs: 15_000 }),
      },
    );
    if (signal.aborted) return { status: "error", message: "Stopped." };
    let report: unknown;
    try {
      report = JSON.parse(await readFile(path.join(workdir, "report.json"), "utf8"));
    } catch {
      const tail = (result.stderr || result.stdout).trim().split("\n").slice(-3).join(" ");
      return { status: "error", message: `ZAP produced no report${tail ? `: ${tail}` : "."}` };
    }
    return { status: "ok", findings: parseZapReport(report, new URL(url).host), report };
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }
}
