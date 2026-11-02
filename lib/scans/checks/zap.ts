import { randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import type { RiskInstance } from "@/lib/domain/evidence";
import { owaspFromZapTag, type OwaspCategory } from "@/lib/domain/owasp";
import type { Finding } from "@/types/recon";
import { dockerAvailable, dockerImagePresent, forDocker, runCommand } from "../tools";

/**
 * OWASP ZAP in Docker, driven by ZAP's Automation Framework so the report can use the
 * "traditional-json-plus" template: ZAP's own OWASP Top 10 tags, CWE / WASC, and every
 * instance with its request and response. "baseline" spiders and applies the passive
 * rules; "full" adds the active scan (attack payloads; authorized targets only).
 */

export const ZAP_IMAGE = "zaproxy/zap-stable";
export type ZapMode = "baseline" | "full";

const MINUTES: Record<ZapMode, number> = { baseline: 5, full: 25 };
const MAX_INSTANCES = 20;
const MAX_HEADER = 8_000;
const MAX_BODY = 4_000;

/** Automation plan; the URL is JSON-encoded, which is also a valid YAML string. */
export function zapPlan(url: string, mode: ZapMode): string {
  const active = mode === "full"
    ? ["  - type: activeScan", "    parameters:", "      maxScanDurationInMins: 15", "  - type: passiveScan-wait", "    parameters:", "      maxDuration: 3"]
    : [];
  return [
    "env:",
    "  contexts:",
    "    - name: aegis",
    "      urls:",
    `        - ${JSON.stringify(url)}`,
    "  parameters:",
    "    failOnError: false",
    "    progressToStdout: true",
    "jobs:",
    "  - type: passiveScan-config",
    "    parameters:",
    "      maxAlertsPerRule: 10",
    "  - type: spider",
    "    parameters:",
    "      maxDuration: 1",
    "  - type: passiveScan-wait",
    "    parameters:",
    "      maxDuration: 5",
    ...active,
    "  - type: report",
    "    parameters:",
    "      template: traditional-json-plus",
    "      reportDir: /zap/wrk",
    "      reportFile: report",
    "",
  ].join("\n");
}

interface ZapInstance {
  uri?: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  otherinfo?: string;
  "request-header"?: string;
  "request-body"?: string;
  "response-header"?: string;
  "response-body"?: string;
}

interface ZapAlert {
  name?: string;
  alert?: string;
  pluginid?: string;
  riskcode?: string;
  confidence?: string;
  desc?: string;
  solution?: string;
  reference?: string;
  cweid?: string;
  wascid?: string;
  tags?: { tag?: string; link?: string }[];
  instances?: ZapInstance[];
}

const RISK: Record<string, Finding["severity"] | null> = { "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": null };
const CONFIDENCE: Record<string, string> = { "0": "False positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed" };

const stripHtml = (html = "") => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
const clip = (text: string | undefined, max: number) =>
  !text ? undefined : text.length > max ? `${text.slice(0, max)}\n… (${text.length - max} more characters)` : text;

function references(html = ""): string[] {
  return [...new Set(html.split(/<\/?p>|\s+/).map((s) => s.trim()).filter((s) => /^https?:\/\//.test(s)))];
}

function owaspOf(alert: ZapAlert): OwaspCategory | undefined {
  for (const t of alert.tags ?? []) {
    const category = t.tag ? owaspFromZapTag(t.tag, t.link ?? "") : null;
    if (category) return category;
  }
  return undefined;
}

/** ZAP JSON report -> findings with structured evidence, skipping informational alerts. Pure. */
export function parseZapReport(report: unknown, displayHost: string, dockerHost?: string): Finding[] {
  const sites = (report as { site?: unknown } | null)?.site;
  if (!Array.isArray(sites)) return [];
  // URLs inside the report use the address the container saw; show the real one.
  const unmap = (text: string | undefined) => (text && dockerHost ? text.split(dockerHost).join(displayHost) : text);
  return (sites as { alerts?: ZapAlert[] }[]).flatMap((site) =>
    (site.alerts ?? []).flatMap((alert): Finding[] => {
      const severity = RISK[alert.riskcode ?? "0"];
      if (!severity) return [];
      const instances: RiskInstance[] = (alert.instances ?? []).slice(0, MAX_INSTANCES).flatMap((i) =>
        i.uri
          ? [{
              uri: unmap(i.uri) as string,
              method: i.method || undefined,
              param: i.param || undefined,
              attack: i.attack || undefined,
              evidence: i.evidence || undefined,
              otherInfo: i.otherinfo || undefined,
              requestHeader: clip(unmap(i["request-header"]), MAX_HEADER),
              requestBody: clip(i["request-body"], MAX_BODY),
              responseHeader: clip(i["response-header"], MAX_HEADER),
              responseBody: clip(i["response-body"], MAX_BODY),
            }]
          : [],
      );
      const owasp = owaspOf(alert);
      return [
        {
          host: displayHost,
          title: alert.name ?? alert.alert ?? "ZAP alert",
          severity,
          description: stripHtml(alert.desc),
          recommendation: stripHtml(alert.solution),
          category: "zap",
          references: references(alert.reference),
          details: {
            pluginId: alert.pluginid,
            ...(alert.cweid && alert.cweid !== "-1" ? { cweId: alert.cweid } : {}),
            ...(alert.wascid && alert.wascid !== "-1" && alert.wascid !== "0" ? { wascId: alert.wascid } : {}),
            ...(alert.confidence ? { confidence: CONFIDENCE[alert.confidence] ?? alert.confidence } : {}),
            ...(owasp ? { owasp } : {}),
            instances,
          },
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
  await chmod(workdir, 0o777);
  const scanUrl = forDocker(url);
  await writeFile(path.join(workdir, "plan.yaml"), zapPlan(scanUrl, mode), "utf8");
  const name = `aegis-zap-${randomBytes(4).toString("hex")}`;
  try {
    const result = await runCommand(
      "docker",
      [
        "run", "--rm", "--name", name,
        "--add-host", "host.docker.internal:host-gateway",
        "-v", `${workdir}:/zap/wrk:rw`,
        ZAP_IMAGE, "zap.sh", "-cmd", "-autorun", "/zap/wrk/plan.yaml",
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
    const displayHost = new URL(url).host;
    const dockerHost = new URL(scanUrl).host;
    return { status: "ok", findings: parseZapReport(report, displayHost, dockerHost !== displayHost ? dockerHost : undefined), report };
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }
}
