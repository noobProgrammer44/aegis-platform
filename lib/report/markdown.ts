import { INTENSITY_PROFILES } from "@/lib/recon/intensity";
import type { Finding, ScanResult, Severity } from "@/types/recon";

/**
 * Render a completed ScanResult into a clean Markdown report — the professional
 * pentest-deliverable artifact. Pure function, server-side (imported by the
 * /api/scan/report route).
 */

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/** Escape a value for a Markdown table cell. */
const cell = (s: string): string =>
  s.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ").trim();

export function buildMarkdownReport(scan: ScanResult): string {
  const out: string[] = [];
  const counts = countBySeverity(scan.findings);
  const breakdown =
    SEVERITY_ORDER.filter((s) => counts[s] > 0)
      .map((s) => `${counts[s]} ${s}`)
      .join(" · ") || "none";
  const intensityLabel =
    INTENSITY_PROFILES[scan.scanIntensity]?.label ?? scan.scanIntensity;

  out.push(`# Aegis — Attack Surface Report`);
  out.push("");
  out.push(`**Target:** \`${scan.target}\`  `);
  out.push(
    `**Scope / mode:** ${scan.mode === "direct" ? "Direct target" : "Domain enumeration"}  `,
  );
  out.push(`**Authorization:** ${scan.authTier}  `);
  out.push(`**Scan intensity:** ${intensityLabel}  `);
  out.push(`**Stages run:** ${scan.stagesRun.join(" → ") || "—"}  `);
  out.push(`**Started:** ${fmt(scan.startedAt)}  `);
  out.push(`**Finished:** ${fmt(scan.endedAt)}  `);
  out.push("");
  out.push(
    "> **Authorized-use artifact.** Active scanning was performed only where authorization was asserted (see Authorization above). Aegis performs assessment, not exploitation.",
  );
  out.push("");

  // Executive summary
  out.push(`## Executive summary`);
  out.push("");
  out.push(`**Risk score: ${scan.riskScore}** — ${riskLabel(scan.findings)}`);
  out.push("");
  out.push(`- **Live hosts:** ${scan.liveHosts.length}`);
  out.push(`- **Open ports:** ${scan.openPorts.length}`);
  out.push(`- **Findings:** ${scan.findings.length} (${breakdown})`);
  if (scan.aiSummary) {
    out.push("");
    out.push(scan.aiSummary);
  }
  out.push("");

  // Findings grouped by severity
  out.push(`## Findings (${scan.findings.length})`);
  out.push("");
  if (scan.findings.length === 0) {
    out.push("_No findings._");
    out.push("");
  } else {
    for (const sev of SEVERITY_ORDER) {
      const group = scan.findings.filter((f) => f.severity === sev);
      if (group.length === 0) continue;
      out.push(`### ${sev} (${group.length})`);
      out.push("");
      out.push(`| Host | Finding | Recommendation |`);
      out.push(`| --- | --- | --- |`);
      for (const f of group) {
        out.push(
          `| ${cell(f.host)} | **${cell(f.title)}** — ${cell(f.description)} | ${cell(f.recommendation)} |`,
        );
      }
      out.push("");
    }
  }

  // Open ports
  out.push(`## Open ports (${scan.openPorts.length})`);
  out.push("");
  if (scan.openPorts.length === 0) {
    out.push("_No open ports found (or the port scan did not run)._");
  } else {
    out.push(`| Host | Port | Service |`);
    out.push(`| --- | --- | --- |`);
    for (const p of scan.openPorts) {
      out.push(`| ${cell(p.host)} | ${p.port} | ${cell(p.service)} |`);
    }
  }
  out.push("");

  // Detected technologies
  out.push(`## Detected technologies`);
  out.push("");
  const techHosts = scan.fingerprints.filter((fp) => fp.technologies.length > 0);
  if (techHosts.length === 0) {
    out.push("_No technologies detected._");
  } else {
    for (const fp of techHosts) {
      const techs = fp.technologies
        .map((t) => (t.version ? `${t.name} ${t.version}` : t.name))
        .join(", ");
      out.push(`- **${cell(fp.host)}** — ${cell(techs)}`);
    }
  }
  out.push("");

  // Methodology
  out.push(`## Methodology`);
  out.push("");
  out.push("Aegis runs a staged external attack-surface assessment:");
  out.push("");
  out.push(
    "1. **Discovery (passive)** — subdomains from Certificate Transparency (crt.sh) + DNS resolution. Never touches the target.",
  );
  out.push(
    "2. **Live probe (active)** — HTTP/HTTPS liveness, page titles, response headers, timing.",
  );
  out.push(
    "3. **Port scan (active)** — TCP-connect scan of common ports; open web ports are fed back through probe/fingerprint.",
  );
  out.push(
    "4. **Crawl & fingerprint (active)** — technology/version detection, shallow crawl, exposed-path checks.",
  );
  out.push(
    "5. **Surface analysis** — missing security headers, TLS certificate checks, exposed paths, version hints → severity-ranked findings.",
  );
  out.push(
    "6. **Deep vulnerability detection** — nuclei (Dockerized) templated scanning, merged into the findings.",
  );
  out.push("");
  out.push(
    `Active stages are gated by an authorization check and paced by the **${intensityLabel}** intensity setting (rate-limited and concurrency-capped for responsible scanning). Aegis reports weaknesses for remediation; it does not exploit them.`,
  );
  out.push("");
  out.push(`---`);
  out.push(`*Report generated by Aegis on ${fmt(scan.endedAt)}.*`);

  return out.join("\n");
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const f of findings) c[f.severity]++;
  return c;
}

function riskLabel(findings: Finding[]): string {
  const c = countBySeverity(findings);
  if (c.CRITICAL) return "Critical";
  if (c.HIGH) return "High";
  if (c.MEDIUM) return "Elevated";
  if (c.LOW) return "Low";
  return "Clean";
}

function fmt(iso: string): string {
  try {
    return new Date(iso).toUTCString();
  } catch {
    return iso;
  }
}
