/**
 * Fills a separate demo database with sample targets, scans and risks so the UI can be
 * reviewed with realistic data. Never touches data/aegis.db.
 *
 *   npm run seed:demo                  # writes data/demo.db
 *   AEGIS_DB_PATH=data/demo.db npm run dev -- -p 3001   # browse it
 *
 * All hosts use the reserved example.com / example.org domains.
 */
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_WORKSPACE_ID, newId, openDb } from "@/lib/db/client";
import { upsertDiscoveredDomain } from "@/lib/db/repos/discovered-domains";
import { upsertHealthSnapshot } from "@/lib/db/repos/health-snapshots";
import { saveRisks } from "@/lib/db/repos/risks";
import { createScan, updateScan } from "@/lib/db/repos/scans";
import { createScheduledScan } from "@/lib/db/repos/scheduled-scans";
import { createTarget, updateTarget } from "@/lib/db/repos/targets";
import { renameWorkspace } from "@/lib/db/repos/workspaces";
import { countScoredRisks, gradeFor, healthFromRisks } from "@/lib/domain/health-score";
import type { Risk, RiskDefinition, ScanType, ThreatLevel } from "@/types/aegis";

const DAY = 86_400_000;
const now = Date.now();
const daysAgo = (days: number) => new Date(now - days * DAY).toISOString();
const WS = DEFAULT_WORKSPACE_ID;

const file = path.resolve(process.env.AEGIS_DB_PATH ?? "data/demo.db");
if (path.basename(file) === "aegis.db") {
  throw new Error("Refusing to seed data/aegis.db; point AEGIS_DB_PATH at a demo file.");
}
fs.rmSync(file, { force: true });
fs.rmSync(`${file}-wal`, { force: true });
fs.rmSync(`${file}-shm`, { force: true });
const db = openDb(file);
renameWorkspace(db, WS, "Demo workspace");

const targets = [
  createTarget(db, WS, { target: "example.com", kind: "domain", label: "Marketing site", tags: ["web", "prod"] }),
  createTarget(db, WS, { target: "https://app.example.com", kind: "url", label: "Customer app", tags: ["web", "prod"] }),
  createTarget(db, WS, { target: "api.example.com", kind: "domain", label: "Public API", tags: ["api", "prod"] }),
  createTarget(db, WS, { target: "staging.example.org", kind: "domain", label: "Staging", tags: ["staging"] }),
  createTarget(db, WS, { target: "203.0.113.0/28", kind: "cidr", label: "Office range", tags: ["network"] }),
];

type Finding = [targetIndex: number, ScanType, ThreatLevel, string, number, Partial<RiskDefinition>?];
const findings: Finding[] = [
  [1, "NUCLEI", "CRITICAL", "Exposed .env file with database credentials", 41],
  [2, "NUCLEI", "HIGH", "GraphQL introspection enabled", 18],
  [1, "SURFACE", "HIGH", "Outdated jQuery 1.12.4 with known XSS", 63],
  [3, "JS_SECRETS", "HIGH", "Stripe secret key in public JavaScript bundle", 6],
  [0, "SURFACE", "MEDIUM", "Missing Content-Security-Policy header", 120],
  [1, "SURFACE", "MEDIUM", "Missing Content-Security-Policy header", 120],
  [2, "SURFACE", "MEDIUM", "Missing Content-Security-Policy header", 90],
  [3, "SURFACE", "MEDIUM", "Missing Content-Security-Policy header", 30],
  [3, "TLS", "MEDIUM", "TLS certificate expires in 9 days", 2],
  [4, "NMAP", "MEDIUM", "SSH (22/tcp) open to the internet", 75, { additionalInfo: { port: 22 } }],
  [0, "SURFACE", "LOW", "Missing Referrer-Policy header", 120],
  [2, "SURFACE", "LOW", "Server header discloses nginx/1.18.0", 45],
  [0, "EMAIL", "LOW", "DMARC policy is p=none", 14],
  [4, "NMAP", "LOW", "HTTP (80/tcp) open", 75, { additionalInfo: { port: 80 } }],
];

const risks: Risk[] = findings.map(([ti, scanType, threatLevel, title, age, extra], i) => ({
  id: newId("rsk"),
  workspaceId: WS,
  targetId: targets[ti].id,
  fingerprint: `${scanType}:${title}`,
  definition: {
    scanType,
    title,
    threatLevel,
    description: `${title} was detected on ${targets[ti].target}.`,
    solution: "See the references for remediation guidance.",
    references: ["https://owasp.org/www-project-top-ten/"],
    cvss: null,
    additionalInfo: {},
    ...extra,
  },
  status: "OPEN",
  isAccepted: i === 13,
  acceptedReason: i === 13 ? "Redirects to HTTPS" : null,
  acceptedBy: i === 13 ? "manual" : null,
  firstDetectedAt: daysAgo(age),
  lastDetectedAt: daysAgo(0.2),
  closedAt: null,
  lastScanId: null,
  createdAt: daysAgo(age),
  updatedAt: daysAgo(0.2),
}));
const closed: Risk[] = [
  { ...risks[4], id: newId("rsk"), fingerprint: "SURFACE:x-frame", status: "CLOSED", closedAt: daysAgo(3),
    definition: { ...risks[4].definition, title: "Missing X-Frame-Options header" } },
  { ...risks[9], id: newId("rsk"), fingerprint: "NMAP:3389", status: "CLOSED", closedAt: daysAgo(10),
    definition: { ...risks[9].definition, title: "RDP (3389/tcp) open to the internet", threatLevel: "HIGH" } },
];
saveRisks(db, [...risks, ...closed]);

for (const target of targets) {
  const own = risks.filter((r) => r.targetId === target.id);
  updateTarget(db, WS, target.id, { health: healthFromRisks(own), lastScannedAt: daysAgo(0.2) });
}

const scanSpecs: [ScanType, number[], "SUCCEEDED" | "RUNNING" | "FAILED", number][] = [
  ["SURFACE", [0, 1, 2, 3], "RUNNING", 0.01],
  ["NUCLEI", [1, 2], "SUCCEEDED", 0.2],
  ["JS_SECRETS", [1, 3], "SUCCEEDED", 0.9],
  ["NMAP", [4], "SUCCEEDED", 2],
  ["TLS", [0, 1, 2, 3], "FAILED", 4],
];
for (const [type, idx, state, age] of scanSpecs) {
  const scan = createScan(db, WS, {
    type,
    targetIds: idx.map((i) => targets[i].id),
    targets: idx.map((i) => targets[i].target),
  });
  db.prepare("UPDATE scans SET created_at = ? WHERE id = ?").run(daysAgo(age), scan.id);
  updateScan(db, WS, scan.id, {
    state,
    progress: state === "RUNNING" ? 45 : 100,
    startedAt: daysAgo(age),
    finishedAt: state === "RUNNING" ? null : daysAgo(age - 0.01),
    error: state === "FAILED" ? "sslyze is not installed" : null,
  });
}

createScheduledScan(db, WS, {
  name: "Weekly web surface",
  schedule: "WEEKLY",
  scanTypes: ["SURFACE", "TLS"],
  targetsFilter: { targetIds: [], tags: ["web"] },
  startAt: daysAgo(14),
  nextRun: new Date(now + 3 * DAY).toISOString(),
});

for (const [name, via] of [["vpn.example.com", 0], ["old-admin.example.com", 0], ["docs.api.example.com", 2]] as const) {
  upsertDiscoveredDomain(db, WS, {
    name,
    viaTargetId: targets[via].id,
    viaTarget: targets[via].target,
    resolves: true,
    records: { A: ["203.0.113.40"] },
  }, daysAgo(1));
}

// Daily workspace snapshots: the score was worse a month ago and has improved since.
for (let d = 60; d >= 0; d -= 1) {
  const health = healthFromRisks(risks);
  const score = Math.min(1000, health.score + Math.round(Math.max(0, d - 20) * 2.5));
  upsertHealthSnapshot(db, {
    workspaceId: WS,
    targetId: null,
    day: daysAgo(d).slice(0, 10),
    score,
    grade: gradeFor(score),
    counts: countScoredRisks(risks),
    assets: targets.length,
  });
}

db.close();
process.stdout.write(`Seeded demo data into ${file}\n`);
