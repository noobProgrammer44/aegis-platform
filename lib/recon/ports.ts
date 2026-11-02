import net from "node:net";
import pLimit from "p-limit";
import { delay, intensityProfile, type ScanIntensity } from "@/lib/recon/intensity";
import type { Finding, LiveHost, OpenPort } from "@/types/recon";

/**
 * Port scan (ACTIVE) — a pure Node TCP-connect scan over a curated list of common
 * ports. No raw sockets, no Docker, no root: each port is a net.Socket connect
 * test. Concurrency and inter-request delay come from the scan-intensity setting.
 * Gated behind `activeAllowed` like every other active stage.
 */

const PORT_TIMEOUT_MS = 1500;

/** Curated "top ~100" common ports → best-guess service. */
const PORT_SERVICES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
  80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
  139: "NetBIOS", 143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
  445: "SMB", 465: "SMTPS", 500: "IKE", 512: "rexec", 513: "rlogin", 514: "Syslog",
  587: "SMTP (submission)", 631: "IPP", 636: "LDAPS", 873: "rsync", 993: "IMAPS",
  995: "POP3S", 1025: "MSRPC", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
  1521: "Oracle DB", 1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel (TLS)",
  2181: "ZooKeeper", 2375: "Docker API", 2376: "Docker API (TLS)", 3000: "HTTP-alt (Node/Grafana)",
  3260: "iSCSI", 3306: "MySQL", 3389: "RDP", 3690: "SVN", 4040: "Spark/ngrok UI",
  4444: "Metasploit", 5000: "HTTP-alt (Flask/UPnP)", 5432: "PostgreSQL", 5555: "ADB",
  5601: "Kibana", 5672: "AMQP (RabbitMQ)", 5900: "VNC", 5984: "CouchDB", 6000: "X11",
  6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic", 8000: "HTTP-alt",
  8008: "HTTP-alt", 8009: "AJP", 8080: "HTTP-proxy", 8081: "HTTP-alt", 8086: "InfluxDB",
  8089: "Splunk", 8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "SonarQube/PHP-FPM",
  9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka", 9200: "Elasticsearch",
  9300: "Elasticsearch", 9418: "Git", 10000: "Webmin", 11211: "Memcached",
  15672: "RabbitMQ mgmt", 27017: "MongoDB", 27018: "MongoDB", 50000: "SAP",
};

const PORTS = Object.keys(PORT_SERVICES).map(Number);

/** Data stores / admin services that should never be internet-reachable. */
const RISKY_PORTS = new Set([
  1433, 1521, 2375, 2376, 2181, 3306, 5432, 5601, 5672, 5984, 6379, 6443, 8086,
  9042, 9092, 9200, 9300, 11211, 15672, 27017, 27018,
]);

/** Open web ports worth re-probing/fingerprinting. */
const WEB_PORTS = new Set([80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888]);

export interface PortScanResult {
  openPorts: OpenPort[];
  findings: Finding[];
  /** host:port of open web services, to feed back into probe/fingerprint. */
  webTargets: string[];
}

export async function scanPorts(
  hosts: LiveHost[],
  activeAllowed: boolean,
  intensityValue: ScanIntensity | string,
): Promise<PortScanResult> {
  if (!activeAllowed) {
    throw new Error(
      "Active scanning is not authorized. Enable 'Active scan' before port scanning.",
    );
  }

  const profile = intensityProfile(intensityValue);

  // One scan per unique hostname across all live hosts.
  const hostnames = new Set<string>();
  for (const host of hosts) {
    try {
      hostnames.add(new URL(host.url).hostname);
    } catch {
      /* skip unparseable */
    }
  }

  const limit = pLimit(profile.concurrency);
  const openPorts: OpenPort[] = [];

  const tasks: Promise<void>[] = [];
  for (const hostname of hostnames) {
    for (const port of PORTS) {
      tasks.push(
        limit(async () => {
          if (profile.delayMs) await delay(profile.delayMs);
          if (await checkPort(hostname, port, PORT_TIMEOUT_MS)) {
            openPorts.push({
              host: hostname,
              port,
              service: PORT_SERVICES[port] ?? "unknown",
            });
          }
        }),
      );
    }
  }
  await Promise.all(tasks);

  openPorts.sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port);

  const findings = openPorts.map(toPortFinding);
  const webTargets = openPorts
    .filter((p) => WEB_PORTS.has(p.port))
    .map((p) => `${p.host}:${p.port}`);

  return { openPorts, findings, webTargets };
}

/** TCP-connect liveness test for a single port. */
function checkPort(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(port, host);
  });
}

function toPortFinding(p: OpenPort): Finding {
  const risky = RISKY_PORTS.has(p.port);
  return {
    host: `${p.host}:${p.port}`,
    title: `Open port ${p.port} — ${p.service}`,
    severity: risky ? "HIGH" : "INFO",
    description: risky
      ? `${p.service} (port ${p.port}) is reachable on ${p.host}. Data stores and admin services exposed to the network are high-value, often-unauthenticated targets.`
      : `Port ${p.port} (${p.service}) is open on ${p.host}.`,
    recommendation: risky
      ? "Restrict this service to trusted networks (firewall / security group / bind to localhost) and require authentication."
      : "Confirm this port is intended to be publicly reachable; firewall or close it otherwise.",
    port: p.port,
    service: p.service,
  };
}
