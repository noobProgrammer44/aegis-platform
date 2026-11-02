import net from "node:net";
import { Agent, ProxyAgent, buildConnector, type Dispatcher } from "undici";
import { SocksClient } from "socks";

/**
 * Optional proxy support (anti-block, opt-in). Reads config from env:
 *   PROXY_URL="http://host:port"                 — a single proxy
 *   PROXY_LIST="http://a:1,socks5://b:2"         — a list, rotated round-robin
 * Supports HTTP(S) and SOCKS4/5. Default: NO proxy. Only the active stages use
 * it, and those are authorization-gated — so proxy use sits behind the auth tier.
 */

export function proxyList(): string[] {
  const list = (process.env.PROXY_LIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const single = process.env.PROXY_URL?.trim();
  if (single) list.unshift(single);
  return [...new Set(list)];
}

export function hasProxy(): boolean {
  return proxyList().length > 0;
}

let rotation = 0;
/** Next proxy URL in round-robin rotation, or null if none configured. */
export function nextProxy(): string | null {
  const list = proxyList();
  if (list.length === 0) return null;
  return list[rotation++ % list.length];
}

function isSocks(url: string): boolean {
  return /^socks/i.test(url);
}

function socksProxy(url: string) {
  const u = new URL(url);
  const type: 4 | 5 = u.protocol === "socks4:" ? 4 : 5;
  return {
    host: u.hostname,
    port: Number(u.port) || 1080,
    type,
    userId: u.username || undefined,
    password: u.password || undefined,
  };
}

// One dispatcher per proxy URL (reuse connection pools across requests).
const dispatcherCache = new Map<string, Dispatcher>();

/** An undici dispatcher that routes fetch through the proxy (HTTP or SOCKS). */
export function proxyDispatcher(proxyUrl: string): Dispatcher {
  const cached = dispatcherCache.get(proxyUrl);
  if (cached) return cached;

  let dispatcher: Dispatcher;
  if (!isSocks(proxyUrl)) {
    dispatcher = new ProxyAgent(proxyUrl);
  } else {
    const tlsConnect = buildConnector({});
    dispatcher = new Agent({
      connect(opts, callback) {
        SocksClient.createConnection({
          proxy: socksProxy(proxyUrl),
          command: "connect",
          destination: {
            host: String(opts.hostname),
            port: Number(opts.port) || (opts.protocol === "https:" ? 443 : 80),
          },
        })
          .then(({ socket }) => {
            if (opts.protocol === "https:") {
              tlsConnect({ ...opts, httpSocket: socket }, callback);
            } else {
              callback(null, socket);
            }
          })
          .catch((err: Error) => callback(err, null));
      },
    });
  }
  dispatcherCache.set(proxyUrl, dispatcher);
  return dispatcher;
}

/** Rotate to the next proxy and return its fetch dispatcher, or null if none. */
export function nextProxyDispatcher(): { url: string; dispatcher: Dispatcher } | null {
  const url = nextProxy();
  if (!url) return null;
  return { url, dispatcher: proxyDispatcher(url) };
}

/** TCP-connect liveness test for the port scan, routed through a proxy. */
export function proxiedConnect(
  host: string,
  port: number,
  proxyUrl: string,
  timeoutMs: number,
): Promise<boolean> {
  if (isSocks(proxyUrl)) {
    return SocksClient.createConnection({
      proxy: socksProxy(proxyUrl),
      command: "connect",
      destination: { host, port },
      timeout: timeoutMs,
    })
      .then(({ socket }) => {
        socket.destroy();
        return true;
      })
      .catch(() => false);
  }

  // HTTP CONNECT tunnel (note: many HTTP proxies only allow CONNECT to 443).
  return new Promise((resolve) => {
    const u = new URL(proxyUrl);
    const socket = net.connect(Number(u.port) || 8080, u.hostname);
    let settled = false;
    const finish = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      const auth = u.username
        ? `Proxy-Authorization: Basic ${Buffer.from(`${u.username}:${u.password}`).toString("base64")}\r\n`
        : "";
      socket.write(
        `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`,
      );
    });
    socket.once("data", (d) => finish(/^HTTP\/1\.[01] 200/.test(d.toString())));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}
