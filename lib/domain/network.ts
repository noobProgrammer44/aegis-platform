/**
 * IPv4 and hostname helpers for target parsing and local auto-authorization.
 * Addresses are unsigned 32-bit numbers; arithmetic is used instead of bitwise
 * operators, which are signed in JavaScript.
 */

/** 0-255 without leading zeros ("010" is ambiguous: octal in some parsers). */
const OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export interface Cidr {
  /** First address of the range. */
  network: number;
  prefix: number;
  /** Number of addresses in the range. */
  size: number;
}

export function parseIPv4(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4 || !parts.every((part) => OCTET.test(part))) return null;
  return parts.reduce((acc, part) => acc * 256 + Number(part), 0);
}

export function formatIPv4(address: number): string {
  return [24, 16, 8, 0].map((shift) => Math.floor(address / 2 ** shift) % 256).join(".");
}

/** Parses `a.b.c.d/n`, normalizing the address to the network's first address. */
export function parseCidr(value: string): Cidr | null {
  const match = /^([\d.]+)\/(\d{1,2})$/.exec(value);
  if (!match) return null;
  const address = parseIPv4(match[1]);
  const prefix = Number(match[2]);
  if (address === null || prefix > 32) return null;
  const size = 2 ** (32 - prefix);
  return { network: address - (address % size), prefix, size };
}

export function formatCidr(cidr: Cidr): string {
  return `${formatIPv4(cidr.network)}/${cidr.prefix}`;
}

export function cidrContains(cidr: Cidr, address: number): boolean {
  return address >= cidr.network && address < cidr.network + cidr.size;
}

/** Loopback, RFC 1918 private and link-local ranges: addresses on your own machine or LAN. */
const LOCAL_RANGES: readonly Cidr[] = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
  "0.0.0.0/32",
].map((range) => parseCidr(range) as Cidr);

export function isLocalIPv4(address: number): boolean {
  return LOCAL_RANGES.some((range) => cidrContains(range, address));
}

/** True only when the whole range sits inside one local range. */
export function isLocalCidr(cidr: Cidr): boolean {
  const last = cidr.network + cidr.size - 1;
  return LOCAL_RANGES.some((range) => cidrContains(range, cidr.network) && cidrContains(range, last));
}

/** `localhost`, `*.localhost` and mDNS `*.local` names. */
export function isLocalHostname(hostname: string): boolean {
  const name = hostname.toLowerCase().replace(/\.$/, "");
  return name === "localhost" || name.endsWith(".localhost") || name.endsWith(".local");
}
