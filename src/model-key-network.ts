import * as Schema from "effect/Schema";
import { VeilError } from "./index.js";

/**
 * Where a Team-supplied OpenAI-compatible base URL may point. Fungi's
 * custodian fetches it from inside Fungi's own network, so every name must
 * resolve only to public unicast addresses, checked at intake and again
 * before each egress (SSRF defence; see
 * wiki/3-resources/decisions/adr-byok-model-keys-v1.md).
 */

/** Resolves a hostname to its A and AAAA addresses. */
export type HostResolver = (
  hostname: string,
  signal: AbortSignal,
) => Promise<readonly string[]>;

const deniedSuffixes = [
  ".localhost",
  ".local",
  ".internal",
  ".lan",
  ".home.arpa",
  ".intranet",
  ".corp",
];

function ipv4Octets(value: string): readonly number[] | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((part) =>
    /^(0|[1-9][0-9]{0,2})$/u.test(part) ? Number(part) : Number.NaN,
  );
  return octets.every((octet) => octet >= 0 && octet <= 255) ? octets : null;
}

function publicIpv4([a = 0, b = 0, c = 0]: readonly number[]): boolean {
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

/** Expand an IPv6 literal to eight 16-bit groups, or null if it is not one. */
function ipv6Groups(value: string): readonly number[] | null {
  let text = value.toLowerCase();
  if (!/^[0-9a-f:.]+$/u.test(text) || !text.includes(":")) return null;
  const lastColon = text.lastIndexOf(":");
  const suffix = text.slice(lastColon + 1);
  if (suffix.includes(".")) {
    // Rewrite a trailing dotted IPv4 as its two hex groups.
    const octets = ipv4Octets(suffix);
    if (octets === null) return null;
    const [a = 0, b = 0, c = 0, d = 0] = octets;
    text = `${text.slice(0, lastColon + 1)}${(a * 256 + b).toString(16)}:${(c * 256 + d).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const read = (part: string | undefined) =>
    part === undefined || part === "" ? [] : part.split(":");
  const head = read(halves[0]);
  const rest = read(halves[1]);
  const groups = [...head, ...rest].map((group) =>
    /^[0-9a-f]{1,4}$/u.test(group) ? Number.parseInt(group, 16) : Number.NaN,
  );
  if (groups.some(Number.isNaN)) return null;
  if (halves.length === 1) return groups.length === 8 ? groups : null;
  if (groups.length >= 8) return null;
  return [
    ...groups.slice(0, head.length),
    ...Array.from({ length: 8 - groups.length }, () => 0),
    ...groups.slice(head.length),
  ];
}

function publicIpv6(groups: readonly number[]): boolean {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] =
    groups;
  const embedded = [g6 >> 8, g6 & 255, g7 >> 8, g7 & 255];
  // ::/96 holds the unspecified address, loopback and deprecated IPv4-compatible
  // addresses; none is public unicast.
  if (groups.slice(0, 6).every((group) => group === 0)) return false;
  // IPv4-mapped ::ffff:a.b.c.d and NAT64 64:ff9b::a.b.c.d carry an IPv4 target.
  if (groups.slice(0, 5).every((group) => group === 0) && g5 === 0xffff)
    return publicIpv4(embedded);
  if (
    g0 === 0x64 &&
    g1 === 0xff9b &&
    g2 === 0 &&
    g3 === 0 &&
    g4 === 0 &&
    g5 === 0
  )
    return publicIpv4(embedded);
  // 6to4 2002:AABB:CCDD:: embeds an IPv4 target in its second and third groups.
  if (g0 === 0x2002) return publicIpv4([g1 >> 8, g1 & 255, g2 >> 8, g2 & 255]);
  return !(
    // Local-use NAT64 64:ff9b:1::/48 and Teredo 2001::/32 hide an IPv4 target.
    (g0 === 0x64 && g1 === 0xff9b) ||
    (g0 === 0x2001 && g1 === 0) ||
    (g0 & 0xfe00) === 0xfc00 ||
    (g0 & 0xffc0) === 0xfe80 ||
    (g0 & 0xffc0) === 0xfec0 ||
    (g0 === 0 &&
      g1 === 0 &&
      g2 === 0 &&
      g3 === 0 &&
      g4 === 0xffff &&
      g5 === 0) ||
    (g0 === 0x2001 && g1 === 2 && g2 === 0) ||
    (g0 === 0x2001 && (g1 & 0xfff0) === 0x10) ||
    (g0 & 0xff00) === 0xff00 ||
    (g0 === 0x2001 && g1 === 0x0db8) ||
    (g0 === 0x0100 && groups.slice(1, 4).every((group) => group === 0))
  );
}

/** Whether an address literal is public unicast. Non-literals return null. */
export function publicAddress(address: string): boolean | null {
  const bare = address.replace(/^\[|\]$/gu, "");
  const v4 = ipv4Octets(bare);
  if (v4 !== null) return publicIpv4(v4);
  const v6 = ipv6Groups(bare);
  return v6 === null ? null : publicIpv6(v6);
}

/** Static checks on a base URL's host, before any resolution. */
export function assertPublicHostName(hostname: string): void {
  const host = hostname.toLowerCase().replace(/\.$/u, "");
  const literal = publicAddress(host);
  if (literal !== null) {
    if (!literal) throw new VeilError("denied");
    return;
  }
  if (
    host === "localhost" ||
    !host.includes(".") ||
    deniedSuffixes.some((suffix) => host.endsWith(suffix))
  )
    throw new VeilError("denied");
}

/**
 * The one canonical text for a literal address, or null for a name. A caller
 * that connects to a literal passes this form so the socket layer reads exactly
 * the address that was classified.
 */
export function canonicalAddress(address: string): string | null {
  const bare = address.replace(/^\[|\]$/gu, "");
  const v4 = ipv4Octets(bare);
  if (v4 !== null) return v4.join(".");
  const v6 = ipv6Groups(bare);
  return v6 === null ? null : v6.map((group) => group.toString(16)).join(":");
}

/**
 * Resolve once and return the checked addresses in canonical form. Every answer
 * must be public: one inward answer refuses the name, and no answer is
 * unavailable. A literal address is its own single answer.
 */
export async function resolvePublicAddresses(
  hostname: string,
  resolve: HostResolver,
  signal: AbortSignal,
): Promise<readonly string[]> {
  assertPublicHostName(hostname);
  const literal = canonicalAddress(hostname.replace(/\.$/u, ""));
  if (literal !== null) return [literal];
  let answers: readonly string[];
  try {
    answers = await resolve(hostname, signal);
  } catch {
    throw new VeilError(signal.aborted ? "cancelled" : "unavailable");
  }
  if (answers.length === 0) throw new VeilError("unavailable");
  const addresses = new Set<string>();
  for (const answer of answers) {
    const canonical = canonicalAddress(answer);
    if (canonical === null || publicAddress(canonical) !== true)
      throw new VeilError("denied");
    addresses.add(canonical);
  }
  return [...addresses];
}

/** Every address the name resolves to must be public; no answer is unavailable. */
export async function assertPublicResolution(
  hostname: string,
  resolve: HostResolver,
  signal: AbortSignal,
): Promise<void> {
  await resolvePublicAddresses(hostname, resolve, signal);
}

const dohAnswerSchema = Schema.Struct({
  Answer: Schema.optional(
    Schema.Array(Schema.Struct({ type: Schema.Number, data: Schema.String })),
  ),
});

/**
 * Resolve through DNS-over-HTTPS JSON (Cloudflare's public resolver), which a
 * Worker can reach where it has no socket DNS. CNAME chains are followed by the
 * resolver; only A (1) and AAAA (28) data are returned.
 */
export function createDnsOverHttpsResolver(
  fetcher: typeof fetch = fetch,
  endpoint = "https://cloudflare-dns.com/dns-query",
): HostResolver {
  return async (hostname, signal) => {
    const answers = await Promise.all(
      (["A", "AAAA"] as const).map(async (type) => {
        const url = new URL(endpoint);
        url.searchParams.set("name", hostname);
        url.searchParams.set("type", type);
        const response = await fetcher(url, {
          headers: { accept: "application/dns-json" },
          signal,
          // Workers reject `redirect: "error"`; a 3xx is simply not `ok`.
          redirect: "manual",
        });
        if (!response.ok) throw new VeilError("unavailable");
        const decoded = Schema.decodeUnknownSync(
          Schema.fromJsonString(dohAnswerSchema),
        )(await response.text());
        return (decoded.Answer ?? []).flatMap((entry) =>
          entry.type === 1 || entry.type === 28 ? [entry.data] : [],
        );
      }),
    );
    return answers.flat();
  };
}
