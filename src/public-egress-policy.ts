import ipaddr from "ipaddr.js";
import { VeilError } from "./index.js";
import { canonicalAddress } from "./model-key-network.js";

/** Host-owned policy, never populated from a Connector or OpenAPI document. */
export type PublicEgressPolicy = Readonly<{
  extraPorts?: readonly number[];
  deniedHostSuffixes?: readonly string[];
  deniedCidrs?: readonly string[];
}>;

/** Validate host-owned entries using the maintained IP parser and WHATWG URL grammar. */
export function validatePublicEgressPolicyEntries(
  configuration: PublicEgressPolicy,
): boolean {
  const cidrs = configuration.deniedCidrs ?? [];
  const suffixes = configuration.deniedHostSuffixes ?? [];
  if (
    new Set(cidrs).size !== cidrs.length ||
    new Set(suffixes).size !== suffixes.length
  )
    return false;
  for (const cidr of cidrs) {
    if (!ipaddr.isValidCIDR(cidr)) return false;
    const [address, prefix] = ipaddr.parseCIDR(cidr);
    if (address instanceof ipaddr.IPv4) {
      if (
        prefix < 8 ||
        cidr !==
          `${ipaddr.IPv4.networkAddressFromCIDR(cidr).toString()}/${String(prefix)}`
      )
        return false;
    } else {
      if (
        prefix < 16 ||
        address.zoneId !== undefined ||
        [
          "::ffff:0:0/96",
          "::ffff:0:0:0/96",
          "64:ff9b::/96",
          "64:ff9b:1::/48",
          "2002::/16",
          "2001::/32",
        ].some((range) => {
          const [embedded, embeddedPrefix] = ipaddr.IPv6.parseCIDR(range);
          return address.match(embedded, Math.min(prefix, embeddedPrefix));
        }) ||
        cidr !==
          `${ipaddr.IPv6.networkAddressFromCIDR(cidr).toRFC5952String()}/${String(prefix)}`
      )
        return false;
    }
  }
  for (const suffix of suffixes) {
    const input = `https://${suffix}`;
    if (!URL.canParse(input)) return false;
    const url = new URL(input);
    const labels = suffix.split(".");
    if (
      url.hostname !== suffix ||
      url.username ||
      url.password ||
      url.port ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      ipaddr.isValid(suffix) ||
      labels.length < 2 ||
      suffix.length > 253 ||
      !labels.every(
        (label) =>
          label.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label),
      )
    )
      return false;
  }
  return true;
}

/** The maintained IP parser owns CIDR matching, including mapped IPv4. */
export function createPublicEgressPolicy(
  configuration: PublicEgressPolicy = {},
) {
  if (!validatePublicEgressPolicyEntries(configuration))
    throw new VeilError("invalid_input");
  const ports = new Set([443, ...(configuration.extraPorts ?? [])]);
  if (
    [...ports].some(
      (port) => !Number.isInteger(port) || port < 1 || port > 65535,
    )
  )
    throw new VeilError("invalid_input");
  try {
    const suffixes = configuration.deniedHostSuffixes ?? [];
    const ranges = (configuration.deniedCidrs ?? []).map((cidr) =>
      ipaddr.parseCIDR(cidr),
    );
    function address(value: string) {
      const canonical = canonicalAddress(value);
      if (
        canonical !== null &&
        ipaddr.subnetMatch(
          ipaddr.process(canonical),
          { denied: ranges },
          "allowed",
        ) === "denied"
      )
        throw new VeilError("denied");
    }
    return {
      destination(url: URL) {
        const port =
          url.port === ""
            ? url.protocol === "https:"
              ? 443
              : 80
            : Number(url.port);
        if (!ports.has(port)) throw new VeilError("denied");
        const hostname = url.hostname.toLowerCase().replace(/\.$/u, "");
        if (
          suffixes.some(
            (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`),
          )
        )
          throw new VeilError("denied");
        address(hostname);
      },
      addresses(values: readonly string[]) {
        for (const value of values) address(value);
      },
    };
  } catch {
    throw new VeilError("invalid_input");
  }
}
