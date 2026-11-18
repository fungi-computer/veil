import { Buffer } from "node:buffer";
import { RE2JS } from "re2js";
import { z } from "zod";
import { configuration } from "../dist/redaction-rules.js";
import { VeilError } from "./index.js";

/**
 * Veil's one redactor. Masking is the backstop; injection is the control:
 * stored values stay at their custody owner and are placed only at final
 * egress, never handed to an Agent. Redaction catches a value that reaches
 * output anyway, in the listed encodings only.
 *
 * - Known values (primary). The owner builds a {@link FingerprintSet} (HMAC-SHA256
 *   of every encoded variant under a subkey derived from its own key) and gives
 *   Session hosts only that set; {@link createFingerprintRedactor} matches it.
 *   {@link createKnownValueRedactor} is for owner-side doors that already hold
 *   the raw value at final send (echo checks); Session hosts never use it.
 * - Unknown keys (secondary). {@link createPatternRedactor} runs gitleaks'
 *   vendored default rules on RE2.
 */
export type RedactionResult = Readonly<{
  text: string;
  status: "clean" | "redacted" | "unavailable";
}>;

export type RedactionStream = Readonly<{
  /** Await each write before the next; overlapping writes withhold the stream. */
  write: (chunk: string) => Promise<RedactionResult>;
  finish: () => Promise<RedactionResult>;
}>;

export type KnownValueRedactor = Readonly<{
  /** True also when custody could not supply the values (fail closed). */
  contains: (text: string) => Promise<boolean>;
  redact: (text: string) => Promise<RedactionResult>;
  stream: () => RedactionStream;
}>;

export type PatternRedactor = Readonly<{
  contains: (text: string) => boolean;
  redact: (text: string) => RedactionResult;
}>;

const masked = "[REDACTED]";
const unavailable = "[output withheld: redaction unavailable]";
// Private defensive ceilings, not Vault account quotas. Exceeding one withholds
// output; it never selects a partial set of secrets or a raw pass-through.
const maxTextLength = 64 * 1024 * 1024;
const maxValues = 1024;
const maxSecretLength = 16 * 1024;
const maxRegisteredLength = 1024 * 1024;
// Fingerprint windows are anchored on each variant's first code units, so a
// fingerprinted value needs at least this many. Eight code units are at least
// eight UTF-8 bytes, which leave at least nine stable base64 characters at
// every byte alignment (8 * 8 / 6 - 2), so trimmed variants stay anchorable.
const anchorLength = 8;
const fingerprintInfo = "fungi.veil.redaction.fingerprint.v1";

/**
 * The base64 characters a value contributes wherever it sits in a larger
 * base64 document. With `offset` bytes (mod 3) before it, a character is
 * stable only when all six of its bits come from the value: the leading
 * characters mixed with preceding bytes, and the trailing partial character
 * and padding, depend on the surrounding document (GitHub Actions' masker).
 */
function stableBase64(bytes: Buffer): string[] {
  return [0, 1, 2].flatMap((offset) => {
    const encoded = Buffer.concat([Buffer.alloc(offset), bytes]).toString(
      "base64",
    );
    const stable = encoded.slice(
      Math.ceil((8 * offset) / 6),
      Math.floor((8 * (offset + bytes.length)) / 6),
    );
    return [stable, stable.replaceAll("+", "-").replaceAll("/", "_")];
  });
}

/** JSON writers that escape every non-ASCII code unit as `\uXXXX`. */
function asciiJson(value: string): string[] {
  const escaped = JSON.stringify(value)
    .slice(1, -1)
    .replace(
      /[^\x20-\x7e]/gu,
      (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
  return [
    escaped,
    escaped.replace(
      /\\u([0-9a-f]{4})/gu,
      (_, hex: string) => `\\u${hex.toUpperCase()}`,
    ),
  ];
}

function variants(value: string): string[] {
  const bytes = Buffer.from(value);
  const uri = encodeURIComponent(value);
  return [
    ...new Set([
      value,
      `Bearer ${value}`,
      JSON.stringify(value).slice(1, -1),
      ...asciiJson(value),
      uri,
      uri.replace(/%[0-9A-F]{2}/gu, (part) => part.toLowerCase()),
      bytes.toString("hex"),
      bytes.toString("hex").toUpperCase(),
      // A standalone encoding is covered whole (padding included); embedded
      // ones by the stable inner characters at all three byte alignments.
      bytes.toString("base64"),
      bytes.toString("base64url"),
      ...stableBase64(bytes),
    ]),
  ].filter(Boolean);
}

const validValues = (values: readonly string[]) =>
  values.length <= maxValues &&
  values.every(
    (value) =>
      value.length > 0 &&
      value.length <= maxSecretLength &&
      value.isWellFormed(),
  ) &&
  values.reduce((length, value) => length + value.length, 0) <=
    maxRegisteredLength;

const regex = z.string().transform((source) => RE2JS.compile(source));
const allowlist = z.strictObject({
  description: z.string().optional(),
  regexTarget: z.enum(["secret", "match", "line"]).default("secret"),
  condition: z.enum(["OR", "AND"]).default("OR"),
  regexes: z.array(regex).default([]),
  stopwords: z.array(z.string()).default([]),
  paths: z.array(regex).default([]),
});
const patternConfig = z.strictObject({
  title: z.string(),
  minVersion: z.string(),
  allowlist,
  rules: z.array(
    z.strictObject({
      id: z.string(),
      description: z.string(),
      regex: regex.optional(),
      path: regex.optional(),
      entropy: z.number().default(0),
      secretGroup: z.number().int().nonnegative().default(0),
      keywords: z.array(z.string()).default([]),
      allowlists: z.array(allowlist).default([]),
    }),
  ),
});
type PatternConfig = z.infer<typeof patternConfig>;
type Allowlist = z.infer<typeof allowlist>;
let compiledPatterns: PatternConfig | undefined;

function entropy(value: string): number {
  const counts = new Map<string, number>();
  let length = 0;
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
    length++;
  }
  let result = 0;
  for (const count of counts.values()) {
    const probability = count / length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

function allowed(
  list: Allowlist,
  secret: string,
  match: string,
  line: string,
): boolean {
  const target =
    list.regexTarget === "match"
      ? match
      : list.regexTarget === "line"
        ? line
        : secret;
  const checks: boolean[] = [];
  if (list.regexes.length > 0)
    checks.push(
      list.regexes.some((expression) => expression.matcher(target).find()),
    );
  if (list.stopwords.length > 0)
    checks.push(
      list.stopwords.some((word) =>
        secret.toLowerCase().includes(word.toLowerCase()),
      ),
    );
  // Text has no trusted filename. Never let a path exemption excuse a paste.
  if (list.paths.length > 0) checks.push(false);
  return (
    checks.length > 0 &&
    (list.condition === "AND" ? checks.every(Boolean) : checks.some(Boolean))
  );
}

function* patternMatches(text: string, config: PatternConfig) {
  const lower = text.toLowerCase();
  for (const rule of config.rules) {
    // pkcs12-file is filename-only. Its path is compiled and retained, but no
    // filename exists at this text seam. Content rules run even without a path.
    if (rule.regex === undefined) continue;
    if (
      rule.keywords.length > 0 &&
      !rule.keywords.some((word) => lower.includes(word))
    )
      continue;
    const matcher = rule.regex.matcher(text);
    while (matcher.find()) {
      let group = rule.secretGroup;
      if (group === 0) {
        for (
          let candidate = 1;
          candidate <= matcher.groupCount();
          candidate++
        ) {
          if (matcher.group(candidate)) {
            group = candidate;
            break;
          }
        }
      }
      const secret = matcher.group(group) ?? "";
      if (
        secret.length === 0 ||
        (rule.entropy > 0 && entropy(secret) <= rule.entropy)
      )
        continue;
      const start = matcher.start();
      const end = matcher.end();
      const lineStart = start === 0 ? 0 : text.lastIndexOf("\n", start - 1) + 1;
      const newline = text.indexOf("\n", end);
      const line = text.slice(
        lineStart,
        newline === -1 ? text.length : newline,
      );
      const match = matcher.group() ?? "";
      if (
        allowed(config.allowlist, secret, match, line) ||
        rule.allowlists.some((list) => allowed(list, secret, match, line))
      )
        continue;
      yield { start: matcher.start(group), end: matcher.end(group) };
    }
  }
}

/**
 * Secondary detection of unknown keys in complete text (not streaming).
 * Uses the unchanged gitleaks defaults: RE2, keywords, capture groups, entropy
 * and content allowlists. No filename/commit context or inline suppression comments
 * are trusted here. Unbounded pattern lengths cannot use known-value holdback.
 */
export function createPatternRedactor(): PatternRedactor {
  compiledPatterns ??= patternConfig.parse(configuration);
  const config = compiledPatterns;
  return {
    contains: (text) =>
      text.length > maxTextLength || !patternMatches(text, config).next().done,
    redact: (text) => {
      if (text.length > maxTextLength)
        return { text: unavailable, status: "unavailable" };
      let marks: Uint8Array | undefined;
      for (const match of patternMatches(text, config)) {
        marks ??= new Uint8Array(text.length);
        marks.fill(1, match.start, match.end);
      }
      return marks === undefined
        ? { text, status: "clean" }
        : { text: replaceMarked(text, marks), status: "redacted" };
    },
  };
}

/** A bitmap unions overlapping matches without rescanning replacement text. */
function replaceMarked(text: string, marks: Uint8Array): string {
  const output: string[] = [];
  let start = 0;
  let index = 0;
  while (index < text.length) {
    if (marks[index] !== 1) {
      index++;
      continue;
    }
    output.push(text.slice(start, index), masked);
    while (marks[index] === 1) index++;
    start = index;
  }
  output.push(text.slice(start));
  return output.join("");
}

/** Marks every registered variant in `text`; resolves whether any matched. */
type Matcher = Readonly<{
  holdback: number;
  mark: (text: string, marks: Uint8Array) => Promise<boolean>;
}>;

/**
 * Streams hold back the longest variant's length minus one. A marked run that
 * reaches into that tail stays held, raw, until no overlapping value can extend
 * it; only settled text leaves, already redacted. The tail is never released
 * raw, including at finish or at the size ceiling (which withholds instead).
 */
function knownStream(matcher: Matcher | null): RedactionStream {
  let held = "";
  let failed = matcher === null;
  let busy = false;
  let finished = false;
  const poisoned = () => failed;
  const withhold = (): RedactionResult => {
    held = "";
    failed = true;
    return { text: unavailable, status: "unavailable" };
  };
  return {
    write: async (chunk) => {
      if (failed || busy || finished || matcher === null) return withhold();
      if (held.length + chunk.length > maxTextLength) return withhold();
      busy = true;
      held += chunk;
      const marks = new Uint8Array(held.length);
      // A rejection leaves `busy` set, so every later call withholds.
      const found = await matcher.mark(held, marks);
      busy = false;
      // An overlapping call during the await withheld the stream.
      if (poisoned()) return withhold();
      let settled = Math.max(0, held.length - matcher.holdback);
      if (settled > 0 && marks[settled - 1] === 1)
        while (settled > 0 && marks[settled - 1] === 1) settled--;
      const text = replaceMarked(
        held.slice(0, settled),
        marks.subarray(0, settled),
      );
      held = held.slice(settled);
      return {
        text,
        status:
          found && marks.subarray(0, settled).includes(1)
            ? "redacted"
            : "clean",
      };
    },
    finish: async () => {
      if (finished)
        return { text: "", status: failed ? "unavailable" : "clean" };
      if (failed || busy || matcher === null) {
        finished = true;
        return withhold();
      }
      finished = true;
      const marks = new Uint8Array(held.length);
      const found = await matcher.mark(held, marks);
      const text = found ? replaceMarked(held, marks) : held;
      held = "";
      return { text, status: found ? "redacted" : "clean" };
    },
  };
}

function knownRedactor(matcher: Matcher | null): KnownValueRedactor {
  const match = async (text: string) => {
    if (matcher === null || text.length > maxTextLength) return null;
    const marks = new Uint8Array(text.length);
    return { marks, found: await matcher.mark(text, marks) };
  };
  return {
    contains: async (text) => (await match(text))?.found ?? true,
    redact: async (text) => {
      const result = await match(text);
      if (result === null) return { text: unavailable, status: "unavailable" };
      return result.found
        ? { text: replaceMarked(text, result.marks), status: "redacted" }
        : { text, status: "clean" };
    },
    stream: () => knownStream(matcher),
  };
}

/**
 * Owner side only: a door that holds the raw value at final send (an echo
 * check). `null` means custody is unavailable; `[]` means none is stored.
 */
export function createKnownValueRedactor(
  values: readonly string[] | null,
): KnownValueRedactor {
  if (values === null || !validValues(values)) return knownRedactor(null);
  const registered = [...new Set(values.flatMap(variants))];
  return knownRedactor({
    holdback: Math.max(0, ...registered.map((value) => value.length - 1)),
    mark: (text, marks) => {
      let found = false;
      for (const value of registered) {
        let start = text.indexOf(value);
        while (start !== -1) {
          marks.fill(1, start, start + value.length);
          found = true;
          start = text.indexOf(value, start + 1);
        }
      }
      return Promise.resolve(found);
    },
  });
}

/**
 * What a Session host receives: HMAC-SHA256 fingerprints of every encoded
 * variant under `key`, a subkey derived from the owner's key material. It
 * holds no value and no key that can open a sealed record. Each entry is
 * `[anchor, length, fingerprint]`: a keyed rolling hash of the variant's first
 * eight code units (the scan prefilter), its length and its HMAC.
 */
export type FingerprintSet = Readonly<{
  version: 1;
  /** base64url HMAC-SHA256 subkey (32 bytes). */
  key: string;
  entries: readonly (readonly [number, number, string])[];
}>;

const fingerprintSet = z.strictObject({
  version: z.literal(1),
  key: z.base64url().length(43),
  entries: z
    .array(
      z.tuple([
        z.number().int().nonnegative().max(0xffffffff),
        z
          .number()
          .int()
          .min(anchorLength)
          .max(8 * maxSecretLength),
        z.base64url().length(43),
      ]),
    )
    .max(maxValues * 16),
});

/** Polynomial hash modulo 2^32 with a key-derived odd base. */
function anchorBase(key: Uint8Array): number {
  return (Buffer.from(key).readUInt32LE(0) | 1) >>> 0;
}
function anchorAt(text: string, start: number, base: number): number {
  let hash = 0;
  for (let index = start; index < start + anchorLength; index++)
    hash = (Math.imul(hash, base) + text.charCodeAt(index)) >>> 0;
  return hash;
}

const encoder = new TextEncoder();
type HmacKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;
async function hmacKey(bytes: Uint8Array): Promise<HmacKey> {
  return crypto.subtle.importKey(
    "raw",
    bytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}
async function fingerprint(key: HmacKey, window: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(window),
  );
  return Buffer.from(signature).toString("base64url");
}

/**
 * Owner side: `ownerKey` is the owner's own key material (the per-owner DEK);
 * HKDF-SHA256 with a redaction-only label derives the HMAC subkey, so the set
 * cannot open records. Refuses (`invalid_input`) a key shorter than 32 bytes and
 * values Vault must not store: empty, under eight code units, ill-formed or
 * over the ceilings.
 */
export async function createFingerprintSet(
  ownerKey: Uint8Array,
  values: readonly string[],
): Promise<FingerprintSet> {
  if (
    ownerKey.byteLength < 32 ||
    !validValues(values) ||
    values.some((value) => value.length < anchorLength)
  )
    throw new VeilError("invalid_input");
  const material = await crypto.subtle.importKey(
    "raw",
    ownerKey,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const subkey = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: encoder.encode(fingerprintInfo),
      },
      material,
      256,
    ),
  );
  const key = await hmacKey(subkey);
  const base = anchorBase(subkey);
  const entries: [number, number, string][] = [];
  for (const variant of new Set(values.flatMap(variants)))
    entries.push([
      anchorAt(variant, 0, base),
      variant.length,
      await fingerprint(key, variant),
    ]);
  return {
    version: 1,
    key: Buffer.from(subkey).toString("base64url"),
    entries,
  };
}

/**
 * Session side: matches a received {@link FingerprintSet}; it never sees values.
 * `null` or a malformed set yields a redactor that withholds all output.
 */
export async function createFingerprintRedactor(
  set: unknown,
): Promise<KnownValueRedactor> {
  const parsed = fingerprintSet.safeParse(set);
  if (!parsed.success) return knownRedactor(null);
  const subkey = Buffer.from(parsed.data.key, "base64url");
  const key = await hmacKey(subkey);
  const base = anchorBase(subkey);
  let shift = 1;
  for (let index = 1; index < anchorLength; index++)
    shift = Math.imul(shift, base) >>> 0;
  const lengths = new Map<number, Set<number>>();
  const fingerprints = new Set<string>();
  for (const [anchor, length, print] of parsed.data.entries) {
    lengths.set(anchor, (lengths.get(anchor) ?? new Set()).add(length));
    fingerprints.add(print);
  }
  return knownRedactor({
    holdback: Math.max(
      0,
      ...parsed.data.entries.map(([, length]) => length - 1),
    ),
    mark: async (text, marks) => {
      let found = false;
      if (text.length < anchorLength || lengths.size === 0) return found;
      let hash = anchorAt(text, 0, base);
      for (let start = 0; ; start++) {
        for (const length of lengths.get(hash) ?? []) {
          if (start + length > text.length) continue;
          if (
            fingerprints.has(
              await fingerprint(key, text.slice(start, start + length)),
            )
          ) {
            marks.fill(1, start, start + length);
            found = true;
          }
        }
        if (start + anchorLength >= text.length) return found;
        hash =
          (Math.imul(
            (hash - Math.imul(text.charCodeAt(start), shift)) | 0,
            base,
          ) +
            text.charCodeAt(start + anchorLength)) >>>
          0;
      }
    },
  });
}
