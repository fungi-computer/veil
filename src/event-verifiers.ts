import { defineIdFamily } from "@fungi.computer/cairn/id";
import nodeCrypto from "node:crypto";
import { z } from "zod";

/** The ways an inbound event may prove it came from the binding's sender. */
export const EVENT_VERIFIERS = [
  "fungi-v1",
  "github",
  "secret-url",
  "standard-webhooks",
] as const;
export type EventVerifier = (typeof EVENT_VERIFIERS)[number];

/** `secret-url` carries an unsigned shared token, so the UI labels it less secure. */
export const EVENT_VERIFIER_SECURITY = {
  "fungi-v1": "signed",
  github: "signed",
  "secret-url": "less_secure",
  "standard-webhooks": "signed",
} as const satisfies Record<EventVerifier, "signed" | "less_secure">;

/** Senders that supply no delivery id (secret-url) get one minted here. */
const eventIds = defineIdFamily({
  family: "veil",
  version: 1,
  kinds: { delivery: { prefix: "event_delivery" } },
});

export type EventRefusal = "missing" | "bad_signature" | "stale" | "malformed";

/** Never carries a secret, a signature or any header value. */
export type EventVerification =
  | Readonly<{ status: "ok"; eventId: string }>
  | Readonly<{ status: "refused"; reason: EventRefusal }>;

/** The parts of one inbound request a verifier reads; the caller bounds `body`. */
export type EventRequest = Readonly<{
  headers: Pick<Headers, "get">;
  body: Uint8Array;
  /** The token the caller extracted from the URL; only `secret-url` reads it. */
  urlToken: string | null;
  nowSeconds: number;
}>;

const secretSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const fungiSignatureSchema = z.string().regex(/^v1=[a-f0-9]{64}$/u);
const githubSignatureSchema = z.string().regex(/^sha256=[a-f0-9]{64}$/u);
const githubDeliverySchema = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/u);
const timestampSchema = z
  .string()
  .regex(/^\d{1,12}$/u)
  .transform(Number)
  .pipe(z.number().int().nonnegative());

/** A signed timestamp further than this from the receiver's clock is refused. */
export const WEBHOOK_SIGNATURE_MAX_SKEW_SECONDS = 300;

const refused = (reason: EventRefusal): EventVerification => ({
  status: "refused",
  reason,
});

/** The one comparison of secret-derived bytes. Callers pass shape-checked, fixed-length values. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && nodeCrypto.timingSafeEqual(a, b);
}

const present = (value: string | null): value is string =>
  value !== null && value !== "";

/**
 * Parse the signed-request headers and refuse a stale or future timestamp.
 * Needs no secret, so an ingress can refuse malformed traffic before it reads
 * any binding state.
 */
export function parseFungiSignatureHeaders(
  input: Readonly<{
    timestamp: string | null;
    signature: string | null;
    nowSeconds: number;
  }>,
):
  | Readonly<{ ok: true; timestamp: number; signature: string }>
  | Readonly<{ ok: false; reason: "missing" | "malformed" | "stale" }> {
  if (!present(input.timestamp) || !present(input.signature))
    return { ok: false, reason: "missing" };
  const timestamp = timestampSchema.safeParse(input.timestamp);
  const signature = fungiSignatureSchema.safeParse(input.signature);
  if (!timestamp.success || !signature.success)
    return { ok: false, reason: "malformed" };
  if (
    Math.abs(input.nowSeconds - timestamp.data) >
    WEBHOOK_SIGNATURE_MAX_SKEW_SECONDS
  )
    return { ok: false, reason: "stale" };
  return { ok: true, timestamp: timestamp.data, signature: signature.data };
}

/**
 * `x-fungi-timestamp` plus `x-fungi-signature: v1=HMAC-SHA256(secret, "<timestamp>.<body>")`,
 * keyed by the decoded secret. The event id is the signature, so a replay of
 * the same signed request is the same event.
 */
export function verifyFungiV1(
  secret: string,
  request: EventRequest,
): EventVerification {
  const headers = parseFungiSignatureHeaders({
    timestamp: request.headers.get("x-fungi-timestamp"),
    signature: request.headers.get("x-fungi-signature"),
    nowSeconds: request.nowSeconds,
  });
  if (!headers.ok) return refused(headers.reason);
  const expected = nodeCrypto
    .createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(`${String(headers.timestamp)}.`)
    .update(request.body)
    .digest();
  const claimed = headers.signature.slice(3);
  if (!constantTimeEqual(expected, Buffer.from(claimed, "hex")))
    return refused("bad_signature");
  return { status: "ok", eventId: claimed };
}

/**
 * GitHub's `X-Hub-Signature-256: sha256=HMAC-SHA256(secret, raw body)`, keyed by
 * the secret's text exactly as it was pasted into GitHub. `X-GitHub-Delivery`
 * is the event id; GitHub does not sign it, so the receiver must also bound
 * what one delivery id can admit.
 */
export function verifyGithub(
  secret: string,
  request: EventRequest,
): EventVerification {
  const signature = request.headers.get("x-hub-signature-256");
  const delivery = request.headers.get("x-github-delivery");
  if (!present(signature) || !present(delivery)) return refused("missing");
  const parsedSignature = githubSignatureSchema.safeParse(signature);
  const parsedDelivery = githubDeliverySchema.safeParse(delivery);
  if (!parsedSignature.success || !parsedDelivery.success)
    return refused("malformed");
  const expected = nodeCrypto
    .createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(request.body)
    .digest();
  if (
    !constantTimeEqual(
      expected,
      Buffer.from(parsedSignature.data.slice(7), "hex"),
    )
  )
    return refused("bad_signature");
  return { status: "ok", eventId: parsedDelivery.data };
}

/**
 * An unsigned shared token in the URL: anyone who sees the URL can send events,
 * and the body is not authenticated. The sender supplies no event id and no
 * timestamp, so every accepted request is a new event with a fresh id.
 */
export function verifySecretUrl(
  secret: string,
  request: EventRequest,
): EventVerification {
  if (!present(request.urlToken)) return refused("missing");
  const token = secretSchema.safeParse(request.urlToken);
  if (!token.success) return refused("malformed");
  if (
    !constantTimeEqual(
      Buffer.from(token.data, "utf8"),
      Buffer.from(secret, "utf8"),
    )
  )
    return refused("bad_signature");
  return { status: "ok", eventId: eventIds.delivery.generate() };
}

const standardIdSchema = z.string().regex(/^[\x21-\x7e]{1,256}$/u);
const standardSignatureSchema = z
  .string()
  .regex(/^v1,[A-Za-z0-9+/]+={0,2}$/u)
  .transform((value) => Buffer.from(value.slice(3), "base64"));

/**
 * The Standard Webhooks key bytes behind a binding's secret, in the
 * `whsec_<base64>` form senders (including Oyster's EVENTS delivery) take.
 */
export function standardWebhookSecret(secret: string): string {
  return `whsec_${Buffer.from(secret, "base64url").toString("base64")}`;
}

/**
 * Standard Webhooks: `webhook-id`, `webhook-timestamp` and
 * `webhook-signature: v1,<base64 HMAC-SHA256(key, "id.timestamp.body")>`,
 * space-separated so senders can rotate keys. The id is signed, so a sender's
 * re-signed retry keeps its event id and a captured body cannot be replayed
 * under a new one.
 */
export function verifyStandardWebhooks(
  secret: string,
  request: EventRequest,
): EventVerification {
  const id = request.headers.get("webhook-id");
  const timestamp = request.headers.get("webhook-timestamp");
  const signatures = request.headers.get("webhook-signature");
  if (!present(id) || !present(timestamp) || !present(signatures))
    return refused("missing");
  const parsedId = standardIdSchema.safeParse(id);
  const parsedTimestamp = timestampSchema.safeParse(timestamp);
  const parsedSignatures = signatures
    .split(" ")
    .map((value) => standardSignatureSchema.safeParse(value));
  if (
    !parsedId.success ||
    !parsedTimestamp.success ||
    parsedSignatures.some((parsed) => !parsed.success)
  )
    return refused("malformed");
  if (
    Math.abs(request.nowSeconds - parsedTimestamp.data) >
    WEBHOOK_SIGNATURE_MAX_SKEW_SECONDS
  )
    return refused("stale");
  const expected = nodeCrypto
    .createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(`${parsedId.data}.${String(parsedTimestamp.data)}.`)
    .update(request.body)
    .digest();
  const matched = parsedSignatures.some(
    (parsed) => parsed.success && constantTimeEqual(expected, parsed.data),
  );
  return matched
    ? { status: "ok", eventId: parsedId.data }
    : refused("bad_signature");
}
