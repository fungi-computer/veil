import * as Schema from "effect/Schema";
import { VeilError } from "./index.js";

const text = Schema.NonEmptyString;
export const tagsSchema = Schema.Struct({
  veil_team_id: text,
  veil_attempt_id: text,
  veil_principal_id: text,
});
export const sessionSchema = Schema.Struct({
  data: Schema.Struct({
    token: text,
    connect_link: text,
    expires_at: Schema.DateFromString,
  }),
});
export const webhookEnvelopeSchema = Schema.Struct({
  type: text,
  operation: Schema.optional(text),
});
/** Nango auth webhook fields shared by creation and refresh notifications. */
export const authWebhookSchema = Schema.Struct({
  type: Schema.Literal("auth"),
  operation: Schema.Literals(["creation", "refresh"]),
  success: Schema.Boolean,
  connectionId: text,
  providerConfigKey: text,
  tags: tagsSchema,
  endUser: Schema.Struct({ endUserId: text, organizationId: text }),
});
export function publicUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new VeilError("invalid_input");
  }
  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new VeilError("invalid_input");
  return url;
}

/** The Connect document handed to browsers: Nango's issued link, confined to
 * the configured Connect UI and pinned to the configured public API. */
export function connectDocument(
  session: Readonly<{ token: string; connectUrl: string }>,
  base: URL,
  api: URL,
): string {
  let document: URL;
  try {
    document = new URL(session.connectUrl);
  } catch {
    throw new VeilError("invalid_response");
  }
  if (
    document.origin !== base.origin ||
    document.pathname !== base.pathname ||
    document.username ||
    document.password ||
    document.hash ||
    document.searchParams.get("session_token") !== session.token
  )
    throw new VeilError("invalid_response");
  document.searchParams.set("apiURL", api.href);
  return document.href;
}
