/**
 * Which model credentials Fungi may use, and where. This is the single owner of
 * provider login policy: the local runtime, the TUI login registry and the Hub
 * read it; none of them decides visibility on its own.
 *
 * Stance: like Pi and OpenCode, offer a person's own subscription locally and
 * hosted, and turn a provider off through `subscriptionKillSwitch` if it
 * objects or blocks tokens. A subscription is always one person's: never
 * Team-scoped, shared or pooled. The new OpenAI ChatGPT plan flow is
 * local-only; hosted use awaits OpenAI approval. The retired Codex provider
 * is forbidden on both hosts.
 * See wiki/3-resources/decisions/adr-byok-model-keys-v1.md.
 */

/** The owner's own machine, or Fungi's servers acting for a Team. */
export type CredentialHost = "local" | "hosted";

/** A provider API key, or the provider's consumer subscription sign-in. */
export type CredentialMethod = "api_key" | "subscription";

export type CredentialPermission =
  | Readonly<{ status: "allowed" }>
  | Readonly<{ status: "forbidden"; reason: string; source: string }>
  /** Not reviewed against the provider's terms: local status quo, never hosted. */
  | Readonly<{ status: "unreviewed" }>;

type ProviderCredentialPolicy = Readonly<
  Record<
    CredentialMethod,
    Readonly<Record<CredentialHost, CredentialPermission>>
  >
>;

const allowed: CredentialPermission = { status: "allowed" };
const unreviewed: CredentialPermission = { status: "unreviewed" };
const notOffered: CredentialPermission = {
  status: "forbidden",
  reason: "The provider does not offer this credential method",
  source: "provider documentation",
};
const retiredCodex: CredentialPermission = {
  status: "forbidden",
  reason: "Use OpenAI instead of the retired OpenAI Codex provider",
  source: "wiki/3-resources/decisions/adr-byok-model-keys-v1.md",
};
const apiKeyOnly = {
  api_key: { local: allowed, hosted: allowed },
  subscription: { local: notOffered, hosted: notOffered },
} satisfies ProviderCredentialPolicy;

/**
 * Reviewed providers, keyed by Pi provider id. `openai-compatible` is a
 * Team-configured OpenAI-shaped base URL, authenticated by an API key.
 */
export const modelCredentialPolicy = Object.freeze({
  fungi: {
    api_key: { local: notOffered, hosted: notOffered },
    subscription: { local: allowed, hosted: notOffered },
  },
  anthropic: {
    api_key: { local: allowed, hosted: allowed },
    // Local: Pi's Claude Pro/Max OAuth, as Pi and OpenCode ship it. Hosted: the
    // unmodified Claude Code binary on the owner's Computer, signed in by them.
    subscription: { local: allowed, hosted: allowed },
  },
  "openai-codex": {
    api_key: { local: retiredCodex, hosted: retiredCodex },
    subscription: { local: retiredCodex, hosted: retiredCodex },
  },
  openai: {
    api_key: { local: allowed, hosted: allowed },
    subscription: {
      local: allowed,
      hosted: {
        status: "forbidden",
        reason: "ChatGPT plan usage in a hosted app requires OpenAI approval",
        source: "https://developers.openai.com/siwc/token-sharing-open-source",
      },
    },
  },
  openrouter: apiKeyOnly,
  "openai-compatible": apiKeyOnly,
} satisfies Readonly<Record<string, ProviderCredentialPolicy>>);

const reviewedPolicies = new Map<string, ProviderCredentialPolicy>(
  Object.entries(modelCredentialPolicy),
);

/**
 * Per-provider off switch for subscription sign-in, local and hosted alike.
 * Set an entry to `true` when a provider objects or starts refusing tokens.
 */
export const subscriptionKillSwitch: Readonly<Record<string, boolean>> =
  Object.freeze({ fungi: false, anthropic: false, openai: false });

/**
 * Read a runtime kill-switch override: a comma-separated provider list such as
 * `anthropic,openai`. Hosts supply it from runtime configuration (a
 * Worker secret or an environment variable), so turning a provider off needs
 * no code change or release. An override can only switch providers off.
 */
export function subscriptionKillSwitchFrom(
  raw: string | undefined,
): Readonly<Record<string, boolean>> {
  const killed = (raw ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((providerId) => /^[a-z0-9][a-z0-9-]{0,63}$/u.test(providerId))
    .map((providerId) => [providerId, true] as const);
  return Object.freeze({
    ...subscriptionKillSwitch,
    ...Object.fromEntries(killed),
  });
}

/** The one decision every login surface and credential store consults. */
export function modelCredentialPermission(
  providerId: string,
  method: CredentialMethod,
  host: CredentialHost,
): CredentialPermission {
  const policy = reviewedPolicies.get(providerId);
  return policy?.[method][host] ?? unreviewed;
}

/** Who owns a credential: one Fungi user, or the whole Team. */
export type CredentialScope = "user" | "team";

export type LoginRequest = Readonly<{
  providerId: string;
  method: CredentialMethod;
  host: CredentialHost;
  scope: CredentialScope;
}>;

/**
 * Whether this login may be offered or this credential attached. A
 * subscription belongs to one person: it is never Team-scoped, shared or
 * pooled, and a provider's kill switch turns it off. Unreviewed providers stay
 * local.
 */
export function loginAllowed(
  request: LoginRequest,
  killSwitch: Readonly<Record<string, boolean>> = subscriptionKillSwitch,
): boolean {
  if (request.method === "subscription") {
    if (request.scope !== "user") return false;
    if (killSwitch[request.providerId] === true) return false;
  }
  const permission = modelCredentialPermission(
    request.providerId,
    request.method,
    request.host,
  );
  switch (permission.status) {
    case "allowed":
      return true;
    case "forbidden":
      return false;
    case "unreviewed":
      return request.host === "local";
  }
}

/** The owner recorded with a stored credential. */
export type CredentialBinding =
  | Readonly<{ scope: "user"; teamId: string; userId: string }>
  | Readonly<{ scope: "team"; teamId: string }>;

/**
 * The run asking to use a credential. An Agent or Computer acts for the user
 * who owns it; a Team key is its own actor and owns no personal credential.
 */
export type CredentialRunner =
  | Readonly<{ teamId: string; kind: "user"; userId: string }>
  | Readonly<{
      teamId: string;
      kind: "agent" | "computer";
      ownerUserId: string;
    }>
  | Readonly<{ teamId: string; kind: "team-key" }>;

/**
 * Whether a run may use a stored credential. Team credentials serve any run in
 * their Team; a user's credential serves only that user and their own Agents
 * and Computers, never another member's run or a Team key.
 */
export function credentialUsableBy(
  binding: CredentialBinding,
  runner: CredentialRunner,
): boolean {
  if (binding.teamId !== runner.teamId) return false;
  if (binding.scope === "team") return true;
  switch (runner.kind) {
    case "user":
      return runner.userId === binding.userId;
    case "agent":
    case "computer":
      return runner.ownerUserId === binding.userId;
    case "team-key":
      return false;
  }
}
