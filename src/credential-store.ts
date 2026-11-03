import { Buffer } from "node:buffer";
import * as Schema from "effect/Schema";
import { defineIdFamily } from "@fungi.computer/cairn";

/**
 * Veil's one encrypted credential store. A host holds a dedicated 32-byte
 * master key as a host secret; credentials (model API keys, connector tokens)
 * are sealed under it with WebCrypto AES-GCM, bound to an owner address, and
 * leave the store only into a callback. Listings carry no secret.
 */

/** Stable, secret-free reason a credential could not be sealed, opened or stored. */
export class CredentialError extends Error {
  constructor(readonly code: "unavailable" | "denied" | "absent" | "limit") {
    super(code);
    this.name = "CredentialError";
  }
}

/** Dedicated 32-byte base64url keys; the active key seals, retained keys open. */
export type CredentialKeyring = Readonly<{
  activeKeyId: string;
  keys: Readonly<Record<string, string>>;
}>;

const keySchema = Schema.String.pipe(
  Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/u)),
);
const keyIdSchema = Schema.String.pipe(
  Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{1,64}$/u)),
);
const envelopeSchema = Schema.Struct({
  version: Schema.Literal(1),
  keyId: keyIdSchema,
  iv: Schema.String.pipe(
    Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{16}$/u)),
  ),
  ciphertext: Schema.String.pipe(
    Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{22,22000}$/u)),
  ),
});
const encoder = new TextEncoder();

/**
 * WebCrypto owns authenticated encryption. `domain` and `context` are the
 * additional authenticated data: a sealed value opens only for its own owner.
 */
export function createCredentialSealer(
  configuration: CredentialKeyring,
  domain: string,
) {
  const keys = new Map<
    string,
    Promise<Awaited<ReturnType<typeof crypto.subtle.importKey>>>
  >();
  let activeKeyId: string;
  try {
    activeKeyId = Schema.decodeUnknownSync(keyIdSchema)(
      configuration.activeKeyId,
    );
    for (const [id, encoded] of Object.entries(configuration.keys)) {
      Schema.decodeUnknownSync(keyIdSchema)(id);
      const parsed = Schema.decodeUnknownSync(keySchema)(encoded);
      const bytes = Uint8Array.from(Buffer.from(parsed, "base64url"));
      if (bytes.length !== 32) throw new CredentialError("unavailable");
      keys.set(
        id,
        crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
          "encrypt",
          "decrypt",
        ]),
      );
    }
    if (!keys.has(activeKeyId)) throw new CredentialError("unavailable");
  } catch {
    throw new CredentialError("unavailable");
  }
  const key = (id: string) => {
    const found = keys.get(id);
    if (!found) throw new CredentialError("denied");
    return found;
  };
  const binding = (keyId: string, context: readonly (string | null)[]) =>
    encoder.encode(JSON.stringify([domain, keyId, ...context]));
  return {
    async seal(
      context: readonly (string | null)[],
      credential: string,
    ): Promise<string> {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: binding(activeKeyId, context),
        },
        await key(activeKeyId),
        encoder.encode(credential),
      );
      return JSON.stringify({
        version: 1,
        keyId: activeKeyId,
        iv: Buffer.from(iv).toString("base64url"),
        ciphertext: Buffer.from(ciphertext).toString("base64url"),
      });
    },
    async open(
      context: readonly (string | null)[],
      sealed: string,
    ): Promise<string> {
      try {
        const envelope = Schema.decodeUnknownSync(
          Schema.fromJsonString(envelopeSchema),
        )(sealed);
        const plaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: Uint8Array.from(Buffer.from(envelope.iv, "base64url")),
            additionalData: binding(envelope.keyId, context),
          },
          await key(envelope.keyId),
          Uint8Array.from(Buffer.from(envelope.ciphertext, "base64url")),
        );
        return new TextDecoder().decode(plaintext);
      } catch {
        throw new CredentialError("denied");
      }
    },
  };
}
export type CredentialSealer = ReturnType<typeof createCredentialSealer>;

/** What a listing shows: no secret, no ciphertext. */
export type CredentialRecord = Readonly<{
  credentialId: string;
  kind: string;
  label: string;
  createdAt: number;
  validatedAt: number;
}>;

/** One stored row: the listing fields plus the sealed envelope. */
export type StoredCredential = CredentialRecord & Readonly<{ sealed: string }>;

/** Durable Object style key-value storage; the store owns the `credential:` prefix. */
export type CredentialStorage = Readonly<{
  get(key: string): Promise<StoredCredential | undefined>;
  put(key: string, value: StoredCredential): Promise<void>;
  delete(key: string): Promise<boolean>;
  list(prefix: string): Promise<Map<string, StoredCredential>>;
}>;

const ids = defineIdFamily({
  family: "veil-credential",
  version: 1,
  kinds: { credential: { prefix: "cred" } },
});
const prefix = "credential:";

export function createCredentialStore(options: {
  storage: CredentialStorage;
  sealer: CredentialSealer;
  now?: () => number;
  /** Most credentials one store holds. */
  limit?: number;
}) {
  const now = options.now ?? Date.now;
  const limit = options.limit ?? 64;
  const publicRecord = (row: StoredCredential): CredentialRecord => ({
    credentialId: row.credentialId,
    kind: row.kind,
    label: row.label,
    createdAt: row.createdAt,
    validatedAt: row.validatedAt,
  });
  const row = async (credentialId: string) =>
    options.storage.get(`${prefix}${credentialId}`);
  return {
    /** Seal one credential bound to its id and kind. */
    async put(input: {
      kind: string;
      label: string;
      secret: string;
    }): Promise<CredentialRecord> {
      if ((await options.storage.list(prefix)).size >= limit)
        throw new CredentialError("limit");
      const credentialId = ids.credential.generate();
      const at = now();
      const stored: StoredCredential = {
        credentialId,
        kind: input.kind,
        label: input.label,
        createdAt: at,
        validatedAt: at,
        sealed: await options.sealer.seal(
          [credentialId, input.kind],
          input.secret,
        ),
      };
      await options.storage.put(`${prefix}${credentialId}`, stored);
      return publicRecord(stored);
    },
    async list(kind?: string): Promise<readonly CredentialRecord[]> {
      return [...(await options.storage.list(prefix)).values()]
        .filter((item) => kind === undefined || item.kind === kind)
        .map(publicRecord)
        .sort((a, b) => a.createdAt - b.createdAt);
    },
    async get(credentialId: string): Promise<CredentialRecord | null> {
      const found = await row(credentialId);
      return found === undefined ? null : publicRecord(found);
    },
    async remove(credentialId: string): Promise<"deleted" | "absent"> {
      return (await options.storage.delete(`${prefix}${credentialId}`))
        ? "deleted"
        : "absent";
    },
    /** The only way out: the secret exists for the callback and nowhere else. */
    async withSecret<T>(
      credentialId: string,
      action: (secret: string, record: CredentialRecord) => Promise<T> | T,
    ): Promise<T> {
      const found = await row(credentialId);
      if (found === undefined) throw new CredentialError("absent");
      const secret = await options.sealer.open(
        [found.credentialId, found.kind],
        found.sealed,
      );
      return action(secret, publicRecord(found));
    },
  };
}
export type CredentialStore = ReturnType<typeof createCredentialStore>;
