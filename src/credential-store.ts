import { Buffer } from "node:buffer";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { defineIdFamily } from "@fungi.computer/cairn";
import type { SqlStore } from "./connections/contract.js";

/**
 * Veil's one encrypted credential store. A host holds a dedicated 32-byte
 * master key as a host secret; credentials (model API keys, connector tokens)
 * are sealed under it with WebCrypto AES-GCM, bound to an owner address, and
 * leave the store only into a callback. Listings carry no secret.
 */

/**
 * Stable, secret-free reason a credential could not be sealed, opened or
 * stored. `unknown-key`: the envelope names a key id the keyring does not
 * hold, a configuration fault a restored key fixes. `denied`: the envelope is
 * malformed, bound elsewhere, or does not decrypt, which no keyring change fixes.
 */
export class CredentialError extends Error {
  constructor(
    readonly code:
      "unavailable" | "denied" | "unknown-key" | "absent" | "limit",
  ) {
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
const envelopeSchema = (version: 1 | 2) =>
  Schema.Struct({
    version: Schema.Literal(version),
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
  return credentialSealer(configuration, domain, 1);
}

function credentialSealer(
  configuration: CredentialKeyring,
  domain: string,
  version: 1 | 2,
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
        version,
        keyId: activeKeyId,
        iv: Buffer.from(iv).toString("base64url"),
        ciphertext: Buffer.from(ciphertext).toString("base64url"),
      });
    },
    async open(
      context: readonly (string | null)[],
      sealed: string,
    ): Promise<string> {
      const envelope = Schema.decodeUnknownOption(
        Schema.fromJsonString(envelopeSchema(version)),
      )(sealed);
      if (Option.isNone(envelope)) throw new CredentialError("denied");
      const { keyId, iv, ciphertext } = envelope.value;
      const found = keys.get(keyId);
      if (found === undefined) throw new CredentialError("unknown-key");
      try {
        const plaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: Uint8Array.from(Buffer.from(iv, "base64url")),
            additionalData: binding(keyId, context),
          },
          await found,
          Uint8Array.from(Buffer.from(ciphertext, "base64url")),
        );
        return new TextDecoder().decode(plaintext);
      } catch {
        throw new CredentialError("denied");
      }
    },
  };
}
export type CredentialSealer = ReturnType<typeof createCredentialSealer>;

/**
 * One random data key per owner, wrapped separately from its credential rows.
 * Only the wrapping key changes during rotation. Reads never cache the data
 * key, so deleting its row also disables already-constructed custody handles.
 * SQLite owns create-if-absent and compare-and-swap across concurrent handles.
 */
export function createOwnerCredentialSealer(options: {
  storage: SqlStore;
  keyring: CredentialKeyring;
  domain: string;
  ownerId: string;
}) {
  const { storage, keyring, domain, ownerId } = options;
  if (ownerId.length === 0) throw new CredentialError("unavailable");
  const wrapper = createCredentialSealer(keyring, `${domain}.data-key`);
  storage.sql.exec(
    "CREATE TABLE IF NOT EXISTS veil_credential_keys (owner_id TEXT PRIMARY KEY, wrapped_key TEXT NOT NULL) STRICT",
  );
  const rowSchema = Schema.Struct({ wrapped_key: Schema.String });
  const read = () => {
    const row = storage.sql
      .exec(
        "SELECT wrapped_key FROM veil_credential_keys WHERE owner_id = ?",
        ownerId,
      )
      .toArray()[0];
    return row === undefined
      ? undefined
      : Schema.decodeUnknownSync(rowSchema)(row).wrapped_key;
  };
  const load = async (create: boolean) => {
    let wrapped = read();
    if (wrapped === undefined && create) {
      const generated = Buffer.from(
        crypto.getRandomValues(new Uint8Array(32)),
      ).toString("base64url");
      const candidate = await wrapper.seal([ownerId], generated);
      storage.sql.exec(
        "INSERT INTO veil_credential_keys (owner_id, wrapped_key) VALUES (?, ?) ON CONFLICT(owner_id) DO NOTHING",
        ownerId,
        candidate,
      );
      wrapped = read();
    }
    if (wrapped === undefined) throw new CredentialError("denied");
    const dataKey = await wrapper.open([ownerId], wrapped);
    const envelope = Schema.decodeUnknownSync(
      Schema.fromJsonString(envelopeSchema(1)),
    )(wrapped);
    if (envelope.keyId !== keyring.activeKeyId) {
      const next = await wrapper.seal([ownerId], dataKey);
      const changed = storage.sql
        .exec(
          "UPDATE veil_credential_keys SET wrapped_key = ? WHERE owner_id = ? AND wrapped_key = ? RETURNING owner_id",
          next,
          ownerId,
          wrapped,
        )
        .toArray();
      if (changed.length === 0) throw new CredentialError("unavailable");
    }
    return credentialSealer(
      { activeKeyId: "data", keys: { data: dataKey } },
      `${domain}.records`,
      2,
    );
  };
  return {
    async seal(context: readonly (string | null)[], credential: string) {
      return (await load(true)).seal([ownerId, ...context], credential);
    },
    async open(context: readonly (string | null)[], sealed: string) {
      const records = await load(false);
      // Only the wrapped data key can name a key the keyring lacks. A record
      // has the one "data" key, so any other key id there is tampering.
      return records
        .open([ownerId, ...context], sealed)
        .catch((cause: unknown) => {
          throw cause instanceof CredentialError && cause.code === "unknown-key"
            ? new CredentialError("denied")
            : cause;
        });
    },
    /** Rewrap without touching any credential. Missing/deleted keys refuse. */
    async rewrap(): Promise<void> {
      await load(false);
    },
    /** Crypto-shred this owner's records; no in-memory data key survives. */
    destroy(): void {
      storage.sql.exec(
        "DELETE FROM veil_credential_keys WHERE owner_id = ?",
        ownerId,
      );
    },
  };
}
export type OwnerCredentialSealer = ReturnType<
  typeof createOwnerCredentialSealer
>;

/**
 * An owner's credential store: no keyring means no custody, and the owner's
 * envelope migration completes before any row is read or written, so the
 * store never holds a pre-migration row in hand.
 */
export function createOwnerCredentialStore(options: {
  owner: SqlStore;
  storage: CredentialStorage;
  ownerId: string;
  domain: string;
  keyring: CredentialKeyring | undefined;
  migrate?: () => Promise<void>;
  now?: () => number;
}): CredentialStore {
  const { keyring, storage, now } = options;
  if (keyring === undefined) {
    const unavailable = () =>
      Promise.reject(new CredentialError("unavailable"));
    // Listing and removal need no key; sealing and opening refuse.
    return createCredentialStore({
      storage,
      sealer: { seal: unavailable, open: unavailable },
      now: now ?? Date.now,
    });
  }
  let migration: Promise<void> | undefined;
  const ready = async () => {
    const running = (migration ??= (
      options.migrate ?? (() => migrateCredentialEnvelopes(options))
    )());
    try {
      await running;
    } catch (cause) {
      // A failed attempt is retried by the next use instead of being cached.
      if (migration === running) migration = undefined;
      throw cause;
    }
  };
  const gated: CredentialStorage = {
    get: async (key) => {
      await ready();
      return storage.get(key);
    },
    put: async (key, value) => {
      await ready();
      return storage.put(key, value);
    },
    delete: async (key) => {
      await ready();
      return storage.delete(key);
    },
    list: async (prefix) => {
      await ready();
      return storage.list(prefix);
    },
  };
  return createCredentialStore({
    storage: gated,
    sealer: createOwnerCredentialSealer({
      storage: options.owner,
      ownerId: options.ownerId,
      domain: options.domain,
      keyring,
    }),
    now: now ?? Date.now,
  });
}

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

/**
 * Explicit host migration, never a fallback reader. Each replaced row is a
 * restartable checkpoint; the completion marker closes the old representation.
 * The host runs this before admitting credential writes.
 */
export async function migrateCredentialEnvelopes(options: {
  owner: SqlStore;
  storage: CredentialStorage;
  ownerId: string;
  domain: string;
  keyring: CredentialKeyring | undefined;
}): Promise<void> {
  const { owner, storage, ownerId, domain, keyring } = options;
  owner.sql.exec(
    "CREATE TABLE IF NOT EXISTS veil_credential_migrations (owner_id TEXT NOT NULL, domain TEXT NOT NULL, version INTEGER NOT NULL, PRIMARY KEY (owner_id, domain)) STRICT",
  );
  // Without custody configured nothing can be opened or sealed; migrate once it is.
  if (keyring === undefined) return;
  const rows = await storage.list("credential:");
  const current = createOwnerCredentialSealer({
    storage: owner,
    ownerId,
    domain,
    keyring,
  });
  const complete =
    owner.sql
      .exec(
        "SELECT version FROM veil_credential_migrations WHERE owner_id = ? AND domain = ? AND version = 1",
        ownerId,
        domain,
      )
      .toArray().length !== 0;
  if (!complete) {
    const legacy = createCredentialSealer(keyring, domain);
    const decodeVersion = Schema.decodeUnknownSync(
      Schema.fromJsonString(
        Schema.Struct({ version: Schema.Literals([1, 2]) }),
      ),
    );
    for (const [key, row] of rows) {
      let version: 1 | 2;
      try {
        version = decodeVersion(row.sealed).version;
      } catch {
        throw new CredentialError("denied");
      }
      const context = [row.credentialId, row.kind];
      if (version === 2) {
        // A prior attempt committed this row before interruption.
        await current.open(context, row.sealed);
      } else {
        const secret = await legacy.open(context, row.sealed);
        await storage.put(key, {
          ...row,
          sealed: await current.seal(context, secret),
        });
      }
    }
    owner.sql.exec(
      "INSERT INTO veil_credential_migrations (owner_id, domain, version) VALUES (?, ?, 1) ON CONFLICT(owner_id, domain) DO UPDATE SET version = 1",
      ownerId,
      domain,
    );
  }
  if (rows.size !== 0) await current.rewrap();
}

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
