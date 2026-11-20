import * as Schema from "effect/Schema";
import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import {
  createCredentialSealer,
  createOwnerCredentialSealer,
  createCredentialStore,
  CredentialError,
  type CredentialStorage,
  type StoredCredential,
} from "../src/credential-store.js";

const key = (fill: number) =>
  Buffer.from(new Uint8Array(32).fill(fill)).toString("base64url");
const keyring = { activeKeyId: "k1", keys: { k1: key(1) } };
const envelope = Schema.fromJsonString(
  Schema.Struct({
    version: Schema.Number,
    keyId: Schema.String,
    iv: Schema.String,
    ciphertext: Schema.String,
  }),
);

/** The same envelope with its ciphertext's first character changed. */
function tampered(sealed: string): string {
  const parsed = Schema.decodeUnknownSync(envelope)(sealed);
  const first = parsed.ciphertext.startsWith("A") ? "B" : "A";
  return JSON.stringify({
    ...parsed,
    ciphertext: `${first}${parsed.ciphertext.slice(1)}`,
  });
}

describe("owner envelope custody", () => {
  it("refuses copied ciphertext and copied wrapped keys under another owner", async () => {
    const database = new DatabaseSync(":memory:");
    try {
      const storage = fromNodeSqlite(database);
      const options = { storage, domain: "test.vault", keyring };
      const first = createOwnerCredentialSealer({
        ...options,
        ownerId: "team-a",
      });
      const other = createOwnerCredentialSealer({
        ...options,
        ownerId: "team-b",
      });
      const context = ["credential-1", "mcp"];
      const sealed = await first.seal(context, "synthetic-private");
      await other.seal(context, "different-private");
      await expect(other.open(context, sealed)).rejects.toMatchObject({
        code: "denied",
      });
      database.exec(
        "UPDATE veil_credential_keys SET wrapped_key = (SELECT wrapped_key FROM veil_credential_keys WHERE owner_id = 'team-a') WHERE owner_id = 'team-b'",
      );
      await expect(other.open(context, sealed)).rejects.toMatchObject({
        code: "denied",
      });
      await expect(
        first.open(["credential-2", "mcp"], sealed),
      ).rejects.toMatchObject({ code: "denied" });
      // The record layer has one key id, so an edited one is tampering, not a
      // missing keyring key.
      const parsed = Schema.decodeUnknownSync(envelope)(sealed);
      await expect(
        first.open(
          context,
          Schema.encodeSync(envelope)({ ...parsed, keyId: "rotated" }),
        ),
      ).rejects.toMatchObject({ code: "denied" });
    } finally {
      database.close();
    }
  });

  it("deleting the owner data key disables every existing custody handle and record", async () => {
    const database = new DatabaseSync(":memory:");
    try {
      const options = {
        storage: fromNodeSqlite(database),
        domain: "test.vault",
        ownerId: "team-a",
        keyring,
      };
      const first = createOwnerCredentialSealer(options);
      const other = createOwnerCredentialSealer(options);
      const kinds = ["model-key/openai", "discord-bot", "mcp"];
      const records = await Promise.all(
        kinds.map((kind) => first.seal([kind], `synthetic-${kind}`)),
      );
      first.destroy();
      for (const [index, sealed] of records.entries()) {
        await expect(
          other.open([kinds[index] ?? ""], sealed),
        ).rejects.toMatchObject({ code: "denied" });
      }
      await first.seal(["new"], "new-private");
      await expect(
        first.open([kinds[0] ?? ""], records[0] ?? ""),
      ).rejects.toMatchObject({ code: "denied" });
    } finally {
      database.close();
    }
  });

  it("rotates the wrapping key without rewriting credentials or retaining the old master key", async () => {
    const database = new DatabaseSync(":memory:");
    try {
      const storage = fromNodeSqlite(database);
      const options = { storage, domain: "test.vault", ownerId: "team-a" };
      const original = createOwnerCredentialSealer({ ...options, keyring });
      const canary = `sk-test-VAULTCANARY-${crypto.randomUUID()}`;
      const sealed = await original.seal(
        ["credential-1", "model-key/openai"],
        canary,
      );
      const rotating = createOwnerCredentialSealer({
        ...options,
        keyring: { activeKeyId: "k2", keys: { ...keyring.keys, k2: key(2) } },
      });
      await rotating.rewrap();
      const reopened = createOwnerCredentialSealer({
        ...options,
        keyring: { activeKeyId: "k2", keys: { k2: key(2) } },
      });
      expect(
        await reopened.open(["credential-1", "model-key/openai"], sealed),
      ).toBe(canary);
      const bytes = JSON.stringify(
        database.prepare("SELECT * FROM veil_credential_keys").all(),
      );
      expect(bytes).not.toContain(canary);
      expect(bytes).not.toContain(key(1));
      expect(bytes).not.toContain(key(2));
      expect(sealed).not.toContain(canary);
    } finally {
      database.close();
    }
  });
});

function memory(): CredentialStorage & { dump(): string } {
  const rows = new Map<string, StoredCredential>();
  return {
    get: (id) => Promise.resolve(rows.get(id)),
    put: (id, value) => {
      rows.set(id, structuredClone(value));
      return Promise.resolve();
    },
    delete: (id) => Promise.resolve(rows.delete(id)),
    list: (prefix) =>
      Promise.resolve(
        new Map([...rows].filter(([id]) => id.startsWith(prefix))),
      ),
    dump: () => JSON.stringify([...rows]),
  };
}

describe("credential sealer", () => {
  it("opens only under the same domain and context", async () => {
    const sealer = createCredentialSealer(keyring, "test.v1");
    const sealed = await sealer.seal(["a", "b"], "s3cret");
    expect(sealed).not.toContain("s3cret");
    expect(await sealer.open(["a", "b"], sealed)).toBe("s3cret");
    await expect(sealer.open(["a", "c"], sealed)).rejects.toMatchObject({
      code: "denied",
    });
    await expect(
      createCredentialSealer(keyring, "other.v1").open(["a", "b"], sealed),
    ).rejects.toMatchObject({ code: "denied" });
    await expect(
      createCredentialSealer(
        { activeKeyId: "k1", keys: { k1: key(2) } },
        "test.v1",
      ).open(["a", "b"], sealed),
    ).rejects.toMatchObject({ code: "denied" });
    // A keyring without the envelope's key id is a configuration fault, told
    // apart from a corrupt or tampered envelope.
    await expect(
      createCredentialSealer(
        { activeKeyId: "k2", keys: { k2: key(2) } },
        "test.v1",
      ).open(["a", "b"], sealed),
    ).rejects.toMatchObject({ code: "unknown-key" });
    await expect(
      sealer.open(["a", "b"], tampered(sealed)),
    ).rejects.toMatchObject({ code: "denied" });
    await expect(sealer.open(["a", "b"], "{}")).rejects.toMatchObject({
      code: "denied",
    });
  });

  it("refuses a malformed keyring", () => {
    expect(() =>
      createCredentialSealer({ activeKeyId: "k1", keys: { k1: "short" } }, "d"),
    ).toThrow(CredentialError);
    expect(() =>
      createCredentialSealer(
        { activeKeyId: "nope", keys: { k1: key(1) } },
        "d",
      ),
    ).toThrow(CredentialError);
  });
});

describe("credential store", () => {
  const make = (storage = memory()) =>
    createCredentialStore({
      storage,
      sealer: createCredentialSealer(keyring, "fungi.veil.credential.v1"),
      now: () => 5,
    });

  it("stores sealed bytes, lists without secrets and reveals only to a callback", async () => {
    const storage = memory();
    const store = make(storage);
    const record = await store.put({
      kind: "model-key/openai",
      label: "Work",
      secret: "sk-abc",
    });
    expect(record).toMatchObject({
      kind: "model-key/openai",
      label: "Work",
      createdAt: 5,
      validatedAt: 5,
    });
    expect(storage.dump()).not.toContain("sk-abc");
    expect(JSON.stringify(await store.list())).not.toContain("sk-abc");
    expect(await store.list("model-key/anthropic")).toEqual([]);
    expect(
      await store.withSecret(record.credentialId, (secret) => secret.length),
    ).toBe(6);
  });

  it("fails explicitly once removed or when the id is another record's", async () => {
    const store = make();
    const one = await store.put({ kind: "k", label: "1", secret: "aaa" });
    expect(await store.remove(one.credentialId)).toBe("deleted");
    expect(await store.remove(one.credentialId)).toBe("absent");
    await expect(
      store.withSecret(one.credentialId, () => "x"),
    ).rejects.toMatchObject({
      code: "absent",
    });
  });

  it("enforces its capacity", async () => {
    const store = createCredentialStore({
      storage: memory(),
      sealer: createCredentialSealer(keyring, "d"),
      limit: 1,
    });
    await store.put({ kind: "k", label: "1", secret: "a" });
    await expect(
      store.put({ kind: "k", label: "2", secret: "b" }),
    ).rejects.toMatchObject({ code: "limit" });
  });
});
