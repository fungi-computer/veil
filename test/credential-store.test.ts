import { describe, expect, it } from "vitest";
import {
  createCredentialSealer,
  createCredentialStore,
  CredentialError,
  type CredentialStorage,
  type StoredCredential,
} from "../src/credential-store.js";

const key = (fill: number) =>
  Buffer.from(new Uint8Array(32).fill(fill)).toString("base64url");
const keyring = { activeKeyId: "k1", keys: { k1: key(1) } };

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
