import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { createCredentialSealer } from "../src/credential-store.js";
import {
  createFingerprintRedactor,
  createFingerprintSet,
  createKnownValueRedactor,
  createPatternRedactor,
  type KnownValueRedactor,
} from "../src/redaction.js";

const ownerKey = new Uint8Array(32).fill(7);
const constructors = {
  "owner raw values": (values: readonly string[]) =>
    Promise.resolve(createKnownValueRedactor(values)),
  "Session fingerprints": async (values: readonly string[]) =>
    createFingerprintRedactor(await createFingerprintSet(ownerKey, values)),
} satisfies Record<
  string,
  (values: readonly string[]) => Promise<KnownValueRedactor>
>;

async function streamed(
  redactor: KnownValueRedactor,
  chunks: readonly string[],
): Promise<string> {
  const stream = redactor.stream();
  let output = "";
  for (const chunk of chunks) output += (await stream.write(chunk)).text;
  return output + (await stream.finish()).text;
}

describe.each(Object.entries(constructors))("%s", (_name, make) => {
  it("finds stored passwords inside Basic credentials at every byte alignment", async () => {
    const secret = "VaultCanary/unique-97+password";
    const redactor = await make([secret]);
    for (const user of ["a", "ab", "abc"]) {
      const credential = Buffer.from(`${user}:${secret}`).toString("base64");
      expect(await redactor.contains(`Basic ${credential}`), user).toBe(true);
      expect((await redactor.redact(`Basic ${credential}`)).text).not.toContain(
        credential,
      );
    }
  });

  it("redacts a secret inside a larger base64 document at every byte alignment", async () => {
    // Assembled at runtime so the public-split secret scan sees no literal.
    const secret = ["vault-mid-b64", "canary-41"].join("-");
    const redactor = await make([secret]);
    for (const encoding of ["base64", "base64url"] as const) {
      for (const pad of ["", "x", "xy"]) {
        const head = `{"token":"${pad}`;
        const payload = Buffer.from(`${head}${secret}"}`).toString(encoding);
        // Characters whose six bits all come from the secret's bytes.
        const first = Math.ceil((8 * head.length) / 6);
        const last = Math.floor((8 * (head.length + secret.length)) / 6);
        const stable = payload.slice(first, last);
        const label = `${encoding} pad=${String(pad.length)}`;
        expect(await redactor.contains(payload), label).toBe(true);
        const { text } = await redactor.redact(payload);
        expect(text, label).not.toContain(stable);
        const marker = text.indexOf("[REDACTED]");
        expect(marker, label).toBeGreaterThanOrEqual(0);
        expect(marker, label).toBeLessThanOrEqual(first);
        expect(text.length - marker - 10, label).toBeLessThanOrEqual(
          payload.length - last,
        );
        for (let chunks = 2; chunks <= 5; chunks++) {
          const width = Math.ceil(payload.length / chunks);
          const parts: string[] = [];
          for (let start = 0; start < payload.length; start += width)
            parts.push(payload.slice(start, start + width));
          expect(await streamed(redactor, parts), label).not.toContain(stable);
        }
      }
    }
  });

  it("redacts a non-ASCII value written with JSON \\u escapes", async () => {
    const secret = "clé-secrète-vault-ü-17";
    const redactor = await make([secret]);
    const escaped = secret.replace(
      /[^\x20-\x7e]/gu,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
    const text = `{"token":"${escaped}"}`;
    expect((await redactor.redact(text)).text).toBe('{"token":"[REDACTED]"}');
  });

  it("merges overlapping known values into one marker without rewriting it", async () => {
    const redactor = await make(["abcdefDEFGHI", "DEFGHIjklmno", "REDACTED"]);
    expect(await redactor.redact("abcdefDEFGHIjklmno")).toEqual({
      text: "[REDACTED]",
      status: "redacted",
    });
  });

  it("redacts a secret split across two to five stream chunks", async () => {
    const secret = "stream-canary-vault-97";
    const redactor = await make([secret]);
    for (let chunks = 2; chunks <= 5; chunks++) {
      const width = Math.ceil(secret.length / chunks);
      const parts: string[] = [];
      for (let start = 0; start < secret.length; start += width)
        parts.push(secret.slice(start, start + width));
      expect(await streamed(redactor, parts)).toBe("[REDACTED]");
    }
  });

  it("covers every supported encoding at every two-chunk seam", async () => {
    const secret = 'vault-canary-ü/"?97+=';
    const redactor = await make([secret]);
    const forms = [
      secret,
      `Bearer ${secret}`,
      JSON.stringify(secret).slice(1, -1),
      encodeURIComponent(secret),
      encodeURIComponent(secret).toLowerCase(),
      Buffer.from(secret).toString("hex"),
      Buffer.from(secret).toString("hex").toUpperCase(),
      Buffer.from(secret).toString("base64"),
      Buffer.from(secret).toString("base64url"),
      ...["a", "ab", "abc"].map((user) =>
        Buffer.from(`${user}:${secret}`).toString("base64"),
      ),
    ];
    for (const form of forms) {
      expect(await redactor.contains(`prefix ${form} suffix`)).toBe(true);
      const whole = (await redactor.redact(form)).text;
      expect(whole).not.toContain(form);
      expect(whole).toContain("[REDACTED]");
      // A Basic form keeps its username's base64 prefix; the secret never leaves.
      for (let split = 1; split < form.length; split++)
        expect(
          await streamed(redactor, [form.slice(0, split), form.slice(split)]),
          `split ${String(split)}`,
        ).toBe(whole);
    }
  });

  it("keeps a matched run held until an overlapping secret can no longer extend it", async () => {
    const redactor = await make(["alpha-secret-key", "secret-key-omega"]);
    const stream = redactor.stream();
    const output = [
      await stream.write("alpha-secret-key-"),
      await stream.write("omega then arbitrary tail"),
      await stream.finish(),
    ];
    expect(output.map(({ text }) => text).join("")).toBe(
      "[REDACTED] then arbitrary tail",
    );
    expect((await stream.write("after finish")).status).toBe("unavailable");
  });

  it("holds exactly longest variant minus one and flushes clean text unchanged", async () => {
    // ASCII secret's hex encoding is its longest variant: 40 characters.
    const stream = (await make(["vault-key-1234567890"])).stream();
    expect((await stream.write(".".repeat(100))).text).toBe(".".repeat(61));
    expect(await stream.finish()).toEqual({
      text: ".".repeat(39),
      status: "clean",
    });
  });

  it("withholds a stream whose writes overlap instead of interleaving output", async () => {
    const stream = (await make(["vault-key-1234567890"])).stream();
    const first = stream.write("first chunk ".repeat(10));
    const second = stream.write("second chunk ".repeat(10));
    expect((await second).status).toBe("unavailable");
    expect(await first).toEqual({
      text: "[output withheld: redaction unavailable]",
      status: "unavailable",
    });
    expect((await stream.finish()).text).not.toContain("chunk");
  });

  it("does not mistake Git SHAs, UUIDs or discussions of API keys for a secret", async () => {
    const text =
      "API key setup 18c3145d6874aaf873cecb863c150da1b6e64ca0 6c72b8dc-4744-46da-a99a-d58db4290d48";
    const redactor = await make(["unrelated-stored-canary-17"]);
    expect(await redactor.contains(text)).toBe(false);
    expect(await redactor.redact(text)).toEqual({ text, status: "clean" });
  });
});

it("withholds raw-value output when custody is unavailable or values are invalid", async () => {
  const missing = createKnownValueRedactor(null);
  expect(await missing.contains("anything")).toBe(true);
  expect(await missing.redact("private output")).toEqual({
    text: "[output withheld: redaction unavailable]",
    status: "unavailable",
  });
  const stream = missing.stream();
  expect((await stream.write("private output")).status).toBe("unavailable");
  expect((await stream.finish()).text).not.toContain("private output");
  expect(await createKnownValueRedactor([]).redact("ordinary output")).toEqual({
    text: "ordinary output",
    status: "clean",
  });
  for (const values of [[""], ["x".repeat(16385)], ["\ud800"]])
    expect(
      (await createKnownValueRedactor(values).redact("private output")).status,
    ).toBe("unavailable");
});

it("withholds Session output when the fingerprint set is missing or malformed", async () => {
  const good = await createFingerprintSet(ownerKey, ["vault-canary-fp-01"]);
  for (const set of [
    null,
    {},
    { ...good, version: 2 },
    { ...good, key: "short" },
    { ...good, entries: [[1, 3, "x"]] },
  ]) {
    const redactor = await createFingerprintRedactor(set);
    expect(await redactor.contains("ordinary output")).toBe(true);
    expect((await redactor.redact("private output")).status).toBe(
      "unavailable",
    );
    expect((await redactor.stream().write("private output")).text).toBe(
      "[output withheld: redaction unavailable]",
    );
  }
  const empty = await createFingerprintRedactor(
    await createFingerprintSet(ownerKey, []),
  );
  expect(await empty.redact("ordinary output")).toEqual({
    text: "ordinary output",
    status: "clean",
  });
});

it("refuses values the fingerprint matcher cannot anchor and a weak owner key", async () => {
  for (const [key, values] of [
    [ownerKey, ["short7!"]],
    [ownerKey, ["\ud800-vault-value"]],
    [new Uint8Array(16), ["vault-canary-fp-02"]],
  ] as const)
    await expect(createFingerprintSet(key, values)).rejects.toMatchObject({
      code: "invalid_input",
    });
});

it("gives Session hosts no stored value and no key that can open the record", async () => {
  // A unique provider-shaped canary, assembled so source scanners see no key.
  const secret = ["sk-test", "VAULTCANARY", "5f1c2e"].join("-");
  const sealer = createCredentialSealer(
    {
      activeKeyId: "owner",
      keys: { owner: Buffer.from(ownerKey).toString("base64url") },
    },
    "vault.test.v1",
  );
  const sealed = await sealer.seal(["team", "secret"], secret);
  const set = await createFingerprintSet(ownerKey, [secret]);
  const wire = JSON.stringify(set);
  for (const form of [
    secret,
    Buffer.from(secret).toString("base64"),
    Buffer.from(secret).toString("hex"),
    encodeURIComponent(secret),
  ])
    expect(wire).not.toContain(form);
  expect(set.key).not.toBe(Buffer.from(ownerKey).toString("base64url"));
  await expect(
    createCredentialSealer(
      { activeKeyId: "owner", keys: { owner: set.key } },
      "vault.test.v1",
    ).open(["team", "secret"], sealed),
  ).rejects.toMatchObject({ code: "denied" });
  const redactor = await createFingerprintRedactor(JSON.parse(wire));
  expect((await redactor.redact(`env: ${secret}`)).text).toBe(
    "env: [REDACTED]",
  );
});

it("detects an unknown GitHub token in a paste without any stored value", () => {
  const token = ["ghp_", "7Zk9P2mQa4Wv6Xc8Bn0Ds3Fg5Hj1Lr9Ty2Ui"].join("");
  const redactor = createPatternRedactor();
  const paste = `please use ${token} for this request`;
  expect(redactor.contains(paste)).toBe(true);
  expect(redactor.redact(paste).text).not.toContain(token);
});

it("does not mistake Git SHAs, UUIDs or discussions of API keys for an unknown key", () => {
  const text =
    "API key setup 18c3145d6874aaf873cecb863c150da1b6e64ca0 6c72b8dc-4744-46da-a99a-d58db4290d48";
  const redactor = createPatternRedactor();
  expect(redactor.contains(text)).toBe(false);
  expect(redactor.redact(text)).toEqual({ text, status: "clean" });
});

it("honors gitleaks entropy and content allowlists but not an untrusted allow comment", () => {
  const redactor = createPatternRedactor();
  expect(redactor.contains(`ghp_${"a".repeat(36)}`)).toBe(false);
  expect(redactor.contains('api_key = "${MY_API_KEY}"')).toBe(false);
  const token = ["ghp_", "7Zk9P2mQa4Wv6Xc8Bn0Ds3Fg5Hj1Lr9Ty2Ui"].join("");
  expect(redactor.contains(`${token} # gitleaks:allow`)).toBe(true);
  expect(redactor.redact(`api_key = "${token}"`).text).not.toContain(token);
});

it("rejects an unsupported upstream RE2 rule at build time and names its id", () => {
  const source = readFileSync(
    new URL("../vendor/gitleaks.toml", import.meta.url),
    "utf8",
  );
  const build = new URL(
    "../scripts/build-redaction-rules.mjs",
    import.meta.url,
  );
  const result = spawnSync(process.execPath, [build.pathname, "--check"], {
    encoding: "utf8",
    input: `${source}\n[[rules]]\nid = "unsupported-rule-canary"\ndescription = "Invalid RE2"\nregex = '(?=secret)'\n`,
    timeout: 10000,
  });
  expect(result.error).toBeUndefined();
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("unsupported-rule-canary");
  expect(result.stderr).toContain("could not compile");
});
