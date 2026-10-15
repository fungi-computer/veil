import { expect, it } from "vitest";
import * as Effect from "effect/Effect";
import * as gatekeeper from "../src/gatekeeper.js";
import type { OpenApiAccess, OpenApiCredentialStore } from "../src/openapi.js";
import type { PublicConnect, PublicSocket } from "../src/public-fetch.js";

const access: OpenApiAccess = {
  teamId: "team-test",
  connectorId: "connector-test",
  baseUrl: "https://pets.example/v1/",
  auth: { kind: "bearer" },
};
const testKey = Buffer.alloc(32, 7).toString("base64url");
const credential = "synthetic-gatekeeper-credential";

function fixture() {
  const ciphertext = new Map<string, string>();
  const requests: string[] = [];
  const addresses: string[] = [];
  const store: OpenApiCredentialStore = {
    read: (address) =>
      Promise.resolve(ciphertext.get(address.connectorId) ?? null),
    write: (address, sealed) => {
      ciphertext.set(address.connectorId, sealed);
      return Promise.resolve();
    },
    remove: (address) =>
      Promise.resolve(
        ciphertext.delete(address.connectorId) ? "deleted" : "absent",
      ),
  };
  const connect: PublicConnect = ({ hostname }) => {
    addresses.push(hostname);
    let release: () => void = () => {
      throw new Error("Write latch not initialized");
    };
    const written = new Promise<void>((resolve) => {
      release = resolve;
    });
    let sent = false;
    const socket: PublicSocket = {
      opened: Promise.resolve(),
      readable: new ReadableStream({
        async pull(controller) {
          await written;
          if (sent) controller.close();
          else {
            sent = true;
            controller.enqueue(
              new TextEncoder().encode(
                'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}',
              ),
            );
          }
        },
      }),
      writable: new WritableStream({
        write(bytes) {
          requests.push(new TextDecoder().decode(bytes));
          release();
        },
      }),
      startTls: () => socket,
      close: () => Promise.resolve(),
    };
    return socket;
  };
  const lookup: typeof fetch = (input) =>
    Promise.resolve(
      Response.json({
        Status: 0,
        Answer:
          new URL(new Request(input).url).searchParams.get("type") === "AAAA"
            ? []
            : [{ type: 1, data: "93.184.215.14" }],
      }),
    );
  return {
    options: { connect, fetch: lookup, store },
    ciphertext,
    requests,
    addresses,
  };
}

it("native Effects and Promise facade share configured keyring, store and pinned DNS", async () => {
  const f = fixture();
  const env = {
    OPENAPI_CREDENTIAL_MASTER_KEY: testKey,
    OPENAPI_CREDENTIAL_KEY_ID: "test-primary",
  };
  const effects = gatekeeper.configuredOpenApiEffects(env, f.options);
  const door = gatekeeper.configuredOpenApiDoor(env, f.options);
  await Effect.runPromise(effects.seal(access, credential));
  expect(f.ciphertext.size).toBe(1);
  expect([...f.ciphertext.values()].join("")).not.toContain(credential);
  const response = await door.send(
    access,
    new Request("https://pets.example/v1/pets"),
  );
  expect(await response.json()).toEqual({ ok: true });
  expect(f.addresses).toEqual(["93.184.215.14"]);
  expect(f.requests.join("").toLowerCase()).toContain(
    `authorization: bearer ${credential}`,
  );
  expect(await Effect.runPromise(effects.remove(access))).toBe("deleted");
  expect(f.ciphertext.size).toBe(0);
});

it("both factories apply the same host-owned deny policy before custody", async () => {
  const f = fixture();
  const options = {
    ...f.options,
    networkPolicy: {
      deniedHostSuffixes: ["pets.example"],
      deniedCidrs: ["188.245.165.0/24"],
    },
  };
  const env = { OPENAPI_CREDENTIAL_MASTER_KEY: testKey };
  const effects = gatekeeper.configuredOpenApiEffects(env, options);
  const door = gatekeeper.configuredOpenApiDoor(env, options);
  expect(
    await Effect.runPromise(
      Effect.match(effects.seal(access, credential), {
        onFailure: (error) => error.code,
        onSuccess: () => "accepted",
      }),
    ),
  ).toBe("denied");
  await expect(
    door.seal(access, credential, new AbortController().signal),
  ).rejects.toMatchObject({ code: "denied" });
  expect(f.ciphertext.size).toBe(0);
  expect(f.requests).toHaveLength(0);
});
