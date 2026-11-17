import assert from "node:assert/strict";
import * as Effect from "effect/Effect";
import { it } from "vitest";
import {
  ConnectionsError,
  type CustodyAdapter,
} from "../src/connections/index.js";
import {
  proveConnectionsCaller,
  repository,
} from "./fixtures/connections-caller-laws.js";

it("keeps the same caller laws with deterministic external custody", async () => {
  const held = new Map<string, string>();
  let paused = false;
  let count = 0;
  let status = 200;
  const secret = "synthetic-caller-credential";
  const custody: CustodyAdapter = {
    put: (address, value) =>
      Effect.sync(() => {
        held.set(address.connectionId, value);
        return address.connectionId;
      }),
    inject: (_address, locator, request) =>
      Effect.suspend(() => {
        if (paused || request.signal.aborted)
          return Effect.fail(new ConnectionsError("unavailable"));
        const value = held.get(locator);
        if (value === undefined)
          return Effect.fail(new ConnectionsError("reconnect_required"));
        assert.equal(
          value === secret,
          true,
          "custody injects its stored credential",
        );
        assert.equal(new URL(request.url).pathname, "/repos/fixture/selected");
        count += 1;
        return Effect.succeed(Response.json(repository, { status }));
      }),
    remove: (_address, locator) =>
      Effect.suspend(() =>
        paused
          ? Effect.fail(new ConnectionsError("unavailable"))
          : Effect.succeed(held.delete(locator) ? "deleted" : "absent"),
      ),
  };
  await proveConnectionsCaller({
    custody,
    baseUrl: "https://metadata.example.com",
    secret,
    requests: () => count,
    pause: () => {
      paused = true;
      return Promise.resolve();
    },
    resume: () => {
      paused = false;
      return Promise.resolve();
    },
    providerStatus: (next) => {
      status = next;
    },
  });
  assert.equal(held.size, 0);
});
