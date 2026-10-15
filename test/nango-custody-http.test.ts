import { afterEach, expect, it, vi } from "vitest";
import { createNangoModelKeyCustodian } from "../src/nango-model-keys.js";
import { createNangoWorldSeatCustodian } from "../src/nango-world-seat.js";

afterEach(() => vi.unstubAllGlobals());

type Door = Readonly<{
  name: string;
  create: (serverUrl?: string) => Readonly<{
    seal: (signal: AbortSignal) => Promise<void>;
    remove: (signal: AbortSignal) => Promise<"deleted" | "absent">;
  }>;
}>;

const doors: readonly Door[] = [
  {
    name: "model key",
    create: (serverUrl = "https://nango.example") => {
      const custodian = createNangoModelKeyCustodian({
        serverUrl,
        apiKey: "synthetic-host-key",
        integrations: { openai: "openai-key" },
      });
      return {
        seal: (signal) =>
          custodian.seal(
            {
              teamId: "team_1",
              locator: "key_1",
              provider: "openai",
              apiKey: "synthetic-credential",
            },
            signal,
          ),
        remove: (signal) =>
          custodian.remove({ locator: "key_1", provider: "openai" }, signal),
      };
    },
  },
  {
    name: "world seat",
    create: (serverUrl = "https://nango.example") => {
      const custodian = createNangoWorldSeatCustodian({
        serverUrl,
        apiKey: "synthetic-host-key",
        integrationId: "world-seat",
      });
      return {
        seal: (signal) =>
          custodian.seal(
            {
              teamId: "team_1",
              locator: "seat_1",
              endpoint: "https://vishnu.shiit.app/mcp",
              token: "synthetic-credential",
            },
            signal,
          ),
        remove: (signal) => custodian.remove({ locator: "seat_1" }, signal),
      };
    },
  },
];

it.each(doors)(
  "$name custody uses the same Nango origin policy",
  ({ create }) => {
    for (const serverUrl of [
      "http://nango.example",
      "https://user:pass@nango.example",
      "https://nango.example/path",
      "https://nango.example/?key=1",
    ])
      expect(() => create(serverUrl)).toThrow();
    expect(() => create("http://127.0.0.1:3003")).not.toThrow();
  },
);

it.each(doors)(
  "$name custody maps cancellation at the Nango boundary",
  async ({ create }) => {
    const custodian = create();
    const controller = new AbortController();
    controller.abort();
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(custodian.seal(controller.signal)).rejects.toMatchObject({
      code: "cancelled",
    });
    expect(fetch).not.toHaveBeenCalled();
  },
);

it.each(doors)(
  "$name custody rejects malformed Nango responses",
  async ({ create }) => {
    const custodian = create();
    vi.stubGlobal("fetch", () =>
      Promise.resolve(Response.json({ connection_id: "wrong_locator" })),
    );

    await expect(
      custodian.seal(new AbortController().signal),
    ).rejects.toMatchObject({
      code: "invalid_response",
    });
    vi.stubGlobal("fetch", () =>
      Promise.resolve(
        Response.json({ error: { code: "other_error" } }, { status: 400 }),
      ),
    );
    await expect(
      custodian.remove(new AbortController().signal),
    ).rejects.toMatchObject({ code: "invalid_response" });
  },
);
