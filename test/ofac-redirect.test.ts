import { expect, it, vi } from "vitest";
import { configuredProviderEgress, providerFetch } from "../src/gatekeeper.js";

const OFAC =
  "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML";
const S3 =
  "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com";
const DOWNLOAD = `${S3}/Published/list-id/2026-10-27/publication-id/SDN.XML?X-Amz-Signature=synthetic`;
const XML = "<sdnList/>";

function transport(responses: readonly Response[]) {
  const seen: Request[] = [];
  const fetch: typeof globalThis.fetch = (input, init) => {
    seen.push(new Request(input, init));
    const response = responses[seen.length - 1];
    if (response === undefined) throw new Error("unexpected extra hop");
    return Promise.resolve(response);
  };
  return { seen, fetch };
}

const redirect = (location: string, status = 302) =>
  new Response(null, {
    status,
    headers: { location, "set-cookie": "upstream-cookie" },
  });

it("follows exactly one pinned OFAC 302 GET without forwarding headers or credentials", async () => {
  const cancelled = vi.fn();
  const first = new Response(new ReadableStream({ cancel: cancelled }), {
    status: 302,
    headers: {
      location: DOWNLOAD,
      "set-cookie": "upstream-cookie",
      authorization: "upstream-secret",
    },
  });
  const { seen, fetch } = transport([first, new Response(XML)]);
  const controller = new AbortController();
  const egress = configuredProviderEgress(
    { SANCTIONS_SDN_URL: OFAC },
    { fetch },
  );
  const response = await providerFetch(egress, "sanctions-screen")(OFAC, {
    signal: controller.signal,
    headers: {
      authorization: "caller-secret",
      cookie: "caller-cookie",
      "x-api-key": "caller-key",
      "x-extra": "caller-extra",
    },
  });
  expect(await response.text()).toBe(XML);
  expect(cancelled).toHaveBeenCalledOnce();
  expect(seen.map((request) => request.url)).toEqual([OFAC, DOWNLOAD]);
  for (const request of seen) {
    expect(request.method).toBe("GET");
    expect(request.redirect).toBe("manual");
    expect([...request.headers]).toEqual([["accept", "application/xml"]]);
    expect(request.body).toBeNull();
  }
  controller.abort(new Error("original deadline"));
  expect(seen.map((request) => request.signal.aborted)).toEqual([true, true]);
  expect(egress.baseUrl("sanctions-screen")).toBe(OFAC);
  expect(response.url).toBe("");
  expect([...response.headers]).toEqual([["content-type", "application/xml"]]);
});

it("refuses unpinned hosts, paths, schemes, ports and userinfo without another fetch", async () => {
  for (const location of [
    "https://evil.example/Published/a/SDN.XML",
    DOWNLOAD.replace("amazonaws.com", "amazonaws.com.evil.example"),
    DOWNLOAD.replace("https:", "http:"),
    DOWNLOAD.replace(".com/", ".com:444/"),
    DOWNLOAD.replace("https://", "https://user:password@"),
    DOWNLOAD.replace("/Published/", "/Other/"),
    DOWNLOAD.replace("/SDN.XML", "/ALT.XML"),
    `${DOWNLOAD}#fragment`,
    "/Published/a/SDN.XML",
    "not a URL",
    `${S3}/Published/${"a".repeat(8192)}/SDN.XML`,
  ]) {
    const { fetch, seen } = transport([redirect(location)]);
    await expect(
      configuredProviderEgress({ SANCTIONS_SDN_URL: OFAC }, { fetch }).fetch(
        "sanctions-screen",
        OFAC,
      ),
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(seen).toHaveLength(1);
  }
});

it("refuses a second redirect, every non-302 redirect and direct S3 entry", async () => {
  for (const secondLocation of [DOWNLOAD, "https://evil.example/"]) {
    const { fetch, seen } = transport([
      redirect(DOWNLOAD),
      redirect(secondLocation),
    ]);
    await expect(
      configuredProviderEgress({ SANCTIONS_SDN_URL: OFAC }, { fetch }).fetch(
        "sanctions-screen",
        OFAC,
      ),
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(seen).toHaveLength(2);
  }
  for (const status of [301, 303, 307, 308]) {
    const { fetch, seen } = transport([redirect(DOWNLOAD, status)]);
    await expect(
      configuredProviderEgress({ SANCTIONS_SDN_URL: OFAC }, { fetch }).fetch(
        "sanctions-screen",
        OFAC,
      ),
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(seen).toHaveLength(1);
  }
  const { fetch, seen } = transport([]);
  const egress = configuredProviderEgress(
    { SANCTIONS_SDN_URL: OFAC },
    { fetch },
  );
  await expect(
    egress.fetch("sanctions-screen", DOWNLOAD),
  ).rejects.toMatchObject({ code: "denied" });
  for (const method of ["POST", "HEAD", "PUT"]) {
    await expect(
      egress.fetch("sanctions-screen", OFAC, { method }),
    ).rejects.toMatchObject({ code: "denied" });
  }
  expect(seen).toHaveLength(0);
});

it("does not allow the pinned redirect for either RPC route", async () => {
  const env = {
    SOLANA_RPC_URL: "https://mainnet.helius-rpc.com/",
    SOLANA_RPC_API_KEY: "synthetic-primary",
    SOLANA_RPC_FALLBACK_URL: "https://example.solana-mainnet.quiknode.pro/",
    SOLANA_RPC_FALLBACK_API_KEY: "synthetic-fallback",
  };
  for (const route of ["solana-rpc", "solana-rpc-fallback"] as const) {
    const { fetch, seen } = transport([redirect(DOWNLOAD)]);
    const egress = configuredProviderEgress(env, { fetch });
    await expect(
      egress.fetch(route, egress.baseUrl(route) ?? "", {
        method: "POST",
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getSlot" }),
      }),
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(seen).toHaveLength(1);
  }
});

it("does not restart the caller's deadline across the hop or return abort details", async () => {
  const controller = new AbortController();
  const deadline = new Error("private deadline detail");
  const seen: Request[] = [];
  const fetch: typeof globalThis.fetch = (input, init) => {
    const request = new Request(input, init);
    seen.push(request);
    if (seen.length === 1) return Promise.resolve(redirect(DOWNLOAD));
    return new Promise<Response>((_resolve, reject) => {
      request.signal.addEventListener(
        "abort",
        () => {
          reject(deadline);
        },
        { once: true },
      );
      controller.abort(deadline);
    });
  };
  await expect(
    configuredProviderEgress({ SANCTIONS_SDN_URL: OFAC }, { fetch }).fetch(
      "sanctions-screen",
      OFAC,
      { signal: controller.signal },
    ),
  ).rejects.toMatchObject({ code: "unavailable", message: "unavailable" });
  expect(seen).toHaveLength(2);
  expect(seen.every((request) => request.signal.aborted)).toBe(true);
});

it("does not start the download if the original deadline expires during redirect cleanup", async () => {
  const controller = new AbortController();
  const first = new Response(
    new ReadableStream({
      cancel() {
        controller.abort(new Error("original deadline"));
      },
    }),
    { status: 302, headers: { location: DOWNLOAD } },
  );
  const { fetch, seen } = transport([first]);
  await expect(
    configuredProviderEgress({ SANCTIONS_SDN_URL: OFAC }, { fetch }).fetch(
      "sanctions-screen",
      OFAC,
      { signal: controller.signal },
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  expect(seen).toHaveLength(1);
});

it("keeps the response size bound on the download and cancels an oversized body", async () => {
  const cancelled = vi.fn();
  const chunk = new Uint8Array(1024 * 1024);
  const { fetch, seen } = transport([
    redirect(DOWNLOAD),
    new Response(
      new ReadableStream({
        pull(controller) {
          controller.enqueue(chunk);
        },
        cancel: cancelled,
      }),
    ),
  ]);
  await expect(
    configuredProviderEgress({ SANCTIONS_SDN_URL: OFAC }, { fetch }).fetch(
      "sanctions-screen",
      OFAC,
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  expect(seen).toHaveLength(2);
  expect(cancelled).toHaveBeenCalledOnce();
});
