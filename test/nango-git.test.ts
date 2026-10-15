import { afterEach, expect, it, vi } from "vitest";
import { createNangoGitCustodian } from "../src/nango-git.js";

const custodian = createNangoGitCustodian({
  serverUrl: "https://nango.example",
  apiKey: "synthetic-host-key",
  integrationId: "github-git",
});
const access = {
  repository: { owner: "fungi-computer", name: "Botanical-next" },
  locator: "private-connection",
  integrationId: "github-git",
};
const root = "https://github.com/fungi-computer/Botanical-next.git";
afterEach(() => vi.unstubAllGlobals());

it("owns Nango headers and preserves native Git request and response bytes", async () => {
  const bytes = new Uint8Array([0, 255, 128, 10]);
  vi.stubGlobal("fetch", async (input: URL, init: RequestInit) => {
    expect(input.href).toBe(
      "https://nango.example/proxy/fungi-computer/Botanical-next.git/git-upload-pack",
    );
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer synthetic-host-key");
    expect(headers.get("Connection-Id")).toBe("private-connection");
    expect(headers.get("Provider-Config-Key")).toBe("github-git");
    expect(headers.get("Nango-Proxy-Authorization")).toBeNull();
    expect(headers.get("Nango-Proxy-Git-Protocol")).toBe("version=2");
    expect(init.redirect).toBe("manual");
    expect(new Uint8Array(await new Response(init.body).arrayBuffer())).toEqual(
      bytes,
    );
    return new Response(bytes, {
      headers: {
        "Content-Type": "application/x-git-upload-pack-result",
        "Set-Cookie": "private=value",
      },
    });
  });
  const response = await custodian.readGit(
    access,
    new Request(`${root}/git-upload-pack`, {
      method: "POST",
      body: bytes,
      headers: {
        Authorization: "untrusted",
        "Connection-Id": "other",
        "Nango-Proxy-Authorization": "untrusted",
        "Git-Protocol": "version=2",
      },
    }),
  );
  expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
  expect(response.headers.get("Set-Cookie")).toBeNull();
});

it("pushes to the authorized repository and returns GitHub's report unchanged", async () => {
  const pack = new Uint8Array([80, 65, 67, 75, 0, 1]);
  // A protected-branch refusal is GitHub's report-status, not a proxy error.
  const report =
    "0030\x01000eunpack ok\n0035\x01ng refs/heads/main protected branch hook declined\n00000000";
  const seen: string[] = [];
  vi.stubGlobal("fetch", async (input: URL, init: RequestInit) => {
    seen.push(`${init.method ?? "GET"} ${input.href}`);
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer synthetic-host-key");
    expect(headers.get("Connection-Id")).toBe("private-connection");
    expect(headers.get("Nango-Proxy-Authorization")).toBeNull();
    if (init.method === "GET")
      return new Response("advertisement", {
        headers: {
          "Content-Type": "application/x-git-receive-pack-advertisement",
        },
      });
    expect(headers.get("Nango-Proxy-Content-Type")).toBe(
      "application/x-git-receive-pack-request",
    );
    expect(new Uint8Array(await new Response(init.body).arrayBuffer())).toEqual(
      pack,
    );
    return new Response(report, {
      headers: { "Content-Type": "application/x-git-receive-pack-result" },
    });
  });
  const advertised = await custodian.readGit(
    access,
    new Request(`${root}/info/refs?service=git-receive-pack`, {
      headers: { Authorization: "Basic untrusted" },
    }),
  );
  expect(advertised.headers.get("Content-Type")).toBe(
    "application/x-git-receive-pack-advertisement",
  );
  await advertised.body?.cancel();
  const pushed = await custodian.readGit(
    access,
    new Request(`${root}/git-receive-pack`, { method: "POST", body: pack }),
  );
  expect(await pushed.text()).toBe(report);
  expect(seen).toEqual([
    "GET https://nango.example/proxy/fungi-computer/Botanical-next.git/info/refs?service=git-receive-pack",
    "POST https://nango.example/proxy/fungi-computer/Botanical-next.git/git-receive-pack",
  ]);
});

it.each([
  [429, {}, "rate_limited"],
  [403, { "X-RateLimit-Remaining": "0" }, "rate_limited"],
  [404, {}, "repository_not_installed"],
  [403, {}, "denied"],
] as const)(
  "types GitHub's push refusal %i %o as %s",
  async (status, headers, code) => {
    vi.stubGlobal("fetch", () =>
      Promise.resolve(
        new Response("synthetic-private-error", { status, headers }),
      ),
    );
    await expect(
      custodian.readGit(
        access,
        new Request(`${root}/git-receive-pack`, { method: "POST", body: "x" }),
      ),
    ).rejects.toMatchObject({ code, message: code });
  },
);

it("denies another repository, other hosts and non-Git requests before egress", async () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  for (const request of [
    new Request(
      "https://github.com/fungi-computer/other.git/info/refs?service=git-upload-pack",
    ),
    new Request(
      "https://github.com/fungi-computer/other.git/git-receive-pack",
      {
        method: "POST",
      },
    ),
    new Request(
      "https://gitlab.com/fungi-computer/Botanical-next.git/git-receive-pack",
      { method: "POST" },
    ),
    new Request(`${root}/git-receive-pack`, { method: "PUT" }),
    new Request(`${root}/HEAD`),
  ])
    await expect(custodian.readGit(access, request)).rejects.toMatchObject({
      code: "denied",
    });
  expect(fetch).not.toHaveBeenCalled();
});

it("does not expose custody error bodies or follow redirects", async () => {
  for (const status of [302, 401, 500]) {
    vi.stubGlobal("fetch", () =>
      Promise.resolve(
        new Response("synthetic-private-error", {
          status,
          headers: { Location: "https://other.example" },
        }),
      ),
    );
    await expect(
      custodian.readGit(
        access,
        new Request(`${root}/info/refs?service=git-upload-pack`),
      ),
    ).rejects.toMatchObject({ message: "unavailable", code: "unavailable" });
  }
});

it("denies pre-aborted work without fetching", async () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const abort = new AbortController();
  abort.abort();
  await expect(
    custodian.readGit(
      access,
      new Request(`${root}/info/refs?service=git-upload-pack`, {
        signal: abort.signal,
      }),
    ),
  ).rejects.toMatchObject({ code: "cancelled" });
  expect(fetch).not.toHaveBeenCalled();
});

it("rejects non-Git success bodies rather than labeling them Git", async () => {
  vi.stubGlobal("fetch", () =>
    Promise.resolve(
      new Response("private unexpected page", {
        headers: { "Content-Type": "text/html" },
      }),
    ),
  );
  await expect(
    custodian.readGit(
      access,
      new Request(`${root}/info/refs?service=git-upload-pack`),
    ),
  ).rejects.toMatchObject({ code: "invalid_response" });
});

it("forwards cancellation to the maintained fetch", async () => {
  const abort = new AbortController();
  vi.stubGlobal(
    "fetch",
    (_url: URL, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener(
          "abort",
          () => {
            reject(new Error("synthetic private transport error"));
          },
          { once: true },
        );
        abort.abort();
      }),
  );
  await expect(
    custodian.readGit(
      access,
      new Request(`${root}/info/refs?service=git-upload-pack`, {
        signal: abort.signal,
      }),
    ),
  ).rejects.toMatchObject({ code: "cancelled", message: "cancelled" });
});

it("does not reinterpret a connection from the metadata integration", async () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(
    custodian.readGit(
      { ...access, integrationId: "github-metadata" },
      new Request(`${root}/info/refs?service=git-upload-pack`),
    ),
  ).rejects.toMatchObject({ code: "denied" });
  expect(fetch).not.toHaveBeenCalled();
});
