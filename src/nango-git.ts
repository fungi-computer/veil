import { VeilError } from "./index.js";
import { bestEffortCleanup } from "./best-effort-cleanup.js";

/** Private Team-owned Computer authorization, never an Agent metadata Grant. */
export type GitRepositoryAccess = Readonly<{
  repository: Readonly<{ owner: string; name: string }>;
  locator: string;
  integrationId: string;
}>;

type GitOperation = Readonly<{
  push: boolean;
  /** The request content type GitHub expects for a POST, or null for a GET. */
  requestType: string | null;
  responseType: string;
}>;

/** The four smart-HTTP exchanges this proxy admits for one repository, the
 * same operation table as the Artifacts custodian. Receive-pack is admitted
 * here; GitHub's own installation permission and branch rules decide it. */
function gitOperation(
  request: Request,
  url: URL,
  base: string,
): GitOperation | null {
  for (const service of ["git-upload-pack", "git-receive-pack"] as const) {
    const push = service === "git-receive-pack";
    if (
      request.method === "GET" &&
      url.pathname === `${base}/info/refs` &&
      url.search === `?service=${service}`
    )
      return {
        push,
        requestType: null,
        responseType: `application/x-${service}-advertisement`,
      };
    if (
      request.method === "POST" &&
      url.pathname === `${base}/${service}` &&
      url.search === ""
    )
      return {
        push,
        requestType: `application/x-${service}-request`,
        responseType: `application/x-${service}-result`,
      };
  }
  return null;
}

/** GitHub refusals keep a typed code; vendor bodies never cross this port. */
function upstreamRefusal(response: Response): VeilError {
  if (
    response.status === 429 ||
    (response.status === 403 &&
      response.headers.get("X-RateLimit-Remaining") === "0")
  )
    return new VeilError("rate_limited");
  // GitHub hides a repository outside the installation behind 404.
  if (response.status === 404) return new VeilError("repository_not_installed");
  // A read-only installation token is refused write with 403.
  if (response.status === 403) return new VeilError("denied");
  return new VeilError("unavailable");
}

/** The caller must obtain fresh Computer/repository authorization before each
 * invocation. This adapter owns Nango control headers, not authorization state. */
export function createNangoGitCustodian(
  options: Readonly<{
    serverUrl: string;
    apiKey: string;
    integrationId: string;
  }>,
) {
  if (!URL.canParse(options.serverUrl)) throw new VeilError("invalid_input");
  const server = new URL(options.serverUrl);
  if (
    !options.apiKey ||
    !options.integrationId ||
    server.username ||
    server.password ||
    server.search ||
    server.hash ||
    server.pathname !== "/" ||
    !["http:", "https:"].includes(server.protocol)
  )
    throw new VeilError("invalid_input");

  return {
    /** Fetch, clone and push for one authorized repository. */
    async readGit(
      access: GitRepositoryAccess,
      request: Request,
    ): Promise<Response> {
      if (access.integrationId !== options.integrationId)
        throw new VeilError("denied");
      const url = new URL(request.url);
      const parts = [access.repository.owner, access.repository.name];
      if (
        !access.locator ||
        parts.some((part) => !part || part === "." || part === "..")
      )
        throw new VeilError("invalid_input");
      const base = `/${parts.map(encodeURIComponent).join("/")}.git`;
      const operation = gitOperation(request, url, base);
      if (
        url.origin !== "https://github.com" ||
        url.username ||
        url.password ||
        url.hash ||
        operation === null
      )
        throw new VeilError("denied");
      const headers = new Headers({
        Authorization: `Bearer ${options.apiKey}`,
        "Provider-Config-Key": options.integrationId,
        "Connection-Id": access.locator,
      });
      if (operation.requestType !== null) {
        headers.set("Content-Type", operation.requestType);
        headers.set("Nango-Proxy-Content-Type", operation.requestType);
      }
      const protocol = request.headers.get("Git-Protocol");
      if (protocol !== null) headers.set("Nango-Proxy-Git-Protocol", protocol);
      let response: Response;
      try {
        request.signal.throwIfAborted();
        response = await fetch(
          new URL(`/proxy${url.pathname}${url.search}`, server),
          {
            method: request.method,
            headers,
            body: operation.requestType === null ? null : request.body,
            signal: request.signal,
            redirect: "manual",
            // Native Node fetch requires this for a stream; Workers accepts it.
            duplex: "half",
          },
        );
      } catch (cause) {
        throw new VeilError(
          request.signal.aborted ? "cancelled" : "unavailable",
          cause,
        );
      }
      if (!response.ok) {
        await bestEffortCleanup(
          "nango-git-response-body",
          () => response.body?.cancel() ?? Promise.resolve(),
        );
        // Reads keep their retried `unavailable`; a push names its refusal.
        throw operation.push
          ? upstreamRefusal(response)
          : new VeilError("unavailable");
      }
      if (response.headers.get("Content-Type") !== operation.responseType) {
        await bestEffortCleanup(
          "nango-git-response-body",
          () => response.body?.cancel() ?? Promise.resolve(),
        );
        throw new VeilError("invalid_response");
      }
      // A protected-branch or hook refusal is GitHub's own report-status
      // inside this 200 body; the Computer's git prints it unchanged.
      return new Response(response.body, {
        status: response.status,
        headers: {
          "Content-Type": operation.responseType,
          "Cache-Control": "no-store",
        },
      });
    },
  };
}
