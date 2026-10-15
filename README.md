# Veil (`@fungi.computer/veil`)

This package keeps provider credentials behind trusted Team doors. It owns
GitHub Connection custody, model-key grants and the Agent's anonymous public-web
fetch. A guest receives an authorized operation, not the provider token or its
private locator.

## Set up and check

The host supplies Team Connection authority and a `CredentialCustodian` to
`createGitHubConnections`. Model input cannot select a repository or private
locator. The `@fungi.computer/veil/nango` adapter needs a configured Nango
origin, API key, webhook signing key, integration ID and public Connect URLs;
these are host secrets or configuration, never browser or model input. Without
custody configuration, report unavailable rather than manufacturing a
connection.

Run `pnpm --filter @fungi.computer/veil test` for the package's synthetic
custody, signed-webhook and public-fetch checks. For an exercised connection
lifecycle, start with `test/nango-git.test.ts`; a unit test does not prove a
live Nango service or provider account.

The root export in `src/index.ts` defines Team Connection receipts and
`createGitHubConnections`. `package.json` lists the Nango, model-key and
public-fetch subpaths used by trusted hosts; do not import private locators from
these modules into guest code.

## Nango adapter

`@fungi.computer/veil/nango` exports `createNangoCustodian`. The trusted host
supplies a Nango server origin, API key, separate webhook signing key, one
integration ID, and the public Connect UI base and public API URL. These are
host configuration, never browser or model input. `openSession` returns the
Connect document browsers open: Nango's issued link, confined to the configured
Connect UI and pinned to the public API with `apiURL`. Unconfigured hosts must
report unavailable instead of substituting fake custody.

The adapter uses `@nangohq/node@0.71.6` to verify the raw callback body and
ordinary `fetch` with each invocation's AbortSignal for REST operations. It does
not call credential-returning connection inspection. Connect sessions carry
Team-created attempt/principal/Team tags and restrict the integration. Signed
webhooks are verified before decoding; the adapter handles only a successful
`creation` and a failed `refresh` (reconnect evidence) and refuses every other
operation as `unsupported`. It also checks end-user and organization
correlation; Team owns final activation and replay decisions. A verified
completion the Team refuses (late, unknown, superseded, or failing activation)
is deleted from custody, and the settled deletion is recorded.

Reconciliation queries `/connections` with exact integration, end-user,
organization and attempt tags and a limit of two. The selected server filters
before applying that limit: zero matches remain unresolved, multiple matches are
ambiguous, and every returned row is checked again before a single completion is
accepted. It never selects the first candidate from an arbitrary page.

The pinned public deletion endpoint returns `200 {success:true}` after deletion
and `400 {error:{code:"unknown_connection"}}` when the selected connection is
absent. Other responses, including generic 404 and `success:false`, do not
settle cleanup. This mapping is specific to the selected server implementation,
not a generic Nango error policy. Provider/proxy failures stay unavailable,
except a proxied provider `401` carrying GitHub's own error body, which marks
the Connection reconnect-required; Nango's own `401` envelope stays unavailable.

The one proxy operation is `GET /proxy/repos/{owner}/{name}` with private Nango
connection/integration headers. Veil's existing caller decodes credential-free
metadata and verifies the repository ID. Cancellation stops waiting through the
maintained transport; it does not prove upstream work stopped or rolled back.

## Public-web door

`@fungi.computer/veil/public-fetch` is the one sanctioned egress for the Agent's
`web.fetch`. `configuredPublicFetch({ connect, fetch })` returns `get`, an
anonymous GET that carries no credential and only `Accept` and `User-Agent`
request headers. Each call resolves the name once (DNS-over-HTTPS through
`fetch`), refuses the whole name if any answer is not public unicast (IPv4 and
IPv6, including loopback, private, link-local, metadata, IPv4-mapped, NAT64,
6to4 and Teredo forms), and passes only those checked addresses to the host's
socket primitive (`cloudflare:sockets` `connect` in the Hub). The URL's own name
stays the `Host` header and the TLS server name, so a second lookup cannot move
the connection. `get` never follows a redirect; the caller's next hop is a new
call that resolves and checks again. The response is framed by `http-parser-js`;
compressed, layered-coded and over-long-header responses are refused.

Workerd's `startTls({ expectedServerHostname })` verifies the certificate
against that name; it reports a verification failure on the first read, which
the door types as `unavailable`.

## Model credentials and failure handling

`src/model-credentials.ts` selects which key class may serve an inference
request. Personal keys do not become an App's credential; App-originated
requests use Team-authorized custody or refuse. The custodian handles provider
egress and lifecycle. An authorized Team actor can disconnect a Connection; a
failed refresh marks it reconnect-required. A late or superseded completion is
not silently activated. A canceled request stops the caller waiting, but does
not prove the provider stopped work already admitted.

No provider credential, service startup, hosted deployment or backup recovery is
established by installing or testing this adapter. Verify the configured service
and Team owner separately. The manifest declares MIT; follow the repository's
contribution instructions.

## OpenAPI door

`@fungi.computer/veil/openapi` exposes the private `createOpenApiDoor` Promise
facade. `./openapi-effect` owns the same typed Effect program. Only the Team
Connector owner calls this door, after checking current attachment revision,
selected operation and read/write effect. This is not a guest raw-request tool.

Anonymous, API-key header/query and bearer requests share the public-fetch
socket implementation: public HTTPS only, one checked DNS resolution, pinned
address with the original Host/TLS name, and no redirect following. The owner
passes the pinned base URL and the selected operation's declared header names.
The door refuses reserved headers, auth overrides and targets outside the base
path. Request and response bodies are capped at 256 KiB, the whole operation at
30 seconds, and the HTTP parser caps response headers at 64 KiB. Responses carry
only text/JSON and their media type; upstream cookies and other headers are not
returned. Non-2xx responses expose `upstream_status` and the numeric status,
without upstream error text. Common credential echoes are redacted.

`configuredOpenApiDoor` reads `OPENAPI_CREDENTIAL_MASTER_KEY` only in the
Gatekeeper. This dedicated 32-byte base64url Worker secret seals credentials
with WebCrypto AES-GCM. The host supplies an `OpenApiCredentialStore` that
persists ciphertext only, keyed by Team and Connector. Authenticated data binds
it to that owner, pinned base and auth policy. The store must honor cancellation
before a write; ciphertext stays with its private owner, never an Agent fact,
browser DTO or log. Removal is idempotent. Changing the base or auth policy
requires resealing; a copied ciphertext cannot authorize another owner or host.
The host owns durable cleanup and key provisioning/recovery; this package does
not install a secret, persist plaintext or contact a remote service during
tests. Missing custody or credentials is a typed refusal, not anonymous
fallback.

OAuth is restricted to host-configured `OpenApiOAuthProvider` ports, backed by
the existing Nango proxy. The provider fixes its base; a spec cannot choose
another destination. Nango retains OAuth custody and its own egress policy. No
generic OAuth provider or new Nango instance is introduced. An unconfigured
provider refuses `oauth_not_configured`. API-key/bearer traffic never uses
Nango.

C4's typed refusals are `denied`, `invalid_input`, `invalid_response`,
`too_large`, `timeout`, `cancelled`, `unavailable`, `credentials_missing`,
`oauth_not_configured` and `upstream_status` (with numeric `status`). Errors
never carry request URLs, credential bytes, raw response text or transport
causes.

The host supplies `networkPolicy.extraPorts` (default empty),
`deniedHostSuffixes` (exact names plus child names), and `deniedCidrs` for its
own infrastructure. No deployment addresses are hardcoded. OpenAPI permits HTTPS
on 443 unless the host explicitly adds a port. The same pinned HTTP adapter
checks policy against the URL host and **every** checked DNS answer; one denied
answer refuses the whole call. CIDR parsing and matching belong to ipaddr.js,
including mapped IPv4. The older anonymous public-web GET contract also permits
ordinary HTTP port 80; arbitrary ports require host configuration. These
policies come from trusted host configuration, never Connector data.

Custody uses `keys: { activeKeyId, keys }`, with dedicated 32-byte base64url
keys indexed by a bounded non-secret id. Envelopes carry version 1 and key id;
the key id is authenticated along with Team, Connector, base and auth policy. On
rotation, retain old keys for reads while all new seals use the active key.
Retire an old key only once its remaining records have been resealed or removed.
`configuredOpenApiDoor` uses `OPENAPI_CREDENTIAL_KEY_ID` (default `primary`) for
`OPENAPI_CREDENTIAL_MASTER_KEY`, plus host-supplied `previousCredentialKeys`.
Key material never leaves this private custody port. Unknown key ids and
copied/substituted ids refuse; there is no old-envelope shim.

Responses redact raw, JSON-escaped, percent-encoded, base64 and base64url
credential echoes before returning a body. Response headers remain limited to
the media type, with sensitive media types refused; upstream errors still carry
only the numeric status. OAuth ports now receive `teamId` as well as the private
locator; the adapter must verify that the connection belongs to that Team. C7
must obtain the locator exclusively from the Team-owned Connector record and
collapse connect-unavailable/timeout into one Agent-facing code.
