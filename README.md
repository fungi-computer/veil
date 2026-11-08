# Veil (`@fungi.computer/veil`)

Veil keeps provider credentials away from Agents. A host stores API keys, OAuth
connections and model keys behind trusted owner doors, and an Agent receives an
authorized operation, never the provider token or where it lives. It owns the
shared connections core (MCP, OpenAPI and a repository's git endpoint),
model-key grants and the Agent's anonymous public-web fetch.

## Install

```sh
npm install @fungi.computer/veil
```

## Set up

The host supplies the owner's SQLite, a `CustodyAdapter` and its live
authorization to `createConnections` (`@fungi.computer/veil/connections`).
Custody is `sealed` by default; Nango is the optional adapter
(`@fungi.computer/veil/connections/nango`). Model input cannot choose a
connection, repository or private locator. Without custody configuration, report
unavailable rather than manufacturing a connection.

GitHub REST is an ordinary `openapi` connection with an `oauth` credential:
through an operator-registered provider on either custody adapter, or through a
Nango integration. A custodian-run integration is pinned by the host
(`configuredCustodyIntegrations`) to one surface kind and one origin, and the
core refuses it at `begin` and again before every send, so the credential Nango
holds never goes anywhere else. GitHub REST is pinned to `api.github.com`.

A Computer's git is not a connection in this core.
`@fungi.computer/veil/github-app` wraps Nango's `github-app` integration
(`NANGO_GITHUB_APP_INTEGRATION_ID`, never the same as
`NANGO_GITHUB_INTEGRATION_ID`): it opens the installation consent, verifies the
signed completion, finds a lost one, deletes a connection and reads the current
installation token. The Hub places that token on a request to `github.com` and
nowhere else.

## Nango adapter

`createNangoCustody` takes a Nango server origin, API key, a separate webhook
signing key, one API-key integration for pasted credentials, and the public
Connect UI base and public API URL. These are host configuration, never browser
or model input. `connect` returns the Connect document browsers open: Nango's
issued link, confined to the configured Connect UI and pinned to the public API
with `apiURL`. `verifyCompletion` verifies the raw callback body with
`@nangohq/node` before decoding it, and the core settles only an attempt the
owner began. Unconfigured hosts must report unavailable instead of substituting
fake custody.

`inject` sends through Nango's proxy, which attaches and refreshes the
credential; the pinned deletion endpoint returns `200 {success:true}` after
deletion and `400 {error:{code:"unknown_connection"}}` when the connection is
absent, and only those settle cleanup. A proxy `404` is the custodian no longer
holding the connection and marks it reconnect-required. `find` asks Nango for
the one connection that carries an attempt's state, actor and Team, so a sign-in
whose signed completion was lost still settles. Cancellation stops the caller
waiting; it does not prove upstream work stopped or rolled back.

`configuredComputerGitIntegration(env)` names the integration through which a
Computer's git signs in (`NANGO_GITHUB_APP_INTEGRATION_ID`);
`NANGO_GITHUB_INTEGRATION_ID` joins the integrations an owner may sign in
through for REST connections.

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

## Keyed routes and the sanctions door

`configuredProviderEgress(env, { keyed })` also serves routes the host
registers. A `KeyedRoute` names two Worker bindings, a credential-free HTTPS
root (`urlBinding`) and a secret (`keyBinding`), plus `accepts(root)` to pin the
configured root, where the secret travels (`{ in: "query", name }` or
`{ in: "path" }`), and a Zod `body` schema for the one JSON POST shape the route
may send. Veil reads both bindings itself, so the host names them and never sees
their values. A host route may not shadow a Veil route, reuse one binding for
both, or name one of Veil's own custody bindings; construction refuses it.

Like the existing Hub search caller (`apps/hub/src/agent-web-search.ts`,
`configuredWebSearch`), a caller obtains `baseUrl(route)` and passes
credential-free requests through `providerFetch(egress, route)`. Requests go to
exactly the pinned root as single POSTs whose JSON body the host schema accepts;
caller headers, queries and alternate paths are not forwarded. The
credential-bearing URL is never returned from `baseUrl`. Missing, invalid or
unaccepted bindings refuse `unavailable` before fetch; other destinations,
methods or bodies refuse `denied`. Redirects and non-2xx responses refuse
`unavailable`; no upstream error body, headers or URL is returned. Successful
bodies are bounded to 64 MiB and refused on a credential echo (raw, JSON-escaped
or percent-encoded); request bodies are bounded to 64 KiB. Transport failures,
including aborts, expose only fixed `VeilError` codes. Keep keys in the existing
private Worker-secret custody, never Team storage, public config, telemetry or
logs. The final transport sees the authorized URL and must not log it.

Veil also owns one anonymous door:

| Route              | Destination / allowed calls                                                                      | Private bindings                             |
| ------------------ | ------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| `sanctions-screen` | GET exactly `https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML` | `SANCTIONS_SDN_URL` (that exact URL, opt-in) |

The sanctions GET alone may manually follow **one HTTP 302** from the exact OFAC
export to
`https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com`, with a
path beginning `/Published/` and ending `/SDN.XML`. OFAC's signed query is
retained; caller headers/credentials and upstream cookies are not forwarded. The
Location string is capped at 8,192 code units, must have no userinfo or
fragment, and cannot change HTTPS or port 443. Veil cancels the redirect body
before the second GET, uses the original abort signal (including any caller
deadline, never restarted) and keeps the same 64 MiB download bound. Another
host/path, a missing/invalid Location, a second redirect or any other redirect
status refuses `unavailable`. Direct entry at S3 and non-GET sanctions requests
remain refused. OFAC's public list requires **no credential**, so there is no
sanctions API key binding. The caller parses the XML and decides what a match
means; this door only fetches the published list.

Provider contract source:
[OFAC data formats](https://ofac.treasury.gov/specially-designated-nationals-list-data-formats-data-schemas)
and the exact official export above. Unit fixtures prove custody and route
policy, not provisioned keys or live upstreams.

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

## Contribute

Run `pnpm --filter @fungi.computer/veil test` for the package's synthetic
custody, signed-webhook and public-fetch checks. A unit test does not prove a
live Nango service or provider account.

See [`LICENSE`](LICENSE).
