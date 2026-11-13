# @fungi.computer/veil

## 0.7.2

### Patch Changes

- @fungi.computer/forage@0.3.7
  - @fungi.computer/mycelium@0.3.10

## 0.7.1

### Patch Changes

- @fungi.computer/forage@0.3.6
  - @fungi.computer/mycelium@0.3.9

## 0.7.0

### Minor Changes

- Changes since 0.6.6:

  - feat(model-keys): connect every API-key provider Pi ships from one list

## 0.6.6

### Patch Changes

- Changes since 0.6.5:

  - fix(oyster): connect Cloudflare model keys from Settings

## 0.6.5

### Patch Changes

- @fungi.computer/forage@0.3.5
  - @fungi.computer/mycelium@0.3.8

## 0.6.4

### Patch Changes

- Updated dependencies
  - @fungi.computer/mycelium@0.3.7
  - @fungi.computer/forage@0.3.4

## 0.6.3

### Patch Changes

- Updated dependencies
  - @fungi.computer/mycelium@0.3.6
  - @fungi.computer/forage@0.3.3

## 0.6.2

### Patch Changes

- Changes since 0.6.1:

  - fix(veil): keep exhausted credential cleanup pending
  - fix(oyster): qualify the packed dependency inventory for strangers

- Updated dependencies
  - @fungi.computer/mycelium@0.3.5
  - @fungi.computer/forage@0.3.2

## 0.6.1

### Patch Changes

- Changes since 0.6.0:

  - fix(oyster): complete runtime dependency qualification closure

## 0.6.0

### Minor Changes

- Changes since 0.5.0:

  - feat(connections): move GitHub and Computer Git onto the shared connections
    core
  - fix(connections): pin each OAuth provider's credential to its declared API
    origins
  - feat(connections): move GitHub and Computer Git onto the shared connections
    core

## 0.5.0

### Minor Changes

- Changes since 0.4.0:

  - fix(connections): keep the provider type free of SDK declarations and order
    webhook checks
  - fix(connections): satisfy the lint, type and suppression gates
  - feat(connections): let Nango hold credentials and run sign-ins as optional
    custody
  - feat(connections): sign in to MCP and REST connections on the hub
  - feat(connections): bring MCP connections and the one connections port to the
    hub
  - feat(connections): one connections panel and port on the standalone host
  - perf(veil): keep the MCP client and Forage out of the Team's eager graph
  - fix(veil): call the store transaction as a method
  - fix(veil): name the connector module and report undecodable tables without a
    swallow
  - fix(hub): satisfy the gates for the connections-backed openapi connectors
  - feat(hub): serve openapi connectors from the veil connections core
  - feat(veil): connection labels, owner test calls and cleanup visibility
  - feat(veil): connection records with updates, effects and typed calls
  - fix(oyster): classify the sign-in callback route and update the settings
    fixtures
  - feat(veil): oauth credentials for connections

## 0.4.0

### Minor Changes

- Changes since 0.3.0:

  - feat(oyster): serve agent servers through veil connections
  - fix(oyster): declare the model-key routes and keep route law clean
  - feat(oyster): bring your own model key on standalone Oyster
  - fix(veil): export the contract types the public ports expose
  - fix(veil): export the refusal code type its error exposes
  - fix(veil): drop the unused vault type re-export
  - fix(veil): drop the private applyPlacement re-export
  - fix(veil): forward connection request bodies as bytes and keep error causes
  - feat(veil): connections core with sealed custody adapter

### Patch Changes

- @fungi.computer/forage@0.3.1

## 0.3.0

### Minor Changes

- Changes since 0.2.1:

  - fix(veil): follow one pinned OFAC download redirect
  - feat(veil): add read-only snapshot provider routes
  - fix(veil): distinguish unavailable credential methods
  - fix(veil): disallow hosted Claude subscription login

## 0.2.1

### Patch Changes

- Changes since 0.2.0:

  - fix(release): inline Gitleaks fixture allows

## 0.2.0

### Minor Changes

- Changes since 0.1.0:

  - feat(stranger): typecheck each public entry in its own environment
  - fix: cover Computer and Oyster packed dependency closures
  - feat(oyster): public release 0.2.0

### Patch Changes

- Updated dependencies
  - @fungi.computer/cairn@0.1.0

## 0.1.0

### Minor Changes

- Changes since 0.0.1:

  - perf(veil): build schemas on first use, not at import
  - feat(oyster): public release 0.1.0

## 0.0.1

### Patch Changes

- Initial public release of @fungi.computer/veil.
