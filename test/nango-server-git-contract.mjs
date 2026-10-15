/* global console, process */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Run after the pinned server's ordinary build, in its configured test process.
// This checks the maintained HTTP representation boundary, not authentication,
// credential refresh, Git negotiation, streaming settlement or Computer access.
const source = resolve(process.argv[2]);
assert.equal(
  execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: source,
    encoding: "utf8",
  }).trim(),
  "7c00d83c6d6e6155a2e49a76061d0aa4d6bd464b",
);
const { isBinaryContentType } = await import(
  pathToFileURL(resolve(source, "packages/server/dist/utils/utils.js"))
);
const { parseHeaders } = await import(
  pathToFileURL(
    resolve(source, "packages/server/dist/controllers/proxy/allProxy.js"),
  )
);

const { destroy: destroyLogs } = await import(
  pathToFileURL(resolve(source, "packages/logs/dist/index.js"))
);
const { egressTelemetryRecorder } = await import(
  pathToFileURL(
    resolve(source, "packages/server/dist/utils/egressTelemetry.js"),
  )
);

function assertContract() {
  assert.equal(
    isBinaryContentType("application/x-git-upload-pack-request"),
    true,
  );
  assert.equal(isBinaryContentType("application/json"), false);

  // Native Git headers are not implicitly forwarded by the Nango API route.
  // The existing final-egress caller must use Nango's maintained header namespace.
  assert.deepEqual(
    parseHeaders({
      rawHeaders: [
        "Content-Type",
        "application/x-git-upload-pack-request",
        "Git-Protocol",
        "version=2",
        "Authorization",
        "Bearer synthetic-nango-api-credential",
      ],
    }),
    {},
  );
  assert.deepEqual(
    parseHeaders({
      rawHeaders: [
        "Nango-Proxy-Content-Type",
        "application/x-git-upload-pack-request",
        "Nango-Proxy-Git-Protocol",
        "version=2",
        "Authorization",
        "Bearer synthetic-nango-api-credential",
      ],
    }),
    {
      "Content-Type": "application/x-git-upload-pack-request",
      "Git-Protocol": "version=2",
    },
  );
}
const outcomes = await Promise.allSettled([
  Promise.resolve().then(assertContract),
]);
const failures = outcomes.flatMap((outcome) =>
  outcome.status === "rejected" ? [outcome.reason] : [],
);
{
  // Same maintained owners used by server.ts shutdown. No forced process exit,
  // private timer access, signal-handler removal or production graph patch.
  const results = await Promise.allSettled([
    destroyLogs(),
    egressTelemetryRecorder.shutdown(),
  ]);
  for (const result of results) {
    if (result.status === "rejected") failures.push(result.reason);
    else if (result.value?.isErr()) failures.push(result.value.error);
  }
}

if (failures.length)
  throw new AggregateError(failures, "Nango contract or cleanup failed");
console.log(
  JSON.stringify({
    result: "passed",
    scope:
      "Pinned server Git request body classification and proxy header parsing only",
  }),
);
