/* global process, fetch, console */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { promisify } from "node:util";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Same maintained Testcontainers packages and service versions as pinned
// Nango tests/setup.ts. Only the PostgreSQL and log migration services needed
// by runServer are started; no Nango server or background service is replaced.
export default async function setup() {
  assert.ok(process.env.NANGO_QUALIFICATION_SOURCE);
  // Optional URL fields must be absent, not empty strings, under Nango's parser.
  delete process.env.NANGO_REDIS_URL;
  delete process.env.CLICKHOUSE_URL;
  const source = resolve(process.env.NANGO_QUALIFICATION_SOURCE);
  const requireNango = createRequire(join(source, "package.json"));
  const load = (name) => import(pathToFileURL(requireNango.resolve(name)));
  const { PostgreSqlContainer } = await load("@testcontainers/postgresql");
  const { ElasticsearchContainer } = await load(
    "@testcontainers/elasticsearch",
  );
  const storageRoot = "/mnt/fungi-data/botanical-work";
  await mkdir(storageRoot, { recursive: true, mode: 0o700 });
  const dataDirectory = await mkdtemp(join(storageRoot, "nango-git-es-"));
  // Official Elasticsearch image runs as UID1000; this directory is created
  // by the same local UID. No privileged container or permission widening.
  assert.equal(process.getuid(), 1000);
  const exec = promisify(execFile);
  const { stdout: hostFilesystem } = await exec("stat", [
    "-f",
    "-c",
    "%i %S %b",
    dataDirectory,
  ]);
  const containers = [];
  const close = async () => {
    const results = await Promise.allSettled(
      containers.map((container) => container.stop()),
    );
    const errors = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (errors.length)
      throw new AggregateError(errors, "Fixture cleanup failed");
    await rm(dataDirectory, { recursive: true, force: true });
  };
  try {
    const pg = await new PostgreSqlContainer("postgres:15.5-alpine")
      .withDatabase("postgres")
      .withUsername("postgres")
      .withPassword("nango_test")
      .start();
    containers.push(pg);
    Object.assign(process.env, {
      NANGO_DB_PASSWORD: "nango_test",
      NANGO_DB_HOST: pg.getHost(),
      NANGO_DB_USER: "postgres",
      NANGO_DB_PORT: String(pg.getPort()),
      NANGO_DB_NAME: "postgres",
      NANGO_DB_SSL: "false",
      NANGO_DATABASE_URL: pg.getConnectionUri(),
      RECORDS_DATABASE_URL: pg.getConnectionUri(),
    });
    const es = await new ElasticsearchContainer("elasticsearch:8.13.0")
      .withBindMounts([
        {
          source: dataDirectory,
          target: "/usr/share/elasticsearch/data",
          mode: "rw",
        },
      ])
      .withEnvironment({
        "discovery.type": "single-node",
        "xpack.security.enabled": "false",
      })
      .withStartupTimeout(120000)
      .start();
    containers.push(es);
    const identity = await es.exec(["id", "-u"]);
    assert.equal(identity.exitCode, 0);
    assert.equal(identity.output.trim(), "1000");
    const mounted = await es.exec([
      "stat",
      "-f",
      "-c",
      "%i %S %b",
      "/usr/share/elasticsearch/data",
    ]);
    assert.equal(mounted.exitCode, 0);
    assert.equal(mounted.output.trim(), hostFilesystem.trim());
    const statsResponse = await fetch(`${es.getHttpUrl()}/_nodes/stats/fs`);
    assert.equal(statsResponse.status, 200);
    const stats = await statsResponse.json();
    const nodes = Object.values(stats.nodes);
    assert.equal(nodes.length, 1);
    const { total_in_bytes: total, available_in_bytes: available } =
      nodes[0].fs.total;
    assert.ok(
      available > total * 0.1,
      "Mounted Elasticsearch data must remain below default high watermark",
    );
    console.log("Nango Git Elasticsearch mounted storage", {
      uid: 1000,
      total,
      available,
    });
    Object.assign(process.env, {
      NANGO_LOGS_ES_URL: es.getHttpUrl(),
      NANGO_LOGS_ES_USER: "",
      NANGO_LOGS_ES_PWD: "",
      NANGO_LOGS_PROVIDER: "elasticsearch",
    });
    return close;
  } catch (error) {
    try {
      await close();
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "Fixture setup failed", {
        cause: cleanupError,
      });
    }
    throw error;
  }
}
