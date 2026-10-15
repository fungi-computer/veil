import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import process from "node:process";
import { clearTimeout, setTimeout } from "node:timers";

const exec = promisify(execFile);

// Test-only real Git HTTP upstream. BusyBox owns HTTP/CGI/basic authentication;
// the installed git-http-backend owns negotiation and pack generation. This is
// not a provider emulator or the Computer's production egress implementation.
export async function startGitFixture({
  port,
  computerRepository = false,
  repositoryPath: configuredRepositoryPath,
}) {
  assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
  const bridge = networkInterfaces().docker0?.find(
    (entry) => entry.family === "IPv4" && !entry.internal,
  );
  assert.equal(bridge?.address, "172.17.0.1");
  const root = await mkdtemp(join(tmpdir(), "veil-nango-git-"));
  let server;
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    if (server?.pid) {
      const exited =
        server.exitCode === null && server.signalCode === null
          ? once(server, "exit")
          : Promise.resolve();
      const killGroup = (signal) => {
        try {
          process.kill(-server.pid, signal);
        } catch (error) {
          if (error.code !== "ESRCH") throw error;
        }
      };
      killGroup("SIGTERM");
      const force = setTimeout(() => killGroup("SIGKILL"), 5000);
      force.unref();
      try {
        await exited;
      } finally {
        clearTimeout(force);
        // The HTTP parent exiting does not establish CGI child settlement.
        // Collect any remaining member of this fixture's private process group.
        killGroup("SIGKILL");
      }
    }
    await rm(root, { recursive: true, force: true });
  };
  try {
    const work = join(root, "source");
    const repositories = join(root, "repositories");
    const repositoryPath =
      configuredRepositoryPath ??
      (computerRepository
        ? "fungi-computer/Botanical-next.git"
        : "repository.git");
    const web = join(root, "web");
    await mkdir(repositories);
    await mkdir(dirname(join(repositories, repositoryPath)), {
      recursive: true,
    });
    await mkdir(join(web, "cgi-bin"), { recursive: true });
    await exec("git", ["init", "--initial-branch=main", work]);
    await writeFile(join(work, "README.md"), "Synthetic Nango Git fixture.\n");
    await writeFile(join(work, "bytes.bin"), new Uint8Array([0, 255, 128, 10]));
    await exec("git", ["add", "README.md", "bytes.bin"], { cwd: work });
    await exec(
      "git",
      [
        "-c",
        "user.name=Veil local qualification",
        "-c",
        "user.email=qualification@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "Synthetic Git HTTP input",
      ],
      { cwd: work },
    );
    const { stdout: revision } = await exec("git", ["rev-parse", "HEAD"], {
      cwd: work,
    });
    await exec("git", [
      "clone",
      "--bare",
      work,
      join(repositories, repositoryPath),
    ]);
    const { stdout: gitExecPath } = await exec("git", ["--exec-path"]);
    const backend = join(gitExecPath.trim(), "git-http-backend");
    // CGI uses the maintained executable directly, with no response parser.
    const cgi = join(web, "cgi-bin", "git");
    await writeFile(cgi, '#!/bin/sh\nexec "$GIT_FIXTURE_BACKEND"\n');
    await chmod(cgi, 0o700);
    const credential = "synthetic-git-http-only";
    const config = join(root, "httpd.conf");
    await writeFile(config, `/cgi-bin/git:x-access-token:${credential}\n`, {
      mode: 0o600,
    });
    server = spawn(
      "busybox",
      [
        "httpd",
        "-f",
        "-p",
        `${bridge.address}:${port}`,
        "-h",
        web,
        "-c",
        config,
      ],
      {
        env: {
          PATH: "/usr/bin:/bin",
          GIT_PROJECT_ROOT: repositories,
          GIT_HTTP_EXPORT_ALL: "1",
          GIT_FIXTURE_BACKEND: backend,
        },
        stdio: "ignore",
        detached: true,
      },
    );
    await once(server, "spawn");
    return {
      url: `http://${bridge.address}:${port}/cgi-bin/git/${repositoryPath}`,
      // The maintained Nango proxy prepends this fixed fixture base to the
      // unchanged /fungi-computer/Botanical-next.git production request path.
      proxyBase: `http://${bridge.address}:${port}/cgi-bin/git`,
      revision: revision.trim(),
      credential,
      repositoryDirectory: join(repositories, repositoryPath),
      server,
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
