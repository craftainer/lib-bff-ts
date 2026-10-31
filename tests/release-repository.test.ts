import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

// scripts/release-lib.sh's check_repository: the guard that fails a release
// before publish when package.json's repository.url is not the GitHub repo.
const lib = resolve(import.meta.dirname, "../scripts/release-lib.sh");
const tmp = mkdtempSync(join(tmpdir(), "repo-guard-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

let n = 0;
function tarballWith(pkg: object): string {
  const dir = join(tmp, `pkg${n++}`);
  mkdirSync(join(dir, "package"), { recursive: true });
  writeFileSync(join(dir, "package", "package.json"), JSON.stringify(pkg));
  const tgz = join(dir, "pkg.tgz");
  const tar = spawnSync("tar", ["-czf", tgz, "-C", dir, "package"]);
  expect(tar.status).toBe(0);
  return tgz;
}

function check(tarball: string, repo?: string) {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env["GITHUB_REPOSITORY"];
  if (repo !== undefined) env["GITHUB_REPOSITORY"] = repo;
  return spawnSync(
    "bash",
    ["-c", `source "${lib}" && check_repository "$1"`, "bash", tarball],
    {
      env,
      encoding: "utf8",
    },
  );
}

describe("check_repository", () => {
  const repo = "craftainer/lib-example";

  it.each([
    `git+https://github.com/${repo}.git`,
    `https://github.com/${repo}`,
    `https://github.com/${repo}/`,
    `https://github.com/${repo}.git/`,
    `http://github.com/${repo}`,
    `git://github.com/${repo}.git`,
    `git+ssh://git@github.com/${repo}.git`,
    `ssh://git@github.com/${repo}`,
    `git@github.com:${repo}.git`,
    `git+ssh://git@github.com:${repo}.git`,
    `github:${repo}`,
    repo,
    // Forms npm's hosted-git-info normalizes: scheme case-insensitive, a
    // `www.` prefix dropped, host case-insensitive in a plain http(s) URL.
    `HTTPS://GitHub.com/${repo}`,
    `https://www.github.com/${repo}.git`,
    `https://GITHUB.COM/${repo}`,
    `git+https://www.github.com/${repo}.git`,
    `GIT+HTTPS://github.com/${repo}`,
    `git+ssh://git@www.github.com/${repo}.git`,
    `git@www.github.com:${repo}.git`,
  ])("passes when %s matches", (url) => {
    const r = check(tarballWith({ repository: { type: "git", url } }), repo);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("OK:");
  });

  it("accepts the string form", () => {
    const r = check(
      tarballWith({ repository: `https://github.com/${repo}` }),
      repo,
    );
    expect(r.status).toBe(0);
  });

  it("fails on a mismatched repository and says how to fix it", () => {
    const r = check(
      tarballWith({
        repository: {
          type: "git",
          url: "git+https://github.com/craftainer/template-npm-package.git",
        },
      }),
      repo,
    );
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(
      "expected it to name https://github.com/craftainer/lib-example",
    );
    expect(r.stderr).toContain(`git+https://github.com/${repo}.git`);
  });

  it.each([
    "https://gitlab.com/craftainer/lib-example",
    "https://github.com/craftainer/lib-example/tree/main",
    "https://github.com/craftainer/lib-example.git#main",
    "https://github.com/craftainer/lib-example-2",
    "https://github.com/other/craftainer/lib-example",
    "gitlab:craftainer/lib-example",
    "https://example.com/github.com/craftainer/lib-example",
    "not a url",
    // npm itself rejects a mixed-case host behind git+ and in git/ssh/scp URLs.
    "git+https://GitHub.com/craftainer/lib-example",
    "git@GitHub.com:craftainer/lib-example.git",
    "ssh://git@GitHub.com/craftainer/lib-example",
    "https://notgithub.com/craftainer/lib-example",
  ])("fails on %s", (url) => {
    const r = check(tarballWith({ repository: { url } }), repo);
    expect(r.status).toBe(1);
  });

  it("fails on a different case (npm compares case-sensitively)", () => {
    const r = check(
      tarballWith({
        repository: { url: "https://github.com/Craftainer/lib-example" },
      }),
      repo,
    );
    expect(r.status).toBe(1);
  });

  it("fails when repository is missing or empty", () => {
    expect(check(tarballWith({}), repo).status).toBe(1);
    expect(check(tarballWith({ repository: { url: "" } }), repo).status).toBe(
      1,
    );
  });

  it("skips with a notice when GITHUB_REPOSITORY is unset", () => {
    const r = check(tarballWith({}));
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("NOTICE: GITHUB_REPOSITORY not set");
  });

  it("treats a value starting with - as data, not a node option", () => {
    for (const url of ["--version", "-p", "--eval=1"]) {
      const r = spawnSync(
        "bash",
        ["-c", `source "${lib}" && normalize_repo_url "$1"`, "bash", url],
        { encoding: "utf8" },
      );
      expect(r.status).toBe(0);
      expect(r.stdout).toBe("");
      expect(r.stderr).toBe("");
    }
  });
});
