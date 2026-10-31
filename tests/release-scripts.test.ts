import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

// release-verify-published.sh and release-publish.sh against a stub `npm`
// on PATH and a copy of scripts/ next to a fake dist/, so no registry is
// touched and the repository's own dist/ is not needed.
const scripts = resolve(import.meta.dirname, "../scripts");
const tmp = mkdtempSync(join(tmpdir(), "release-scripts-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const NPM_VERSION = /^NPM_VERSION=(.+)$/m.exec(
  readFileSync(join(scripts, "release-lib.sh"), "utf8"),
)![1]!;

let n = 0;
// A work dir with scripts/, dist/<tarball> for name@version, and a stub npm
// that logs its arguments to npm.log and answers `view` per STUB_VIEW.
function setup(name = "@scope/pkg", version = "1.2.3") {
  const dir = join(tmp, `w${n++}`);
  mkdirSync(join(dir, "scripts"), { recursive: true });
  mkdirSync(join(dir, "dist"));
  mkdirSync(join(dir, "bin"));
  for (const f of [
    "release-lib.sh",
    "release-verify-published.sh",
    "release-publish.sh",
  ]) {
    copyFileSync(join(scripts, f), join(dir, "scripts", f));
  }
  const pkgDir = join(dir, "pk", "package");
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(
    join(pkgDir, "package.json"),
    JSON.stringify({
      name,
      version,
      repository: "https://github.com/craftainer/lib-example",
    }),
  );
  const tar = spawnSync("tar", [
    "-czf",
    join(dir, "dist", "p.tgz"),
    "-C",
    join(dir, "pk"),
    "package",
  ]);
  expect(tar.status).toBe(0);
  const stub = join(dir, "bin", "npm");
  writeFileSync(
    join(dir, "bin", "sleep"),
    `#!/usr/bin/env bash\necho "$1" >>"${dir}/sleep.log"\n`,
  );
  chmodSync(join(dir, "bin", "sleep"), 0o755);
  writeFileSync(
    stub,
    `#!/usr/bin/env bash
echo "$*" >>"${dir}/npm.log"
case "$1" in
  --version) echo ${NPM_VERSION} ;;
  view) # view --json <spec> <field>
    case "$3" in
      *@*.*.*) # name@version lookup
        case "\${STUB_VIEW:-}" in
          found) echo '"${version}"' ;;
          found-on-2) # empty on the first lookup only
            if [ -e "${dir}/seen" ]; then echo '"${version}"'; else touch "${dir}/seen"; fi ;;
          empty) ;;
          e404) echo '{"error":{"code":"E404","summary":"Not Found"}}'; echo "npm error code E404" >&2; exit 1 ;;
          # a failure whose text merely mentions E404
          loose404) echo '{"error":{"code":"ETIMEDOUT","summary":"proxy said E404"}}'; echo "npm error E404 via proxy" >&2; exit 1 ;;
          neterr) echo '{"error":{"code":"ENETWORK"}}'; echo "npm error code ENETWORK" >&2; exit 1 ;;
        esac ;;
      *) echo "" ;; # dist-tags.latest: no latest yet
    esac ;;
  install) # install_into: lay out the package the way npm would
    mkdir -p "node_modules/${name}"
    echo '{"name":"${name}","version":"${version}","main":"index.js"}' >"node_modules/${name}/package.json"
    echo 'module.exports = { ok: 1 }' >"node_modules/${name}/index.js" ;;
  *) ;; # stage publish / publish
esac
`,
  );
  chmodSync(stub, 0o755);
  return dir;
}

function run(dir: string, script: string, env: Record<string, string>) {
  return spawnSync("bash", [join(dir, "scripts", script)], {
    cwd: dir,
    encoding: "utf8",
    env: {
      PATH: `${join(dir, "bin")}:${process.env["PATH"]}`,
      HOME: process.env["HOME"] ?? "/tmp",
      GITHUB_REPOSITORY: "craftainer/lib-example",
      RELEASE_CHECK_ATTEMPTS: "2",
      RELEASE_CHECK_DELAY: "0",
      ...env,
    },
  });
}

const npmLog = (dir: string) => {
  try {
    return readFileSync(join(dir, "npm.log"), "utf8");
  } catch {
    return "";
  }
};

describe("release-verify-published.sh", () => {
  it.each(["empty", "e404"])(
    "fails with a clear message when the version never appears (%s)",
    (view) => {
      const dir = setup();
      const r = run(dir, "release-verify-published.sh", {
        NPM_PUBLISH: "1",
        STUB_VIEW: view,
      });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("@scope/pkg@1.2.3 is not on the registry");
      expect(r.stderr).toContain("npm stage approve");
      expect(
        npmLog(dir).match(/^view --json @scope\/pkg@1\.2\.3/gm),
      ).toHaveLength(2);
    },
  );

  it("installs and imports the published version once it is found", () => {
    const dir = setup();
    const r = run(dir, "release-verify-published.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "found",
    });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("OK: import @scope/pkg");
    expect(npmLog(dir)).toMatch(/^install .*@scope\/pkg@1\.2\.3/m);
  });

  it("retries while the version propagates, then verifies it", () => {
    const dir = setup();
    const r = run(dir, "release-verify-published.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "found-on-2",
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("attempt 1/2: not found; retrying");
  });

  it("keeps retrying for minutes, with capped backoff, before failing", () => {
    const dir = setup();
    const r = run(dir, "release-verify-published.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "empty",
      RELEASE_CHECK_ATTEMPTS: "",
      RELEASE_CHECK_DELAY: "",
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("not on the registry after 10 attempts");
    expect(npmLog(dir).match(/^view --json /gm)).toHaveLength(10);
    const sleeps = readFileSync(join(dir, "sleep.log"), "utf8")
      .trim()
      .split("\n")
      .map(Number);
    expect(sleeps).toEqual([5, 10, 20, 40, 60, 60, 60, 60, 60]);
  });

  it("does not treat an error that merely mentions E404 as not-found", () => {
    const dir = setup();
    const r = run(dir, "release-verify-published.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "loose404",
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("ETIMEDOUT");
    expect(
      npmLog(dir).match(/^view --json @scope\/pkg@1\.2\.3/gm),
    ).toHaveLength(1);
  });

  it("fails on a lookup error other than not-found, without retrying", () => {
    const dir = setup();
    const r = run(dir, "release-verify-published.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "neterr",
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("ENETWORK");
    expect(
      npmLog(dir).match(/^view --json @scope\/pkg@1\.2\.3/gm),
    ).toHaveLength(1);
  });
});

describe("release-publish.sh", () => {
  it("skips a version that is already on the registry (re-runnable)", () => {
    const dir = setup();
    const r = run(dir, "release-publish.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "found",
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("already on the registry -- nothing to publish");
    expect(npmLog(dir)).not.toMatch(/^(stage )?publish/m);
  });

  it("stops on a lookup error other than not-found, without publishing", () => {
    const dir = setup();
    const r = run(dir, "release-publish.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "neterr",
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("ENETWORK");
    expect(npmLog(dir)).not.toMatch(/^(stage )?publish/m);
  });

  it("does not publish when an error merely mentions E404", () => {
    const dir = setup();
    const r = run(dir, "release-publish.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "loose404",
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("ETIMEDOUT");
    expect(npmLog(dir)).not.toMatch(/^(stage )?publish/m);
  });

  it("treats a real E404 (unknown package) as not published", () => {
    const dir = setup();
    const r = run(dir, "release-publish.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "e404",
    });
    expect(r.status).toBe(0);
    expect(npmLog(dir)).toMatch(/^publish /m);
  });

  it("warns that a staged version cannot be re-detected (token path)", () => {
    const dir = setup();
    const r = run(dir, "release-publish.sh", {
      NPM_PUBLISH: "1",
      NPM_TOKEN: "t",
      STUB_VIEW: "empty",
    });
    expect(r.status).toBe(0);
    expect(npmLog(dir)).toMatch(/^stage publish /m);
    expect(r.stdout).toContain(
      "cannot see the stage and would stage a duplicate",
    );
  });

  it("publishes a version that is not on the registry yet", () => {
    const dir = setup();
    const r = run(dir, "release-publish.sh", {
      NPM_PUBLISH: "1",
      STUB_VIEW: "empty",
    });
    expect(r.status).toBe(0);
    expect(npmLog(dir)).toMatch(/^publish .*--provenance/m);
  });
});
