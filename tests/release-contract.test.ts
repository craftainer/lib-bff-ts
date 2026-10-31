import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// The Makefile half of template-base's release contract (>= 1.9.0): the npm
// upload belongs to `publish-packages`, which runs once in its own job, and
// the per-arch `publish` must not upload anything.
const root = resolve(import.meta.dirname, "..");

function dryRun(target: string) {
  return spawnSync("make", ["-n", target], { cwd: root, encoding: "utf8" });
}

describe("release Makefile contract", () => {
  it("publish-packages runs the npm upload script", () => {
    const r = dryRun("publish-packages");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(
      "scripts/release-run.sh scripts/release-publish.sh",
    );
  });

  it("declares publish-packages phony, so a stray file cannot shadow it", () => {
    const makefile = readFileSync(resolve(root, "Makefile"), "utf8");
    expect(makefile).toMatch(/^\.PHONY:.*\bpublish-packages\b/m);
  });

  it("publish (per arch) does not upload packages", () => {
    const r = dryRun("publish");
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain("release-publish.sh");
    expect(r.stdout).not.toMatch(/npm (stage )?publish/);
  });

  it("verify-published runs the registry check script, after publishing", () => {
    const r = dryRun("verify-published");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain(
      "scripts/release-run.sh scripts/release-verify-published.sh",
    );
    const makefile = readFileSync(resolve(root, "Makefile"), "utf8");
    expect(makefile).toMatch(/^\.PHONY:.*\bverify-published\b/m);
  });

  it("verify-published does nothing without NPM_PUBLISH", () => {
    const env = { ...process.env };
    delete env.NPM_PUBLISH;
    const r = spawnSync("scripts/release-verify-published.sh", {
      cwd: root,
      encoding: "utf8",
      env,
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("nothing to verify");
  });

  it("release-check gates the release, so it never reaches the registry", () => {
    const script = readFileSync(
      resolve(root, "scripts/release-check.sh"),
      "utf8",
    );
    expect(script).not.toContain("NPM_PUBLISH");
    expect(script).not.toContain("npm view");
  });
});
