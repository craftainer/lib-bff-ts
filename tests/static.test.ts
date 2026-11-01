import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LightMyRequestResponse } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeBff, type TestBff } from "./helpers/bff.ts";

const INDEX = "<!doctype html><title>spa</title><script src=/assets/a.js>";
const HTML = { accept: "text/html,application/xhtml+xml", "x-csrf": "1" };
let dir: string;
let bff: TestBff;
let bare: TestBff;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "bff-static-"));
  await mkdir(join(dir, "assets"));
  await mkdir(join(dir, "api"));
  await mkdir(join(dir, "empty"));
  await writeFile(join(dir, "index.html"), INDEX);
  await writeFile(join(dir, "favicon.svg"), "<svg/>");
  await writeFile(join(dir, ".secret"), "s3cret");
  await writeFile(join(dir, "assets", "a-1f2e3d.js"), "console.log(1)");
  await writeFile(join(dir, "api", "shadow.txt"), "shadow");
  const idp = { issuer: "http://localhost:1" };
  bff = await makeBff(idp, { env: { BFF_STATIC_DIR: dir } });
  bare = await makeBff(idp);
});

afterAll(async () => {
  await bff.app.close();
  await bare.app.close();
  await rm(dir, { recursive: true, force: true });
});

function get(
  url: string,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> {
  return bff.app.inject({ method: "GET", url, headers });
}

describe("static files", () => {
  it("serves index.html at / with no-cache", async () => {
    const res = await get("/");
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(INDEX);
    expect(res.headers["content-type"]).toMatch(/^text\/html/);
    expect(res.headers["cache-control"]).toBe("no-cache");
  });

  it("serves index.html by name with no-cache", async () => {
    const res = await get("/index.html");
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-cache");
  });

  it("caches hashed assets as immutable", async () => {
    const res = await get("/assets/a-1f2e3d.js");
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe("console.log(1)");
    expect(res.headers["cache-control"]).toBe(
      "public, max-age=31536000, immutable",
    );
  });

  it("revalidates other files", async () => {
    const res = await get("/favicon.svg");
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-cache");
    expect(res.headers["etag"]).toBeDefined();
  });

  it("denies dotfiles", async () => {
    const res = await get("/.secret");
    expect(res.statusCode).toBe(403);
    expect(res.body).not.toContain("s3cret");
  });

  it("does not list directories", async () => {
    for (const url of ["/assets/", "/empty/", "/empty"]) {
      const res = await get(url);
      expect(res.statusCode, url).toBe(404);
      expect(res.body, url).not.toContain("a-1f2e3d.js");
    }
  });

  it("does not serve files that would shadow the reserved prefixes", async () => {
    const res = await get("/api/shadow.txt", { "x-csrf": "1" });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: "not_found" });
  });

  it("does not escape the static root", async () => {
    for (const url of [
      "/../package.json",
      "/%2e%2e/package.json",
      "/a/..%2f..%2fx",
    ]) {
      const res = await get(url);
      expect(res.statusCode, url).toBeGreaterThanOrEqual(400);
    }
  });
});

describe("SPA fallback", () => {
  it("serves index.html for an unknown path when the client accepts HTML", async () => {
    const res = await get("/orders/42", HTML);
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(INDEX);
    expect(res.headers["cache-control"]).toBe("no-cache");
  });

  it("answers a JSON 404 for an unknown path without Accept: text/html", async () => {
    for (const headers of [
      {},
      { accept: "application/json" },
      { accept: "*/*" },
    ]) {
      const res = await get("/orders/42", headers);
      expect(res.statusCode).toBe(404);
      expect(res.json()).toEqual({ error: "not_found" });
    }
  });

  it("answers a JSON 404 under the reserved prefixes, even for HTML clients", async () => {
    for (const url of [
      "/api",
      "/api/unknown",
      "/api/unknown/x",
      "/bff/unknown",
      "/health",
      "/health/unknown",
      "/.well-known/unknown",
      "/.well-known",
    ]) {
      const res = await get(url, HTML);
      expect(res.statusCode, url).toBe(404);
      expect(res.json(), url).toEqual({ error: "not_found" });
    }
  });

  it("only falls back for GET", async () => {
    const res = await bff.app.inject({
      method: "POST",
      url: "/orders/42",
      headers: HTML,
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: "not_found" });
  });

  it("does not shadow the real routes", async () => {
    const res = await get("/health/live", HTML);
    expect(res.json()).toEqual({ status: "ok" });
  });
});

describe("without a static directory", () => {
  it("is a no-op: no files, no fallback, a JSON 404", async () => {
    for (const url of ["/", "/index.html", "/orders/42"]) {
      const res = await bare.app.inject({
        method: "GET",
        url,
        headers: HTML,
      });
      expect(res.statusCode, url).toBe(404);
      expect(res.json(), url).toEqual({ error: "not_found" });
    }
  });
});
