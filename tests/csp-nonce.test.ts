import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../src/config.ts";
import { CSP_NONCE_PLACEHOLDER } from "../src/index.ts";
import { makeBff, type TestBff } from "./helpers/bff.ts";

const idp = { issuer: "http://localhost:1" };
const HTML = { accept: "text/html" };
const INDEX = `<!doctype html><meta property="csp-nonce" nonce="${CSP_NONCE_PLACEHOLDER}"><link rel="stylesheet" nonce="${CSP_NONCE_PLACEHOLDER}" href="/assets/a.css"><script type="module" nonce="${CSP_NONCE_PLACEHOLDER}" src="/assets/a.js"></script>`;

let dir: string;
let bff: TestBff;
const open: TestBff[] = [];

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "bff-nonce-"));
  await writeFile(join(dir, "index.html"), INDEX);
  bff = await makeBff(idp, { env: { BFF_STATIC_DIR: dir } });
  open.push(bff);
});

afterAll(async () => {
  await Promise.all(open.map((b) => b.app.close()));
  await rm(dir, { recursive: true, force: true });
});

function nonceOf(csp: string): string {
  const match = /style-src-elem 'self' 'nonce-([^']+)'/.exec(csp);
  if (match?.[1] === undefined) {
    throw new Error(`no nonce in ${csp}`);
  }
  return match[1];
}

describe("CSP nonce on SPA HTML", () => {
  it("is 16 random bytes, base64, and fully replaces the placeholder", async () => {
    const res = await bff.app.inject({ method: "GET", url: "/" });
    const nonce = nonceOf(String(res.headers["content-security-policy"]));
    expect(Buffer.from(nonce, "base64")).toHaveLength(16);
    expect(res.body).not.toContain(CSP_NONCE_PLACEHOLDER);
    expect(res.body.split(`nonce="${nonce}"`)).toHaveLength(4);
  });

  it("does not double-decode the path: %25 is no 500, %2569ndex.html is no index", async () => {
    const pct = await bff.app.inject({ method: "GET", url: "/%25" });
    expect(pct.statusCode).toBe(404);
    const dbl = await bff.app.inject({
      method: "GET",
      url: "/%2569ndex.html",
    });
    expect(dbl.statusCode).toBe(404);
    expect(dbl.body).not.toContain("nonce=");
  });

  it("answers HEAD on the SPA fallback with the HTML headers", async () => {
    const res = await bff.app.inject({
      method: "HEAD",
      url: "/orders/42",
      headers: HTML,
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toContain("text/html");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(String(res.headers["content-security-policy"])).toContain(
      "style-src-elem 'self' 'nonce-",
    );
  });

  it("is unique per request, on every HTML entry point", async () => {
    const seen = new Set<string>();
    for (const [url, headers] of [
      ["/", {}],
      ["/", {}],
      ["/index.html", {}],
      ["/index.html?x=1", {}],
      ["/orders/42", HTML],
      ["/orders/43", HTML],
    ] as const) {
      const res = await bff.app.inject({ method: "GET", url, headers });
      expect(res.statusCode, url).toBe(200);
      const nonce = nonceOf(String(res.headers["content-security-policy"]));
      expect(res.body, url).toContain(`nonce="${nonce}"`);
      seen.add(nonce);
    }
    expect(seen.size).toBe(6);
  });

  it("sends the nonce policy and keeps every other directive", async () => {
    const res = await bff.app.inject({ method: "GET", url: "/" });
    const nonce = nonceOf(String(res.headers["content-security-policy"]));
    expect(res.headers["content-security-policy"]).toBe(
      `default-src 'self'; script-src 'self'; style-src 'self'; style-src-elem 'self' 'nonce-${nonce}'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`,
    );
  });

  it("serves the HTML no-store, also for HEAD", async () => {
    for (const method of ["GET", "HEAD"] as const) {
      const res = await bff.app.inject({ method, url: "/" });
      expect(res.headers["cache-control"], method).toBe("no-store");
      expect(res.headers["content-type"], method).toMatch(/^text\/html/);
    }
  });

  it("leaves other responses on the fixed CSP", async () => {
    for (const url of ["/assets/missing.js", "/health/live"]) {
      const res = await bff.app.inject({ method: "GET", url });
      expect(res.headers["content-security-policy"], url).not.toContain(
        "nonce-",
      );
    }
    const json404 = await bff.app.inject({ method: "GET", url: "/orders/1" });
    expect(json404.statusCode).toBe(404);
    expect(json404.json()).toEqual({ error: "not_found" });
    expect(json404.headers["content-security-policy"]).not.toContain("nonce-");
  });

  it("nonces a percent-encoded index path and rejects a malformed one", async () => {
    const encoded = await bff.app.inject({
      method: "GET",
      url: "/%69ndex.html",
    });
    expect(encoded.headers["content-security-policy"]).toContain("nonce-");
    const bad = await bff.app.inject({ method: "GET", url: "/%E0%A4%A" });
    expect(bad.statusCode).toBe(400);
    const post = await bff.app.inject({
      method: "POST",
      url: "/",
      headers: { "x-csrf": "1" },
    });
    expect(post.body).not.toContain("<!doctype");
    expect(post.headers["content-security-policy"]).not.toContain("nonce-");
  });

  it("answers 404 when index.html is missing", async () => {
    const empty = await mkdtemp(join(tmpdir(), "bff-nonce-empty-"));
    const other = await makeBff(idp, { env: { BFF_STATIC_DIR: empty } });
    open.push(other);
    expect(
      (await other.app.inject({ method: "GET", url: "/" })).statusCode,
    ).toBe(404);
    const fallback = await other.app.inject({
      method: "GET",
      url: "/x",
      headers: HTML,
    });
    expect(fallback.statusCode).toBe(404);
    await rm(empty, { recursive: true, force: true });
    expect(other.logs.some((l) => l.msg === "cannot read index.html")).toBe(
      false,
    );
  });

  it("logs an unreadable index.html (not ENOENT) and still falls through", async () => {
    const odd = await mkdtemp(join(tmpdir(), "bff-nonce-dir-"));
    await mkdir(join(odd, "index.html"));
    const other = await makeBff(idp, { env: { BFF_STATIC_DIR: odd } });
    open.push(other);
    const res = await other.app.inject({
      method: "GET",
      url: "/x",
      headers: HTML,
    });
    expect(res.statusCode).toBe(404);
    expect(other.logs.some((l) => l.msg === "cannot read index.html")).toBe(
      true,
    );
    await rm(odd, { recursive: true, force: true });
  });
});

describe("API_CACHE_CONTROL", () => {
  async function cacheControl(
    env: Record<string, string>,
    upstream: string | null,
  ): Promise<unknown> {
    const b = await makeBff(idp, { env });
    open.push(b);
    b.app.get("/api/own", async (_request, reply) => {
      if (upstream !== null) {
        void reply.header("Cache-Control", upstream);
      }
      return reply.send({});
    });
    const res = await b.app.inject({
      method: "GET",
      url: "/api/own",
      headers: { "x-csrf": "1" },
    });
    return res.headers["cache-control"];
  }

  it("forces no-store by default and with no-store", async () => {
    expect(await cacheControl({}, "public, max-age=300")).toBe("no-store");
    expect(
      await cacheControl(
        { API_CACHE_CONTROL: "no-store" },
        "public, max-age=5",
      ),
    ).toBe("no-store");
  });

  it("upstream: passes the upstream value through, defaults a missing one", async () => {
    const env = { API_CACHE_CONTROL: "upstream" };
    expect(await cacheControl(env, "private, max-age=300")).toBe(
      "private, max-age=300",
    );
    expect(await cacheControl(env, null)).toBe("no-store");
  });

  it("upstream: rewrites public to private and keeps the rest", async () => {
    const env = { API_CACHE_CONTROL: "upstream" };
    expect(await cacheControl(env, "public, max-age=300")).toBe(
      "private, max-age=300",
    );
    expect(await cacheControl(env, "max-age=60, PUBLIC, s-maxage=5")).toBe(
      "max-age=60, private, s-maxage=5",
    );
  });

  it("is validated by loadConfig", () => {
    const env = {
      PUBLIC_ORIGIN: "https://app.example.com",
      OIDC_ISSUER: "https://idp.example.com/realms/x",
      OIDC_CLIENT_SECRET: "s3cret",
      SESSION_STORE_URL: "rediss://valkey:6379",
    };
    expect(loadConfig({ ...env, API_CACHE_CONTROL: "upstream" })).toMatchObject(
      { apiCacheControl: "upstream" },
    );
    expect(loadConfig({ ...env, API_CACHE_CONTROL: "" })).toMatchObject({
      apiCacheControl: "no-store",
    });
    expect(() => loadConfig({ ...env, API_CACHE_CONTROL: "public" })).toThrow(
      ConfigError,
    );
  });
});
