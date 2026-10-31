import { request } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import "../src/index.ts";
import type { SessionData, SessionStore } from "../src/session.ts";
import { createMemorySessionStore } from "../src/session.ts";
import { makeBff, type TestBff } from "./helpers/bff.ts";
import { startIdp, type TestIdp } from "./helpers/idp.ts";
import {
  deadPort,
  startUpstream,
  type Seen,
  type TestUpstream,
} from "./helpers/upstream.ts";

let idp: TestIdp;
let up: TestUpstream;
let store: SessionStore;
let bff: TestBff;
let sessionId: string;
let session: SessionData;
let dead: number;

beforeAll(async () => {
  idp = await startIdp();
  up = await startUpstream();
  dead = await deadPort();
  store = createMemorySessionStore();
  bff = await makeBff(idp, {
    store,
    env: {
      BFF_UPSTREAMS: JSON.stringify({
        crud: { url: up.url, audience: "api", methods: ["GET", "POST"] },
        events: {
          url: up.url,
          audience: "api",
          methods: ["GET"],
          stream: true,
        },
        prefixed: { url: `${up.url}/v1/`, audience: "api", methods: ["GET"] },
        dead: {
          url: `http://127.0.0.1:${dead}`,
          audience: "api",
          methods: ["GET"],
        },
        xchg: {
          url: up.url,
          audience: "api",
          methods: ["GET"],
          tokenExchange: true,
        },
      }),
    },
  });
  // Stand-in for the analytics plugin (LB5): consent comes from a test header.
  bff.app.addHook("onRequest", async (request) => {
    const flag = request.headers["x-test-consent"];
    if (flag !== undefined) {
      request.bffAnalyticsConsent = flag === "1";
    }
  });
  await bff.browser.login();
  sessionId = bff.browser.bffJar.get("__Host-Http-session") as string;
  session = (await store.get(sessionId)) as SessionData;
});

afterAll(async () => {
  await bff.app.close();
  await up.close();
  await idp.close();
});

async function listening(): Promise<void> {
  if (!bff.app.server.listening) {
    await bff.app.listen({ port: 0, host: "127.0.0.1" });
  }
}

function last(): Seen {
  return up.seen[up.seen.length - 1] as Seen;
}

/** A GET with the path sent exactly as given (no client-side normalisation). */
function rawGet(
  port: number,
  path: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path,
        headers: { "x-csrf": "1", cookie: `__Host-Http-session=${sessionId}` },
      },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => (body += chunk.toString()));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function get(
  url: string,
  headers: Record<string, string> = {},
): ReturnType<TestBff["browser"]["request"]> {
  return bff.browser.request("GET", url, { csrf: true, headers });
}

describe("routing and the allowlist", () => {
  it("strips the prefix and keeps the query", async () => {
    const res = await get("/api/crud/items/7?limit=2&x=a%20b");
    expect(res.statusCode).toBe(200);
    expect(last().url).toBe("/items/7?limit=2&x=a%20b");
    expect(last().method).toBe("GET");
  });

  it("reaches the upstream root with and without a trailing slash", async () => {
    await get("/api/crud");
    expect(last().url).toBe("/");
    await get("/api/crud/");
    expect(last().url).toBe("/");
  });

  it("keeps the upstream's own base path", async () => {
    await get("/api/prefixed/things?a=1");
    expect(last().url).toBe("/v1/things?a=1");
    await get("/api/prefixed");
    expect(last().url).toBe("/v1/");
  });

  it("answers 405 with Allow for methods outside the allowlist", async () => {
    const before = up.seen.length;
    const res = await bff.browser.request("DELETE", "/api/crud/items/1", {
      csrf: true,
    });
    expect(res.statusCode).toBe(405);
    expect(res.headers["allow"]).toBe("GET, POST");
    expect(res.json()).toEqual({ error: "method_not_allowed" });
    const head = await bff.app.inject({
      method: "HEAD",
      url: "/api/crud/items",
      headers: { "x-csrf": "1", cookie: `__Host-Http-session=${sessionId}` },
    });
    expect(head.statusCode).toBe(405);
    expect(up.seen.length).toBe(before);
  });

  it("does not reach anything outside the allowlist", async () => {
    const before = up.seen.length;
    for (const url of ["/api/nope/x", "/api", "/api/", "/api/crudx/items"]) {
      const res = await get(url);
      expect(res.statusCode, url).toBe(404);
      expect(res.json(), url).toEqual({ error: "not_found" });
    }
    expect(up.seen.length).toBe(before);
  });

  it("rejects path traversal, encoded or not, and backslashes", async () => {
    const before = up.seen.length;
    await listening();
    const { port } = bff.app.server.address() as { port: number };
    for (const url of [
      "/api/crud/../x",
      "/api/crud/%2e%2e/x",
      "/api/crud/%2E%2e/x",
      "/api/crud/a/./b",
      "/api/crud/a/%2e/b",
      "/api/crud/..%2fx",
      "/api/crud/a%5c..%5cb",
      "/api/crud/a\\..\\b",
    ]) {
      const res = await rawGet(port, url);
      expect(res.status, url).toBe(400);
      expect(JSON.parse(res.body), url).toEqual({ error: "invalid_path" });
    }
    expect(up.seen.length).toBe(before);
  });

  it("lets Fastify reject malformed percent-encoding before the proxy sees it", async () => {
    await listening();
    const { port } = bff.app.server.address() as { port: number };
    const before = up.seen.length;
    for (const url of ["/api/crud/%zz", "/api/crud/%ff", "/api/crud/%c0%ae"]) {
      expect((await rawGet(port, url)).status, url).toBe(400);
    }
    expect(up.seen.length).toBe(before);
  });

  it("cannot be redirected to another host with a double slash", async () => {
    const res = await get("/api/crud//evil.example/x");
    expect(res.statusCode).toBe(200);
    expect(last().url).toBe("//evil.example/x");
    expect(last().headers.host).toBe(`127.0.0.1:${up.port}`);
  });

  it("answers 502 when the upstream is unreachable", async () => {
    const res = await get("/api/dead/x");
    expect(res.statusCode).toBe(502);
    expect(res.json()).toEqual({ error: "bad_gateway" });
  });
});

describe("request headers", () => {
  it("forwards only the allowlist and sets the Bearer token", async () => {
    await get("/api/crud/h", {
      accept: "application/json",
      "accept-language": "de",
      "if-none-match": '"abc"',
      "if-modified-since": "Wed, 21 Oct 2015 07:28:00 GMT",
      traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      tracestate: "a=b",
      "x-request-id": "req-1",
      "sec-gpc": "1",
      dnt: "1",
      authorization: "Bearer attacker",
      "x-forwarded-for": "6.6.6.6",
      "x-forwarded-proto": "gopher",
      "x-forwarded-host": "evil.example",
      forwarded: "for=6.6.6.6",
      "analytics-consent": "1",
      "x-secret": "nope",
      origin: "http://localhost:8080",
      "user-agent": "curl/8",
    });
    const h = last().headers;
    expect(h.authorization).toBe(`Bearer ${session.accessToken}`);
    expect(h.accept).toBe("application/json");
    expect(h["accept-language"]).toBe("de");
    expect(h["if-none-match"]).toBe('"abc"');
    expect(h["if-modified-since"]).toBe("Wed, 21 Oct 2015 07:28:00 GMT");
    expect(h.traceparent).toMatch(/^00-0af7/);
    expect(h.tracestate).toBe("a=b");
    expect(h["x-request-id"]).toBe("req-1");
    expect(h["sec-gpc"]).toBe("1");
    expect(h.dnt).toBe("1");
    expect(h.cookie).toBeUndefined();
    expect(h["x-csrf"]).toBeUndefined();
    expect(h["x-forwarded-for"]).toBeUndefined();
    expect(h["x-forwarded-proto"]).toBeUndefined();
    expect(h["x-forwarded-host"]).toBeUndefined();
    expect(h.forwarded).toBeUndefined();
    expect(h["analytics-consent"]).toBeUndefined();
    expect(h["x-secret"]).toBeUndefined();
    expect(h.origin).toBeUndefined();
    expect(h["user-agent"]).not.toBe("curl/8");
  });

  it("drops the session cookie before it reaches the upstream", async () => {
    await get("/api/crud/c");
    expect(last().headers.cookie).toBeUndefined();
  });

  it("sets Analytics-Consent: 1 only when bffAnalyticsConsent is true", async () => {
    await get("/api/crud/consent", { "x-test-consent": "1" });
    expect(last().headers["analytics-consent"]).toBe("1");
    await get("/api/crud/consent", { "x-test-consent": "0" });
    expect(last().headers["analytics-consent"]).toBeUndefined();
    await get("/api/crud/consent");
    expect(last().headers["analytics-consent"]).toBeUndefined();
  });

  it("never lets a client-sent Analytics-Consent through when consent is false", async () => {
    await get("/api/crud/consent", {
      "x-test-consent": "0",
      "analytics-consent": "1",
    });
    expect(last().headers["analytics-consent"]).toBeUndefined();
  });

  it("relays request bodies byte for byte, for any content type", async () => {
    const json = '{"a": 1,   "b":[2,3]}';
    await bff.browser.request("POST", "/api/crud/items", {
      csrf: true,
      headers: { "content-type": "application/json" },
      body: json,
    });
    expect(last().body).toBe(json);
    expect(last().headers["content-type"]).toBe("application/json");
    expect(last().headers["content-length"]).toBe(String(json.length));

    await bff.browser.request("POST", "/api/crud/items", {
      csrf: true,
      headers: { "content-type": "application/octet-stream" },
      body: "raw bytes",
    });
    expect(last().body).toBe("raw bytes");

    await bff.browser.request("POST", "/api/crud/items", {
      csrf: true,
      headers: { "content-type": "text/csv" },
      body: "a,b\n1,2",
    });
    expect(last().body).toBe("a,b\n1,2");
  });
});

describe("authentication", () => {
  it("answers 401 without a session and never calls the upstream", async () => {
    const before = up.seen.length;
    const res = await bff.app.inject({
      method: "GET",
      url: "/api/crud/items",
      headers: { "x-csrf": "1" },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "unauthorized" });
    expect(up.seen.length).toBe(before);
  });

  it("refreshes an expiring token through accessTokenFor", async () => {
    await get("/api/crud/before");
    const old = (last().headers.authorization ?? "").slice(7);
    await store.put(sessionId, { ...session, accessExpiresAt: 0 }, 600);
    const res = await get("/api/crud/after");
    expect(res.statusCode).toBe(200);
    const fresh = (last().headers.authorization ?? "").slice(7);
    expect(fresh).not.toBe(old);
    session = (await store.get(sessionId)) as SessionData;
    expect(session.accessToken).toBe(fresh);
  });

  it("propagates the 401 of a failed refresh and ends the session", async () => {
    const second = await makeBff(idp, {
      env: {
        BFF_UPSTREAMS: JSON.stringify({
          crud: { url: up.url, audience: "api", methods: ["GET"] },
        }),
      },
    });
    await second.browser.login();
    const id = second.browser.bffJar.get("__Host-Http-session") as string;
    const data = (await second.store.get(id)) as SessionData;
    await second.store.put(
      id,
      { ...data, accessExpiresAt: 0, refreshToken: "revoked" },
      600,
    );
    const before = up.seen.length;
    const res = await second.browser.request("GET", "/api/crud/x", {
      csrf: true,
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "session_expired" });
    expect(up.seen.length).toBe(before);
    await second.app.close();
  });

  it("propagates the 503 when the IdP is unavailable during a refresh", async () => {
    const down = await makeBff({ issuer: "http://localhost:1" }, { store });
    await store.put(sessionId, { ...session, accessExpiresAt: 0 }, 600);
    const res = await down.browser.request("GET", "/api/crud/x", {
      csrf: true,
      headers: { cookie: `__Host-Http-session=${sessionId}` },
    });
    expect(res.statusCode).toBe(503);
    await down.app.close();
    await store.put(sessionId, session, 600);
  });

  it("answers 500 and logs when token exchange is configured", async () => {
    const res = await get("/api/xchg/x");
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: "internal_error" });
    expect(
      bff.logs.some(
        (line) => line["msg"] === "request failed" && line["level"] === 50,
      ),
    ).toBe(true);
  });
});

describe("responses", () => {
  it("drops Set-Cookie, CORS and HSTS from the upstream and keeps our headers", async () => {
    const res = await get("/api/crud/cookie");
    expect(res.statusCode).toBe(200);
    expect(res.setCookies).toEqual([]);
    expect(res.headers["set-cookie"]).toBeUndefined();
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["strict-transport-security"]).toBeUndefined();
    expect(res.headers["x-upstream"]).toBe("yes");
    expect(res.headers["content-security-policy"]).not.toBe("default-src *");
    expect(res.headers["cache-control"]).toBe("no-store");
  });

  it("streams server-sent events without buffering", async () => {
    await listening();
    const { port } = bff.app.server.address() as { port: number };
    const res = await fetch(`http://127.0.0.1:${port}/api/events/events`, {
      headers: {
        "x-csrf": "1",
        cookie: `__Host-Http-session=${sessionId}`,
        accept: "text/event-stream",
      },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    const reader = (res.body as ReadableStream<Uint8Array>).getReader();
    const first = await reader.read();
    // The first event arrives while the upstream response is still open.
    expect(new TextDecoder().decode(first.value)).toBe("data: one\n\n");
    up.release();
    const second = await reader.read();
    expect(new TextDecoder().decode(second.value)).toBe("data: two\n\n");
    expect((await reader.read()).done).toBe(true);
  });
});
