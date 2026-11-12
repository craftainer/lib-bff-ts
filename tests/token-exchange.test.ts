import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import "../src/index.ts";
import type { SessionData, SessionStore } from "../src/session.ts";
import { createMemorySessionStore } from "../src/session.ts";
import { makeBff, testConfig, type TestBff } from "./helpers/bff.ts";
import { startIdp, type TestIdp } from "./helpers/idp.ts";
import { startUpstream, type TestUpstream } from "./helpers/upstream.ts";

let idp: TestIdp;
let up: TestUpstream;

const SESSION_COOKIE = "__Host-Http-session";

function upstreams(): string {
  return JSON.stringify({
    plain: { url: up.url, audience: "plain-api", methods: ["GET"] },
    crud: {
      url: up.url,
      audience: "crud-api",
      methods: ["GET"],
      tokenExchange: true,
    },
    twin: {
      url: up.url,
      audience: "crud-api",
      methods: ["GET"],
      tokenExchange: true,
    },
    other: {
      url: up.url,
      audience: "other-api",
      methods: ["GET"],
      tokenExchange: true,
    },
  });
}

/** Wraps a store, replacing selected methods. */
function wrap(
  inner: SessionStore,
  overrides: Partial<Record<keyof SessionStore, unknown>>,
): SessionStore {
  return new Proxy(inner, {
    get(target, prop) {
      if (Object.hasOwn(overrides, prop)) {
        return overrides[prop as keyof SessionStore];
      }
      const value = Reflect.get(target, prop) as unknown;
      return typeof value === "function"
        ? (value as (...a: unknown[]) => unknown).bind(target)
        : value;
    },
  });
}

function register(bff: TestBff): void {
  bff.app.get("/bff/test-token", async (request, reply) => {
    if (request.bffSession === null) {
      return reply.code(401).send({ error: "no session" });
    }
    const upstream = (request.query as { u?: string }).u ?? "crud";
    return { token: await request.bffSession.accessTokenFor(upstream) };
  });
}

async function loggedIn(
  opts: { env?: Record<string, string>; store?: SessionStore } = {},
): Promise<{
  bff: TestBff;
  id: string;
  data: SessionData;
  inner: SessionStore;
}> {
  const inner = opts.store ?? createMemorySessionStore();
  const bff = await makeBff(idp, {
    store: inner,
    env: { BFF_UPSTREAMS: upstreams(), ...opts.env },
  });
  register(bff);
  await bff.browser.login();
  const id = bff.browser.bffJar.get(SESSION_COOKIE) as string;
  return { bff, id, data: (await inner.get(id)) as SessionData, inner };
}

async function token(bff: TestBff, u = "crud"): Promise<string> {
  const res = await bff.browser.request("GET", `/bff/test-token?u=${u}`);
  expect(res.statusCode).toBe(200);
  return res.json<{ token: string }>().token;
}

beforeAll(async () => {
  idp = await startIdp();
  up = await startUpstream();
});

afterAll(async () => {
  await up.close();
  await idp.close();
});

beforeEach(() => {
  idp.exchange.calls.length = 0;
  idp.exchange.fail = undefined;
  idp.exchange.echo = false;
  idp.exchange.expiresIn = 300;
  idp.exchange.delayMs = 0;
  idp.exchange.issuedTokenType =
    "urn:ietf:params:oauth:token-type:access_token";
  idp.exchange.tokenType = "Bearer";
  up.seen.length = 0;
});

describe("per-audience token exchange", () => {
  it("exchanges the session token for the upstream's audience (RFC 8693)", async () => {
    const { bff, id, data, inner } = await loggedIn();
    const exchanged = await token(bff);
    expect(exchanged).not.toBe(data.accessToken);
    expect(idp.exchange.calls).toEqual([
      {
        client: "bff",
        subject_token: data.accessToken,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        audience: "crud-api",
        scope: undefined,
        auth: expect.stringMatching(/^(post|basic)$/),
      },
    ]);
    const stored = (await inner.get(id)) as SessionData;
    expect(stored.exchanged?.["crud-api"]?.accessToken).toBe(exchanged);
    expect(stored.accessToken).toBe(data.accessToken);
    expect(stored.version).toBe(data.version + 1);
    await bff.app.close();
  });

  it("caches per audience: a second call, and another upstream with the same audience, reuse it", async () => {
    const { bff } = await loggedIn();
    const first = await token(bff);
    expect(await token(bff)).toBe(first);
    expect(await token(bff, "twin")).toBe(first);
    expect(idp.exchange.calls).toHaveLength(1);
    const second = await token(bff, "other");
    expect(second).not.toBe(first);
    expect(idp.exchange.calls.map((c) => c["audience"])).toEqual([
      "crud-api",
      "other-api",
    ]);
    await bff.app.close();
  });

  it("leaves upstreams without tokenExchange on the session token", async () => {
    const { bff, data } = await loggedIn();
    expect(await token(bff, "plain")).toBe(data.accessToken);
    expect(idp.exchange.calls).toHaveLength(0);
    await bff.app.close();
  });

  it("forwards the exchanged token upstream, not the session token", async () => {
    const { bff, data } = await loggedIn();
    const res = await bff.browser.request("GET", "/api/crud/x", {
      csrf: true,
    });
    expect(res.statusCode).toBe(200);
    const auth = String(up.seen[0]?.headers["authorization"]);
    expect(auth).toMatch(/^Bearer .+/);
    expect(auth).not.toContain(data.accessToken);
    await bff.app.close();
  });

  it("shares one exchange between concurrent requests of a process", async () => {
    idp.exchange.delayMs = 60;
    const { bff } = await loggedIn();
    const all = await Promise.all([token(bff), token(bff), token(bff)]);
    expect(new Set(all).size).toBe(1);
    expect(idp.exchange.calls).toHaveLength(1);
    await bff.app.close();
  });

  it("lets replicas exchange on their own and converges on the cached token", async () => {
    idp.exchange.delayMs = 60;
    const { bff, inner, id } = await loggedIn();
    const second = await makeBff(idp, {
      store: inner,
      env: { BFF_UPSTREAMS: upstreams() },
    });
    register(second);
    second.browser.bffJar.set(SESSION_COOKIE, id);
    const both = await Promise.all([token(bff), token(second)]);
    expect(both.length).toBe(2);
    const stored = ((await inner.get(id)) as SessionData).exchanged?.[
      "crud-api"
    ]?.accessToken;
    expect(both).toContain(stored);
    // From now on both replicas serve the cached token.
    expect(await token(bff)).toBe(stored);
    expect(await token(second)).toBe(stored);
    await bff.app.close();
    await second.app.close();
  });

  it("serves the token without caching it while a refresh holds the lock", async () => {
    const { bff, inner, id } = await loggedIn();
    await inner.acquireLock(id, 60_000);
    expect(await token(bff)).toBeTruthy();
    expect(((await inner.get(id)) as SessionData).exchanged).toBeUndefined();
    await bff.app.close();
  });

  it("merges the cached token into a session that was refreshed meanwhile", async () => {
    const inner = createMemorySessionStore();
    const store = wrap(inner, {
      acquireLock: async (id: string, ttlMs: number) => {
        const current = (await inner.get(id)) as SessionData;
        await inner.replace(
          id,
          { ...current, accessToken: "refreshed-meanwhile" },
          600_000,
          current.version,
        );
        return inner.acquireLock(id, ttlMs);
      },
    });
    const { bff, id, data } = await loggedIn({ store });
    await token(bff);
    const after = (await inner.get(id)) as SessionData;
    expect(after.accessToken).toBe("refreshed-meanwhile");
    expect(after.exchanged?.["crud-api"]).toBeDefined();
    expect(after.version).toBe(data.version + 2);
    await bff.app.close();
  });

  it("exchanges again once the cached token is about to expire, dropping dead entries", async () => {
    const { bff, id, data, inner } = await loggedIn();
    const first = await token(bff);
    const stored = (await inner.get(id)) as SessionData;
    await inner.put(
      id,
      {
        ...stored,
        exchanged: {
          "crud-api": {
            accessToken: first,
            expiresAt: Date.now() / 1000 + 10,
          },
          "dead-api": { accessToken: "dead", expiresAt: 1 },
        },
      },
      600,
    );
    const second = await token(bff);
    expect(second).not.toBe(first);
    expect(idp.exchange.calls).toHaveLength(2);
    expect(
      Object.keys(((await inner.get(id)) as SessionData).exchanged ?? {}),
    ).toEqual(["crud-api"]);
    expect(data.exchanged).toBeUndefined();
    await bff.app.close();
  });

  it("keeps the cache across a refresh of the session token and exchanges the refreshed one", async () => {
    const { bff, id, inner } = await loggedIn();
    const first = await token(bff, "crud");
    const stored = (await inner.get(id)) as SessionData;
    await inner.put(id, { ...stored, accessExpiresAt: 0 }, 600);
    expect(await token(bff, "crud")).toBe(first);
    const refreshed = (await inner.get(id)) as SessionData;
    expect(refreshed.accessToken).not.toBe(stored.accessToken);
    expect(refreshed.exchanged?.["crud-api"]?.accessToken).toBe(first);
    // A new audience is exchanged from the refreshed subject token.
    await token(bff, "other");
    expect(idp.exchange.calls.at(-1)?.["subject_token"]).toBe(
      refreshed.accessToken,
    );
    await bff.app.close();
  });

  it("refreshes a stale session token that expired before the exchange", async () => {
    const { bff, id, inner } = await loggedIn();
    const stored = (await inner.get(id)) as SessionData;
    await inner.put(id, { ...stored, accessExpiresAt: 0 }, 600);
    await token(bff);
    const after = (await inner.get(id)) as SessionData;
    expect(after.accessToken).not.toBe(stored.accessToken);
    expect(idp.exchange.calls[0]?.["subject_token"]).toBe(after.accessToken);
    await bff.app.close();
  });

  it("serves a lifetime-less or too-short exchange once and caches nothing", async () => {
    const { bff, id, inner } = await loggedIn();
    idp.exchange.expiresIn = null;
    const a = await token(bff);
    idp.exchange.expiresIn = 5;
    const b = await token(bff);
    expect(a).not.toBe(b);
    expect(idp.exchange.calls).toHaveLength(2);
    expect(((await inner.get(id)) as SessionData).exchanged).toBeUndefined();
    await bff.app.close();
  });

  it("still serves the token when the session moved on while exchanging", async () => {
    const inner = createMemorySessionStore();
    let lose = true;
    const store = wrap(inner, {
      replace: async (...args: Parameters<SessionStore["replace"]>) => {
        if (lose) {
          lose = false;
          return false;
        }
        return inner.replace(...args);
      },
    });
    const { bff, id } = await loggedIn({ store });
    const exchanged = await token(bff);
    expect(exchanged).toBeTruthy();
    expect(((await inner.get(id)) as SessionData).exchanged).toBeUndefined();
    await bff.app.close();
  });

  it("serves and caches the token even if releasing the lock fails", async () => {
    const inner = createMemorySessionStore();
    const store = wrap(inner, {
      releaseLock: () => Promise.reject(new Error("valkey down")),
    });
    const { bff, id } = await loggedIn({ store });
    const exchanged = await token(bff);
    expect(
      ((await inner.get(id)) as SessionData).exchanged?.["crud-api"]
        ?.accessToken,
    ).toBe(exchanged);
    expect(
      bff.logs.some((l) => l["msg"] === "refresh lock release failed"),
    ).toBe(true);
    await bff.app.close();
  });

  it("answers 401 when the session is gone after the exchange", async () => {
    const inner = createMemorySessionStore();
    const store = wrap(inner, {
      acquireLock: async (id: string, ttlMs: number) => {
        await inner.destroy(id);
        return inner.acquireLock(id, ttlMs);
      },
    });
    const { bff } = await loggedIn({ store });
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "session_expired" });
    await bff.app.close();
  });
});

describe("a failed exchange fails closed", () => {
  async function expectBlocked(
    bff: TestBff,
    data: SessionData,
    status: number,
    error: string,
  ): Promise<void> {
    const res = await bff.browser.request("GET", "/api/crud/x", {
      csrf: true,
    });
    expect(res.statusCode).toBe(status);
    expect(res.json()).toEqual({ error });
    expect(up.seen).toHaveLength(0);
    const logged = JSON.stringify(bff.logs);
    expect(logged).not.toContain(data.accessToken);
    expect(logged).not.toContain(data.refreshToken as string);
    expect(logged).not.toContain(data.idToken);
  }

  it("answers 502 and sends nothing upstream when the IdP refuses", async () => {
    const { bff, data, id, inner } = await loggedIn();
    idp.exchange.fail = "invalid_target";
    await expectBlocked(bff, data, 502, "token_exchange_failed");
    const event = bff.logs.find((l) => l["event"] === "token_exchange_failed");
    expect(event).toMatchObject({
      security: true,
      sub: "alice",
      audience: "crud-api",
      reason: "invalid_target",
      level: 40,
    });
    // The session survives: a denied exchange is not a dead login.
    expect(await inner.get(id)).toBeDefined();
    await bff.app.close();
  });

  it("recovers once the IdP accepts the exchange again", async () => {
    const { bff } = await loggedIn();
    idp.exchange.fail = "access_denied";
    expect(
      (await bff.browser.request("GET", "/bff/test-token")).statusCode,
    ).toBe(502);
    idp.exchange.fail = undefined;
    expect(await token(bff)).toBeTruthy();
    await bff.app.close();
  });

  it("answers 502 when the IdP hands the session token back", async () => {
    const { bff, data } = await loggedIn();
    idp.exchange.echo = true;
    await expectBlocked(bff, data, 502, "token_exchange_failed");
    expect(
      bff.logs.find((l) => l["event"] === "token_exchange_failed")?.["reason"],
    ).toBe("token_not_exchanged");
    await bff.app.close();
  });

  it("answers 502 for a token that is not a bearer access token", async () => {
    const { bff, data } = await loggedIn();
    idp.exchange.tokenType = "N_A";
    await expectBlocked(bff, data, 502, "token_exchange_failed");
    idp.exchange.tokenType = "Bearer";
    idp.exchange.issuedTokenType = "urn:ietf:params:oauth:token-type:jwt";
    await expectBlocked(bff, data, 502, "token_exchange_failed");
    await bff.app.close();
  });

  it("answers 503 and keeps the session when the IdP cannot be reached", async () => {
    const inner = createMemorySessionStore();
    const { bff, id, data } = await loggedIn({ store: inner });
    await bff.app.close();
    const down = await makeBff(
      { issuer: "http://localhost:1" },
      { store: inner, env: { BFF_UPSTREAMS: upstreams() } },
    );
    down.browser.bffJar.set(SESSION_COOKIE, id);
    await expectBlocked(down, data, 503, "idp_unavailable");
    expect(await inner.get(id)).toBeDefined();
    expect(
      down.logs.find((l) => l["event"] === "token_exchange_failed")?.["reason"],
    ).toBeTypeOf("string");
    await down.app.close();
  });

  it("answers 502 for an unusable response, 503 when the IdP times out", async () => {
    const { bff, data } = await loggedIn({
      env: { OIDC_TIMEOUT_SECONDS: "1" },
    });
    idp.exchange.raw = "<html>not json</html>";
    await expectBlocked(bff, data, 502, "token_exchange_failed");
    idp.exchange.raw = undefined;
    idp.exchange.delayMs = 1500;
    await expectBlocked(bff, data, 503, "idp_unavailable");
    await bff.app.close();
  });

  it("answers 503 when the IdP goes away after discovery", async () => {
    const gone = await startIdp();
    const bff = await makeBff(gone, { env: { BFF_UPSTREAMS: upstreams() } });
    register(bff);
    await bff.browser.login();
    const id = bff.browser.bffJar.get(SESSION_COOKIE) as string;
    const data = (await bff.store.get(id)) as SessionData;
    await gone.close();
    await expectBlocked(bff, data, 503, "idp_unavailable");
    await bff.app.close();
  });

  it("logs only a well-formed IdP error code as the reason", async () => {
    const { bff } = await loggedIn();
    idp.exchange.fail = "Bad Code! <script>";
    expect(
      (await bff.browser.request("GET", "/bff/test-token")).statusCode,
    ).toBe(502);
    expect(
      bff.logs.find((l) => l["event"] === "token_exchange_failed")?.["reason"],
    ).toBe("invalid_error");
    await bff.app.close();
  });

  it("checks the audience of a JWT, and lets opaque tokens through", async () => {
    const { bff, data } = await loggedIn();
    idp.exchange.jwt = { aud: "other-api" };
    await expectBlocked(bff, data, 502, "token_exchange_failed");
    idp.exchange.jwt = { aud: undefined };
    await expectBlocked(bff, data, 502, "token_exchange_failed");
    expect(
      bff.logs
        .filter((l) => l["event"] === "token_exchange_failed")
        .map((l) => l["reason"]),
    ).toEqual(["audience_missing", "audience_missing"]);
    idp.exchange.jwt = { aud: "crud-api" };
    expect(await token(bff)).toBeTruthy();
    idp.exchange.jwt = { aud: ["x", "other-api"] };
    expect(await token(bff, "other")).toBeTruthy();
    await bff.app.close();
  });

  it("names a non-Error failure 'unknown'", async () => {
    const { bff, data } = await loggedIn();
    // The OIDC client rejects with a bare string.
    const original = bff.app.bffOidc.configuration.bind(bff.app.bffOidc);
    bff.app.bffOidc.configuration = (): ReturnType<typeof original> =>
      Promise.reject("boom" as unknown as Error);
    await expectBlocked(bff, data, 503, "idp_unavailable");
    expect(
      bff.logs.find((l) => l["event"] === "token_exchange_failed")?.["reason"],
    ).toBe("unknown");
    await bff.app.close();
  });

  it("is off unless configured: the schema default keeps the shared token", () => {
    const config = testConfig(idp, { BFF_UPSTREAMS: upstreams() });
    expect(config.upstreams["plain"]?.tokenExchange).toBe(false);
    expect(config.upstreams["crud"]?.tokenExchange).toBe(true);
  });
});
