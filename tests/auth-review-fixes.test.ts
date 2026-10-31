import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { extractRoles } from "../src/auth/roles.ts";
import {
  absoluteExpiry,
  createMemorySessionStore,
  sessionTtlSeconds,
  type SessionData,
  type SessionStore,
} from "../src/session.ts";
import { makeBff, testConfig, type TestBff } from "./helpers/bff.ts";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  startIdp,
  type TestIdp,
} from "./helpers/idp.ts";

let idp: TestIdp;

beforeAll(async () => {
  idp = await startIdp();
});

afterAll(async () => {
  await idp.close();
});

const COOKIE = "__Host-Http-session";

function register(bff: TestBff): void {
  bff.app.get("/bff/test-token", async (request, reply) => {
    if (request.bffSession === null) {
      return reply.code(401).send({ error: "no session" });
    }
    return {
      token: await request.bffSession.accessTokenFor(
        (request.query as { u?: string }).u ?? "crud",
      ),
    };
  });
}

async function loggedIn(
  store: SessionStore,
  account = "alice",
): Promise<{ bff: TestBff; id: string; data: SessionData }> {
  const bff = await makeBff(idp, { store });
  register(bff);
  await bff.browser.login(undefined, account);
  const id = bff.browser.bffJar.get(COOKIE) as string;
  return { bff, id, data: (await store.get(id)) as SessionData };
}

/** A second BFF on the same store whose client secret the IdP rejects (`invalid_client`). */
async function rejectedClient(
  store: SessionStore,
  id: string,
): Promise<TestBff> {
  const bff = await makeBff(idp, {
    store,
    env: { OIDC_CLIENT_SECRET: "wrong-secret" },
  });
  register(bff);
  bff.browser.bffJar.set(COOKIE, id);
  return bff;
}

describe("refresh", () => {
  it("does not resurrect a session that was logged out while the refresh was in flight", async () => {
    const inner = createMemorySessionStore();
    const racing = new Proxy(inner, {
      get(target, prop) {
        if (prop === "replace") {
          return async (
            id: string,
            data: SessionData,
            ttlMs: number,
            version: number,
          ) => {
            await target.destroy(id); // logout lands before the refreshed tokens are written
            return target.replace(id, data, ttlMs, version);
          };
        }
        const value = Reflect.get(target, prop) as unknown;
        return typeof value === "function"
          ? (value as (...a: unknown[]) => unknown).bind(target)
          : value;
      },
    });
    const { bff, id, data } = await loggedIn(racing);
    await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "session_expired" });
    expect(await inner.get(id)).toBeUndefined();
    await bff.app.close();
  });

  it("keeps the session and answers 503 for an OAuth error other than invalid_grant", async () => {
    const store = createMemorySessionStore();
    const { bff, id, data } = await loggedIn(store);
    await store.put(id, { ...data, accessExpiresAt: 0 }, 600);
    const other = await rejectedClient(store, id);
    const res = await other.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({ error: "idp_unavailable" });
    expect(await store.get(id)).toBeDefined();
    await other.app.close();
    await bff.app.close();
  });
});

describe("logout revokes the refresh token (RFC 7009)", () => {
  async function refreshGrantStatus(refreshToken: string): Promise<number> {
    const res = await fetch(`${idp.issuer}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
    });
    return res.status;
  }

  it("revokes it at the IdP", async () => {
    const store = createMemorySessionStore();
    const { bff, data } = await loggedIn(store);
    const refreshToken = data.refreshToken as string;
    const res = await bff.browser.request("POST", "/bff/logout", {
      csrf: true,
    });
    expect(res.statusCode).toBe(200);
    expect(await refreshGrantStatus(refreshToken)).toBe(400);
    expect(bff.logs.some((l) => l["event"] === "token_revocation_failed")).toBe(
      false,
    );
    await bff.app.close();
  });

  it("logs the failure and still logs out when the IdP rejects the revocation", async () => {
    const store = createMemorySessionStore();
    const { bff, id } = await loggedIn(store);
    const other = await rejectedClient(store, id);
    const res = await other.browser.request("POST", "/bff/logout", {
      csrf: true,
    });
    expect(res.statusCode).toBe(200);
    expect(await store.get(id)).toBeUndefined();
    expect(
      other.logs.some(
        (l) => l["event"] === "token_revocation_failed" && l["sub"] === "alice",
      ),
    ).toBe(true);
    await other.app.close();
    await bff.app.close();
  });

  it("gives up after 2 seconds and does not block the logout", async () => {
    const store = createMemorySessionStore();
    const { bff } = await loggedIn(store);
    idp.revocationDelayMs = 2600;
    try {
      const started = Date.now();
      const res = await bff.browser.request("POST", "/bff/logout", {
        csrf: true,
      });
      expect(res.statusCode).toBe(200);
      expect(Date.now() - started).toBeLessThan(2500);
      expect(
        bff.logs.some((l) => l["event"] === "token_revocation_failed"),
      ).toBe(true);
    } finally {
      idp.revocationDelayMs = 0;
    }
    await bff.app.close();
  });

  it("skips revocation without a refresh token", async () => {
    const store = createMemorySessionStore();
    const { bff, id, data } = await loggedIn(store);
    await store.put(id, { ...data, refreshToken: null }, 600);
    const res = await bff.browser.request("POST", "/bff/logout", {
      csrf: true,
    });
    expect(res.statusCode).toBe(200);
    expect(bff.logs.some((l) => l["event"] === "token_revocation_failed")).toBe(
      false,
    );
    await bff.app.close();
  });

  it("skips revocation when the IdP advertises no revocation_endpoint", async () => {
    const plain = await startIdp({ revocation: false });
    try {
      const store = createMemorySessionStore();
      const bff = await makeBff(plain, { store });
      await bff.browser.login();
      const res = await bff.browser.request("POST", "/bff/logout", {
        csrf: true,
      });
      expect(res.statusCode).toBe(200);
      expect(
        bff.logs.some((l) => l["event"] === "token_revocation_failed"),
      ).toBe(false);
      await bff.app.close();
    } finally {
      await plain.close();
    }
  });
});

describe("roles", () => {
  it("builds roles without a prototype and ignores reserved client IDs", () => {
    const claims = JSON.parse(
      '{"realm_access":{"roles":["user"]},"resource_access":{"__proto__":{"roles":["x"]},"realm":{"roles":["evil"]},"app":{"roles":["r"]}}}',
    ) as Record<string, unknown>;
    const skipped: string[] = [];
    const roles = extractRoles(claims, "opaque", (id) => skipped.push(id));
    expect(roles).toEqual({ realm: ["user"], app: ["r"] });
    expect(Object.getPrototypeOf(roles)).toBeNull();
    expect(skipped).toEqual(["realm"]);
    expect(extractRoles(claims, "opaque")).toEqual(roles); // zod already drops a __proto__ key
  });

  it("keeps a client named realm out of the realm roles at login and warns", async () => {
    const store = createMemorySessionStore();
    const { bff, data } = await loggedIn(store, "reserved");
    expect(data.roles).toEqual({ realm: ["user"], [CLIENT_ID]: ["editor"] });
    expect(
      bff.logs.some((l) =>
        String(l["msg"]).includes("reserved client ID in the roles claims"),
      ),
    ).toBe(true);
    await bff.app.close();
  });
});

describe("token lifetimes", () => {
  const config = testConfig({ issuer: "http://localhost:1" });

  it("rounds fractional refresh_expires_in down, to at least one second", () => {
    expect(absoluteExpiry(config, 100, 1799.5)).toBe(1899);
    expect(absoluteExpiry(config, 100, 0.4)).toBe(101);
    expect(absoluteExpiry(config, 100, "soon")).toBe(
      100 + config.session.absoluteSeconds,
    );
  });

  it("derives integer store TTLs of at least one second", () => {
    const data = { absoluteExpiresAt: 110.5 } as SessionData;
    expect(sessionTtlSeconds(config, data, 100)).toBe(10);
    expect(sessionTtlSeconds(config, data, 200)).toBe(1);
  });
});

function storeWith(
  inner: SessionStore,
  overrides: Record<string, (...args: never[]) => unknown>,
): SessionStore {
  return new Proxy(inner, {
    get(target, prop: string) {
      if (prop in overrides) {
        return overrides[prop];
      }
      const value = Reflect.get(target, prop) as unknown;
      return typeof value === "function"
        ? (value as (...a: unknown[]) => unknown).bind(target)
        : value;
    },
  });
}

async function refreshGrantStatus(refreshToken: string): Promise<number> {
  const res = await fetch(`${idp.issuer}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });
  return res.status;
}

describe("refresh that loses the race against a logout", () => {
  async function race(): Promise<{
    bff: TestBff;
    rotated: () => string | undefined;
  }> {
    const inner = createMemorySessionStore();
    let rotated: string | undefined;
    const racing = storeWith(inner, {
      replace: (async (
        id: string,
        data: SessionData,
        ttlMs: number,
        version: number,
      ) => {
        rotated = data.refreshToken ?? undefined;
        await inner.destroy(id);
        return inner.replace(id, data, ttlMs, version);
      }) as never,
    });
    const { bff, id, data } = await loggedIn(racing);
    await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(401);
    return { bff, rotated: () => rotated };
  }

  it("revokes the rotated refresh token it was about to store", async () => {
    const { bff, rotated } = await race();
    expect(rotated()).toBeDefined();
    expect(await refreshGrantStatus(rotated() as string)).toBe(400);
    await bff.app.close();
  });

  it("logs when that revocation fails", async () => {
    idp.revocationDelayMs = 2600;
    try {
      const { bff } = await race();
      expect(
        bff.logs.some((l) => l["event"] === "token_revocation_failed"),
      ).toBe(true);
      await bff.app.close();
    } finally {
      idp.revocationDelayMs = 0;
    }
  });
});

describe("bounded refresh", () => {
  it("answers 503 and keeps the session when the IdP stalls past OIDC_TIMEOUT_SECONDS", async () => {
    const store = createMemorySessionStore();
    const bff = await makeBff(idp, {
      store,
      env: { OIDC_TIMEOUT_SECONDS: "1" },
    });
    register(bff);
    await bff.browser.login();
    const id = bff.browser.bffJar.get(COOKIE) as string;
    const data = (await store.get(id)) as SessionData;
    await store.put(id, { ...data, accessExpiresAt: 0 }, 600);
    idp.tokenDelayMs = 2500;
    try {
      const started = Date.now();
      const res = await bff.browser.request("GET", "/bff/test-token");
      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({ error: "idp_unavailable" });
      expect(Date.now() - started).toBeLessThan(2400);
      expect(await store.get(id)).toBeDefined();
    } finally {
      idp.tokenDelayMs = 0;
    }
    await bff.app.close();
  });

  it("refuses an IdP timeout that is not below the refresh lock TTL", () => {
    expect(() => testConfig(idp, { OIDC_TIMEOUT_SECONDS: "30" })).toThrow(
      /OIDC_TIMEOUT_SECONDS: must be below the 30 s refresh lock TTL/,
    );
    expect(
      testConfig(idp, { OIDC_TIMEOUT_SECONDS: "29" }).oidc.timeoutSeconds,
    ).toBe(29);
  });
});

describe("session cookie hygiene", () => {
  const setCookieFor = (res: { setCookies: string[] }): string | undefined =>
    res.setCookies.find((c) => c.startsWith(`${COOKIE}=`));

  it("drops a cookie that is not a session ID without touching the store", async () => {
    let reads = 0;
    const store = storeWith(createMemorySessionStore(), {
      get: (async () => {
        reads += 1;
        return undefined;
      }) as never,
    });
    const bff = await makeBff(idp, { store });
    bff.browser.bffJar.set(COOKIE, "short");
    const res = await bff.browser.request("GET", "/bff/user");
    expect(res.statusCode).toBe(401);
    expect(setCookieFor(res)).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);
    expect(reads).toBe(0);
    await bff.app.close();
  });

  it("drops the cookie of an unknown or absolutely expired session", async () => {
    const store = createMemorySessionStore();
    const bff = await makeBff(idp, { store });
    const unknown = "U".repeat(43);
    bff.browser.bffJar.set(COOKIE, unknown);
    const res = await bff.browser.request("GET", "/bff/user");
    expect(setCookieFor(res)).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);

    const { id, data } = await loggedIn(store).then(async (l) => {
      await l.bff.app.close();
      return l;
    });
    await store.put(id, { ...data, absoluteExpiresAt: 1 }, 600);
    bff.browser.bffJar.set(COOKIE, id);
    const expired = await bff.browser.request("GET", "/bff/user");
    expect(expired.statusCode).toBe(401);
    expect(setCookieFor(expired)).toMatch(
      /Max-Age=0|Expires=Thu, 01 Jan 1970/i,
    );
    expect(await store.get(id)).toBeUndefined();
    await bff.app.close();
  });
});

describe("upstream lookup", () => {
  it("only knows configured upstream names, not inherited properties", async () => {
    const store = createMemorySessionStore();
    const { bff } = await loggedIn(store);
    for (const name of ["constructor", "toString", "__proto__"]) {
      const res = await bff.browser.request("GET", `/bff/test-token?u=${name}`);
      expect(res.statusCode, name).toBe(500);
    }
    expect(
      (await bff.browser.request("GET", "/bff/test-token?u=crud")).statusCode,
    ).toBe(200);
    expect(Object.getPrototypeOf(bff.config.upstreams)).toBeNull();
    await bff.app.close();
  });
});

describe("error bodies", () => {
  it("answers 429 with rate_limited and hides framework error codes", async () => {
    const bff = await makeBff(idp, { env: { RATE_LIMIT_MAX: "1" } });
    await bff.browser.request("GET", "/bff/callback");
    const limited = await bff.browser.request("GET", "/bff/callback");
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toEqual({ error: "rate_limited" });
    await bff.app.close();
  });
});

describe("no-store on canonical /bff paths", () => {
  it("also covers percent-encoded spellings", async () => {
    const bff = await makeBff(idp);
    const res = await bff.browser.request("GET", "/%62ff/config");
    expect(res.statusCode).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    await bff.app.close();
  });
});

describe("roles claims are validated one part at a time", () => {
  it("keeps valid realm roles when resource_access is malformed, and the reverse", () => {
    expect(
      extractRoles(
        { realm_access: { roles: ["admin"] }, resource_access: { foo: {} } },
        "opaque",
      ),
    ).toEqual({ realm: ["admin"] });
    expect(
      extractRoles(
        {
          realm_access: { roles: "admin" },
          resource_access: { foo: { roles: ["r"] } },
        },
        "opaque",
      ),
    ).toEqual({ foo: ["r"] });
  });
});

/** Trades a refresh token at the IdP directly: what a concurrent refresh would have done. */
async function rotateAtIdp(refreshToken: string): Promise<{
  access_token: string;
  refresh_token: string;
}> {
  const res = await fetch(`${idp.issuer}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });
  return (await res.json()) as { access_token: string; refresh_token: string };
}

const FAR = (): number => Math.floor(Date.now() / 1000) + 3000;

describe("fenced refresh", () => {
  it("a refresh that lost the version race revokes its orphaned refresh token and uses the winner's session", async () => {
    const inner = createMemorySessionStore();
    let orphan: string | undefined;
    const racing = storeWith(inner, {
      replace: (async (
        id: string,
        data: SessionData,
        ttlMs: number,
        version: number,
      ) => {
        orphan = data.refreshToken ?? undefined;
        // Another request refreshed first and stored its result.
        await inner.replace(
          id,
          { ...data, accessToken: "winner", accessExpiresAt: FAR() },
          ttlMs,
          version,
        );
        return inner.replace(id, data, ttlMs, version);
      }) as never,
    });
    const { bff, id, data } = await loggedIn(racing);
    await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ token: "winner" });
    expect(orphan).toBeDefined();
    expect(await refreshGrantStatus(orphan as string)).toBe(400);
    expect((await inner.get(id))?.version).toBe(1);
    await bff.app.close();
  });

  it("leaves a refresh token alone when the IdP did not rotate it", async () => {
    const plain = await startIdp({ rotate: false });
    try {
      const inner = createMemorySessionStore();
      const racing = storeWith(inner, {
        replace: (async (
          id: string,
          data: SessionData,
          ttlMs: number,
          version: number,
        ) => {
          await inner.replace(
            id,
            { ...data, accessToken: "winner", accessExpiresAt: FAR() },
            ttlMs,
            version,
          );
          return inner.replace(id, data, ttlMs, version);
        }) as never,
      });
      const bff = await makeBff(plain, { store: racing });
      register(bff);
      await bff.browser.login();
      const id = bff.browser.bffJar.get(COOKIE) as string;
      const data = (await inner.get(id)) as SessionData;
      await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
      const res = await bff.browser.request("GET", "/bff/test-token");
      expect(res.json()).toEqual({ token: "winner" });
      expect(
        bff.logs.some((l) => l["event"] === "token_revocation_failed"),
      ).toBe(false);
      const stillValid = await fetch(`${plain.issuer}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: data.refreshToken as string,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
        }),
      });
      expect(stillValid.status).toBe(200);
      await bff.app.close();
    } finally {
      await plain.close();
    }
  });

  it("does not throw when revoking the orphan fails because the IdP configuration is unavailable", async () => {
    const inner = createMemorySessionStore();
    const racing = storeWith(inner, {
      replace: (async () => false) as never,
    });
    const { bff, id, data } = await loggedIn(racing);
    await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
    const oidc = bff.app.bffOidc;
    const real = oidc.configuration.bind(oidc);
    let calls = 0;
    oidc.configuration = async () => {
      calls += 1;
      if (calls > 1) {
        throw new Error("discovery failed");
      }
      return real();
    };
    const res = await bff.browser.request("GET", "/bff/test-token");
    // replace said "lost", the session still exists, so the caller gets it back.
    expect(res.statusCode).toBe(200);
    expect(bff.logs.some((l) => l["event"] === "token_revocation_failed")).toBe(
      true,
    );
    await bff.app.close();
  });

  it("uses the winner's session when a concurrent refresh already rotated the token (invalid_grant)", async () => {
    const inner = createMemorySessionStore();
    let gets = 0;
    let winner: SessionData | undefined;
    const store = storeWith(inner, {
      get: (async (id: string) => {
        gets += 1;
        return gets <= 2 && stale !== undefined ? stale : inner.get(id);
      }) as never,
    });
    let stale: SessionData | undefined;
    const { bff, id, data } = await loggedIn(store);
    gets = 0;
    stale = { ...data, accessExpiresAt: 0 };
    const rotated = await rotateAtIdp(data.refreshToken as string);
    winner = {
      ...data,
      accessToken: rotated.access_token,
      refreshToken: rotated.refresh_token,
      accessExpiresAt: FAR(),
      version: 1,
    };
    await inner.put(id, winner, 600);
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ token: rotated.access_token });
    expect(await inner.get(id)).toBeDefined();
    await bff.app.close();
  });

  it("ends the session on invalid_grant when nobody else refreshed or the session is gone", async () => {
    const inner = createMemorySessionStore();
    let gets = 0;
    let stale: SessionData | undefined;
    const store = storeWith(inner, {
      get: (async (id: string) => {
        gets += 1;
        return gets <= 2 && stale !== undefined ? stale : inner.get(id);
      }) as never,
    });
    const { bff, id, data } = await loggedIn(store);
    gets = 0;
    stale = {
      ...data,
      accessExpiresAt: 0,
      refreshToken: "garbage",
    };
    await inner.destroy(id);
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(401);
    await bff.app.close();
  });

  it("refuses to refresh a session that reached its absolute limit while the request ran", async () => {
    const inner = createMemorySessionStore();
    let gets = 0;
    const store = storeWith(inner, {
      get: (async (id: string) => {
        gets += 1;
        const real = await inner.get(id);
        return gets === 2 && real !== undefined
          ? { ...real, absoluteExpiresAt: 1 }
          : real;
      }) as never,
    });
    const { bff, id, data } = await loggedIn(store);
    await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
    gets = 0;
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(401);
    expect(await inner.get(id)).toBeUndefined();
    await bff.app.close();
  });

  it("honours a new refresh_expires_in by shortening the absolute limit", async () => {
    const store = createMemorySessionStore();
    const { bff, id, data } = await loggedIn(store);
    await store.put(id, { ...data, accessExpiresAt: 0 }, 600);
    idp.refreshExpiresIn = 120;
    try {
      const res = await bff.browser.request("GET", "/bff/test-token");
      expect(res.statusCode).toBe(200);
    } finally {
      idp.refreshExpiresIn = undefined;
    }
    const after = (await store.get(id)) as SessionData;
    const now = Math.floor(Date.now() / 1000);
    expect(after.absoluteExpiresAt).toBeLessThanOrEqual(now + 120);
    expect(after.absoluteExpiresAt).toBeLessThan(data.absoluteExpiresAt);
    expect(after.version).toBe(1);
    await bff.app.close();
  });

  it("a failing lock release never masks the outcome", async () => {
    const inner = createMemorySessionStore();
    const store = storeWith(inner, {
      releaseLock: (async () => {
        throw new Error("store connection dropped");
      }) as never,
    });
    const { bff, id, data } = await loggedIn(store);
    await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(200);
    expect(
      bff.logs.some((l) => l["msg"] === "refresh lock release failed"),
    ).toBe(true);
    await bff.app.close();
  });
});

describe("logout racing a refresh", () => {
  it("revokes the refresh token that is stored at logout, not the request's stale snapshot", async () => {
    const inner = createMemorySessionStore();
    let rotatedTo: string | undefined;
    const store = storeWith(inner, {
      touch: (async (id: string, ttl: number) => {
        // A concurrent refresh lands right after this request read the session.
        const snapshot = (await inner.get(id)) as SessionData;
        const next = await rotateAtIdp(snapshot.refreshToken as string);
        rotatedTo = next.refresh_token;
        await inner.replace(
          id,
          { ...snapshot, refreshToken: next.refresh_token },
          60_000,
          snapshot.version,
        );
        return inner.touch(id, ttl);
      }) as never,
    });
    const bff = await makeBff(idp, { store });
    await bff.browser.login();
    const res = await bff.browser.request("POST", "/bff/logout", {
      csrf: true,
    });
    expect(res.statusCode).toBe(200);
    expect(rotatedTo).toBeDefined();
    expect(await refreshGrantStatus(rotatedTo as string)).toBe(400);
    await bff.app.close();
  });
});

describe("back-channel logout while the IdP is unreachable", () => {
  it("answers 503 so the IdP retries, not a permanent 400", async () => {
    const down = await makeBff({ issuer: "http://localhost:1" });
    const res = await down.browser.request("POST", "/bff/backchannel-logout", {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "logout_token=abc",
    });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({ error: "idp_unavailable" });
    await down.app.close();
  });
});
