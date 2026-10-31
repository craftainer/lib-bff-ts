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
    return { token: await request.bffSession.accessTokenFor("crud") };
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
          return async (id: string, data: SessionData, ttlMs: number) => {
            await target.destroy(id); // logout lands before the refreshed tokens are written
            return target.replace(id, data, ttlMs);
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
