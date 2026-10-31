import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { SessionData, SessionStore } from "../src/session.ts";
import { createMemorySessionStore } from "../src/session.ts";
import { makeBff, testConfig, type TestBff } from "./helpers/bff.ts";
import { startIdp, type TestIdp } from "./helpers/idp.ts";

let idp: TestIdp;

type Step = { value: SessionData | undefined } | "real";

/** A store whose next `get` calls return scripted results; afterwards it delegates. */
function scripted(inner: SessionStore): {
  store: SessionStore;
  script: Step[];
} {
  const script: Step[] = [];
  const store = new Proxy(inner, {
    get(target, prop) {
      if (prop === "get") {
        return async (id: string) => {
          const step = script.shift();
          return step === undefined || step === "real"
            ? target.get(id)
            : step.value;
        };
      }
      const value = Reflect.get(target, prop) as unknown;
      return typeof value === "function"
        ? (value as (...a: unknown[]) => unknown).bind(target)
        : value;
    },
  });
  return { store, script };
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
  opts: {
    env?: Record<string, string>;
    config?: ReturnType<typeof testConfig>;
  } = {},
): Promise<{
  bff: TestBff;
  id: string;
  data: SessionData;
  inner: SessionStore;
  script: Step[];
}> {
  const inner = createMemorySessionStore();
  const { store, script } = scripted(inner);
  const bff = await makeBff(idp, { store, ...opts });
  register(bff);
  await bff.browser.login();
  const id = bff.browser.bffJar.get("__Host-Http-session") as string;
  const data = (await inner.get(id)) as SessionData;
  return { bff, id, data, inner, script };
}

beforeAll(async () => {
  idp = await startIdp();
});

afterAll(async () => {
  await idp.close();
});

async function expire(
  inner: SessionStore,
  id: string,
  data: SessionData,
): Promise<void> {
  await inner.put(id, { ...data, accessExpiresAt: 0 }, 600);
}

describe("access token refresh", () => {
  it("returns the current token while it is fresh", async () => {
    const { bff, data } = await loggedIn();
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.json()).toEqual({ token: data.accessToken });
    await bff.app.close();
  });

  it("refreshes an expiring token with rotation, once for concurrent requests", async () => {
    const { bff, id, data, inner } = await loggedIn();
    await expire(inner, id, data);
    const [a, b] = await Promise.all([
      bff.browser.request("GET", "/bff/test-token"),
      bff.browser.request("GET", "/bff/test-token"),
    ]);
    expect(a.statusCode).toBe(200);
    expect(b.statusCode).toBe(200);
    const token = a.json<{ token: string }>().token;
    expect(token).not.toBe(data.accessToken);
    expect(b.json()).toEqual({ token });
    const after = (await inner.get(id)) as SessionData;
    expect(after.refreshToken).not.toBe(data.refreshToken);
    expect(after.accessToken).toBe(token);
    expect(after.accessExpiresAt).toBeGreaterThan(Date.now() / 1000);
    expect(after.sub).toBe(data.sub);
    await bff.app.close();
  });

  it("destroys the session and answers 401 when the refresh is rejected", async () => {
    const { bff, id, data, inner } = await loggedIn();
    await inner.put(
      id,
      { ...data, accessExpiresAt: 0, refreshToken: "revoked-or-garbage" },
      600,
    );
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "session_expired" });
    expect(await inner.get(id)).toBeUndefined();
    expect(
      bff.logs.some(
        (l) => l["event"] === "refresh_failed" && l["sub"] === "alice",
      ),
    ).toBe(true);
    await bff.app.close();
  });

  it("fails like a rejected refresh when there is no refresh token", async () => {
    const { bff, id, data, inner } = await loggedIn();
    await inner.put(
      id,
      { ...data, accessExpiresAt: 0, refreshToken: null },
      600,
    );
    expect(
      (await bff.browser.request("GET", "/bff/test-token")).statusCode,
    ).toBe(401);
    expect(await inner.get(id)).toBeUndefined();
    await bff.app.close();
  });

  it("keeps the session and answers 503 when the IdP is unreachable", async () => {
    const down = await makeBff({ issuer: "http://localhost:1" });
    register(down);
    const data: SessionData = {
      sub: "alice",
      sid: null,
      name: "alice",
      email: null,
      roles: {},
      idToken: "x",
      accessToken: "old",
      refreshToken: "rt",
      accessExpiresAt: 0,
      createdAt: 0,
      absoluteExpiresAt: Date.now() / 1000 + 600,
    };
    await down.store.put("S".repeat(43), data, 600);
    down.browser.bffJar.set("__Host-Http-session", "S".repeat(43));
    const res = await down.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({ error: "idp_unavailable" });
    expect(await down.store.get("S".repeat(43))).toBeDefined();
    await down.app.close();
  });

  it("rejects unknown upstreams and the unimplemented token exchange", async () => {
    const { bff } = await loggedIn();
    expect(
      (await bff.browser.request("GET", "/bff/test-token?u=nope")).statusCode,
    ).toBe(500);
    await bff.app.close();

    const inner = createMemorySessionStore();
    const exchange = await makeBff(idp, {
      store: inner,
      env: {
        BFF_UPSTREAMS: JSON.stringify({
          crud: {
            url: "http://crud.test",
            audience: "api",
            methods: ["GET"],
            tokenExchange: true,
          },
        }),
      },
    });
    register(exchange);
    await exchange.browser.login();
    expect(
      (await exchange.browser.request("GET", "/bff/test-token")).statusCode,
    ).toBe(500);
    await exchange.app.close();
  });
});

describe("refresh lock", () => {
  const fresh = (d: SessionData): SessionData => ({
    ...d,
    accessToken: "refreshed-elsewhere",
    accessExpiresAt: Date.now() / 1000 + 600,
  });

  it("answers 401 when the session vanishes between the request and the lock", async () => {
    const { bff, id, data, inner, script } = await loggedIn();
    await expire(inner, id, data);
    script.push("real", { value: undefined });
    expect(
      (await bff.browser.request("GET", "/bff/test-token")).statusCode,
    ).toBe(401);
    await bff.app.close();
  });

  it("uses a session refreshed by someone else while it took the lock", async () => {
    const { bff, id, data, inner, script } = await loggedIn();
    await expire(inner, id, data);
    script.push("real", { value: fresh(data) });
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.json()).toEqual({ token: "refreshed-elsewhere" });
    await bff.app.close();
  });

  it("waits for the lock holder and uses its result", async () => {
    const { bff, id, data, inner, script } = await loggedIn();
    await expire(inner, id, data);
    await inner.acquireLock(id, 60_000);
    script.push("real", { value: fresh(data) });
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.json()).toEqual({ token: "refreshed-elsewhere" });
    await bff.app.close();
  });

  it("answers 401 if the session vanishes while waiting", async () => {
    const { bff, id, data, inner, script } = await loggedIn();
    await expire(inner, id, data);
    await inner.acquireLock(id, 60_000);
    script.push("real", { value: undefined });
    expect(
      (await bff.browser.request("GET", "/bff/test-token")).statusCode,
    ).toBe(401);
    await bff.app.close();
  });

  it("gives up with 503 when the lock holder never finishes", async () => {
    const base = testConfig(idp);
    const config = {
      ...base,
      session: {
        ...base.session,
        refreshLock: { ttlMs: 5000, waitMs: 60, pollMs: 10 },
      },
    };
    const { bff, id, data, inner } = await loggedIn({ config });
    await expire(inner, id, data);
    await inner.acquireLock(id, 60_000);
    const res = await bff.browser.request("GET", "/bff/test-token");
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({ error: "refresh_in_progress" });
    await bff.app.close();
  });
});
