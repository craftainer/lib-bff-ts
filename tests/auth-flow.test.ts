import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMemorySessionStore } from "../src/session.ts";
import { Browser, makeBff, testConfig, type TestBff } from "./helpers/bff.ts";
import {
  CLIENT_ID,
  PUBLIC_ORIGIN,
  SCOPES,
  startIdp,
  type TestIdp,
} from "./helpers/idp.ts";

let idp: TestIdp;
let bff: TestBff;

function cookieOf(res: { setCookies: string[] }, name: string): string {
  const found = res.setCookies.find((c) => c.startsWith(`${name}=`));
  if (found === undefined) {
    throw new Error(`no ${name} cookie`);
  }
  return found;
}

function sessionId(b: Browser): string {
  return b.bffJar.get("__Host-Http-session") as string;
}

beforeAll(async () => {
  idp = await startIdp();
  bff = await makeBff(idp);
  bff.app.get("/bff/test-token", async (request, reply) => {
    if (request.bffSession === null) {
      return reply.code(401).send({ error: "no session" });
    }
    const upstream = (request.query as { u?: string }).u ?? "crud";
    return { token: await request.bffSession.accessTokenFor(upstream) };
  });
  bff.app.get("/bff/test-boom", async () => {
    throw new Error("secret internal detail");
  });
  bff.app.get("/plain", async (request) => ({
    session: request.bffSession === null ? "none" : "some",
  }));
});

afterAll(async () => {
  await bff.app.close();
  await idp.close();
});

describe("login", () => {
  it("starts the code flow with PKCE S256, state, nonce and a server-side transaction", async () => {
    const b = new Browser(bff.app, idp.issuer);
    const res = await b.request("GET", "/bff/login?returnTo=/dashboard");
    expect(res.statusCode).toBe(302);
    const url = new URL(String(res.headers["location"]));
    expect(url.origin).toBe(idp.issuer);
    expect(url.pathname).toBe("/auth");
    const q = url.searchParams;
    expect(q.get("response_type")).toBe("code");
    expect(q.get("client_id")).toBe(CLIENT_ID);
    expect(q.get("redirect_uri")).toBe(`${PUBLIC_ORIGIN}/bff/callback`);
    expect(q.get("scope")).toBe(SCOPES);
    expect(q.get("code_challenge_method")).toBe("S256");
    expect(q.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(q.get("nonce")).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(q.get("state")).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(q.get("code_verifier")).toBeNull();
    expect(res.headers["cache-control"]).toBe("no-store");

    const cookie = cookieOf(res, "__Host-Http-login");
    expect(cookie).toContain(`__Host-Http-login=${q.get("state")};`);
    expect(cookie).toMatch(/Path=\/;/);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Max-Age=300");
    expect(cookie).not.toContain("Domain");

    // The cookie holds only the ID: the verifier and nonce are server-side.
    expect(res.setCookies.join("\n")).not.toContain(String(q.get("nonce")));
    const tx = await bff.store.takeTransaction(String(q.get("state")));
    expect(tx).toMatchObject({ nonce: q.get("nonce"), returnTo: "/dashboard" });
    expect(tx?.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("completes the flow: session cookie attributes, return path, user profile without tokens", async () => {
    const b = new Browser(bff.app, idp.issuer);
    const cb = await b.login("/dashboard?x=1");
    expect(cb.statusCode).toBe(302);
    expect(cb.headers["location"]).toBe("/dashboard?x=1");
    const cookie = cookieOf(cb, "__Host-Http-session");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toMatch(/Path=\/(;|$)/);
    expect(cookie).not.toMatch(/Domain|Max-Age|Expires/);
    expect(sessionId(b)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(cookieOf(cb, "__Host-Http-login")).toContain("Max-Age=0");

    const user = await b.request("GET", "/bff/user");
    expect(user.statusCode).toBe(200);
    const body = user.json<Record<string, unknown>>();
    expect(body).toEqual({
      sub: "alice",
      name: "User alice",
      email: "alice@example.com",
      roles: { realm: ["user"], [CLIENT_ID]: ["editor"] },
      expiresAt: expect.any(Number),
    });
    expect(user.body).not.toMatch(/token/i);
    expect(user.headers["cache-control"]).toBe("no-store");

    const stored = await bff.store.get(sessionId(b));
    expect(stored?.accessToken).toBeTruthy();
    expect(stored?.refreshToken).toBeTruthy();
    expect(stored?.idToken.split(".")).toHaveLength(3);
    expect(stored?.absoluteExpiresAt).toBeGreaterThan(Date.now() / 1000);
  });

  it("omits email for users without one", async () => {
    const b = new Browser(bff.app, idp.issuer);
    await b.login(undefined, "noemail");
    const body = (await b.request("GET", "/bff/user")).json<
      Record<string, unknown>
    >();
    expect(body).not.toHaveProperty("email");
    expect(body["name"]).toBe("User noemail");
  });

  it("answers 401 without a session or with an unknown session ID", async () => {
    const b = new Browser(bff.app, idp.issuer);
    expect((await b.request("GET", "/bff/user")).statusCode).toBe(401);
    b.bffJar.set("__Host-Http-session", "planted-by-an-attacker");
    const res = await b.request("GET", "/bff/user");
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: "unauthenticated" });
  });

  it("ignores the session cookie outside /bff and /api", async () => {
    const b = new Browser(bff.app, idp.issuer);
    await b.login();
    expect((await b.request("GET", "/plain")).json()).toEqual({
      session: "none",
    });
    expect((await b.request("GET", "/bff/user")).statusCode).toBe(200);
  });

  it("falls back to / for every non same-origin returnTo", async () => {
    for (const returnTo of [
      "//evil.example/x",
      "https://evil.example/",
      "/\\evil.example",
      "/a\r\nSet-Cookie: x=1",
      "javascript:alert(1)",
    ]) {
      const b = new Browser(bff.app, idp.issuer);
      const cb = await b.login(returnTo);
      expect(cb.headers["location"]).toBe("/");
    }
  });

  it("rotates the session ID at login and ends the previous session (fixation)", async () => {
    const b = new Browser(bff.app, idp.issuer);
    await b.login();
    const first = sessionId(b);
    await b.login();
    const second = sessionId(b);
    expect(second).not.toBe(first);
    expect(await bff.store.get(first)).toBeUndefined();
    expect(await bff.store.get(second)).toBeDefined();
  });

  it("rejects a callback whose state does not match the login cookie, or without a cookie", async () => {
    const b = new Browser(bff.app, idp.issuer);
    const { callbackUrl } = await b.startLogin();
    const url = new URL(callbackUrl);

    const other = new Browser(bff.app, idp.issuer);
    const noCookie = await other.request("GET", `${url.pathname}${url.search}`);
    expect(noCookie.statusCode).toBe(400);

    url.searchParams.set("state", "forged");
    const forged = await b.request("GET", `${url.pathname}${url.search}`);
    expect(forged.statusCode).toBe(400);
    expect(forged.json()).toEqual({ error: "login_failed" });
    expect(b.bffJar.has("__Host-Http-session")).toBe(false);
  });

  it("makes the login transaction single use and rejects an unknown one", async () => {
    const b = new Browser(bff.app, idp.issuer);
    const { callbackUrl } = await b.startLogin();
    const url = new URL(callbackUrl);
    const path = `${url.pathname}${url.search}`;
    const state = url.searchParams.get("state") as string;
    expect((await b.request("GET", path)).statusCode).toBe(302);

    b.bffJar.set("__Host-Http-login", state);
    const replay = await b.request("GET", path);
    expect(replay.statusCode).toBe(400);

    b.bffJar.set("__Host-Http-login", "never-issued");
    const unknown = await b.request(
      "GET",
      `/bff/callback?state=never-issued&code=x`,
    );
    expect(unknown.statusCode).toBe(400);
  });

  it("rejects a wrong or missing iss parameter (RFC 9207)", async () => {
    for (const tamper of [
      (u: URL) => u.searchParams.set("iss", "https://evil.example"),
      (u: URL) => u.searchParams.delete("iss"),
    ]) {
      const b = new Browser(bff.app, idp.issuer);
      const { callbackUrl } = await b.startLogin();
      const url = new URL(callbackUrl);
      tamper(url);
      const res = await b.request("GET", `${url.pathname}${url.search}`);
      expect(res.statusCode).toBe(400);
      expect(b.bffJar.has("__Host-Http-session")).toBe(false);
    }
  });

  it("rejects an ID token with the wrong nonce", async () => {
    const b = new Browser(bff.app, idp.issuer);
    const { callbackUrl } = await b.startLogin();
    const url = new URL(callbackUrl);
    const state = url.searchParams.get("state") as string;
    const tx = await bff.store.takeTransaction(state);
    await bff.store.putTransaction(
      state,
      { ...(tx as NonNullable<typeof tx>), nonce: "someone-elses-nonce" },
      60,
    );
    const res = await b.request("GET", `${url.pathname}${url.search}`);
    expect(res.statusCode).toBe(400);
  });

  it("rejects a code that does not match the PKCE verifier", async () => {
    const b = new Browser(bff.app, idp.issuer);
    const { callbackUrl } = await b.startLogin();
    const url = new URL(callbackUrl);
    const state = url.searchParams.get("state") as string;
    const tx = await bff.store.takeTransaction(state);
    await bff.store.putTransaction(
      state,
      { ...(tx as NonNullable<typeof tx>), codeVerifier: "x".repeat(43) },
      60,
    );
    const res = await b.request("GET", `${url.pathname}${url.search}`);
    expect(res.statusCode).toBe(400);
  });

  it("rejects an authorization error response from the IdP", async () => {
    const b = new Browser(bff.app, idp.issuer);
    const { callbackUrl } = await b.startLogin();
    const state = new URL(callbackUrl).searchParams.get("state") as string;
    b.bffJar.set("__Host-Http-login", state);
    const res = await b.request(
      "GET",
      `/bff/callback?error=access_denied&state=${state}&iss=${encodeURIComponent(idp.issuer)}`,
    );
    expect(res.statusCode).toBe(400);
  });
});

describe("logout", () => {
  it("destroys the session and returns the RP-initiated logout URL", async () => {
    const b = new Browser(bff.app, idp.issuer);
    await b.login();
    const id = sessionId(b);
    const idToken = (await bff.store.get(id))?.idToken as string;

    const res = await b.request("POST", "/bff/logout", { csrf: true });
    expect(res.statusCode).toBe(200);
    const url = new URL(res.json<{ logoutUrl: string }>().logoutUrl);
    expect(url.origin + url.pathname).toBe(`${idp.issuer}/session/end`);
    expect(url.searchParams.get("id_token_hint")).toBe(idToken);
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
      `${PUBLIC_ORIGIN}/`,
    );
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(cookieOf(res, "__Host-Http-session")).toContain("Max-Age=0");
    expect(await bff.store.get(id)).toBeUndefined();
    expect((await b.request("GET", "/bff/user")).statusCode).toBe(401);
  });

  it("answers 401 without a session", async () => {
    const b = new Browser(bff.app, idp.issuer);
    expect(
      (await b.request("POST", "/bff/logout", { csrf: true })).statusCode,
    ).toBe(401);
  });

  it("still logs out when the IdP cannot be reached", async () => {
    const down = await makeBff({ issuer: "http://localhost:1" });
    await down.store.put(
      "sess-1",
      {
        sub: "alice",
        sid: null,
        name: "alice",
        email: null,
        roles: {},
        idToken: "x.y.z",
        accessToken: "at",
        refreshToken: null,
        accessExpiresAt: Date.now() / 1000 + 600,
        createdAt: 0,
        absoluteExpiresAt: Date.now() / 1000 + 600,
      },
      600,
    );
    down.browser.bffJar.set("__Host-Http-session", "sess-1");
    const res = await down.browser.request("POST", "/bff/logout", {
      csrf: true,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ logoutUrl: `${PUBLIC_ORIGIN}/` });
    expect(await down.store.get("sess-1")).toBeUndefined();
    await down.app.close();
  });
});

describe("IdP availability", () => {
  it("answers 503 on login when discovery fails, and retries on the next request", async () => {
    const down = await makeBff({ issuer: "http://localhost:1" });
    expect((await down.browser.request("GET", "/bff/login")).statusCode).toBe(
      503,
    );
    const again = await down.browser.request("GET", "/bff/login");
    expect(again.json()).toEqual({ error: "idp_unavailable" });
    await down.app.close();
  });

  it("refuses plain-http IdP URLs unless explicitly allowed", async () => {
    const base = testConfig(idp);
    const strict = await makeBff(idp, {
      config: { ...base, oidc: { ...base.oidc, allowInsecure: false } },
    });
    expect((await strict.browser.request("GET", "/bff/login")).statusCode).toBe(
      503,
    );
    await strict.app.close();
  });

  it("refuses a discovery document whose issuer differs from OIDC_ISSUER", async () => {
    const mismatch = await makeBff(idp, {
      env: {
        OIDC_ISSUER: "http://localhost:1/other",
        OIDC_DISCOVERY_URL: `${idp.issuer}/.well-known/openid-configuration`,
      },
    });
    expect(
      (await mismatch.browser.request("GET", "/bff/login")).statusCode,
    ).toBe(503);
    await mismatch.app.close();
  });
});

describe("rate limiting", () => {
  it("limits /bff/login and logs the rejection", async () => {
    const limited = await makeBff(idp, { env: { RATE_LIMIT_MAX: "2" } });
    const codes: number[] = [];
    for (let i = 0; i < 3; i += 1) {
      codes.push(
        (await limited.browser.request("GET", "/bff/login")).statusCode,
      );
    }
    expect(codes).toEqual([302, 302, 429]);
    expect(limited.logs.some((l) => l["event"] === "rate_limited")).toBe(true);
    const callbacks: number[] = [];
    for (let i = 0; i < 3; i += 1) {
      callbacks.push(
        (await limited.browser.request("GET", "/bff/callback")).statusCode,
      );
    }
    expect(callbacks).toEqual([400, 400, 429]);
    await limited.app.close();
  });
});

describe("config endpoint", () => {
  it("serves public runtime config only", async () => {
    const res = await new Browser(bff.app, idp.issuer).request(
      "GET",
      "/bff/config",
    );
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      analytics: { enabled: true, consent: "implied", respectGpc: true },
      upstreams: ["crud"],
    });
    expect(res.body).not.toContain(bff.config.oidc.clientSecret);
    expect(res.body).not.toContain(bff.config.session.storeUrl);
  });
});

describe("session lifetime", () => {
  it("expires an idle session and slides the idle timeout on use", async () => {
    let now = Date.now();
    const store = createMemorySessionStore({ now: () => now });
    const timed = await makeBff(idp, {
      store,
      env: { SESSION_IDLE_SECONDS: "1800" },
    });
    await timed.browser.login();
    now += 1000 * 1000;
    expect((await timed.browser.request("GET", "/bff/user")).statusCode).toBe(
      200,
    );
    now += 1000 * 1000;
    expect((await timed.browser.request("GET", "/bff/user")).statusCode).toBe(
      200,
    );
    now += 1801 * 1000;
    expect((await timed.browser.request("GET", "/bff/user")).statusCode).toBe(
      401,
    );
    await timed.app.close();
  });

  it("ends a session at its absolute expiry however recently it was used", async () => {
    const b = new Browser(bff.app, idp.issuer);
    await b.login();
    const id = sessionId(b);
    const data = (await bff.store.get(id)) as NonNullable<
      Awaited<ReturnType<typeof bff.store.get>>
    >;
    await bff.store.put(
      id,
      { ...data, absoluteExpiresAt: Math.floor(Date.now() / 1000) - 1 },
      600,
    );
    expect((await b.request("GET", "/bff/user")).statusCode).toBe(401);
    expect(await bff.store.get(id)).toBeUndefined();
  });

  it("caps the absolute expiry at the refresh token lifetime when the IdP reports it", async () => {
    // oidc-provider reports no refresh_expires_in; the cap itself is unit-tested in session.test.ts.
    const b = new Browser(bff.app, idp.issuer);
    await b.login();
    const data = await bff.store.get(sessionId(b));
    expect((data?.absoluteExpiresAt ?? 0) - (data?.createdAt ?? 0)).toBe(
      bff.config.session.absoluteSeconds,
    );
  });
});

describe("error handling", () => {
  it("hides internal error details", async () => {
    const res = await new Browser(bff.app, idp.issuer).request(
      "GET",
      "/bff/test-boom",
    );
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: "internal_error" });
    expect(res.body).not.toContain("secret internal detail");
  });

  it("reports client errors by code", async () => {
    const res = await new Browser(bff.app, idp.issuer).request(
      "POST",
      "/bff/backchannel-logout",
      {
        headers: { "content-type": "application/xml" },
        body: "logout_token=x",
      },
    );
    expect(res.statusCode).toBe(415);
    expect(res.json()).toEqual({ error: "FST_ERR_CTP_INVALID_MEDIA_TYPE" });
  });

  it("keeps testConfig usable for other suites", () => {
    expect(testConfig(idp).oidc.issuer).toBe(idp.issuer);
  });
});
