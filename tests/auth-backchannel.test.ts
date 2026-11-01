import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { isTokenDefect, LogoutTokenError } from "../src/auth/backchannel.ts";
import { Browser, makeBff, type TestBff } from "./helpers/bff.ts";
import { CLIENT_ID, startIdp, type TestIdp } from "./helpers/idp.ts";

const EVENT = "http://schemas.openid.net/event/backchannel-logout";

let idp: TestIdp;
let bff: TestBff;

beforeAll(async () => {
  idp = await startIdp();
  bff = await makeBff(idp);
});

afterAll(async () => {
  await bff.app.close();
  await idp.close();
});

function claims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: idp.issuer,
    aud: CLIENT_ID,
    iat: now,
    exp: now + 120,
    jti: randomUUID(),
    events: { [EVENT]: {} },
    ...over,
  };
}

async function post(
  token: string | undefined,
): Promise<{ statusCode: number }> {
  return new Browser(bff.app, idp.issuer).request(
    "POST",
    "/bff/backchannel-logout",
    {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body:
        token === undefined ? "" : `logout_token=${encodeURIComponent(token)}`,
    },
  );
}

async function session(
  account: string,
): Promise<{ browser: Browser; id: string; sid: string | null }> {
  const browser = new Browser(bff.app, idp.issuer);
  await browser.login(undefined, account);
  const id = browser.bffJar.get("__Host-Http-session") as string;
  return { browser, id, sid: (await bff.store.get(id))?.sid ?? null };
}

describe("back-channel logout", () => {
  let alice1: Awaited<ReturnType<typeof session>>;
  let alice2: Awaited<ReturnType<typeof session>>;
  let bob: Awaited<ReturnType<typeof session>>;

  beforeEach(async () => {
    alice1 = await session("alice");
    alice2 = await session("alice");
    bob = await session("bob");
  });

  it("ends only the session named by sid, without X-CSRF or Origin", async () => {
    expect(alice1.sid).toBeTruthy();
    const token = await idp.sign(claims({ sub: "alice", sid: alice1.sid }));
    expect((await post(token)).statusCode).toBe(200);
    expect(await bff.store.get(alice1.id)).toBeUndefined();
    expect(await bff.store.get(alice2.id)).toBeDefined();
    expect(await bff.store.get(bob.id)).toBeDefined();
    expect(
      bff.logs.some(
        (l) => l["event"] === "backchannel_logout" && l["sessions"] === 1,
      ),
    ).toBe(true);
  });

  it("ends every session of the subject when only sub is given", async () => {
    const token = await idp.sign(claims({ sub: "alice" }));
    expect((await post(token)).statusCode).toBe(200);
    expect(await bff.store.get(alice1.id)).toBeUndefined();
    expect(await bff.store.get(alice2.id)).toBeUndefined();
    expect(await bff.store.get(bob.id)).toBeDefined();
  });

  it("accepts Keycloak's Logout typ", async () => {
    const token = await idp.sign(claims({ sub: "bob" }), { typ: "Logout" });
    expect((await post(token)).statusCode).toBe(200);
  });

  it("rejects a replayed logout token", async () => {
    const token = await idp.sign(claims({ sub: "bob" }));
    expect((await post(token)).statusCode).toBe(200);
    expect((await post(token)).statusCode).toBe(400);
  });

  it("rejects invalid logout tokens and leaves sessions alone", async () => {
    const base = { sub: "alice", sid: alice1.sid };
    const bad: Array<string | undefined> = [
      undefined,
      "not-a-jwt",
      await idp.sign(claims(base), { typ: null }),
      await idp.sign(claims(base), { typ: "JWT" }),
      await idp.sign(claims(base), { typ: "id+jwt" }),
      await idp.sign(claims(base), { key: idp.otherKey }),
      await idp.sign(claims({ ...base, aud: "someone-else" })),
      await idp.sign(claims({ ...base, iss: "https://evil.example" })),
      await idp.sign(claims({ ...base, nonce: "n" })),
      await idp.sign(claims({ ...base, events: undefined })),
      await idp.sign(claims({ ...base, events: null })),
      await idp.sign(claims({ ...base, events: { other: {} } })),
      await idp.sign(
        claims({
          ...base,
          exp: Math.floor(Date.now() / 1000) - 600,
          iat: Math.floor(Date.now() / 1000) - 700,
        }),
      ),
      await idp.sign(
        claims({ ...base, iat: Math.floor(Date.now() / 1000) - 3600 }),
      ),
      await idp.sign(claims({ ...base, jti: undefined })),
      await idp.sign(claims({ ...base, exp: undefined })),
      await idp.sign(claims({ events: { [EVENT]: {} } })),
    ];
    for (const token of bad) {
      expect((await post(token)).statusCode).toBe(400);
    }
    expect(await bff.store.get(alice1.id)).toBeDefined();
    expect(await bff.store.get(alice2.id)).toBeDefined();
    expect(
      bff.logs.filter((l) => l["event"] === "backchannel_logout_rejected")
        .length,
    ).toBeGreaterThanOrEqual(bad.length);
  });
});

describe("back-channel logout retry", () => {
  it("lets the IdP retry the same token after a store failure", async () => {
    let failures = 1;
    const base = bff.store;
    const flaky = new Proxy(base, {
      get(target, prop: string) {
        if (prop === "destroyBySid") {
          return async (sid: string): Promise<number> => {
            if (failures > 0) {
              failures -= 1;
              throw new Error("store unavailable");
            }
            return target.destroyBySid(sid);
          };
        }
        const value = Reflect.get(target, prop) as unknown;
        return typeof value === "function"
          ? (value as (...a: unknown[]) => unknown).bind(target)
          : value;
      },
    });
    const retrying = await makeBff(idp, { store: flaky });
    const browser = new Browser(retrying.app, idp.issuer);
    await browser.login(undefined, "carol");
    const id = browser.bffJar.get("__Host-Http-session") as string;
    const sid = (await base.get(id))?.sid;
    const token = await idp.sign(claims({ sub: "carol", sid }));
    const send = (): Promise<{ statusCode: number }> =>
      new Browser(retrying.app, idp.issuer).request(
        "POST",
        "/bff/backchannel-logout",
        {
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: `logout_token=${encodeURIComponent(token)}`,
        },
      );
    expect((await send()).statusCode).toBe(500);
    expect((await send()).statusCode).toBe(200);
    expect(await base.get(id)).toBeUndefined();
    expect((await send()).statusCode).toBe(400);
    await retrying.app.close();
  });
});

describe("back-channel logout: bad token (400) versus failure to check it (503)", () => {
  async function postTo(
    app: TestBff,
    token: string,
  ): Promise<{ statusCode: number; json: () => Record<string, unknown> }> {
    return new Browser(app.app, idp.issuer).request(
      "POST",
      "/bff/backchannel-logout",
      {
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `logout_token=${encodeURIComponent(token)}`,
      },
    );
  }

  it("answers 400 for each class of bad token", async () => {
    const fresh = await makeBff(idp);
    const hs256 = await new SignJWT(claims({ sub: "alice" }))
      .setProtectedHeader({ alg: "HS256", typ: "logout+jwt" })
      .sign(new TextEncoder().encode("a-shared-secret-of-sufficient-len"));
    const cases: [string, string][] = [
      [
        "bad signature",
        await idp.sign(claims({ sub: "a" }), { key: idp.otherKey }),
      ],
      ["wrong audience", await idp.sign(claims({ sub: "a", aud: "other" }))],
      ["expired", await idp.sign(claims({ sub: "a", iat: 1000, exp: 1100 }))],
      ["wrong typ", await idp.sign(claims({ sub: "a" }), { typ: "JWT" })],
      ["not a JWT", "not-a-jwt"],
      ["algorithm not allowed", hs256],
    ];
    for (const [name, token] of cases) {
      const res = await postTo(fresh, token);
      expect(res.statusCode, name).toBe(400);
      expect(res.json(), name).toEqual({ error: "invalid_request" });
    }
    await fresh.app.close();
  });

  it("answers 503 when the IdP's key set times out", async () => {
    const fresh = await makeBff(idp, { env: { OIDC_TIMEOUT_SECONDS: "1" } });
    idp.jwks.delayMs = 2500;
    try {
      const res = await postTo(fresh, await idp.sign(claims({ sub: "a" })));
      expect(res.statusCode).toBe(503);
      expect(res.json()).toEqual({ error: "idp_unavailable" });
    } finally {
      idp.jwks.delayMs = 0;
    }
    await fresh.app.close();
  });

  it("answers 503 when the IdP's key set answers 500", async () => {
    const fresh = await makeBff(idp);
    idp.jwks.status = 500;
    try {
      const res = await postTo(fresh, await idp.sign(claims({ sub: "a" })));
      expect(res.statusCode).toBe(503);
    } finally {
      idp.jwks.status = undefined;
    }
    await fresh.app.close();
  });

  it("answers 503 for a kid the key set does not know yet (key rotation), and the retry works once it does", async () => {
    const fresh = await makeBff(idp);
    const carol = new Browser(fresh.app, idp.issuer);
    await carol.login(undefined, "carol");
    const id = carol.bffJar.get("__Host-Http-session") as string;
    const claimSet = claims({ sub: "carol" });
    const unknown = await idp.sign(claimSet, { kid: "rotated-key" });
    expect((await postTo(fresh, unknown)).statusCode).toBe(503);
    expect(await fresh.store.get(id)).toBeDefined();
    // The same logout token, signed by a key the IdP does publish, now ends the session.
    expect((await postTo(fresh, await idp.sign(claimSet))).statusCode).toBe(
      200,
    );
    expect(await fresh.store.get(id)).toBeUndefined();
    await fresh.app.close();
  });

  it("classifies errors by their stable jose code, and treats unknown errors as retryable", () => {
    for (const code of [
      "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
      "ERR_JWT_CLAIM_VALIDATION_FAILED",
      "ERR_JWT_EXPIRED",
      "ERR_JWS_INVALID",
      "ERR_JWT_INVALID",
      "ERR_JOSE_ALG_NOT_ALLOWED",
      "ERR_JOSE_NOT_SUPPORTED",
    ]) {
      expect(isTokenDefect(Object.assign(new Error("x"), { code })), code).toBe(
        true,
      );
    }
    expect(isTokenDefect(new LogoutTokenError("nonce"))).toBe(true);
    for (const error of [
      Object.assign(new Error("x"), { code: "ERR_JWKS_TIMEOUT" }),
      Object.assign(new Error("x"), { code: "ERR_JWKS_NO_MATCHING_KEY" }),
      Object.assign(new Error("x"), { code: "ERR_JWKS_INVALID" }),
      Object.assign(new Error("x"), {
        code: "ERR_JWKS_MULTIPLE_MATCHING_KEYS",
      }),
      Object.assign(new Error("x"), { code: "ERR_JOSE_GENERIC" }),
      new TypeError("fetch failed"),
      new Error("something new"),
      null,
      "a string",
    ]) {
      expect(isTokenDefect(error)).toBe(false);
    }
  });
});
