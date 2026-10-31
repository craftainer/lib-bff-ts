import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
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

async function post(token: string | undefined): Promise<{ statusCode: number }> {
  return new Browser(bff.app, idp.issuer).request("POST", "/bff/backchannel-logout", {
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: token === undefined ? "" : `logout_token=${encodeURIComponent(token)}`,
  });
}

async function session(account: string): Promise<{ browser: Browser; id: string; sid: string | null }> {
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
    expect(bff.logs.some((l) => l["event"] === "backchannel_logout" && l["sessions"] === 1)).toBe(true);
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
      await idp.sign(claims(base), { kid: "unknown-kid" }),
      await idp.sign(claims({ ...base, aud: "someone-else" })),
      await idp.sign(claims({ ...base, iss: "https://evil.example" })),
      await idp.sign(claims({ ...base, nonce: "n" })),
      await idp.sign(claims({ ...base, events: undefined })),
      await idp.sign(claims({ ...base, events: null })),
      await idp.sign(claims({ ...base, events: { other: {} } })),
      await idp.sign(claims({ ...base, exp: Math.floor(Date.now() / 1000) - 600, iat: Math.floor(Date.now() / 1000) - 700 })),
      await idp.sign(claims({ ...base, iat: Math.floor(Date.now() / 1000) - 3600 })),
      await idp.sign(claims({ ...base, jti: undefined })),
      await idp.sign(claims({ ...base, exp: undefined })),
      await idp.sign(claims({ events: { [EVENT]: {} } })),
    ];
    for (const token of bad) {
      expect((await post(token)).statusCode).toBe(400);
    }
    expect(await bff.store.get(alice1.id)).toBeDefined();
    expect(await bff.store.get(alice2.id)).toBeDefined();
    expect(bff.logs.filter((l) => l["event"] === "backchannel_logout_rejected").length).toBeGreaterThanOrEqual(bad.length);
  });
});
