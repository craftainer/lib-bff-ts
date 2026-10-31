import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { hardenLogger, securityLog } from "../src/log.ts";
import { makeBff, type TestBff } from "./helpers/bff.ts";
import { startIdp, type TestIdp } from "./helpers/idp.ts";

let idp: TestIdp;
let bff: TestBff;

beforeAll(async () => {
  idp = await startIdp();
  bff = await makeBff(idp);
  bff.app.get("/bff/test-log", async (request) => {
    request.log.info({ headers: { authorization: "Bearer LEAK", cookie: "c=LEAK" } }, "headers");
    return {};
  });
});

afterAll(async () => {
  await bff.app.close();
  await idp.close();
});

describe("security logging", () => {
  it("logs login and logout as structured events and never tokens, cookies, codes or state", async () => {
    const b = bff.browser;
    const { callbackUrl } = await b.startLogin();
    const callback = new URL(callbackUrl);
    const code = callback.searchParams.get("code") as string;
    const state = callback.searchParams.get("state") as string;
    await b.request("GET", `${callback.pathname}${callback.search}`);
    const id = b.bffJar.get("__Host-Http-session") as string;
    const session = await bff.store.get(id);
    await b.request("GET", "/bff/user");
    await b.request("POST", "/bff/logout", { csrf: true });
    await b.request("GET", "/bff/test-log", { headers: { authorization: "Bearer LEAK" } });

    const events = bff.logs.filter((l) => l["security"] === true).map((l) => l["event"]);
    expect(events).toEqual(expect.arrayContaining(["login_started", "login_success", "logout"]));
    expect(bff.logs.find((l) => l["event"] === "login_success")).toMatchObject({ sub: "alice", level: 30 });

    const all = JSON.stringify(bff.logs);
    for (const secret of [
      code,
      state,
      id,
      session?.accessToken,
      session?.refreshToken,
      session?.idToken,
      bff.config.oidc.clientSecret,
      "LEAK",
    ]) {
      expect(all).not.toContain(secret as string);
    }
    const callbackLog = bff.logs.find((l) => (l["req"] as { url?: string } | undefined)?.url === "/bff/callback");
    expect(callbackLog).toBeDefined();
  });
});

describe("hardenLogger", () => {
  it("passes false through and adds redaction and the query-free serializer otherwise", () => {
    expect(hardenLogger(false)).toBe(false);
    for (const input of [undefined, true, { level: "warn" }, { serializers: { res: () => ({}) } }]) {
      const out = hardenLogger(input);
      expect(out).toMatchObject({
        redact: { paths: expect.arrayContaining(["req.headers.authorization", "req.headers.cookie"]) },
        serializers: { req: expect.any(Function) },
      });
    }
    expect(hardenLogger({ level: "warn" })).toMatchObject({ level: "warn" });
    expect(hardenLogger({ serializers: { res: () => ({}) } })).toMatchObject({ serializers: { res: expect.any(Function) } });
  });

  it("serializes requests without the query string", () => {
    const out = hardenLogger(true) as { serializers: { req: (r: unknown) => unknown } };
    expect(out.serializers.req({ method: "GET", url: "/bff/callback?code=abc&state=s", ip: "1.2.3.4" })).toEqual({
      method: "GET",
      url: "/bff/callback",
      remoteAddress: "1.2.3.4",
    });
  });

  it("logs warnings for rejections and info for routine events", () => {
    const seen: Array<[string, unknown]> = [];
    const log = {
      info: (o: unknown) => seen.push(["info", o]),
      warn: (o: unknown) => seen.push(["warn", o]),
    } as never;
    securityLog(log, "login_success", { sub: "a" });
    securityLog(log, "csrf_rejected");
    expect(seen).toEqual([
      ["info", { security: true, event: "login_success", sub: "a" }],
      ["warn", { security: true, event: "csrf_rejected" }],
    ]);
  });
});
