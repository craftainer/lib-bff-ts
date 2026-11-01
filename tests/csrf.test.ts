import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isAnomalousTarget, pathOf } from "../src/log.ts";
import { makeBff, type TestBff } from "./helpers/bff.ts";
import { PUBLIC_ORIGIN, startIdp, type TestIdp } from "./helpers/idp.ts";

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

const send = (
  method: "GET" | "POST" | "PUT",
  url: string,
  headers: Record<string, string> = {},
): Promise<{ statusCode: number; json: () => unknown }> =>
  bff.app.inject({ method, url, headers }) as never;

describe("X-CSRF header", () => {
  it("is required on non-GET /bff requests", async () => {
    const missing = await send("POST", "/bff/logout");
    expect(missing.statusCode).toBe(403);
    expect(missing.json()).toEqual({ error: "csrf_rejected" });
    expect(
      (await send("POST", "/bff/logout", { "x-csrf": "0" })).statusCode,
    ).toBe(403);
    expect(
      (await send("POST", "/bff/logout", { "x-csrf": "true" })).statusCode,
    ).toBe(403);
    expect(
      (await send("POST", "/bff/logout", { "x-csrf": "1" })).statusCode,
    ).toBe(401);
    expect((await send("PUT", "/bff/user")).statusCode).toBe(403);
  });

  it("is required on every /api request, including GET", async () => {
    expect((await send("GET", "/api/crud/heroes")).statusCode).toBe(403);
    expect((await send("GET", "/api")).statusCode).toBe(403);
    // With X-CSRF the guard passes; the proxy then answers a no-session
    // request itself.
    const passed = await send("GET", "/api/crud/heroes", { "x-csrf": "1" });
    expect(passed.statusCode).toBe(401);
    expect(passed.json()).toEqual({ error: "unauthorized" });
  });

  it("is not required on GET /bff requests other than the API", async () => {
    expect((await send("GET", "/bff/user")).statusCode).toBe(401);
    expect((await send("GET", "/bff/config")).statusCode).toBe(200);
  });

  it("is not required for the three exempt requests", async () => {
    expect((await send("GET", "/bff/login")).statusCode).toBe(302);
    expect((await send("GET", "/bff/callback")).statusCode).toBe(400);
    expect((await send("POST", "/bff/backchannel-logout")).statusCode).toBe(
      400,
    );
  });

  it("does not exempt look-alikes or different methods", async () => {
    expect((await send("POST", "/bff/login")).statusCode).toBe(403);
    expect((await send("POST", "/bff/callback")).statusCode).toBe(403);
    expect((await send("GET", "/bff/backchannel-logout")).statusCode).toBe(404);
    expect((await send("POST", "/bff/login/../logout")).statusCode).toBe(403);
    expect((await send("GET", "/x/../api/crud/heroes")).statusCode).toBe(403);
  });
});

describe("Origin and Fetch Metadata", () => {
  const csrf = { "x-csrf": "1" };

  it("rejects an unsafe request from another origin", async () => {
    for (const origin of [
      "https://evil.example",
      "null",
      `${PUBLIC_ORIGIN}.evil.example`,
      `${PUBLIC_ORIGIN}/`,
    ]) {
      const res = await send("POST", "/bff/logout", { ...csrf, origin });
      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({ error: "origin_rejected" });
    }
  });

  it("sends no CORS headers, not even for a preflight", async () => {
    for (const res of [
      await bff.app.inject({
        method: "OPTIONS",
        url: "/bff/user",
        headers: { origin: "https://evil.example" },
      }),
      await bff.app.inject({
        method: "GET",
        url: "/bff/config",
        headers: { origin: PUBLIC_ORIGIN },
      }),
    ]) {
      expect(
        Object.keys(res.headers).filter((h) => h.startsWith("access-control-")),
      ).toEqual([]);
    }
  });

  it("accepts the configured origin and requests without Origin", async () => {
    expect(
      (await send("POST", "/bff/logout", { ...csrf, origin: PUBLIC_ORIGIN }))
        .statusCode,
    ).toBe(401);
    expect((await send("POST", "/bff/logout", csrf)).statusCode).toBe(401);
  });

  it("rejects unsafe requests unless Sec-Fetch-Site is same-origin or none", async () => {
    for (const site of ["cross-site", "same-site"]) {
      expect(
        (await send("POST", "/bff/logout", { ...csrf, "sec-fetch-site": site }))
          .statusCode,
      ).toBe(403);
    }
    for (const site of ["same-origin", "none"]) {
      expect(
        (await send("POST", "/bff/logout", { ...csrf, "sec-fetch-site": site }))
          .statusCode,
      ).toBe(401);
    }
  });

  it("does not apply the origin check to safe methods", async () => {
    const res = await send("GET", "/bff/user", {
      origin: "https://evil.example",
      "sec-fetch-site": "cross-site",
    });
    expect(res.statusCode).toBe(401);
  });

  it("logs rejections as security events without cookie or token values", async () => {
    await bff.app.inject({
      method: "POST",
      url: "/bff/logout",
      headers: {
        cookie: "__Host-Http-session=SUPERSECRETID",
        authorization: "Bearer SUPERSECRETTOKEN",
      },
    });
    const event = bff.logs.find((l) => l["event"] === "csrf_rejected");
    expect(event).toMatchObject({
      security: true,
      method: "POST",
      path: "/bff/logout",
      level: 40,
    });
    expect(JSON.stringify(bff.logs)).not.toContain("SUPERSECRET");
  });
});

describe("request-target canonicalisation", () => {
  it("guards targets that do not start with exactly one slash (fail closed)", async () => {
    for (const url of ["//bff/logout", "//api/x", "///bff/logout"]) {
      expect((await send("POST", url)).statusCode).toBe(403);
      expect((await send("GET", url)).statusCode).toBe(403);
    }
    expect(
      (await send("POST", "//bff/logout", { "x-csrf": "1" })).statusCode,
    ).toBe(404);
  });

  it("guards /bff//logout and percent-encoded spellings of guarded paths", async () => {
    expect((await send("POST", "/bff//logout")).statusCode).toBe(403);
    expect((await send("POST", "/%62ff/logout")).statusCode).toBe(403);
    expect((await send("POST", "/bff%2Flogout")).statusCode).toBe(404);
    expect((await send("GET", "/%61pi/crud")).statusCode).toBe(403);
    // Fastify answers a malformed escape itself, before any hook.
    expect((await send("GET", "/api/%zz")).statusCode).toBe(400);
  });

  it("does not let an encoded spelling slip past the exemption list", async () => {
    // The router decodes `%6C` to `l`, so this is GET /bff/login: exempt, like the plain spelling.
    expect((await send("GET", "/bff/%6Cogin")).statusCode).toBe(302);
    // An encoded backchannel path is still the exempt, token-authenticated POST.
    expect((await send("POST", "/bff/backchannel%2Dlogout")).statusCode).toBe(
      400,
    );
  });
});

describe("pathOf and isAnomalousTarget", () => {
  it("share one canonical, router-consistent reading of a request target", () => {
    expect(pathOf("/bff/user?x=1#f")).toBe("/bff/user");
    expect(pathOf("/%62ff/user")).toBe("/bff/user");
    expect(pathOf("/bad/%zz")).toBe("/bad/%zz");
    expect(isAnomalousTarget("/bff/user?q=//")).toBe(false);
    expect(isAnomalousTarget("//bff/user")).toBe(true);
    expect(isAnomalousTarget("http://evil.test/bff/user")).toBe(true);
    expect(isAnomalousTarget("*")).toBe(true);
    expect(isAnomalousTarget("/bad/%zz")).toBe(true);
  });
});
