import type { LightMyRequestResponse } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { CONSENT_MAX_AGE_SECONDS } from "../src/analytics/index.ts";
import type { TestBff } from "./helpers/bff.ts";
import { makeAnalyticsBff } from "./helpers/analytics.ts";

let bff: TestBff | undefined;
afterEach(async () => {
  await bff?.app.close();
  bff = undefined;
});

async function start(): Promise<TestBff> {
  bff = await makeAnalyticsBff();
  // The I6 flag, as the proxy (LB3) reads it.
  bff.app.get("/probe", async (request) => ({
    consent: request.bffAnalyticsConsent,
  }));
  return bff;
}

const consent = (
  b: TestBff,
  payload: unknown,
  headers: Record<string, string> = {},
): Promise<LightMyRequestResponse> =>
  b.app.inject({
    method: "POST",
    url: "/bff/consent",
    headers: { "x-csrf": "1", "content-type": "application/json", ...headers },
    payload: JSON.stringify(payload),
  });

describe("consent endpoints", () => {
  it("grants consent with a hardened __Host- cookie of about six months", async () => {
    const b = await start();
    const res = await consent(b, { analytics: true });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ analytics: true });
    expect(res.headers["cache-control"]).toBe("no-store");
    const raw = String(res.headers["set-cookie"]);
    expect(raw.split(";")[0]).toBe("__Host-Http-consent=1");
    expect(raw).toMatch(/; HttpOnly/);
    expect(raw).toMatch(/; Secure/);
    expect(raw).toMatch(/; SameSite=Strict/);
    expect(raw).toMatch(/; Path=\//);
    expect(raw).not.toMatch(/Domain/i);
    expect(raw).toContain(`Max-Age=${CONSENT_MAX_AGE_SECONDS}`);
    expect(CONSENT_MAX_AGE_SECONDS).toBe(15_552_000);
  });

  it("withdraws consent by expiring the cookie with the same attributes", async () => {
    const b = await start();
    const res = await consent(b, { analytics: false });
    expect(res.json()).toEqual({ analytics: false });
    const raw = String(res.headers["set-cookie"]);
    expect(raw.split(";")[0]).toBe("__Host-Http-consent=");
    expect(raw).toMatch(/Expires=Thu, 01 Jan 1970/);
    expect(raw).toMatch(/; HttpOnly/);
    expect(raw).toMatch(/; Secure/);
    expect(raw).toMatch(/; SameSite=Strict/);
    expect(raw).toMatch(/; Path=\//);
  });

  it("GET reports the state from the cookie", async () => {
    const b = await start();
    const get = (cookie?: string): Promise<LightMyRequestResponse> =>
      b.app.inject({
        method: "GET",
        url: "/bff/consent",
        headers: cookie === undefined ? {} : { cookie },
      });
    expect((await get()).json()).toEqual({ analytics: false });
    expect((await get("__Host-Http-consent=1")).json()).toEqual({
      analytics: true,
    });
    expect((await get("__Host-Http-consent=yes")).json()).toEqual({
      analytics: false,
    });
  });

  it("sets request.bffAnalyticsConsent only for a granted cookie (I6)", async () => {
    const b = await start();
    const probe = async (cookie?: string): Promise<unknown> =>
      (
        await b.app.inject({
          method: "GET",
          url: "/probe",
          headers: cookie === undefined ? {} : { cookie },
        })
      ).json();
    expect(await probe()).toEqual({ consent: false });
    expect(await probe("__Host-Http-consent=0")).toEqual({ consent: false });
    expect(await probe("__Host-Http-consent=1")).toEqual({ consent: true });
  });

  it.each([
    ["missing field", {}],
    ["not a boolean", { analytics: "yes" }],
    ["extra field", { analytics: true, other: 1 }],
    ["not an object", true],
  ])("rejects %s with 400", async (_label, payload) => {
    const b = await start();
    const res = await consent(b, payload);
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "invalid_consent" });
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it("requires X-CSRF on POST", async () => {
    const b = await start();
    const res = await b.app.inject({
      method: "POST",
      url: "/bff/consent",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ analytics: true }),
    });
    expect(res.statusCode).toBe(403);
  });
});
