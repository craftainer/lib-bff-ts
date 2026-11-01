import { afterAll, describe, expect, it } from "vitest";
import { CONTENT_SECURITY_POLICY, PERMISSIONS_POLICY } from "../src/headers.ts";
import { makeBff, type TestBff } from "./helpers/bff.ts";

const open: TestBff[] = [];

async function make(
  env: Record<string, string> = {},
  issuer = "http://localhost:1",
): Promise<TestBff> {
  const bff = await makeBff({ issuer }, { env });
  open.push(bff);
  return bff;
}

afterAll(async () => {
  await Promise.all(open.map((bff) => bff.app.close()));
});

describe("security headers", () => {
  it("sets the full set on a normal response", async () => {
    const bff = await make();
    const res = await bff.app.inject({ method: "GET", url: "/health/live" });
    expect(res.headers["content-security-policy"]).toBe(
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    expect(res.headers["content-security-policy"]).toBe(
      CONTENT_SECURITY_POLICY,
    );
    expect(res.headers["cross-origin-opener-policy"]).toBe("same-origin");
    expect(res.headers["cross-origin-resource-policy"]).toBe("same-origin");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["permissions-policy"]).toBe(PERMISSIONS_POLICY);
    expect(PERMISSIONS_POLICY).toContain("camera=()");
    expect(PERMISSIONS_POLICY).toContain("geolocation=()");
    expect(PERMISSIONS_POLICY).toContain("microphone=()");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(CONTENT_SECURITY_POLICY).not.toContain("unsafe-inline");
  });

  it("sets them on error responses too", async () => {
    const bff = await make();
    for (const url of ["/nope", "/api/x", "/bff/user"]) {
      const res = await bff.app.inject({ method: "GET", url });
      expect(res.headers["content-security-policy"], url).toBeDefined();
      expect(res.headers["x-content-type-options"], url).toBe("nosniff");
    }
  });

  it("sends no CORS headers", async () => {
    const bff = await make();
    const res = await bff.app.inject({
      method: "GET",
      url: "/health/live",
      headers: { origin: "http://localhost:8080" },
    });
    expect(
      Object.keys(res.headers).filter((h) => h.startsWith("access-control-")),
    ).toEqual([]);
  });

  it("marks API and BFF responses no-store, but leaves other responses alone", async () => {
    const bff = await make();
    const user = await bff.app.inject({ method: "GET", url: "/bff/user" });
    expect(user.headers["cache-control"]).toBe("no-store");
    const api = await bff.app.inject({
      method: "GET",
      url: "/api/crud/x",
      headers: { "x-csrf": "1" },
    });
    expect(api.headers["cache-control"]).toBe("no-store");
    const csrfDenied = await bff.app.inject({ method: "GET", url: "/api/x" });
    expect(csrfDenied.statusCode).toBe(403);
    expect(csrfDenied.headers["cache-control"]).toBe("no-store");
    const health = await bff.app.inject({ method: "GET", url: "/health/live" });
    expect(health.headers["cache-control"]).toBeUndefined();
  });

  it("keeps a Cache-Control a route chose itself", async () => {
    const bff = await make();
    bff.app.get("/api/own", async (_request, reply) =>
      reply.header("Cache-Control", "private, max-age=5").send({}),
    );
    const res = await bff.app.inject({
      method: "GET",
      url: "/api/own",
      headers: { "x-csrf": "1" },
    });
    expect(res.headers["cache-control"]).toBe("private, max-age=5");
  });
});

describe("HSTS", () => {
  it("is absent outside production", async () => {
    const bff = await make();
    const res = await bff.app.inject({ method: "GET", url: "/health/live" });
    expect(res.headers["strict-transport-security"]).toBeUndefined();
  });

  it("is absent in production when the public origin is not https", async () => {
    // `loadConfig` forbids this combination, so build the config directly.
    const base = await make();
    const bff = await makeBff(
      { issuer: "http://localhost:1" },
      { config: { ...base.config, production: true } },
    );
    open.push(bff);
    const res = await bff.app.inject({ method: "GET", url: "/health/live" });
    expect(res.headers["strict-transport-security"]).toBeUndefined();
  });

  it("is sent in production with an https public origin", async () => {
    const bff = await make(
      {
        NODE_ENV: "production",
        PUBLIC_ORIGIN: "https://app.example.com",
        OIDC_ALLOW_INSECURE: "false",
      },
      "https://idp.example.com",
    );
    const res = await bff.app.inject({ method: "GET", url: "/health/live" });
    expect(res.headers["strict-transport-security"]).toBe(
      "max-age=31536000; includeSubDomains",
    );
  });
});
