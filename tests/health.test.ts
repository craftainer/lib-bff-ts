import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createBff } from "../src/app.ts";
import type { SessionStore } from "../src/session.ts";
import { createMemorySessionStore } from "../src/session.ts";
import { makeBff, testConfig } from "./helpers/bff.ts";
import { startIdp, type TestIdp } from "./helpers/idp.ts";

let idp: TestIdp;

beforeAll(async () => {
  idp = await startIdp();
});

afterAll(async () => {
  await idp.close();
});

function failingPing(): SessionStore {
  const store = createMemorySessionStore();
  return new Proxy(store, {
    get(target, prop) {
      if (prop === "ping") {
        return () => Promise.reject(new Error("valkey down"));
      }
      const value = Reflect.get(target, prop) as unknown;
      return typeof value === "function"
        ? (value as (...a: unknown[]) => unknown).bind(target)
        : value;
    },
  });
}

describe("/health", () => {
  it("answers live without touching Valkey or the IdP", async () => {
    // No injected store: the default Valkey client is created but never connects.
    const app = await createBff(testConfig({ issuer: "http://localhost:1" }), {
      logger: false,
    });
    const res = await app.inject({ method: "GET", url: "/health/live" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok" });
    await app.close();
  });

  it("is ready when the store answers and discovery works", async () => {
    const bff = await makeBff(idp);
    const res = await bff.app.inject({ method: "GET", url: "/health/ready" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      status: "ok",
      checks: { store: "ok", idp: "ok" },
    });
    await bff.app.close();
  });

  it("is not ready when the IdP is unreachable", async () => {
    const bff = await makeBff({ issuer: "http://localhost:1" });
    const res = await bff.app.inject({ method: "GET", url: "/health/ready" });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({
      status: "unavailable",
      checks: { store: "ok", idp: "unavailable" },
    });
    expect(
      bff.logs.some(
        (l) => l["check"] === "idp" && l["msg"] === "readiness check failed",
      ),
    ).toBe(true);
    await bff.app.close();
  });

  it("is not ready when the store is unreachable", async () => {
    const bff = await makeBff(idp, { store: failingPing() });
    const res = await bff.app.inject({ method: "GET", url: "/health/ready" });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toEqual({
      status: "unavailable",
      checks: { store: "unavailable", idp: "ok" },
    });
    expect(JSON.stringify(res.json())).not.toContain("valkey down");
    await bff.app.close();
  });
});
