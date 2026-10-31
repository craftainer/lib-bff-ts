import { describe, expect, it } from "vitest";
import {
  absoluteExpiry,
  applyTokens,
  sessionTtlSeconds,
} from "../src/session.ts";
import type { SessionData } from "../src/session.ts";
import { testConfig } from "./helpers/bff.ts";

const config = testConfig({ issuer: "http://localhost:1" });
const base: SessionData = {
  sub: "s",
  sid: null,
  name: "n",
  email: null,
  roles: {},
  idToken: "old-id",
  accessToken: "old-at",
  refreshToken: "old-rt",
  accessExpiresAt: 0,
  createdAt: 0,
  absoluteExpiresAt: 100_000,
};

describe("applyTokens", () => {
  it("takes every new token and the new expiry", () => {
    expect(
      applyTokens(
        base,
        {
          access_token: "at",
          refresh_token: "rt",
          id_token: "id",
          expires_in: 300,
        },
        1000,
      ),
    ).toMatchObject({
      accessToken: "at",
      refreshToken: "rt",
      idToken: "id",
      accessExpiresAt: 1300,
    });
  });

  it("keeps the old refresh and ID tokens when the IdP omits them, and defaults the expiry", () => {
    expect(applyTokens(base, { access_token: "at" }, 1000)).toMatchObject({
      accessToken: "at",
      refreshToken: "old-rt",
      idToken: "old-id",
      accessExpiresAt: 1060,
    });
  });
});

describe("absoluteExpiry", () => {
  it("is the configured maximum unless the refresh token expires sooner", () => {
    const max = config.session.absoluteSeconds;
    expect(absoluteExpiry(config, 1000, undefined)).toBe(1000 + max);
    expect(absoluteExpiry(config, 1000, 0)).toBe(1000 + max);
    expect(absoluteExpiry(config, 1000, "soon")).toBe(1000 + max);
    expect(absoluteExpiry(config, 1000, max * 2)).toBe(1000 + max);
    expect(absoluteExpiry(config, 1000, 600)).toBe(1600);
  });
});

describe("sessionTtlSeconds", () => {
  it("is the idle timeout, never past the absolute expiry, at least a second", () => {
    expect(sessionTtlSeconds(config, base, 0)).toBe(config.session.idleSeconds);
    expect(
      sessionTtlSeconds(config, { ...base, absoluteExpiresAt: 50 }, 0),
    ).toBe(50);
    expect(
      sessionTtlSeconds(config, { ...base, absoluteExpiresAt: 10 }, 20),
    ).toBe(1);
  });
});
