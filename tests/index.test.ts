import { describe, expect, it } from "vitest";
import * as api from "../src/index.ts";

describe("public API", () => {
  it("exports the documented surface", () => {
    expect(Object.keys(api).sort()).toEqual(
      [
        "BffHttpError",
        "CSP_NONCE_PLACEHOLDER",
        "ConfigError",
        "LOGIN_COOKIE_NAME",
        "analytics",
        "auth",
        "createBff",
        "createMemorySessionStore",
        "csrf",
        "headers",
        "health",
        "loadConfig",
        "proxy",
        "securityLog",
        "session",
        "staticFiles",
        "wellKnown",
      ].sort(),
    );
  });
});
