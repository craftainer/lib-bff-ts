import { describe, expect, it } from "vitest";
import * as api from "../src/index.ts";

describe("public API", () => {
  it("exports the documented surface", () => {
    expect(Object.keys(api).sort()).toEqual(
      [
        "BffHttpError",
        "ConfigError",
        "LOGIN_COOKIE_NAME",
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
