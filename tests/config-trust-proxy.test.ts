import { describe, expect, it } from "vitest";
import { createBff } from "../src/app.ts";
import { ConfigError } from "../src/config.ts";
import { createMemorySessionStore } from "../src/session.ts";
import { testConfig } from "./helpers/bff.ts";

const issuer = { issuer: "http://localhost:1" };
const trust = (value: string | undefined): unknown =>
  testConfig(issuer, value === undefined ? {} : { BFF_TRUST_PROXY: value })
    .trustProxy;

describe("BFF_TRUST_PROXY", () => {
  it("accepts true, false, a hop count or an IP/CIDR list; the default is false", () => {
    expect(trust(undefined)).toBe(false);
    expect(trust("false")).toBe(false);
    expect(trust("true")).toBe(true);
    expect(trust("2")).toBe(2);
    expect(trust("10.0.0.0/8, 192.168.1.5,loopback,fd00::/8")).toEqual([
      "10.0.0.0/8",
      "192.168.1.5",
      "loopback",
      "fd00::/8",
    ]);
  });

  it("rejects anything else, including bad CIDRs", () => {
    for (const bad of [
      "yes",
      "1000",
      "10.0.0.0/33",
      "fd00::/129",
      "10.0.0.0/8/8",
      "10.0.0.0/x",
      "999.1.1.1",
      "10.0.0.1,,10.0.0.2",
    ]) {
      expect(() => trust(bad), bad).toThrow(ConfigError);
    }
  });
});

describe("trustProxy in the app", () => {
  async function clientIp(value: string | undefined): Promise<string> {
    const config = testConfig(
      issuer,
      value === undefined ? {} : { BFF_TRUST_PROXY: value },
    );
    const app = await createBff(config, {
      sessionStore: createMemorySessionStore(),
      logger: false,
    });
    app.get("/ip", async (request) => request.ip);
    const res = await app.inject({
      method: "GET",
      url: "/ip",
      remoteAddress: "10.0.0.2",
      headers: { "x-forwarded-for": "1.2.3.4, 10.0.0.1" },
    });
    await app.close();
    return res.body;
  }

  it("ignores X-Forwarded-For unless a proxy is trusted", async () => {
    expect(await clientIp(undefined)).toBe("10.0.0.2");
  });

  it("trusts exactly the configured number of hops", async () => {
    expect(await clientIp("1")).toBe("10.0.0.1");
    expect(await clientIp("2")).toBe("1.2.3.4");
  });

  it("trusts a list of proxies, or every hop for true", async () => {
    expect(await clientIp("10.0.0.2")).toBe("10.0.0.1");
    expect(await clientIp("10.0.0.0/8")).toBe("1.2.3.4");
    expect(await clientIp("true")).toBe("1.2.3.4");
  });
});
