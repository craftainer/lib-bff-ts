import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../src/config.ts";

const base = {
  PUBLIC_ORIGIN: "https://app.example.com",
  OIDC_ISSUER: "https://idp.example.com/realms/x",
  OIDC_CLIENT_SECRET: "s3cret",
  SESSION_STORE_URL: "rediss://valkey:6379",
};

function issues(env: Record<string, string | undefined>): string[] {
  try {
    loadConfig(env);
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigError);
    return (error as ConfigError).issues;
  }
  throw new Error("expected loadConfig to throw");
}

describe("loadConfig", () => {
  it("applies the documented defaults", () => {
    const config = loadConfig({ ...base, EMPTY: "", BFF_UPSTREAMS: "" });
    expect(config).toMatchObject({
      production: false,
      port: 8080,
      host: "0.0.0.0",
      staticDir: null,
      publicOrigin: "https://app.example.com",
      trustProxy: false,
      oidc: {
        issuer: "https://idp.example.com/realms/x",
        discoveryUrl:
          "https://idp.example.com/realms/x/.well-known/openid-configuration",
        clientId: "bff",
        scopes: "openid profile email",
        allowInsecure: false,
      },
      session: {
        idleSeconds: 1800,
        absoluteSeconds: 28800,
        cookieName: "__Host-Http-session",
        loginTtlSeconds: 300,
      },
      rateLimit: { max: 20, windowSeconds: 60 },
      upstreams: {},
      changePasswordUrl: null,
      securityTxt: {
        contact: [],
        expires: null,
        policy: null,
        preferredLanguages: null,
        canonical: null,
      },
      analytics: {
        enabled: true,
        backend: "none",
        endpoint: null,
        siteId: null,
        hostname: null,
        consent: "implied",
        respectGpc: true,
        geo: "none",
        propKeys: [],
      },
    });
  });

  it("reads every variable", () => {
    const config = loadConfig({
      ...base,
      NODE_ENV: "production",
      SESSION_STORE_ALLOW_PLAINTEXT: "true",
      BFF_PORT: "9000",
      BFF_HOST: "127.0.0.1",
      BFF_STATIC_DIR: "/srv/spa",
      BFF_TRUST_PROXY: "true",
      OIDC_DISCOVERY_URL:
        "https://idp-internal:8443/realms/x/.well-known/openid-configuration",
      OIDC_CLIENT_ID: "my-bff",
      OIDC_SCOPES: "openid   offline_access",
      SESSION_IDLE_SECONDS: "60",
      SESSION_ABSOLUTE_SECONDS: "120",
      SESSION_COOKIE_NAME: "__Host-s",
      RATE_LIMIT_MAX: "5",
      RATE_LIMIT_WINDOW_SECONDS: "10",
      BFF_UPSTREAMS: JSON.stringify({
        crud: {
          url: "http://backend:8000",
          audience: "api",
          methods: ["GET", "POST"],
          stream: true,
        },
      }),
      SECURITY_TXT_CONTACT:
        "https://example.com/report, mailto:sec@example.com",
      SECURITY_TXT_EXPIRES: "2027-01-01T00:00:00Z",
      SECURITY_TXT_POLICY: "https://example.com/policy",
      SECURITY_TXT_PREFERRED_LANGUAGES: "en",
      SECURITY_TXT_CANONICAL:
        "https://app.example.com/.well-known/security.txt",
      CHANGE_PASSWORD_URL: "https://idp.example.com/account",
      ANALYTICS_ENABLED: "0",
      ANALYTICS_BACKEND: "umami",
      ANALYTICS_ENDPOINT: "http://umami:3000",
      ANALYTICS_SITE_ID: "abc",
      ANALYTICS_HOSTNAME: "app.example.com",
      ANALYTICS_CONSENT: "opt-in",
      ANALYTICS_RESPECT_GPC: "false",
      ANALYTICS_GEO: "coarse",
      ANALYTICS_PROP_KEYS: "a,b",
    });
    expect(config.production).toBe(true);
    expect(config.port).toBe(9000);
    expect(config.trustProxy).toBe(true);
    expect(config.staticDir).toBe("/srv/spa");
    expect(config.oidc.scopes).toBe("openid offline_access");
    expect(config.upstreams["crud"]).toEqual({
      url: "http://backend:8000",
      audience: "api",
      methods: ["GET", "POST"],
      tokenExchange: false,
      stream: true,
    });
    expect(config.securityTxt.contact).toEqual([
      "https://example.com/report",
      "mailto:sec@example.com",
    ]);
    expect(config.analytics).toMatchObject({
      enabled: false,
      consent: "opt-in",
      propKeys: ["a", "b"],
      respectGpc: false,
    });
  });

  it("allows plain http for a loopback origin and with OIDC_ALLOW_INSECURE", () => {
    const config = loadConfig({
      ...base,
      PUBLIC_ORIGIN: "http://localhost:8081/",
      OIDC_ISSUER: "http://localhost:8080/realms/x/",
      OIDC_ALLOW_INSECURE: "true",
      CHANGE_PASSWORD_URL: "http://localhost:8080/account",
    });
    expect(config.publicOrigin).toBe("http://localhost:8081");
    expect(config.oidc.discoveryUrl).toBe(
      "http://localhost:8080/realms/x/.well-known/openid-configuration",
    );
  });

  it("lists missing required variables", () => {
    expect(issues({})).toEqual(
      expect.arrayContaining([
        expect.stringContaining("PUBLIC_ORIGIN"),
        expect.stringContaining("OIDC_ISSUER"),
        expect.stringContaining("OIDC_CLIENT_SECRET"),
        expect.stringContaining("SESSION_STORE_URL"),
      ]),
    );
  });

  it("rejects malformed scalars without echoing secrets", () => {
    const found = issues({
      ...base,
      OIDC_CLIENT_SECRET: "",
      BFF_PORT: "0",
      SESSION_IDLE_SECONDS: "-1",
      SESSION_COOKIE_NAME: "bad name;",
      BFF_TRUST_PROXY: "yes",
      ANALYTICS_BACKEND: "matomo",
      SESSION_STORE_URL: "http://valkey",
    });
    expect(found.length).toBeGreaterThanOrEqual(6);
    expect(found.join("\n")).not.toContain("s3cret");
  });

  it("refuses insecure IdP URLs unless allowed, and never in production", () => {
    expect(
      issues({ ...base, OIDC_ISSUER: "http://idp.example.com" }),
    ).toContain(
      "OIDC_ISSUER: must be https (set OIDC_ALLOW_INSECURE=true for development)",
    );
    expect(
      issues({
        ...base,
        OIDC_DISCOVERY_URL:
          "http://idp.example.com/.well-known/openid-configuration",
      }),
    ).toContain(
      "OIDC_DISCOVERY_URL: must be https (set OIDC_ALLOW_INSECURE=true for development)",
    );
    expect(
      issues({
        ...base,
        NODE_ENV: "production",
        SESSION_STORE_ALLOW_PLAINTEXT: "true",
        OIDC_ALLOW_INSECURE: "true",
      }),
    ).toContain("OIDC_ALLOW_INSECURE: refused when NODE_ENV=production");
  });

  it("requires the full discovery URL", () => {
    expect(
      issues({
        ...base,
        OIDC_DISCOVERY_URL: "https://idp.example.com/realms/x",
      }),
    ).toContain(
      "OIDC_DISCOVERY_URL: must be the full .../.well-known/openid-configuration URL",
    );
    expect(
      issues({
        ...base,
        OIDC_DISCOVERY_URL:
          "https://idp.example.com/.well-known/openid-configuration?x=1",
      }),
    ).toContain(
      "OIDC_DISCOVERY_URL: must be the full .../.well-known/openid-configuration URL",
    );
    expect(issues({ ...base, OIDC_DISCOVERY_URL: "not a url" })).toContain(
      "OIDC_DISCOVERY_URL: not a valid URL",
    );
  });

  it("requires openid among the scopes", () => {
    expect(issues({ ...base, OIDC_SCOPES: "profile" })).toContain(
      "OIDC_SCOPES: must include openid",
    );
  });

  it("validates PUBLIC_ORIGIN", () => {
    expect(issues({ ...base, PUBLIC_ORIGIN: "nonsense" })).toContain(
      "PUBLIC_ORIGIN: not a valid URL",
    );
    expect(
      issues({ ...base, PUBLIC_ORIGIN: "https://app.example.com/path" })[0],
    ).toContain("must be an origin");
    expect(
      issues({ ...base, PUBLIC_ORIGIN: "http://app.example.com" })[0],
    ).toContain("must be https");
    expect(
      issues({
        ...base,
        PUBLIC_ORIGIN: "http://localhost:3000",
        NODE_ENV: "production",
        SESSION_STORE_ALLOW_PLAINTEXT: "true",
      })[0],
    ).toContain("must be https");
  });

  it("validates session lifetimes and cookie names", () => {
    expect(
      issues({
        ...base,
        SESSION_IDLE_SECONDS: "100",
        SESSION_ABSOLUTE_SECONDS: "50",
      }),
    ).toContain(
      "SESSION_IDLE_SECONDS: must not exceed SESSION_ABSOLUTE_SECONDS",
    );
    expect(
      issues({ ...base, SESSION_COOKIE_NAME: "__Host-Http-login" })[0],
    ).toContain("must differ");
  });

  it("validates BFF_UPSTREAMS", () => {
    expect(issues({ ...base, BFF_UPSTREAMS: "{" })).toContain(
      "BFF_UPSTREAMS: not valid JSON",
    );
    expect(
      issues({
        ...base,
        BFF_UPSTREAMS: JSON.stringify({
          Bad_Name: { url: "http://x", audience: "a", methods: ["GET"] },
        }),
      })[0],
    ).toContain("BFF_UPSTREAMS.");
    expect(
      issues({
        ...base,
        BFF_UPSTREAMS: JSON.stringify({
          a: { url: "ftp://x", audience: "a", methods: ["GET"] },
        }),
      })[0],
    ).toContain("BFF_UPSTREAMS.a.url");
    expect(
      issues({
        ...base,
        BFF_UPSTREAMS: JSON.stringify({
          a: { url: "http://u:p@x/?q=1", audience: "a", methods: ["GET"] },
        }),
      }),
    ).toContain(
      "BFF_UPSTREAMS.a.url: must not contain credentials, query or fragment",
    );
    expect(
      issues({
        ...base,
        BFF_UPSTREAMS: JSON.stringify({
          a: { url: "http://x", audience: "a", methods: [] },
        }),
      })[0],
    ).toContain("BFF_UPSTREAMS.a.methods");
  });

  it("validates analytics settings", () => {
    const found = issues({ ...base, ANALYTICS_BACKEND: "umami" });
    expect(found).toContain(
      "ANALYTICS_ENDPOINT: required (a URL) for the umami backend",
    );
    expect(found).toContain(
      "ANALYTICS_SITE_ID: required for the umami backend",
    );
    expect(
      issues({
        ...base,
        ANALYTICS_BACKEND: "umami",
        ANALYTICS_ENDPOINT: "nope",
        ANALYTICS_SITE_ID: "x",
      }),
    ).toContain("ANALYTICS_ENDPOINT: required (a URL) for the umami backend");
    expect(() =>
      loadConfig({
        ...base,
        ANALYTICS_BACKEND: "umami",
        ANALYTICS_ENABLED: "false",
      }),
    ).not.toThrow();
  });

  it("accepts a complete umami configuration", () => {
    expect(
      loadConfig({
        ...base,
        ANALYTICS_BACKEND: "umami",
        ANALYTICS_ENDPOINT: "http://umami:3000",
        ANALYTICS_SITE_ID: "x",
      }).analytics.backend,
    ).toBe("umami");
  });

  it("validates security.txt and the change-password URL", () => {
    expect(
      issues({
        ...base,
        SECURITY_TXT_CONTACT: "http://insecure",
        SECURITY_TXT_EXPIRES: "tomorrow",
      }),
    ).toEqual([
      "SECURITY_TXT_CONTACT: each entry must be an https:, mailto: or tel: URI",
      "SECURITY_TXT_EXPIRES: must be an ISO 8601 date-time",
    ]);
    expect(
      issues({
        ...base,
        NODE_ENV: "production",
        SESSION_STORE_ALLOW_PLAINTEXT: "true",
        SECURITY_TXT_CONTACT: "mailto:a@b.c",
      }),
    ).toContain(
      "SECURITY_TXT_EXPIRES: required in production when SECURITY_TXT_CONTACT is set (RFC 9116)",
    );
    expect(
      issues({ ...base, CHANGE_PASSWORD_URL: "http://idp/account" }),
    ).toContain("CHANGE_PASSWORD_URL: must be an https URL");
  });
});

describe("SESSION_STORE_URL transport", () => {
  const remote = ["redis://valkey:6379", "valkey://valkey:6379"];

  it("refuses plaintext redis:// and valkey:// to a non-loopback host, whatever NODE_ENV says", () => {
    for (const env of [{}, { NODE_ENV: "production" }, { NODE_ENV: "prod" }]) {
      for (const url of remote) {
        expect(
          issues({ ...base, ...env, SESSION_STORE_URL: url }).join("\n"),
          url,
        ).toContain("SESSION_STORE_URL: plaintext");
      }
    }
  });

  it("accepts it with SESSION_STORE_ALLOW_PLAINTEXT=true", () => {
    for (const url of remote) {
      expect(
        loadConfig({
          ...base,
          NODE_ENV: "production",
          SESSION_STORE_URL: url,
          SESSION_STORE_ALLOW_PLAINTEXT: "true",
        }).session.storeUrl,
      ).toBe(url);
    }
  });

  it("always accepts TLS URLs and plaintext to localhost, 127.0.0.0/8 and ::1", () => {
    for (const url of [
      "rediss://valkey:6379",
      "valkeys://valkey:6379",
      "redis://localhost:6379",
      "valkey://127.0.0.1:6379",
      "redis://127.5.5.5:6379",
      "redis://[::1]:6379",
    ]) {
      expect(
        loadConfig({ ...base, NODE_ENV: "production", SESSION_STORE_URL: url })
          .session.storeUrl,
        url,
      ).toBe(url);
    }
  });
});

describe("SESSION_COOKIE_NAME", () => {
  it("must start with __Host- (ASVS 3.3.3)", () => {
    expect(
      issues({ ...base, SESSION_COOKIE_NAME: "sid" }).join("\n"),
    ).toContain("SESSION_COOKIE_NAME");
    expect(
      issues({ ...base, SESSION_COOKIE_NAME: "__Secure-sid" }),
    ).not.toEqual([]);
    expect(
      loadConfig({ ...base, SESSION_COOKIE_NAME: "__Host-Http-app" }).session
        .cookieName,
    ).toBe("__Host-Http-app");
    expect(
      loadConfig({ ...base, SESSION_COOKIE_NAME: "__Host-app" }).session
        .cookieName,
    ).toBe("__Host-app");
  });
});
