import { afterEach, describe, expect, it, vi } from "vitest";
import { makeBff, testConfig, type TestBff } from "./helpers/bff.ts";

// The well-known routes never contact the IdP, so a placeholder issuer suffices.
const IDP = { issuer: "http://localhost:9" };
const ORIGIN = "http://localhost:8080";

let bff: TestBff | undefined;

async function start(
  env: Record<string, string> = {},
  mutate?: (config: ReturnType<typeof testConfig>) => void,
): Promise<TestBff> {
  const config = testConfig(IDP, env);
  mutate?.(config);
  bff = await makeBff(IDP, { config });
  return bff;
}

function get(path: string): ReturnType<TestBff["browser"]["request"]> {
  return (bff as TestBff).browser.request("GET", path);
}

afterEach(async () => {
  vi.useRealTimers();
  await bff?.app.close();
  bff = undefined;
});

describe("security.txt (RFC 9116)", () => {
  it("is absent (404) without a contact", async () => {
    await start();
    const res = await get("/.well-known/security.txt");
    expect(res.statusCode).toBe(404);
  });

  it("is absent when every contact carries a line break (programmatic config)", async () => {
    await start({}, (config) => {
      config.securityTxt.contact = ["mailto:a@b.c\nX: y"];
    });
    const res = await get("/.well-known/security.txt");
    expect(res.statusCode).toBe(404);
  });

  it("does not redirect the legacy /security.txt path (RFC 9116 section 3 only permits it)", async () => {
    await start({ SECURITY_TXT_CONTACT: "mailto:sec@example.com" });
    const res = await get("/security.txt");
    expect(res.statusCode).toBe(404);
  });

  it("renders every field with the documented content type", async () => {
    await start({
      SECURITY_TXT_CONTACT:
        "https://github.com/craftainer/x/security/advisories/new,mailto:sec@example.com",
      SECURITY_TXT_EXPIRES: "2027-06-30T12:00:00Z",
      SECURITY_TXT_POLICY: "https://example.com/policy",
      SECURITY_TXT_PREFERRED_LANGUAGES: "en, de",
      SECURITY_TXT_CANONICAL: "https://example.com/.well-known/security.txt",
    });
    const res = await get("/.well-known/security.txt");
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("text/plain; charset=utf-8");
    expect(res.body).toBe(
      [
        "Contact: https://github.com/craftainer/x/security/advisories/new",
        "Contact: mailto:sec@example.com",
        "Expires: 2027-06-30T12:00:00Z",
        "Policy: https://example.com/policy",
        "Preferred-Languages: en, de",
        "Canonical: https://example.com/.well-known/security.txt",
        "",
      ].join("\n"),
    );
  });

  it("outside production defaults Expires to startup + 364 days and Canonical to the public origin", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-31T10:00:00.000Z"));
    await start({ SECURITY_TXT_CONTACT: "mailto:sec@example.com" });
    vi.setSystemTime(new Date("2026-11-30T00:00:00.000Z"));
    const res = await get("/.well-known/security.txt");
    expect(res.body).toBe(
      [
        "Contact: mailto:sec@example.com",
        "Expires: 2027-10-30T10:00:00.000Z",
        `Canonical: ${ORIGIN}/.well-known/security.txt`,
        "",
      ].join("\n"),
    );
  });

  it("serves the configured Expires verbatim in production (where config requires one)", async () => {
    await start({
      NODE_ENV: "production",
      PUBLIC_ORIGIN: "https://app.example.com",
      OIDC_ISSUER: "https://idp.example.com",
      OIDC_ALLOW_INSECURE: "false",
      SESSION_STORE_URL: "rediss://valkey.example.com:6379",
      SECURITY_TXT_CONTACT: "mailto:sec@example.com",
      SECURITY_TXT_EXPIRES: "2027-01-01T00:00:00Z",
    });
    const res = await get("/.well-known/security.txt");
    expect(res.body).toBe(
      [
        "Contact: mailto:sec@example.com",
        "Expires: 2027-01-01T00:00:00Z",
        "Canonical: https://app.example.com/.well-known/security.txt",
        "",
      ].join("\n"),
    );
  });

  it("drops a field whose value would start another line", async () => {
    await start({ SECURITY_TXT_CONTACT: "mailto:sec@example.com" }, (c) => {
      c.securityTxt.policy = "https://example.com/p\nContact: mailto:evil@x.y";
      c.securityTxt.preferredLanguages = "en\r\nExpires: 1999-01-01T00:00:00Z";
    });
    const res = await get("/.well-known/security.txt");
    expect(res.body).not.toContain("evil");
    expect(res.body).not.toContain("1999");
    expect(res.body.match(/^Contact:/gm)).toHaveLength(1);
    expect(res.body.match(/^Expires:/gm)).toHaveLength(1);
  });

  it("answers HEAD with the headers and no body", async () => {
    const { app } = await start({
      SECURITY_TXT_CONTACT: "mailto:sec@example.com",
    });
    const res = await app.inject({
      method: "HEAD",
      url: "/.well-known/security.txt",
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("text/plain; charset=utf-8");
    expect(res.body).toBe("");
  });
});

describe("change-password (W3C Change Password URL)", () => {
  it("is absent without CHANGE_PASSWORD_URL", async () => {
    await start();
    expect((await get("/.well-known/change-password")).statusCode).toBe(404);
  });

  it("redirects with 302 to the configured URL", async () => {
    await start({
      CHANGE_PASSWORD_URL: "https://idp.example.com/account/password",
    });
    const res = await get("/.well-known/change-password");
    expect(res.statusCode).toBe(302);
    expect(res.headers["location"]).toBe(
      "https://idp.example.com/account/password",
    );
  });
});

describe("gpc.json (W3C GPC)", () => {
  it("serves gpc and lastUpdate while respectGpc is on (the default)", async () => {
    await start();
    const res = await get("/.well-known/gpc.json");
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe("application/json");
    expect(res.json()).toEqual({ gpc: true, lastUpdate: "2026-10-31" });
    expect(res.body).toBe('{"gpc":true,"lastUpdate":"2026-10-31"}');
  });

  it("is absent when GPC is not respected", async () => {
    await start({ ANALYTICS_RESPECT_GPC: "false" });
    expect((await get("/.well-known/gpc.json")).statusCode).toBe(404);
  });
});

describe("api-catalog (RFC 9727)", () => {
  const CATALOG = `${ORIGIN}/.well-known/api-catalog`;
  const PROFILE = "https://www.rfc-editor.org/info/rfc9727";

  it("lists each upstream as a linkset with the profile parameter", async () => {
    await start({
      BFF_UPSTREAMS: JSON.stringify({
        crud: {
          url: "http://crud.test:8000",
          audience: "api",
          methods: ["GET"],
        },
        "b-2": {
          url: "http://ab.test:8000",
          audience: "api",
          methods: ["GET"],
        },
      }),
    });
    const res = await get("/.well-known/api-catalog");
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toBe(
      `application/linkset+json; profile="${PROFILE}"`,
    );
    expect(res.headers["link"]).toBe(`<${CATALOG}>; rel="api-catalog"`);
    expect(res.json()).toEqual({
      linkset: [
        {
          anchor: CATALOG,
          item: [
            { href: `${ORIGIN}/api/crud/`, title: "crud" },
            { href: `${ORIGIN}/api/b-2/`, title: "b-2" },
          ],
          "api-catalog": [
            {
              href: `${ORIGIN}/api/crud/.well-known/api-catalog`,
              title: "crud",
            },
            {
              href: `${ORIGIN}/api/b-2/.well-known/api-catalog`,
              title: "b-2",
            },
          ],
        },
      ],
    });
  });

  it("answers HEAD with the Link header and the profile, no body", async () => {
    const { app } = await start();
    const res = await app.inject({
      method: "HEAD",
      url: "/.well-known/api-catalog",
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["link"]).toBe(`<${CATALOG}>; rel="api-catalog"`);
    expect(res.headers["content-type"]).toBe(
      `application/linkset+json; profile="${PROFILE}"`,
    );
    expect(res.body).toBe("");
  });

  it("is an empty linkset without upstreams", async () => {
    await start({ BFF_UPSTREAMS: "{}" });
    const res = await get("/.well-known/api-catalog");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ linkset: [] });
  });
});

describe("well-known URIs deliberately not served (ADR 0003)", () => {
  it.each([
    "openid-configuration",
    "oauth-authorization-server",
    "jwks.json",
    "webfinger",
    "host-meta",
    "assetlinks.json",
    "apple-app-site-association",
  ])("answers 404 for /.well-known/%s", async (name) => {
    await start();
    expect((await get(`/.well-known/${name}`)).statusCode).toBe(404);
  });
});
