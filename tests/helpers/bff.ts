import type { FastifyInstance } from "fastify";
import { createBff } from "../../src/app.ts";
import { loadConfig, type BffConfig } from "../../src/config.ts";
import {
  createMemorySessionStore,
  type SessionStore,
} from "../../src/session.ts";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  PUBLIC_ORIGIN,
  SCOPES,
  type TestIdp,
} from "./idp.ts";

export const UPSTREAMS = JSON.stringify({
  crud: {
    url: "http://crud.test:8000",
    audience: "api",
    methods: ["GET", "POST"],
  },
});

/** A `BffConfig` pointing at the test IdP; `env` overrides individual variables. */
export function testConfig(
  idp: Pick<TestIdp, "issuer">,
  env: Record<string, string> = {},
): BffConfig {
  return loadConfig({
    PUBLIC_ORIGIN,
    OIDC_ISSUER: idp.issuer,
    OIDC_ALLOW_INSECURE: "true",
    OIDC_CLIENT_ID: CLIENT_ID,
    OIDC_CLIENT_SECRET: CLIENT_SECRET,
    OIDC_SCOPES: SCOPES,
    SESSION_STORE_URL: "redis://localhost:6379",
    BFF_UPSTREAMS: UPSTREAMS,
    RATE_LIMIT_MAX: "1000",
    ...env,
  });
}

export interface TestBff {
  app: FastifyInstance;
  config: BffConfig;
  store: SessionStore;
  /** Captured JSON log lines. */
  logs: Record<string, unknown>[];
  browser: Browser;
}

/** Creates the BFF over an in-memory session store, capturing its logs. */
export async function makeBff(
  idp: Pick<TestIdp, "issuer">,
  opts: {
    env?: Record<string, string>;
    config?: BffConfig;
    store?: SessionStore;
  } = {},
): Promise<TestBff> {
  const config = opts.config ?? testConfig(idp, opts.env);
  const store = opts.store ?? createMemorySessionStore();
  const logs: Record<string, unknown>[] = [];
  const stream = {
    write(line: string): void {
      logs.push(JSON.parse(line) as Record<string, unknown>);
    },
  };
  const app = await createBff(config, {
    sessionStore: store,
    logger: { level: "info", stream } as never,
  });
  return { app, config, store, logs, browser: new Browser(app, idp.issuer) };
}

type Jar = Map<string, string>;

function absorb(jar: Jar, setCookies: string[]): void {
  for (const raw of setCookies) {
    const [pair = "", ...attributes] = raw
      .split(";")
      .map((part) => part.trim());
    const eq = pair.indexOf("=");
    const name = pair.slice(0, eq);
    const value = pair.slice(eq + 1);
    const expired =
      attributes.some((a) => /^max-age=0$/i.test(a)) ||
      attributes.some((a) => /^expires=thu, 01 jan 1970/i.test(a));
    if (value === "" || expired) {
      jar.delete(name);
    } else {
      jar.set(name, value);
    }
  }
}

function header(jar: Jar): string {
  return [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
}

export interface BffResponse {
  statusCode: number;
  headers: Record<string, string | string[] | number | undefined>;
  body: string;
  json<T = Record<string, unknown>>(): T;
  /** Set-Cookie header values. */
  setCookies: string[];
}

/** A tiny browser: one cookie jar for the BFF, one for the IdP. */
export class Browser {
  readonly bffJar: Jar = new Map();
  readonly idpJar: Jar = new Map();
  readonly #app: FastifyInstance;
  readonly #issuer: string;

  constructor(app: FastifyInstance, issuer: string) {
    this.#app = app;
    this.#issuer = issuer;
  }

  /** Sends a request to the BFF with the jar's cookies and a same-origin browser's headers. */
  async request(
    method: "GET" | "POST" | "PUT" | "DELETE",
    url: string,
    opts: {
      headers?: Record<string, string>;
      body?: string | Record<string, unknown>;
      csrf?: boolean;
    } = {},
  ): Promise<BffResponse> {
    const headers: Record<string, string> = { ...opts.headers };
    if (this.bffJar.size > 0) {
      headers["cookie"] = header(this.bffJar);
    }
    if (opts.csrf === true) {
      headers["x-csrf"] = "1";
    }
    const res = await this.#app.inject({
      method,
      url,
      headers,
      ...(opts.body === undefined ? {} : { payload: opts.body as never }),
    });
    const setCookies = ([] as string[]).concat(
      (res.headers["set-cookie"] as string[] | string | undefined) ?? [],
    );
    absorb(this.bffJar, setCookies);
    return {
      statusCode: res.statusCode,
      headers: res.headers,
      body: res.body,
      json: <T>() => res.json() as T,
      setCookies,
    };
  }

  /** Walks the IdP's redirects and sign-in form; returns the callback URL it ends at. */
  async authenticate(
    authorizationUrl: string,
    account = "alice",
  ): Promise<string> {
    let url = authorizationUrl;
    for (let hop = 0; hop < 12; hop += 1) {
      const res = await fetch(url, {
        redirect: "manual",
        headers: { cookie: header(this.idpJar) },
      });
      absorb(this.idpJar, res.headers.getSetCookie());
      const location = res.headers.get("location");
      if (location !== null) {
        url = new URL(location, url).href;
        if (url.startsWith(PUBLIC_ORIGIN)) {
          return url;
        }
        continue;
      }
      const uid = new URL(url).pathname.split("/").pop();
      const submit = await fetch(`${this.#issuer}/interaction/${uid}`, {
        method: "POST",
        redirect: "manual",
        headers: {
          cookie: header(this.idpJar),
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          prompt: "login",
          login: account,
          password: "irrelevant",
        }),
      });
      absorb(this.idpJar, submit.headers.getSetCookie());
      url = new URL(String(submit.headers.get("location")), url).href;
    }
    throw new Error("IdP redirect loop");
  }

  /** `GET /bff/login`, sign in at the IdP and return the authorization URL and the callback URL. */
  async startLogin(
    returnTo?: string,
    account = "alice",
  ): Promise<{
    authorizationUrl: string;
    callbackUrl: string;
    login: BffResponse;
  }> {
    const query =
      returnTo === undefined ? "" : `?returnTo=${encodeURIComponent(returnTo)}`;
    const login = await this.request("GET", `/bff/login${query}`);
    const authorizationUrl = String(login.headers["location"]);
    return {
      authorizationUrl,
      callbackUrl: await this.authenticate(authorizationUrl, account),
      login,
    };
  }

  /** The complete login: returns the callback response (a redirect carrying the session cookie). */
  async login(returnTo?: string, account = "alice"): Promise<BffResponse> {
    const { callbackUrl } = await this.startLogin(returnTo, account);
    const url = new URL(callbackUrl);
    return this.request("GET", `${url.pathname}${url.search}`);
  }
}
