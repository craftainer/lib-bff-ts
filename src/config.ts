import { isIP } from "node:net";
import { z } from "zod";

/** HTTP methods an upstream may allow. */
const METHODS = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
] as const;

/** Name of the login-transaction cookie (carries only the random `state`). */
export const LOGIN_COOKIE_NAME = "__Host-Http-login";

const DISCOVERY_SUFFIX = "/.well-known/openid-configuration";
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** One entry of `BFF_UPSTREAMS` (I4), mounted at `/api/<name>/*`. */
export interface UpstreamConfig {
  /** Base URL of the upstream, without query or fragment. */
  url: string;
  /** Expected token audience (the upstream validates `aud`). */
  audience: string;
  /** Methods the proxy forwards; everything else is answered 405. */
  methods: string[];
  /** RFC 8693 token exchange for this upstream. Defined but not implemented: `true` is rejected at use. */
  tokenExchange: boolean;
  /** Server-sent events: the proxy disables the body timeout. */
  stream: boolean;
}

/** `ANALYTICS_*` (I3), consumed by the analytics plugin. */
export interface AnalyticsConfig {
  enabled: boolean;
  backend: "none" | "log" | "umami" | "otel";
  /** Umami base URL; adapters append `/api/batch`. */
  endpoint: string | null;
  siteId: string | null;
  /** Sent as `payload.hostname`. */
  hostname: string | null;
  consent: "implied" | "opt-in";
  respectGpc: boolean;
  geo: "none" | "coarse";
  /** Allowlist of event property keys. */
  propKeys: string[];
}

/** `SECURITY_TXT_*` (RFC 9116), consumed by the well-known plugin. */
export interface SecurityTxtConfig {
  contact: string[];
  /** ISO 8601 timestamp. */
  expires: string | null;
  policy: string | null;
  preferredLanguages: string | null;
  canonical: string | null;
}

/** The validated, typed configuration every plugin receives. */
export interface BffConfig {
  /** True when `NODE_ENV=production`. */
  production: boolean;
  port: number;
  host: string;
  /** Directory of the built SPA, or null when the app serves no static files. */
  staticDir: string | null;
  /** The browser-facing origin (`https://host[:port]`, no path). Never derived from the Host header. */
  publicOrigin: string;
  /**
   * Passed to Fastify's `trustProxy` (affects `request.ip`, hence rate
   * limiting): `false`, `true` (trust every hop; avoid), a hop count, or a
   * list of proxy IPs / CIDRs / `loopback`, `linklocal`, `uniquelocal`.
   */
  trustProxy: boolean | number | string[];
  oidc: {
    issuer: string;
    /** Full `.../.well-known/openid-configuration` URL. */
    discoveryUrl: string;
    clientId: string;
    clientSecret: string;
    /** Space-separated scopes, always including `openid`. */
    scopes: string;
    /** Allow plain-http IdP URLs (development only; refused in production). */
    allowInsecure: boolean;
  };
  session: {
    /** `redis://`, `rediss://`, `valkey://` or `valkeys://` URL. */
    storeUrl: string;
    idleSeconds: number;
    absoluteSeconds: number;
    cookieName: string;
    /** Lifetime of the server-side login transaction. */
    loginTtlSeconds: number;
    /** Access tokens closer than this to expiry are refreshed. */
    accessTokenSkewSeconds: number;
    /** Per-session refresh lock; not settable from the environment. */
    refreshLock: { ttlMs: number; waitMs: number; pollMs: number };
  };
  /** In-memory, per replica. */
  rateLimit: { max: number; windowSeconds: number };
  upstreams: Record<string, UpstreamConfig>;
  securityTxt: SecurityTxtConfig;
  /** Target of the `change-password` well-known redirect. */
  changePasswordUrl: string | null;
  analytics: AnalyticsConfig;
}

/** Thrown by {@link loadConfig}; the message lists every problem, never a secret value. */
export class ConfigError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`Invalid configuration:\n- ${issues.join("\n- ")}`);
    this.name = "ConfigError";
    this.issues = issues;
  }
}

const bool = (fallback: boolean): z.ZodType<boolean> =>
  z
    .preprocess(
      (v) => (v === undefined ? String(fallback) : v),
      z
        .enum(["true", "false", "1", "0"])
        .transform((v) => v === "true" || v === "1"),
    )
    .pipe(z.boolean());

const PROXY_KEYWORDS = new Set(["loopback", "linklocal", "uniquelocal"]);

function validProxyEntry(entry: string): boolean {
  if (PROXY_KEYWORDS.has(entry)) {
    return true;
  }
  const [address, prefix, ...rest] = entry.split("/");
  const family = isIP(address as string);
  if (family === 0 || rest.length > 0) {
    return false;
  }
  if (prefix === undefined) {
    return true;
  }
  return (
    /^[0-9]{1,3}$/.test(prefix) && Number(prefix) <= (family === 4 ? 32 : 128)
  );
}

/** `true`/`false`, a non-negative hop count, or a comma-separated IP/CIDR list. */
const trustProxy = z
  .string()
  .optional()
  .transform((v, ctx): boolean | number | string[] => {
    const value = (v ?? "false").trim();
    if (value === "true" || value === "false") {
      return value === "true";
    }
    if (/^[0-9]{1,3}$/.test(value)) {
      return Number(value);
    }
    const entries = value.split(",").map((e) => e.trim());
    if (entries.every((e) => e !== "" && validProxyEntry(e))) {
      return entries;
    }
    ctx.addIssue({
      code: "custom",
      message:
        "must be true, false, a hop count, or a comma-separated list of IPs/CIDRs",
    });
    return z.NEVER;
  });

const positiveInt = (fallback: number, max = 31_536_000): z.ZodType<number> =>
  z
    .preprocess(
      (v) => (v === undefined ? String(fallback) : v),
      z.string().regex(/^[1-9][0-9]*$/, "must be a positive integer"),
    )
    .pipe(z.transform((v) => Number(v)))
    .pipe(z.number().max(max));

const list = z
  .string()
  .optional()
  .transform((v) =>
    (v ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== ""),
  );

const optionalString = z.string().optional();

const upstreamSchema = z
  .object({
    url: z.url({ protocol: /^https?$/ }),
    audience: z.string().min(1),
    methods: z.array(z.enum(METHODS)).min(1),
    tokenExchange: z.boolean().default(false),
    stream: z.boolean().default(false),
  })
  .strict()
  .superRefine((u, ctx) => {
    const parsed = new URL(u.url);
    if (
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.hash !== ""
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["url"],
        message: "must not contain credentials, query or fragment",
      });
    }
  });

const upstreamsSchema = z.record(
  z.string().regex(/^[a-z][a-z0-9-]*$/, "name must match [a-z][a-z0-9-]*"),
  upstreamSchema,
);

const envSchema = z.object({
  NODE_ENV: optionalString,
  BFF_PORT: z
    .preprocess((v) => v ?? "8080", z.string().regex(/^[0-9]+$/))
    .pipe(z.transform((v) => Number(v)))
    .pipe(z.number().int().min(1).max(65535)),
  BFF_HOST: z.string().default("0.0.0.0"),
  BFF_STATIC_DIR: optionalString,
  BFF_TRUST_PROXY: trustProxy,
  PUBLIC_ORIGIN: z.string().min(1),
  OIDC_ISSUER: z.url(),
  OIDC_DISCOVERY_URL: optionalString,
  OIDC_CLIENT_ID: z.string().min(1).default("bff"),
  OIDC_CLIENT_SECRET: z.string().min(1),
  OIDC_SCOPES: z.string().default("openid profile email"),
  OIDC_ALLOW_INSECURE: bool(false),
  SESSION_STORE_URL: z.url({ protocol: /^(redis|rediss|valkey|valkeys)$/ }),
  SESSION_IDLE_SECONDS: positiveInt(1800),
  SESSION_ABSOLUTE_SECONDS: positiveInt(28800),
  SESSION_COOKIE_NAME: z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/, "must be a cookie token")
    .default("__Host-Http-session"),
  RATE_LIMIT_MAX: positiveInt(20, 100_000),
  RATE_LIMIT_WINDOW_SECONDS: positiveInt(60, 86_400),
  BFF_UPSTREAMS: optionalString,
  SECURITY_TXT_CONTACT: list,
  SECURITY_TXT_EXPIRES: optionalString,
  SECURITY_TXT_POLICY: optionalString,
  SECURITY_TXT_PREFERRED_LANGUAGES: optionalString,
  SECURITY_TXT_CANONICAL: optionalString,
  CHANGE_PASSWORD_URL: optionalString,
  ANALYTICS_ENABLED: bool(true),
  ANALYTICS_BACKEND: z.enum(["none", "log", "umami", "otel"]).default("none"),
  ANALYTICS_ENDPOINT: optionalString,
  ANALYTICS_SITE_ID: optionalString,
  ANALYTICS_HOSTNAME: optionalString,
  ANALYTICS_CONSENT: z.enum(["implied", "opt-in"]).default("implied"),
  ANALYTICS_RESPECT_GPC: bool(true),
  ANALYTICS_GEO: z.enum(["none", "coarse"]).default("none"),
  ANALYTICS_PROP_KEYS: list,
});

type Env = z.output<typeof envSchema>;

function isHttpsOrAllowed(url: string, insecure: boolean): boolean {
  return new URL(url).protocol === "https:" || insecure;
}

function parseUpstreams(
  raw: string | undefined,
  issues: string[],
): Record<string, UpstreamConfig> {
  if (raw === undefined) {
    return {};
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    issues.push("BFF_UPSTREAMS: not valid JSON");
    return {};
  }
  const parsed = upstreamsSchema.safeParse(json);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      issues.push(`BFF_UPSTREAMS.${issue.path.join(".")}: ${issue.message}`);
    }
    return {};
  }
  return parsed.data;
}

function publicOrigin(
  raw: string,
  production: boolean,
  issues: string[],
): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    issues.push("PUBLIC_ORIGIN: not a valid URL");
    return raw;
  }
  if (url.origin === "null" || raw.replace(/\/$/, "") !== url.origin) {
    issues.push(
      "PUBLIC_ORIGIN: must be an origin (scheme, host, optional port) with no path, query or credentials",
    );
  } else if (
    url.protocol !== "https:" &&
    (production || !LOOPBACK_HOSTS.has(url.hostname))
  ) {
    issues.push(
      "PUBLIC_ORIGIN: must be https (plain http only for localhost outside production)",
    );
  }
  return url.origin;
}

function checkOidc(env: Env, allowInsecure: boolean, issues: string[]): string {
  if (!isHttpsOrAllowed(env.OIDC_ISSUER, allowInsecure)) {
    issues.push(
      "OIDC_ISSUER: must be https (set OIDC_ALLOW_INSECURE=true for development)",
    );
  }
  const discoveryUrl =
    env.OIDC_DISCOVERY_URL ??
    `${env.OIDC_ISSUER.replace(/\/+$/, "")}${DISCOVERY_SUFFIX}`;
  let parsed: URL | undefined;
  try {
    parsed = new URL(discoveryUrl);
  } catch {
    issues.push("OIDC_DISCOVERY_URL: not a valid URL");
  }
  if (parsed !== undefined) {
    if (
      !parsed.pathname.endsWith(DISCOVERY_SUFFIX) ||
      parsed.search !== "" ||
      parsed.hash !== ""
    ) {
      issues.push(
        `OIDC_DISCOVERY_URL: must be the full ...${DISCOVERY_SUFFIX} URL`,
      );
    }
    if (!isHttpsOrAllowed(discoveryUrl, allowInsecure)) {
      issues.push(
        "OIDC_DISCOVERY_URL: must be https (set OIDC_ALLOW_INSECURE=true for development)",
      );
    }
  }
  if (!env.OIDC_SCOPES.split(/\s+/).includes("openid")) {
    issues.push("OIDC_SCOPES: must include openid");
  }
  return discoveryUrl;
}

function checkAnalytics(env: Env, issues: string[]): void {
  if (env.ANALYTICS_ENABLED && env.ANALYTICS_BACKEND === "umami") {
    if (
      env.ANALYTICS_ENDPOINT === undefined ||
      !URL.canParse(env.ANALYTICS_ENDPOINT)
    ) {
      issues.push("ANALYTICS_ENDPOINT: required (a URL) for the umami backend");
    }
    if (env.ANALYTICS_SITE_ID === undefined) {
      issues.push("ANALYTICS_SITE_ID: required for the umami backend");
    }
  }
}

function checkSecurityTxt(
  env: Env,
  production: boolean,
  issues: string[],
): void {
  for (const contact of env.SECURITY_TXT_CONTACT) {
    if (!/^(https:\/\/|mailto:|tel:)/.test(contact)) {
      issues.push(
        "SECURITY_TXT_CONTACT: each entry must be an https:, mailto: or tel: URI",
      );
    }
  }
  if (
    env.SECURITY_TXT_EXPIRES !== undefined &&
    !z.iso.datetime({ offset: true }).safeParse(env.SECURITY_TXT_EXPIRES)
      .success
  ) {
    issues.push("SECURITY_TXT_EXPIRES: must be an ISO 8601 date-time");
  }
  if (
    production &&
    env.SECURITY_TXT_CONTACT.length > 0 &&
    env.SECURITY_TXT_EXPIRES === undefined
  ) {
    issues.push(
      "SECURITY_TXT_EXPIRES: required in production when SECURITY_TXT_CONTACT is set (RFC 9116)",
    );
  }
}

/**
 * Validates the environment and returns the typed configuration. Empty
 * variables count as unset. Throws {@link ConfigError} listing every problem.
 */
export function loadConfig(env: Record<string, string | undefined>): BffConfig {
  const cleaned: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && value !== "") {
      cleaned[key] = value;
    }
  }
  const result = envSchema.safeParse(cleaned);
  if (!result.success) {
    throw new ConfigError(
      result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
    );
  }
  const e = result.data;
  const issues: string[] = [];
  const production = e.NODE_ENV === "production";

  if (production && e.OIDC_ALLOW_INSECURE) {
    issues.push("OIDC_ALLOW_INSECURE: refused when NODE_ENV=production");
  }
  if (e.SESSION_IDLE_SECONDS > e.SESSION_ABSOLUTE_SECONDS) {
    issues.push(
      "SESSION_IDLE_SECONDS: must not exceed SESSION_ABSOLUTE_SECONDS",
    );
  }
  if (e.SESSION_COOKIE_NAME === LOGIN_COOKIE_NAME) {
    issues.push(`SESSION_COOKIE_NAME: must differ from ${LOGIN_COOKIE_NAME}`);
  }
  const origin = publicOrigin(e.PUBLIC_ORIGIN, production, issues);
  const discoveryUrl = checkOidc(e, e.OIDC_ALLOW_INSECURE, issues);
  const upstreams = parseUpstreams(e.BFF_UPSTREAMS, issues);
  checkAnalytics(e, issues);
  checkSecurityTxt(e, production, issues);
  if (
    e.CHANGE_PASSWORD_URL !== undefined &&
    !e.CHANGE_PASSWORD_URL.startsWith("https://") &&
    !(e.OIDC_ALLOW_INSECURE && e.CHANGE_PASSWORD_URL.startsWith("http://"))
  ) {
    issues.push("CHANGE_PASSWORD_URL: must be an https URL");
  }
  if (issues.length > 0) {
    throw new ConfigError(issues);
  }

  return {
    production,
    port: e.BFF_PORT,
    host: e.BFF_HOST,
    staticDir: e.BFF_STATIC_DIR ?? null,
    publicOrigin: origin,
    trustProxy: e.BFF_TRUST_PROXY,
    oidc: {
      issuer: e.OIDC_ISSUER,
      discoveryUrl,
      clientId: e.OIDC_CLIENT_ID,
      clientSecret: e.OIDC_CLIENT_SECRET,
      scopes: e.OIDC_SCOPES.split(/\s+/).join(" "),
      allowInsecure: e.OIDC_ALLOW_INSECURE,
    },
    session: {
      storeUrl: e.SESSION_STORE_URL,
      idleSeconds: e.SESSION_IDLE_SECONDS,
      absoluteSeconds: e.SESSION_ABSOLUTE_SECONDS,
      cookieName: e.SESSION_COOKIE_NAME,
      loginTtlSeconds: 300,
      accessTokenSkewSeconds: 30,
      refreshLock: { ttlMs: 30_000, waitMs: 30_000, pollMs: 25 },
    },
    rateLimit: {
      max: e.RATE_LIMIT_MAX,
      windowSeconds: e.RATE_LIMIT_WINDOW_SECONDS,
    },
    upstreams,
    securityTxt: {
      contact: e.SECURITY_TXT_CONTACT,
      expires: e.SECURITY_TXT_EXPIRES ?? null,
      policy: e.SECURITY_TXT_POLICY ?? null,
      preferredLanguages: e.SECURITY_TXT_PREFERRED_LANGUAGES ?? null,
      canonical: e.SECURITY_TXT_CANONICAL ?? null,
    },
    changePasswordUrl: e.CHANGE_PASSWORD_URL ?? null,
    analytics: {
      enabled: e.ANALYTICS_ENABLED,
      backend: e.ANALYTICS_BACKEND,
      endpoint: e.ANALYTICS_ENDPOINT ?? null,
      siteId: e.ANALYTICS_SITE_ID ?? null,
      hostname: e.ANALYTICS_HOSTNAME ?? null,
      consent: e.ANALYTICS_CONSENT,
      respectGpc: e.ANALYTICS_RESPECT_GPC,
      geo: e.ANALYTICS_GEO,
      propKeys: e.ANALYTICS_PROP_KEYS,
    },
  };
}
