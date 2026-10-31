import cookie from "@fastify/cookie";
import type { FastifyPluginAsync, FastifyReply } from "fastify";
import fp from "fastify-plugin";
import * as client from "openid-client";
import { setTimeout as sleep } from "node:timers/promises";
import type { BffConfig } from "./config.ts";
import { isAnomalousTarget, pathOf, securityLog } from "./log.ts";
import {
  createOidcClient,
  revokeRefreshToken,
  type OidcClient,
} from "./auth/oidc.ts";
import {
  createValkeySessionStore,
  type LoginTransaction,
  type SessionData,
  type SessionStore,
} from "./auth/store.ts";

export type { LoginTransaction, SessionData, SessionStore };
export { createMemorySessionStore, KvSessionStore } from "./auth/store.ts";
export { MemoryKv, type KvClient } from "./auth/kv.ts";

/** The session of the current request, available as `request.bffSession`. */
export interface BffSession {
  /** The opaque session ID (the cookie value). Never log it. */
  readonly id: string;
  /** A snapshot of the session; refreshed by `accessTokenFor`. */
  readonly data: SessionData;
  /**
   * Returns an access token for the named upstream, refreshing it first when
   * it is about to expire. When the refresh fails the session is destroyed
   * and this rejects with a 401 error.
   */
  accessTokenFor(upstream: string): Promise<string>;
}

declare module "fastify" {
  interface FastifyRequest {
    /** The authenticated session, or null. Set by the `session` plugin. */
    bffSession: BffSession | null;
  }
  interface FastifyInstance {
    /** The session store, shared by the `session`, `auth` and `health` plugins. */
    bffStore: SessionStore;
    /** Lazy access to the IdP. */
    bffOidc: OidcClient;
  }
}

/** An error that maps to an HTTP status and a machine-readable code. */
export class BffHttpError extends Error {
  readonly statusCode: number;
  readonly code: string;

  constructor(statusCode: number, code: string) {
    super(code);
    this.name = "BffHttpError";
    this.statusCode = statusCode;
    this.code = code;
  }
}

/** Current time in epoch seconds. */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** How long the store should keep a session: the idle timeout, never past the absolute one. */
export function sessionTtlSeconds(
  config: BffConfig,
  data: SessionData,
  now: number,
): number {
  return Math.max(
    1,
    Math.floor(
      Math.min(config.session.idleSeconds, data.absoluteExpiresAt - now),
    ),
  );
}

/** The token-endpoint fields the session cares about. */
export type TokenFields = Pick<
  client.TokenEndpointResponse,
  "access_token" | "refresh_token" | "id_token" | "expires_in"
>;

/** Returns the session with refreshed tokens; absent refresh/ID tokens keep their old values. */
export function applyTokens(
  data: SessionData,
  tokens: TokenFields,
  now: number,
): SessionData {
  return {
    ...data,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token ?? data.refreshToken,
    idToken: tokens.id_token ?? data.idToken,
    accessExpiresAt: now + (tokens.expires_in ?? 60),
  };
}

/**
 * The absolute session expiry: the configured maximum, but no later than the
 * refresh token's lifetime when the IdP reports one (RFC 10017 6.1.2.2).
 */
export function absoluteExpiry(
  config: BffConfig,
  now: number,
  refreshExpiresIn: unknown,
): number {
  const max = now + config.session.absoluteSeconds;
  return typeof refreshExpiresIn === "number" && refreshExpiresIn > 0
    ? Math.min(max, now + Math.max(1, Math.floor(refreshExpiresIn)))
    : max;
}

function cookieAttributes(sameSite: "strict" | "lax"): {
  path: string;
  httpOnly: true;
  secure: true;
  sameSite: "strict" | "lax";
} {
  return { path: "/", httpOnly: true, secure: true, sameSite };
}

/** Sets the session cookie: `Secure; HttpOnly; SameSite=Strict; Path=/`, no `Domain`, session-scoped. */
export function setSessionCookie(
  reply: FastifyReply,
  config: BffConfig,
  id: string,
): void {
  void reply.setCookie(
    config.session.cookieName,
    id,
    cookieAttributes("strict"),
  );
}

export function clearSessionCookie(
  reply: FastifyReply,
  config: BffConfig,
): void {
  void reply.clearCookie(config.session.cookieName, cookieAttributes("strict"));
}

function createSession(
  app: { bffStore: SessionStore; bffOidc: OidcClient },
  config: BffConfig,
  id: string,
  initial: SessionData,
  log: Parameters<typeof securityLog>[0],
): BffSession {
  const store = app.bffStore;
  let data = initial;
  const fresh = (d: SessionData): boolean =>
    d.accessExpiresAt - nowSeconds() > config.session.accessTokenSkewSeconds;

  async function fail(d: SessionData): Promise<never> {
    await store.destroy(id);
    securityLog(log, "refresh_failed", { sub: d.sub });
    throw new BffHttpError(401, "session_expired");
  }

  /**
   * Revokes a refresh token that was issued but can no longer be stored. It
   * must never throw: the caller is already on a failure path.
   */
  async function revokeOrphan(d: SessionData, token: string): Promise<void> {
    let failure: Error | undefined;
    try {
      failure = await revokeRefreshToken(
        await app.bffOidc.configuration(),
        token,
      );
    } catch (error) {
      failure = error as Error;
    }
    if (failure !== undefined) {
      securityLog(log, "token_revocation_failed", {
        sub: d.sub,
        reason: failure.name,
      });
    }
  }

  /** The session as another request left it, or a 401 when it is gone. */
  async function reread(): Promise<SessionData> {
    const latest = await store.get(id);
    if (latest === undefined) {
      throw new BffHttpError(401, "session_expired");
    }
    return latest;
  }

  async function refresh(d: SessionData): Promise<SessionData> {
    if (d.refreshToken === null || nowSeconds() >= d.absoluteExpiresAt) {
      return fail(d);
    }
    let tokens: client.TokenEndpointResponse;
    try {
      tokens = await client.refreshTokenGrant(
        await app.bffOidc.configuration(),
        d.refreshToken,
      );
    } catch (error) {
      // Only a definitive rejection of the refresh token ends the session.
      if (
        error instanceof client.ResponseBodyError &&
        error.error === "invalid_grant"
      ) {
        // Rotation: a request that outran the lock holder may have used the
        // token already. If the session moved on, that is its result.
        const latest = await store.get(id);
        return latest !== undefined && latest.version !== d.version
          ? latest
          : fail(d);
      }
      log.error({ err: error }, "token refresh unavailable");
      throw new BffHttpError(503, "idp_unavailable");
    }
    const now = nowSeconds();
    const next = applyTokens(d, tokens, now);
    // A new refresh lifetime can only shorten the absolute limit.
    next.absoluteExpiresAt = Math.min(
      d.absoluteExpiresAt,
      absoluteExpiry(config, now, tokens["refresh_expires_in"]),
    );
    // Fenced write: lands only if nobody refreshed or logged out meanwhile.
    if (
      await store.replace(
        id,
        next,
        sessionTtlSeconds(config, next, now) * 1000,
        d.version,
      )
    ) {
      return { ...next, version: d.version + 1 };
    }
    // Lost the race. The tokens just issued are orphans: when the IdP rotated
    // the refresh token, nobody holds the new one, so revoke it (a token that
    // was not rotated is the winner's and stays).
    if (
      tokens.refresh_token !== undefined &&
      tokens.refresh_token !== d.refreshToken
    ) {
      await revokeOrphan(d, tokens.refresh_token);
    }
    return reread();
  }

  async function current(): Promise<SessionData> {
    if (fresh(data)) {
      return data;
    }
    const { ttlMs, waitMs, pollMs } = config.session.refreshLock;
    const deadline = Date.now() + waitMs;
    for (;;) {
      const token = await store.acquireLock(id, ttlMs);
      if (token !== undefined) {
        try {
          const latest = await reread();
          return fresh(latest) ? latest : await refresh(latest);
        } finally {
          // A failed release must not mask the real outcome; the lock expires.
          await store.releaseLock(id, token).catch((error: unknown) => {
            log.error({ err: error }, "refresh lock release failed");
          });
        }
      }
      // Another request is refreshing this session: wait for its result.
      await sleep(pollMs);
      const latest = await reread();
      if (fresh(latest)) {
        return latest;
      }
      if (Date.now() >= deadline) {
        throw new BffHttpError(503, "refresh_in_progress");
      }
    }
  }

  return {
    id,
    get data(): SessionData {
      return data;
    },
    async accessTokenFor(upstream: string): Promise<string> {
      // Own properties only: `constructor` and friends are not upstreams.
      const target = Object.hasOwn(config.upstreams, upstream)
        ? config.upstreams[upstream]
        : undefined;
      if (target === undefined) {
        throw new Error(`unknown upstream: ${upstream}`);
      }
      if (target.tokenExchange) {
        throw new Error(
          "per-upstream token exchange (RFC 8693) is not implemented",
        );
      }
      data = await current();
      return data.accessToken;
    },
  };
}

/** What `randomId()` produces: 256 random bits, base64url. */
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/;

function needsSession(url: string): boolean {
  const path = pathOf(url);
  return (
    isAnomalousTarget(url) ||
    path.startsWith("/bff/") ||
    path === "/api" ||
    path.startsWith("/api/")
  );
}

const session: FastifyPluginAsync<BffConfig> = async (app, config) => {
  await app.register(cookie);

  const owned = !app.hasDecorator("bffStore");
  if (owned) {
    app.decorate(
      "bffStore",
      createValkeySessionStore(
        config.session.storeUrl,
        config.session.absoluteSeconds,
      ),
    );
  }
  app.decorate("bffOidc", createOidcClient(config));
  app.decorateRequest("bffSession", null);

  app.addHook("onClose", async () => {
    if (owned) {
      await app.bffStore.close();
    }
  });

  app.addHook("onRequest", async (request, reply) => {
    const id = request.cookies[config.session.cookieName];
    if (id === undefined || !needsSession(request.url)) {
      return;
    }
    // Not an ID we issued: never let it reach a store key; drop the cookie.
    if (!SESSION_ID.test(id)) {
      clearSessionCookie(reply, config);
      return;
    }
    const data = await app.bffStore.get(id);
    if (data === undefined) {
      clearSessionCookie(reply, config);
      return;
    }
    const now = nowSeconds();
    if (data.absoluteExpiresAt <= now) {
      await app.bffStore.destroy(id);
      clearSessionCookie(reply, config);
      return;
    }
    await app.bffStore.touch(id, sessionTtlSeconds(config, data, now));
    request.bffSession = createSession(app, config, id, data, request.log);
  });
};

/** Session handling: store, session cookie, `request.bffSession`, token refresh. */
const plugin: FastifyPluginAsync<BffConfig> = fp(session, {
  name: "bff-session",
});
export default plugin;
