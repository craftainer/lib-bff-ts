import rateLimit from "@fastify/rate-limit";
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import * as client from "openid-client";
import { z } from "zod";
import { LOGIN_COOKIE_NAME, type BffConfig } from "../config.ts";
import { pathOf, securityLog } from "../log.ts";
import {
  absoluteExpiry,
  applyTokens,
  clearSessionCookie,
  nowSeconds,
  sessionTtlSeconds,
  setSessionCookie,
} from "../session.ts";
import { isTokenDefect, verifyLogoutToken } from "./backchannel.ts";
import { revokeRefreshToken } from "./oidc.ts";
import { profileOf } from "./claims.ts";
import { extractRoles } from "./roles.ts";
import { safeReturnTo } from "./return-to.ts";
import { randomId } from "./store.ts";

const logoutBodySchema = z.object({ logout_token: z.string().min(1) });

function loginCookie(): {
  path: string;
  httpOnly: true;
  secure: true;
  sameSite: "lax";
} {
  return { path: "/", httpOnly: true, secure: true, sameSite: "lax" };
}

/**
 * The OIDC flows and the SPA-facing session endpoints:
 * `GET /bff/login`, `GET /bff/callback`, `POST /bff/logout`,
 * `GET /bff/user`, `GET /bff/config` and `POST /bff/backchannel-logout`.
 */
const auth: FastifyPluginAsync<BffConfig> = async (app, config) => {
  const redirectUri = `${config.publicOrigin}/bff/callback`;
  const limit = {
    max: config.rateLimit.max,
    timeWindow: config.rateLimit.windowSeconds * 1000,
  };

  await app.register(rateLimit, {
    global: false,
    onExceeded: (request: FastifyRequest) => {
      securityLog(request.log, "rate_limited", {
        path: pathOf(request.url),
        ip: request.ip,
      });
    },
  });

  app.addHook("onRequest", async (request, reply) => {
    if (pathOf(request.url).startsWith("/bff/")) {
      void reply.header("Cache-Control", "no-store");
    }
  });

  function unavailable(
    request: FastifyRequest,
    reply: FastifyReply,
    error: unknown,
  ): FastifyReply {
    request.log.error({ err: error }, "IdP unavailable");
    return reply.code(503).send({ error: "idp_unavailable" });
  }

  /** Best-effort revocation on an explicit logout; a failure is logged, never thrown. */
  async function revoke(
    request: FastifyRequest,
    configuration: client.Configuration,
    refreshToken: string,
    sub: string,
  ): Promise<void> {
    const failure = await revokeRefreshToken(configuration, refreshToken);
    if (failure !== undefined) {
      securityLog(request.log, "token_revocation_failed", {
        sub,
        reason: failure.name,
      });
    }
  }

  app.get(
    "/bff/login",
    { config: { rateLimit: limit } },
    async (request, reply) => {
      let configuration: client.Configuration;
      try {
        configuration = await app.bffOidc.configuration();
      } catch (error) {
        return unavailable(request, reply, error);
      }
      const query = request.query as Record<string, unknown>;
      const state = client.randomState();
      const nonce = client.randomNonce();
      const codeVerifier = client.randomPKCECodeVerifier();
      await app.bffStore.putTransaction(
        state,
        {
          nonce,
          codeVerifier,
          returnTo: safeReturnTo(query["returnTo"], config.publicOrigin),
        },
        config.session.loginTtlSeconds,
      );
      const url = client.buildAuthorizationUrl(configuration, {
        redirect_uri: redirectUri,
        scope: config.oidc.scopes,
        state,
        nonce,
        code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
        code_challenge_method: "S256",
      });
      void reply.setCookie(LOGIN_COOKIE_NAME, state, {
        ...loginCookie(),
        maxAge: config.session.loginTtlSeconds,
      });
      securityLog(request.log, "login_started", { ip: request.ip });
      return reply.redirect(url.href);
    },
  );

  app.get(
    "/bff/callback",
    { config: { rateLimit: limit } },
    async (request, reply) => {
      const query = request.query as Record<string, unknown>;
      const cookieState = request.cookies[LOGIN_COOKIE_NAME];
      void reply.clearCookie(LOGIN_COOKIE_NAME, loginCookie());
      const fail = (reason: string): FastifyReply => {
        securityLog(request.log, "login_failed", { reason, ip: request.ip });
        return reply.code(400).send({ error: "login_failed" });
      };

      // The cookie only carries the transaction ID, which must equal `state`.
      if (cookieState === undefined || query["state"] !== cookieState) {
        return fail("state does not match the login cookie");
      }
      const transaction = await app.bffStore.takeTransaction(cookieState);
      if (transaction === undefined) {
        return fail("unknown or expired login transaction");
      }

      let tokens: client.TokenEndpointResponse &
        client.TokenEndpointResponseHelpers;
      try {
        const configuration = await app.bffOidc.configuration();
        tokens = await client.authorizationCodeGrant(
          configuration,
          new URL(request.url, config.publicOrigin),
          {
            pkceCodeVerifier: transaction.codeVerifier,
            expectedNonce: transaction.nonce,
            expectedState: cookieState,
            idTokenExpected: true,
          },
        );
      } catch (error) {
        return fail((error as Error).name);
      }

      const claims = tokens.claims() as client.IDToken;
      const now = nowSeconds();
      const data = applyTokens(
        {
          ...profileOf(claims),
          roles: extractRoles(claims, tokens.access_token, (clientId) => {
            request.log.warn(
              { clientId: clientId.slice(0, 64) },
              "ignored a reserved client ID in the roles claims",
            );
          }),
          idToken: "",
          accessToken: "",
          refreshToken: null,
          accessExpiresAt: 0,
          createdAt: now,
          version: 0,
          absoluteExpiresAt: absoluteExpiry(
            config,
            now,
            tokens["refresh_expires_in"],
          ),
        },
        tokens,
        now,
      );

      // Session fixation: a fresh ID at every login; any previous session ends.
      if (request.bffSession !== null) {
        await app.bffStore.destroy(request.bffSession.id);
      }
      const id = randomId();
      await app.bffStore.put(id, data, sessionTtlSeconds(config, data, now));
      setSessionCookie(reply, config, id);
      securityLog(request.log, "login_success", {
        sub: data.sub,
        ip: request.ip,
      });
      return reply.redirect(transaction.returnTo);
    },
  );

  app.post("/bff/logout", async (request, reply) => {
    const session = request.bffSession;
    if (session === null) {
      return reply.code(401).send({ error: "unauthenticated" });
    }
    const { sub, idToken } = session.data;
    // Revoke the refresh token stored at the instant of the logout, not the
    // one in this request's snapshot (a concurrent refresh may have rotated it).
    const taken = await app.bffStore.take(session.id);
    const refreshToken = taken?.refreshToken ?? null;
    clearSessionCookie(reply, config);
    securityLog(request.log, "logout", { sub, ip: request.ip });
    let logoutUrl = `${config.publicOrigin}/`;
    let configuration: client.Configuration | undefined;
    try {
      configuration = await app.bffOidc.configuration();
      logoutUrl = client.buildEndSessionUrl(configuration, {
        id_token_hint: idToken,
        post_logout_redirect_uri: logoutUrl,
      }).href;
    } catch (error) {
      request.log.warn({ err: error }, "no IdP logout URL");
    }
    if (configuration !== undefined && refreshToken !== null) {
      await revoke(request, configuration, refreshToken, sub);
    }
    return reply.send({ logoutUrl });
  });

  app.get("/bff/user", async (request, reply) => {
    const session = request.bffSession;
    if (session === null) {
      return reply.code(401).send({ error: "unauthenticated" });
    }
    const { sub, name, email, roles, absoluteExpiresAt } = session.data;
    return reply.send({
      sub,
      name,
      ...(email === null ? {} : { email }),
      roles,
      expiresAt: absoluteExpiresAt,
    });
  });

  app.get("/bff/config", async () => ({
    analytics: {
      enabled: config.analytics.enabled,
      consent: config.analytics.consent,
      respectGpc: config.analytics.respectGpc,
    },
    upstreams: Object.keys(config.upstreams),
  }));

  // No rate limit here on purpose: the IdP is the caller and throttling would
  // drop real logouts; the signed logout token authenticates the request.
  app.post(
    "/bff/backchannel-logout",
    { bodyLimit: 16 * 1024 },
    async (request, reply) => {
      const reject = (reason: string): FastifyReply => {
        securityLog(request.log, "backchannel_logout_rejected", {
          reason,
          ip: request.ip,
        });
        return reply.code(400).send({ error: "invalid_request" });
      };
      const body = logoutBodySchema.safeParse(request.body);
      if (!body.success) {
        return reject("missing logout_token");
      }
      // Not the token's fault: the IdP must see a 5xx and retry later.
      let keys: Awaited<ReturnType<typeof app.bffOidc.jwks>>;
      try {
        keys = await app.bffOidc.jwks();
      } catch (error) {
        return unavailable(request, reply, error);
      }
      let logout: Awaited<ReturnType<typeof verifyLogoutToken>>;
      try {
        logout = await verifyLogoutToken(body.data.logout_token, config, keys);
      } catch (error) {
        // A bad token is final (400); failing to check one is retryable (503).
        return isTokenDefect(error)
          ? reject((error as Error).name)
          : unavailable(request, reply, error);
      }
      if (!(await app.bffStore.claimOnce(`jti:${logout.jti}`, 600))) {
        return reject("logout token replayed");
      }
      let ended: number;
      try {
        ended =
          logout.by === "sid"
            ? await app.bffStore.destroyBySid(logout.value)
            : await app.bffStore.destroyBySub(logout.value);
      } catch (error) {
        // Let the IdP's retry of the same token through instead of a replay rejection.
        await app.bffStore.releaseClaim(`jti:${logout.jti}`);
        throw error;
      }
      securityLog(request.log, "backchannel_logout", {
        sub: logout.sub,
        sessions: ended,
      });
      return reply.send();
    },
  );
};

/** Login, callback, logout, user, config and back-channel logout. Register after `session` and `@fastify/formbody`. */
const plugin: FastifyPluginAsync<BffConfig> = fp(auth, {
  name: "bff-auth",
  dependencies: ["bff-session"],
});
export default plugin;
