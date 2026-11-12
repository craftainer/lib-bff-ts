import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
} from "jose";
import Provider from "oidc-provider";

/** The origin the BFF pretends to be served from in tests (nothing listens there). */
export const PUBLIC_ORIGIN = "http://localhost:8080";
export const CLIENT_ID = "bff";
export const CLIENT_SECRET = "test-client-secret";
export const TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
export const SCOPES = "openid profile email roles offline_access";

/** An in-process `oidc-provider` standing in for Keycloak. */
export interface TestIdp {
  issuer: string;
  provider: Provider;
  /** Signs a logout token (or any JWT) with the IdP's real key unless another key is given. */
  sign(
    payload: Record<string, unknown>,
    opts?: { key?: CryptoKey; kid?: string; typ?: string | null },
  ): Promise<string>;
  /** Milliseconds the token revocation endpoint stalls before answering (0 = none). */
  revocationDelayMs: number;
  /** Milliseconds the token endpoint stalls before answering (0 = none). */
  tokenDelayMs: number;
  /** When set, the token endpoint adds this `refresh_expires_in` to its responses. */
  refreshExpiresIn: number | undefined;
  /** What `/jwks` does: stall for `delayMs`, and/or answer `status` instead of the key set. */
  jwks: { delayMs: number; status: number | undefined };
  /**
   * The RFC 8693 token-exchange grant, which `oidc-provider` lacks and the
   * test IdP adds with `registerGrantType`. Issues an opaque access token that
   * differs from the subject token. Set `fail` to an OAuth error code to
   * answer with it, `issuedTokenType`/`tokenType` to answer oddly, `echo` to
   * hand the subject token back, `expiresIn` (null omits it), `delayMs` to
   * stall. `calls` records the request parameters of every exchange.
   */
  exchange: {
    calls: Record<string, string | undefined>[];
    fail: string | undefined;
    echo: boolean;
    expiresIn: number | null;
    delayMs: number;
    issuedTokenType: string | undefined;
    tokenType: string;
    /** Answer 200 with this raw (non-JSON) body. */
    raw: string | undefined;
    /** Issue a signed JWT with this `aud` (omitted when `undefined`) instead of an opaque token. */
    jwt: { aud: string | string[] | undefined } | undefined;
  };
  /** A foreign key pair for bad-signature tests. */
  otherKey: CryptoKey;
  close(): Promise<void>;
}

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

/** Starts the test IdP: code flow with PKCE, refresh rotation, no consent screen. */
export async function startIdp(
  opts: { revocation?: boolean; rotate?: boolean } = {},
): Promise<TestIdp> {
  const port = await freePort();
  const issuer = `http://localhost:${port}`;
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk: JWK = {
    ...(await exportJWK(privateKey)),
    kid: "test-key",
    alg: "RS256",
    use: "sig",
  };
  const other = await generateKeyPair("RS256");

  const provider = new Provider(issuer, {
    clients: [
      {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uris: [`${PUBLIC_ORIGIN}/bff/callback`],
        post_logout_redirect_uris: [`${PUBLIC_ORIGIN}/`],
        grant_types: ["authorization_code", "refresh_token", TOKEN_EXCHANGE],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
        backchannel_logout_uri: `${PUBLIC_ORIGIN}/bff/backchannel-logout`,
        backchannel_logout_session_required: true,
      },
    ],
    jwks: { keys: [jwk as never] },
    cookies: { keys: ["test-cookie-key"] },
    pkce: { required: () => true },
    features: {
      backchannelLogout: { enabled: true },
      revocation: { enabled: opts.revocation ?? true },
    },
    conformIdTokenClaims: false,
    ttl: {
      AccessToken: 300,
      AuthorizationCode: 60,
      IdToken: 300,
      RefreshToken: 3600,
      Interaction: 600,
      Grant: 3600,
      Session: 3600,
    },
    claims: {
      openid: ["sub", "sid"],
      profile: ["name", "preferred_username"],
      email: ["email"],
      roles: ["realm_access", "resource_access"],
    },
    issueRefreshToken: async () => true,
    rotateRefreshToken: () => opts.rotate ?? true,
    findAccount: async (_ctx, sub) => ({
      accountId: sub,
      claims: async () => ({
        sub,
        name: `User ${sub}`,
        preferred_username: sub,
        ...(sub === "noemail" ? {} : { email: `${sub}@example.com` }),
        realm_access: { roles: ["user"] },
        resource_access: {
          [CLIENT_ID]: { roles: ["editor"] },
          ...(sub === "reserved" ? { realm: { roles: ["evil"] } } : {}),
        },
      }),
    }),
    loadExistingGrant: async (ctx) => {
      const grant = new ctx.oidc.provider.Grant({
        clientId: ctx.oidc.client?.clientId as string,
        accountId: ctx.oidc.session?.accountId as string,
      });
      grant.addOIDCScope(SCOPES);
      await grant.save();
      return grant;
    },
  });

  const delays = {
    revocationMs: 0,
    tokenMs: 0,
    refreshExpiresIn: undefined as number | undefined,
    jwks: { delayMs: 0, status: undefined as number | undefined },
  };
  provider.use(async (ctx, next) => {
    if (ctx.path === "/token/revocation" && delays.revocationMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delays.revocationMs));
    }
    if (ctx.path === "/token" && delays.tokenMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delays.tokenMs));
    }
    if (ctx.path === "/jwks") {
      if (delays.jwks.delayMs > 0) {
        await new Promise((resolve) =>
          setTimeout(resolve, delays.jwks.delayMs),
        );
      }
      if (delays.jwks.status !== undefined) {
        ctx.status = delays.jwks.status;
        ctx.body = { error: "jwks unavailable" };
        return;
      }
    }
    await next();
    if (
      ctx.path === "/token" &&
      delays.refreshExpiresIn !== undefined &&
      typeof ctx.body === "object"
    ) {
      (ctx.body as Record<string, unknown>)["refresh_expires_in"] =
        delays.refreshExpiresIn;
    }
  });

  const exchange: TestIdp["exchange"] = {
    calls: [],
    fail: undefined,
    echo: false,
    expiresIn: 300,
    delayMs: 0,
    issuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    tokenType: "Bearer",
    raw: undefined,
    jwt: undefined,
  };
  provider.registerGrantType(
    TOKEN_EXCHANGE,
    async (ctx) => {
      const params = ctx.oidc.params as Record<string, string | undefined>;
      exchange.calls.push({
        client: ctx.oidc.client?.clientId,
        subject_token: params["subject_token"],
        subject_token_type: params["subject_token_type"],
        requested_token_type: params["requested_token_type"],
        audience: params["audience"],
        scope: params["scope"],
        auth: ctx.get("authorization") === "" ? "post" : "basic",
      });
      if (exchange.delayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, exchange.delayMs));
      }
      if (exchange.fail !== undefined) {
        ctx.status = 400;
        ctx.body = { error: exchange.fail };
        return;
      }
      const { AccessToken } = ctx.oidc.provider;
      const subject = await AccessToken.find(params["subject_token"] as string);
      if (subject === undefined) {
        ctx.status = 400;
        ctx.body = { error: "invalid_request" };
        return;
      }
      const token = new AccessToken({
        accountId: subject.accountId,
        client: ctx.oidc.client as never,
        grantId: subject.grantId,
        gty: TOKEN_EXCHANGE,
        scope: subject.scope,
      });
      if (exchange.raw !== undefined) {
        ctx.status = 200;
        ctx.type = "text/plain";
        ctx.body = exchange.raw;
        return;
      }
      const value = exchange.echo
        ? (params["subject_token"] as string)
        : exchange.jwt !== undefined
          ? await new SignJWT({
              sub: subject.accountId,
              ...(exchange.jwt.aud === undefined
                ? {}
                : { aud: exchange.jwt.aud }),
            })
              .setProtectedHeader({ alg: "RS256", kid: "test-key" })
              .sign(privateKey)
          : await token.save();
      ctx.body = {
        access_token: value,
        token_type: exchange.tokenType,
        ...(exchange.issuedTokenType === undefined
          ? {}
          : { issued_token_type: exchange.issuedTokenType }),
        ...(exchange.expiresIn === null
          ? {}
          : { expires_in: exchange.expiresIn }),
      };
    },
    ["subject_token", "subject_token_type", "requested_token_type", "audience"],
  );

  const server: Server = provider.listen(port, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));

  return {
    issuer,
    provider,
    get revocationDelayMs() {
      return delays.revocationMs;
    },
    set revocationDelayMs(value: number) {
      delays.revocationMs = value;
    },
    jwks: delays.jwks,
    get refreshExpiresIn() {
      return delays.refreshExpiresIn;
    },
    set refreshExpiresIn(value: number | undefined) {
      delays.refreshExpiresIn = value;
    },
    get tokenDelayMs() {
      return delays.tokenMs;
    },
    set tokenDelayMs(value: number) {
      delays.tokenMs = value;
    },
    exchange,
    otherKey: other.privateKey,
    async sign(payload, opts = {}) {
      return new SignJWT(payload)
        .setProtectedHeader({
          alg: "RS256",
          kid: opts.kid ?? "test-key",
          ...(opts.typ === null ? {} : { typ: opts.typ ?? "logout+jwt" }),
        })
        .sign(opts.key ?? privateKey);
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
