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
  opts: { revocation?: boolean } = {},
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
        grant_types: ["authorization_code", "refresh_token"],
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
    rotateRefreshToken: () => true,
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

  const delays = { revocationMs: 0, tokenMs: 0 };
  provider.use(async (ctx, next) => {
    if (ctx.path === "/token/revocation" && delays.revocationMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delays.revocationMs));
    }
    if (ctx.path === "/token" && delays.tokenMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delays.tokenMs));
    }
    await next();
  });

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
    get tokenDelayMs() {
      return delays.tokenMs;
    },
    set tokenDelayMs(value: number) {
      delays.tokenMs = value;
    },
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
