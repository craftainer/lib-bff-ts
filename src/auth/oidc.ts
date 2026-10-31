import * as client from "openid-client";
import { createRemoteJWKSet, type JWTVerifyGetKey } from "jose";
import type { BffConfig } from "../config.ts";

/** Lazy access to the IdP: discovery runs on first use, not at startup. */
export interface OidcClient {
  /** Discovers (once, retrying after a failure) and returns the client configuration. */
  configuration(): Promise<client.Configuration>;
  /** The IdP's signing keys (for back-channel logout tokens). */
  jwks(): Promise<JWTVerifyGetKey>;
}

/**
 * Creates the lazy OIDC client. `OIDC_ISSUER` is the expected `iss`:
 * discovery uses the full discovery URL (so the host the BFF reaches can
 * differ from the public issuer), and the document's `issuer` must equal
 * the configured one.
 */
export function createOidcClient(config: BffConfig): OidcClient {
  let pending: Promise<client.Configuration> | undefined;
  let keys: JWTVerifyGetKey | undefined;

  async function discover(): Promise<client.Configuration> {
    const configuration = await client.discovery(
      new URL(config.oidc.discoveryUrl),
      config.oidc.clientId,
      config.oidc.clientSecret,
      undefined,
      {
        timeout: config.oidc.timeoutSeconds,
        ...(config.oidc.allowInsecure
          ? { execute: [client.allowInsecureRequests] }
          : {}),
      },
    );
    if (configuration.serverMetadata().issuer !== config.oidc.issuer) {
      throw new Error(
        "IdP discovery document issuer does not match OIDC_ISSUER",
      );
    }
    return configuration;
  }

  return {
    configuration(): Promise<client.Configuration> {
      pending ??= discover().catch((error: unknown) => {
        pending = undefined;
        throw error;
      });
      return pending;
    },
    async jwks(): Promise<JWTVerifyGetKey> {
      const metadata = (await this.configuration()).serverMetadata();
      keys ??= createRemoteJWKSet(new URL(String(metadata.jwks_uri)), {
        timeoutDuration: config.oidc.timeoutSeconds * 1000,
      });
      return keys;
    },
  };
}

/** The longest a logout waits for the IdP to revoke a token. */
export const REVOCATION_TIMEOUT_MS = 2000;

/**
 * Best-effort RFC 7009 revocation of a refresh token. Does nothing when the
 * IdP advertises no `revocation_endpoint`. Waits at most
 * {@link REVOCATION_TIMEOUT_MS}; resolves to the error on failure, never
 * rejects, so callers log it and carry on.
 */
export async function revokeRefreshToken(
  configuration: client.Configuration,
  refreshToken: string,
): Promise<Error | undefined> {
  if (configuration.serverMetadata().revocation_endpoint === undefined) {
    return undefined;
  }
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      client.tokenRevocation(configuration, refreshToken, {
        token_type_hint: "refresh_token",
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error("revocation timed out"));
        }, REVOCATION_TIMEOUT_MS);
      }),
    ]);
    return undefined;
  } catch (error) {
    return error as Error;
  } finally {
    clearTimeout(timer);
  }
}
