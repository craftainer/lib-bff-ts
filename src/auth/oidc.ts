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
        timeout: 10,
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
      keys ??= createRemoteJWKSet(new URL(String(metadata.jwks_uri)));
      return keys;
    },
  };
}
