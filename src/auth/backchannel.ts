import { decodeProtectedHeader, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { BffConfig } from "../config.ts";

/** A defect of the logout token itself (as opposed to a failure to check it). */
export class LogoutTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LogoutTokenError";
  }
}

/**
 * jose error codes that mean the token is bad. Matched on `code`, which jose
 * documents as stable, rather than on `instanceof`.
 */
const TOKEN_DEFECT_CODES: ReadonlySet<string> = new Set([
  "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
  "ERR_JWT_CLAIM_VALIDATION_FAILED",
  "ERR_JWT_EXPIRED",
  "ERR_JWS_INVALID",
  "ERR_JWT_INVALID",
  "ERR_JOSE_ALG_NOT_ALLOWED",
  "ERR_JOSE_NOT_SUPPORTED",
]);

/**
 * True when verifying failed because the token is bad (the IdP gets a
 * permanent 400). Anything else, such as a JWKS timeout or non-200 answer, an
 * unknown `kid` (key rotation, or the key-set cooldown) or a network error,
 * is the BFF's inability to check it and must be retried: the caller answers
 * 503. An unknown error class counts as retryable so a logout is never lost.
 */
export function isTokenDefect(error: unknown): boolean {
  if (error instanceof LogoutTokenError) {
    return true;
  }
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && TOKEN_DEFECT_CODES.has(code);
}

const EVENT = "http://schemas.openid.net/event/backchannel-logout";

/** The claims of a verified logout token that the BFF acts on. */
export interface LogoutClaims {
  jti: string;
  sub: string | null;
  /** Which sessions to end: those of one IdP session (`sid`, preferred) or all of a subject. */
  by: "sid" | "sub";
  value: string;
}

/**
 * Verifies an OIDC Back-Channel Logout 1.0 logout token (section 2.6): a
 * `typ` of `logout+jwt` (or Keycloak's `Logout`), a valid signature from the
 * IdP's keys, `iss` equal to the configured issuer, `aud` containing this
 * client, `iat`/`exp`/`jti` present and `iat` recent, the backchannel-logout
 * event, a `sid` or `sub`, and no `nonce`. Rejects with an error otherwise.
 */
export async function verifyLogoutToken(
  token: string,
  config: BffConfig,
  keys: JWTVerifyGetKey,
): Promise<LogoutClaims> {
  // The JOSE `typ` marks the JWT as a logout token, so an ID token cannot be replayed here
  // (OIDC Back-Channel Logout 1.0 section 2.4; ASVS 10.5.5). Keycloak sends "Logout".
  let typ: string | undefined;
  try {
    typ = decodeProtectedHeader(token).typ?.toLowerCase();
  } catch {
    throw new LogoutTokenError("logout token is not a JWT");
  }
  if (typ !== "logout+jwt" && typ !== "logout") {
    throw new LogoutTokenError("logout token has the wrong typ");
  }
  const { payload } = await jwtVerify(token, keys, {
    issuer: config.oidc.issuer,
    audience: config.oidc.clientId,
    algorithms: [
      "RS256",
      "RS384",
      "RS512",
      "PS256",
      "PS384",
      "PS512",
      "ES256",
      "ES384",
      "ES512",
      "EdDSA",
    ],
    requiredClaims: ["iat", "exp", "jti"],
    maxTokenAge: "2 minutes",
    clockTolerance: 30,
  });
  const events = payload["events"];
  if (typeof events !== "object" || events === null || !(EVENT in events)) {
    throw new LogoutTokenError(
      "logout token lacks the backchannel-logout event",
    );
  }
  if ("nonce" in payload) {
    throw new LogoutTokenError("logout token must not contain a nonce");
  }
  const sid = payload["sid"];
  const sub = typeof payload.sub === "string" ? payload.sub : null;
  const jti = String(payload.jti);
  if (typeof sid === "string") {
    return { jti, sub, by: "sid", value: sid };
  }
  if (sub === null) {
    throw new LogoutTokenError("logout token has neither sid nor sub");
  }
  return { jti, sub, by: "sub", value: sub };
}
