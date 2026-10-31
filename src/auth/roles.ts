import { decodeJwt } from "jose";
import { z } from "zod";

const rolesSchema = z
  .object({
    realm_access: z.object({ roles: z.array(z.string()) }).optional(),
    resource_access: z
      .record(z.string(), z.object({ roles: z.array(z.string()) }))
      .optional(),
  })
  .catch({});

/** Client IDs that must never become role keys: `realm` is the realm-roles key, `__proto__` is unsafe. */
const RESERVED_KEYS: ReadonlySet<string> = new Set(["realm", "__proto__"]);

function fromClaims(
  claims: Record<string, unknown>,
  onSkipped: (clientId: string) => void,
): Map<string, string[]> {
  const parsed = rolesSchema.parse(claims);
  const roles = new Map<string, string[]>();
  if (parsed.realm_access !== undefined) {
    roles.set("realm", parsed.realm_access.roles);
  }
  for (const [clientId, access] of Object.entries(
    parsed.resource_access ?? {},
  )) {
    if (RESERVED_KEYS.has(clientId)) {
      onSkipped(clientId);
    } else {
      roles.set(clientId, access.roles);
    }
  }
  return roles;
}

function claimsOf(token: string): Record<string, unknown> {
  try {
    return decodeJwt(token);
  } catch {
    return {};
  }
}

/**
 * Collects roles for the UI from Keycloak-style claims, keyed `realm` for
 * realm roles and by client ID for client roles. The access token is only
 * decoded, not verified: the BFF received it straight from the token
 * endpoint. Roles are a UI hint; authorization stays in the upstreams.
 * An opaque access token or malformed claims yield no roles from that source.
 */
export function extractRoles(
  idTokenClaims: Record<string, unknown>,
  accessToken: string,
  onSkipped: (clientId: string) => void = () => undefined,
): Record<string, string[]> {
  const merged = new Map<string, string[]>();
  for (const source of [
    fromClaims(claimsOf(accessToken), onSkipped),
    fromClaims(idTokenClaims, onSkipped),
  ]) {
    for (const [key, roles] of source) {
      merged.set(key, [...new Set([...(merged.get(key) ?? []), ...roles])]);
    }
  }
  // No prototype: a role key can never collide with Object.prototype members.
  const result: Record<string, string[]> = Object.create(null) as Record<
    string,
    string[]
  >;
  for (const [key, roles] of merged) {
    result[key] = roles;
  }
  return result;
}
