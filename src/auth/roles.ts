import { decodeJwt } from "jose";
import { z } from "zod";

const rolesSchema = z
  .object({
    realm_access: z.object({ roles: z.array(z.string()) }).optional(),
    resource_access: z.record(z.string(), z.object({ roles: z.array(z.string()) })).optional(),
  })
  .catch({});

function fromClaims(claims: Record<string, unknown>): Record<string, string[]> {
  const parsed = rolesSchema.parse(claims);
  const roles: Record<string, string[]> = {};
  if (parsed.realm_access !== undefined) {
    roles["realm"] = parsed.realm_access.roles;
  }
  for (const [clientId, access] of Object.entries(parsed.resource_access ?? {})) {
    roles[clientId] = access.roles;
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
export function extractRoles(idTokenClaims: Record<string, unknown>, accessToken: string): Record<string, string[]> {
  const merged: Record<string, string[]> = {};
  for (const source of [fromClaims(claimsOf(accessToken)), fromClaims(idTokenClaims)]) {
    for (const [key, roles] of Object.entries(source)) {
      merged[key] = [...new Set([...(merged[key] ?? []), ...roles])];
    }
  }
  return merged;
}
