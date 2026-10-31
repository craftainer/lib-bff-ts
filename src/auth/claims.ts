/** Returns a claim if it is a non-empty string. */
export function stringClaim(
  claims: Record<string, unknown>,
  name: string,
): string | null {
  const value = claims[name];
  return typeof value === "string" && value !== "" ? value : null;
}

/** The user fields a session keeps from the validated ID token. */
export function profileOf(claims: { sub: string } & Record<string, unknown>): {
  sub: string;
  sid: string | null;
  name: string;
  email: string | null;
} {
  return {
    sub: claims.sub,
    sid: stringClaim(claims, "sid"),
    name:
      stringClaim(claims, "name") ??
      stringClaim(claims, "preferred_username") ??
      claims.sub,
    email: stringClaim(claims, "email"),
  };
}
