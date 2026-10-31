function hasControlCharacter(value: string): boolean {
  return [...value].some((ch) => {
    const code = ch.charCodeAt(0);
    return code < 0x20 || code === 0x7f;
  });
}

/**
 * Validates the `returnTo` login parameter. Only a same-origin path
 * (optionally with a query) is accepted; anything else, including
 * protocol-relative (`//host`), backslash and control-character tricks,
 * falls back to `/`. This prevents open redirects after login.
 */
export function safeReturnTo(raw: unknown, publicOrigin: string): string {
  if (
    typeof raw !== "string" ||
    !raw.startsWith("/") ||
    raw.startsWith("//") ||
    raw.includes("\\") ||
    hasControlCharacter(raw)
  ) {
    return "/";
  }
  const url = new URL(raw, publicOrigin);
  const target = `${url.pathname}${url.search}`;
  // Dot segments can collapse "/..//evil.example" into the protocol-relative "//evil.example".
  return target.startsWith("//") ? "/" : target;
}
