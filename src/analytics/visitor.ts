import { createHmac, randomBytes } from "node:crypto";

/** Characters kept of the base64url HMAC (132 bits). */
const TOKEN_LENGTH = 22;

function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * Derives the pseudonymous daily visitor token the Umami adapter sends as
 * `payload.ip`: `base64url(HMAC-SHA256(dailySalt, ip + "\n" + userAgent))`
 * cut to 22 characters. The salt is 32 random bytes held only in memory and
 * replaced when the UTC date changes, so tokens cannot be linked across days
 * and cannot be reversed without the salt. Each replica has its own salt.
 *
 * `now` and `random` are test seams.
 */
export function createVisitorToken(
  now: () => number = Date.now,
  random: () => Buffer = () => randomBytes(32),
): (ip: string, userAgent: string | undefined) => string {
  let day = "";
  let salt: Buffer = Buffer.alloc(0);
  return (ip, userAgent) => {
    const today = utcDay(now());
    if (today !== day) {
      day = today;
      salt = random();
    }
    return createHmac("sha256", salt)
      .update(`${ip}\n${userAgent ?? ""}`)
      .digest("base64url")
      .slice(0, TOKEN_LENGTH);
  };
}
