import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import type { BffConfig } from "./config.ts";
import { pathOf } from "./log.ts";

/**
 * Content-Security-Policy for the SPA (OWASP CSP and Secure Headers cheat
 * sheets; ASVS 5.0 V3): same-origin everything, no inline script or style,
 * no plugins, no framing, no `<base>`.
 */
export const CONTENT_SECURITY_POLICY: string = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join("; ");

/** Powerful features switched off for every origin. */
export const PERMISSIONS_POLICY: string =
  "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

const STATIC_HEADERS: Record<string, string> = {
  "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  // OWASP Secure Headers Project: nothing in this app needs the referrer,
  // and the OIDC redirects work without it.
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": PERMISSIONS_POLICY,
  "X-Content-Type-Options": "nosniff",
};

function isDynamic(path: string): boolean {
  return path.startsWith("/api/") || path.startsWith("/bff/");
}

/**
 * Security headers on every response, including errors and proxied
 * responses (an upstream cannot weaken them). Set in `onSend`, so they win
 * over anything a route or upstream set. The BFF sends no CORS headers.
 * `/api/*` and `/bff/*` responses carry user data, so they get
 * `Cache-Control: no-store` unless the route already chose a policy.
 */
const headers: FastifyPluginAsync<BffConfig> = async (app, config) => {
  const hsts =
    config.production && config.publicOrigin.startsWith("https://")
      ? "max-age=31536000; includeSubDomains"
      : null;

  app.addHook("onSend", async (request, reply, payload) => {
    for (const [name, value] of Object.entries(STATIC_HEADERS)) {
      void reply.header(name, value);
    }
    if (hsts !== null) {
      void reply.header("Strict-Transport-Security", hsts);
    }
    if (
      isDynamic(pathOf(request.url)) &&
      reply.getHeader("cache-control") === undefined
    ) {
      void reply.header("Cache-Control", "no-store");
    }
    return payload;
  });
};

/** Security headers (CSP, COOP, CORP, HSTS, ...). Register first. */
const plugin: FastifyPluginAsync<BffConfig> = fp(headers, {
  name: "bff-headers",
});
export default plugin;
