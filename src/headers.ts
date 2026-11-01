import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import type { BffConfig } from "./config.ts";
import { pathOf } from "./log.ts";

declare module "fastify" {
  interface FastifyRequest {
    /**
     * The CSP nonce of this request's SPA HTML response, set by the static
     * plugin; `null` for every other response.
     */
    cspNonce: string | null;
  }
}

const CSP_DIRECTIVES_BEFORE_STYLE = ["default-src 'self'", "script-src 'self'"];
const CSP_DIRECTIVES_AFTER_STYLE = [
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
];

/**
 * Content-Security-Policy for the SPA (OWASP CSP and Secure Headers cheat
 * sheets; ASVS 5.0 V3): same-origin everything, no inline script or style,
 * no plugins, no framing, no `<base>`.
 */
export const CONTENT_SECURITY_POLICY: string = [
  ...CSP_DIRECTIVES_BEFORE_STYLE,
  "style-src 'self'",
  ...CSP_DIRECTIVES_AFTER_STYLE,
].join("; ");

/**
 * The policy of an SPA HTML response carrying a per-request nonce (ADR
 * 0005). Style elements need the nonce (MUI/Emotion inject `<style>` tags);
 * inline `style` attributes, which MUI also needs, are allowed without one
 * (`style-src-attr`). Scripts stay `'self'` only. `style-src 'self'` stays
 * as the fallback for browsers without CSP 3's `style-src-elem` split.
 */
export function contentSecurityPolicyWithNonce(nonce: string): string {
  return [
    ...CSP_DIRECTIVES_BEFORE_STYLE,
    "style-src 'self'",
    `style-src-elem 'self' 'nonce-${nonce}'`,
    "style-src-attr 'unsafe-inline'",
    ...CSP_DIRECTIVES_AFTER_STYLE,
  ].join("; ");
}

/** Powerful features switched off for every origin. */
export const PERMISSIONS_POLICY: string =
  "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

const STATIC_HEADERS: Record<string, string> = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  // OWASP Secure Headers Project: nothing in this app needs the referrer,
  // and the OIDC redirects work without it.
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": PERMISSIONS_POLICY,
  "X-Content-Type-Options": "nosniff",
};

function isApi(path: string): boolean {
  return path === "/api" || path.startsWith("/api/");
}

function isDynamic(path: string): boolean {
  return path.startsWith("/api/") || path.startsWith("/bff/");
}

/**
 * Security headers on every response, including errors and proxied
 * responses (an upstream cannot weaken them). Set in `onSend`, so they win
 * over anything a route or upstream set. The BFF sends no CORS headers.
 * `/api/*` responses (whatever the upstream said, unless
 * `apiCacheControl` is `upstream`) and `/bff/*` responses carry user data,
 * so they get `Cache-Control: no-store`; BFF routes may choose their own
 * policy. A request with a `cspNonce` gets the nonce policy.
 */
const headers: FastifyPluginAsync<BffConfig> = async (app, config) => {
  const hsts =
    config.production && config.publicOrigin.startsWith("https://")
      ? "max-age=31536000; includeSubDomains"
      : null;

  app.decorateRequest("cspNonce", null);

  app.addHook("onSend", async (request, reply, payload) => {
    void reply.header(
      "Content-Security-Policy",
      request.cspNonce === null
        ? CONTENT_SECURITY_POLICY
        : contentSecurityPolicyWithNonce(request.cspNonce),
    );
    for (const [name, value] of Object.entries(STATIC_HEADERS)) {
      void reply.header(name, value);
    }
    if (hsts !== null) {
      void reply.header("Strict-Transport-Security", hsts);
    }
    const path = pathOf(request.url);
    if (isApi(path)) {
      // The upstream chose its own policy, but this is per-user data;
      // `upstream` mode (ADR 0005) keeps it and defaults only a missing one.
      if (
        config.apiCacheControl === "no-store" ||
        reply.getHeader("cache-control") === undefined
      ) {
        void reply.header("Cache-Control", "no-store");
      }
    } else if (
      isDynamic(path) &&
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
