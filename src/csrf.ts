import type { FastifyPluginAsync, FastifyReply } from "fastify";
import fp from "fastify-plugin";
import type { BffConfig } from "./config.ts";
import { securityLog } from "./log.ts";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * The only requests that need no `X-CSRF` header: the two top-level
 * navigations of the login flow, and the IdP's back-channel logout call,
 * which is authenticated by its signed logout token instead.
 */
const EXEMPT = new Set(["GET /bff/login", "GET /bff/callback", "POST /bff/backchannel-logout"]);

function pathOf(url: string): string {
  return new URL(url, "http://localhost").pathname;
}

/**
 * CSRF defence for the BFF (RFC 10017 6.1.3.3.2): every `/api/*` request and
 * every non-GET `/bff/*` request must carry `X-CSRF: 1`, which a cross-site
 * page cannot add without a CORS preflight (the BFF sends no CORS headers).
 * In addition, unsafe methods are rejected when `Sec-Fetch-Site` says the
 * request is not same-origin or `Origin` is not `PUBLIC_ORIGIN`.
 */
const csrf: FastifyPluginAsync<BffConfig> = async (app, config) => {
  app.addHook("onRequest", async (request, reply) => {
    const path = pathOf(request.url);
    const method = request.method;
    if (EXEMPT.has(`${method} ${path}`)) {
      return;
    }
    const safe = SAFE_METHODS.has(method);
    const isApi = path === "/api" || path.startsWith("/api/");
    const isBff = path.startsWith("/bff/");
    const reject = (event: "csrf_rejected" | "origin_rejected", reason: string): FastifyReply => {
      securityLog(request.log, event, { method, path, reason, ip: request.ip });
      return reply.code(403).send({ error: event });
    };

    if (!safe) {
      const site = request.headers["sec-fetch-site"];
      if (site !== undefined && site !== "same-origin" && site !== "none") {
        return reject("origin_rejected", `sec-fetch-site: ${String(site).slice(0, 20)}`);
      }
      const origin = request.headers["origin"];
      if (origin !== undefined && origin !== config.publicOrigin) {
        return reject("origin_rejected", "origin mismatch");
      }
    }
    if ((isApi || (isBff && !safe)) && request.headers["x-csrf"] !== "1") {
      return reject("csrf_rejected", "missing X-CSRF header");
    }
  });
};

/** The CSRF / Origin guard. Register before `session` and `auth`. */
const plugin: FastifyPluginAsync<BffConfig> = fp(csrf, { name: "bff-csrf" });
export default plugin;
