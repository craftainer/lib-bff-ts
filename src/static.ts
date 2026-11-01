import fastifyStatic from "@fastify/static";
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import type { BffConfig } from "./config.ts";
import { pathOf } from "./log.ts";

/** Paths the SPA fallback and the file server never answer. */
const RESERVED = ["/api", "/bff", "/health", "/.well-known"];

function isReserved(path: string): boolean {
  return RESERVED.some(
    (prefix) => path === prefix || path.startsWith(`${prefix}/`),
  );
}

/**
 * The nonce placeholder the SPA build must emit: set Vite's
 * `html.cspNonce` to this exact string. Every occurrence in `index.html` is
 * replaced by a fresh nonce on each response.
 */
export const CSP_NONCE_PLACEHOLDER = "__CSP_NONCE__";

/**
 * Serves the built SPA from `config.staticDir` (when set) with an SPA
 * fallback, and answers every other unknown path with a JSON 404.
 *
 * - `@fastify/static` runs in wildcard mode (`wildcard: true`), so its glob
 *   code path (LB1 advisory decision) is never reached.
 * - Dotfiles are denied (403); there is no directory listing (`list` unset).
 * - `Cache-Control`: files under `assets/` (Vite's hashed output) are
 *   `public, max-age=31536000, immutable`; everything else is `no-cache`
 *   (revalidate with the ETag).
 * - `index.html`, at `/`, `/index.html` and as the fallback, is read per
 *   request, gets a fresh CSP nonce in place of `CSP_NONCE_PLACEHOLDER`
 *   (the `headers` plugin then sends the matching CSP) and is `no-store`.
 * - The fallback: a GET with `Accept: text/html` for an unknown path outside
 *   `/api`, `/bff`, `/health` and `/.well-known` serves `index.html`.
 */
const staticFiles: FastifyPluginAsync<BffConfig> = async (app, config) => {
  const root = config.staticDir === null ? null : resolve(config.staticDir);

  /** Sends the nonced `index.html`; false when it cannot be read. */
  async function sendIndex(
    dir: string,
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<boolean> {
    let html: string;
    try {
      html = await readFile(join(dir, "index.html"), "utf8");
    } catch {
      return false;
    }
    const nonce = randomBytes(16).toString("base64");
    request.cspNonce = nonce;
    void reply
      .code(200)
      .type("text/html; charset=utf-8")
      .header("Cache-Control", "no-store")
      .send(html.replaceAll(CSP_NONCE_PLACEHOLDER, nonce));
    return true;
  }

  if (root !== null) {
    app.addHook("onRequest", async (request, reply) => {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return;
      }
      // pathOf already decodes once, as the router does; a second decode
      // would throw on `%25` and treat `/%2569ndex.html` as the index.
      const path = pathOf(request.url);
      if (path === "/" || path === "/index.html") {
        if (await sendIndex(root, request, reply)) {
          return reply;
        }
      }
    });
  }

  if (root !== null) {
    const assets = join(root, "assets") + sep;
    await app.register(fastifyStatic, {
      root,
      wildcard: true,
      dotfiles: "deny",
      cacheControl: false,
      allowedPath: (pathName) => !isReserved(pathName),
      setHeaders: (reply, path) => {
        void reply.header(
          "Cache-Control",
          path.startsWith(assets)
            ? "public, max-age=31536000, immutable"
            : "no-cache",
        );
      },
    });
  }

  app.setNotFoundHandler(async (request, reply) => {
    if (
      root !== null &&
      request.method === "GET" &&
      (request.headers.accept ?? "").includes("text/html") &&
      !isReserved(pathOf(request.url)) &&
      (await sendIndex(root, request, reply))
    ) {
      return reply;
    }
    return reply.code(404).send({ error: "not_found" });
  });
};

/** Static SPA serving and the JSON 404. Register last. */
const plugin: FastifyPluginAsync<BffConfig> = fp(staticFiles, {
  name: "bff-static",
});
export default plugin;
