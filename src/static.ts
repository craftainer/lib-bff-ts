import fastifyStatic from "@fastify/static";
import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
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
 * Serves the built SPA from `config.staticDir` (when set) with an SPA
 * fallback, and answers every other unknown path with a JSON 404.
 *
 * - `@fastify/static` runs in wildcard mode (`wildcard: true`), so its glob
 *   code path (LB1 advisory decision) is never reached.
 * - Dotfiles are denied (403); there is no directory listing (`list` unset).
 * - `Cache-Control`: files under `assets/` (Vite's hashed output) are
 *   `public, max-age=31536000, immutable`; everything else, `index.html`
 *   included, is `no-cache` (revalidate with the ETag).
 * - The fallback: a GET with `Accept: text/html` for an unknown path outside
 *   `/api`, `/bff`, `/health` and `/.well-known` serves `index.html`.
 */
const staticFiles: FastifyPluginAsync<BffConfig> = async (app, config) => {
  const root = config.staticDir === null ? null : resolve(config.staticDir);

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

  app.setNotFoundHandler((request, reply) => {
    if (
      root !== null &&
      request.method === "GET" &&
      (request.headers.accept ?? "").includes("text/html") &&
      !isReserved(pathOf(request.url))
    ) {
      return reply.code(200).sendFile("index.html");
    }
    return reply.code(404).send({ error: "not_found" });
  });
};

/** Static SPA serving and the JSON 404. Register last. */
const plugin: FastifyPluginAsync<BffConfig> = fp(staticFiles, {
  name: "bff-static",
});
export default plugin;
