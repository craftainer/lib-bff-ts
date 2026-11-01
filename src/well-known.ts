import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import type { BffConfig } from "./config.ts";

/** Date this library started honouring GPC (the `lastUpdate` of `gpc.json`). Not "today". */
const GPC_LAST_UPDATE = "2026-10-31";

/** RFC 9727 section 4.2: the profile URI that marks a linkset as an API catalog. */
const API_CATALOG_PROFILE = "https://www.rfc-editor.org/info/rfc9727";

/** RFC 9116 section 2.5.5 recommends an `Expires` less than a year ahead. */
const DEFAULT_EXPIRES_DAYS = 364;
const DAY_MS = 24 * 60 * 60 * 1000;

/** A value is usable as a `security.txt` field only when it cannot start a new line (field injection). */
function isSingleLine(value: string): boolean {
  return !/[\r\n]/.test(value);
}

function securityTxt(config: BffConfig, now: Date): string {
  const { securityTxt: cfg, publicOrigin } = config;
  const expires =
    cfg.expires ??
    new Date(now.getTime() + DEFAULT_EXPIRES_DAYS * DAY_MS).toISOString();
  const canonical = cfg.canonical ?? `${publicOrigin}/.well-known/security.txt`;
  const fields: [string, string | null][] = [
    ...cfg.contact.map((c): [string, string] => ["Contact", c]),
    ["Expires", expires],
    ["Policy", cfg.policy],
    ["Preferred-Languages", cfg.preferredLanguages],
    ["Canonical", canonical],
  ];
  return fields
    .filter((f): f is [string, string] => f[1] !== null && isSingleLine(f[1]))
    .map(([name, value]) => `${name}: ${value}\n`)
    .join("");
}

/** RFC 9264 linkset (`application/linkset+json`) with one entry per configured upstream. */
function apiCatalog(config: BffConfig): Buffer {
  const origin = config.publicOrigin;
  const names = Object.keys(config.upstreams);
  // Names match [a-z][a-z0-9-]* (config schema), so they are URL-safe as is.
  const linkset =
    names.length === 0
      ? []
      : [
          {
            anchor: `${origin}/.well-known/api-catalog`,
            item: names.map((name) => ({
              href: `${origin}/api/${name}/`,
              title: name,
            })),
            "api-catalog": names.map((name) => ({
              href: `${origin}/api/${name}/.well-known/api-catalog`,
              title: name,
            })),
          },
        ];
  // A Buffer, so Fastify adds no `charset` parameter to the media type.
  return Buffer.from(JSON.stringify({ linkset }));
}

/**
 * Well-known endpoints (ADR 0003). Each is served only when its config
 * enables it, else the route is absent and answers 404:
 * `security.txt` (RFC 9116, needs `securityTxt.contact`), `change-password`
 * (302 to `changePasswordUrl`), `gpc.json` (while `analytics.respectGpc`)
 * and `api-catalog` (RFC 9727, always). GET and HEAD both work.
 */
const wellKnown: FastifyPluginAsync<BffConfig> = async (app, config) => {
  if (config.securityTxt.contact.length > 0) {
    // Computed once at startup, so the default `Expires` is stable between requests.
    const body = securityTxt(config, new Date());
    app.get("/.well-known/security.txt", async (_request, reply) =>
      reply.type("text/plain; charset=utf-8").send(body),
    );
  }

  const changePasswordUrl = config.changePasswordUrl;
  if (changePasswordUrl !== null) {
    app.get("/.well-known/change-password", async (_request, reply) =>
      reply.redirect(changePasswordUrl, 302),
    );
  }

  if (config.analytics.respectGpc) {
    const body = Buffer.from(
      JSON.stringify({ gpc: true, lastUpdate: GPC_LAST_UPDATE }),
    );
    app.get("/.well-known/gpc.json", async (_request, reply) =>
      reply.type("application/json").send(body),
    );
  }

  const catalog = apiCatalog(config);
  app.get("/.well-known/api-catalog", async (_request, reply) =>
    reply
      .type(`application/linkset+json; profile="${API_CATALOG_PROFILE}"`)
      .header(
        "link",
        `<${config.publicOrigin}/.well-known/api-catalog>; rel="api-catalog"`,
      )
      .send(catalog),
  );
};

/** Well-known endpoints. Register after `auth`. */
const plugin: FastifyPluginAsync<BffConfig> = fp(wellKnown, {
  name: "bff-well-known",
});
export default plugin;
