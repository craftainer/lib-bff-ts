import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import type { BffConfig } from "./config.ts";

type Check = "ok" | "unavailable";

/**
 * `GET /health/live` always answers 200 (the process is up; it touches
 * neither Valkey nor the IdP). `GET /health/ready` answers 200 only when the
 * session store answers a PING and IdP discovery succeeds, else 503. Both
 * dependencies connect lazily, so readiness is what triggers them.
 */
const health: FastifyPluginAsync<BffConfig> = async (app) => {
  app.get("/health/live", async () => ({ status: "ok" }));

  app.get("/health/ready", async (request, reply) => {
    const [store, idp] = await Promise.allSettled([app.bffStore.ping(), app.bffOidc.configuration()]);
    const checks: Record<"store" | "idp", Check> = {
      store: store.status === "fulfilled" ? "ok" : "unavailable",
      idp: idp.status === "fulfilled" ? "ok" : "unavailable",
    };
    for (const [name, result] of [
      ["store", store],
      ["idp", idp],
    ] as const) {
      if (result.status === "rejected") {
        request.log.warn({ check: name, err: String(result.reason) }, "readiness check failed");
      }
    }
    const ready = checks.store === "ok" && checks.idp === "ok";
    return reply.code(ready ? 200 : 503).send({ status: ready ? "ok" : "unavailable", checks });
  });
};

/** Health endpoints. Register after `session`. */
const plugin: FastifyPluginAsync<BffConfig> = fp(health, { name: "bff-health", dependencies: ["bff-session"] });
export default plugin;
