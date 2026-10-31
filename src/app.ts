import formbody from "@fastify/formbody";
import Fastify, { type FastifyError, type FastifyInstance, type FastifyServerOptions } from "fastify";
import auth from "./auth/index.ts";
import type { BffConfig } from "./config.ts";
import csrf from "./csrf.ts";
import health from "./health.ts";
import { hardenLogger } from "./log.ts";
import session, { BffHttpError, type SessionStore } from "./session.ts";

/** Options for {@link createBff}. */
export interface CreateBffOptions {
  /** Replaces the Valkey store (tests, single-process use). The caller closes it. */
  sessionStore?: SessionStore;
  /**
   * Fastify's `logger` option. Option objects get the library's request
   * serializer (no query strings) and header redaction. Default: JSON logs
   * at `info`.
   */
  logger?: FastifyServerOptions["logger"];
}

/**
 * Builds the BFF without starting it, so the app can add its own routes
 * before `listen()`. It never calls `ready()`. Discovery and the Valkey
 * connection are lazy: the first login, an authenticated request or
 * `/health/ready` triggers them, so `/health/live` works with neither.
 */
export async function createBff(config: BffConfig, opts: CreateBffOptions = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: hardenLogger(opts.logger), trustProxy: config.trustProxy });

  app.setErrorHandler((error: FastifyError, request, reply) => {
    const status = error.statusCode ?? 500;
    if (error instanceof BffHttpError || status < 500) {
      return reply.code(status).send({ error: error.code });
    }
    request.log.error({ err: error }, "request failed");
    return reply.code(500).send({ error: "internal_error" });
  });

  if (opts.sessionStore !== undefined) {
    app.decorate("bffStore", opts.sessionStore);
  }

  // Registration list, in the order of interface I1. LB3 to LB5 replace
  // their comment with the real line and keep this order.
  // LB3: await app.register(headers, config);
  await app.register(csrf, config);
  await app.register(session, config);
  await app.register(health, config);
  await app.register(formbody, { bodyLimit: 16 * 1024 });
  await app.register(auth, config);
  // LB4: await app.register(wellKnown, config);
  // LB5: await app.register(analytics, config);
  // LB3: await app.register(proxy, config);
  // LB3: await app.register(staticFiles, config);

  return app;
}
