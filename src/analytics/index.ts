import type {
  FastifyBaseLogger,
  FastifyPluginAsync,
  FastifyRequest,
} from "fastify";
import fp from "fastify-plugin";
import { z } from "zod";
import type { AnalyticsConfig, BffConfig } from "../config.ts";
import {
  createLogAdapter,
  createOtelAdapter,
  createUmamiAdapter,
  noneAdapter,
} from "./adapters.ts";
import { BoundedQueue } from "./queue.ts";
import type { Adapter, AnalyticsEvent } from "./types.ts";
import { bodySchema } from "./validate.ts";
import { createVisitorToken } from "./visitor.ts";

/** The consent cookie. `__Host-` pins it to this origin: Secure, Path=/, no Domain. */
export const CONSENT_COOKIE_NAME = "__Host-Http-consent";
/**
 * Consent lifetime: about six months, the maximum CNIL recommends before the
 * choice is asked again (<https://www.cnil.fr/en/sheet-ndeg16-use-analytics-your-websites-and-applications>).
 */
export const CONSENT_MAX_AGE_SECONDS: number = 180 * 24 * 60 * 60;

/** Queue capacity and flush interval of the Umami adapter (I3). */
const QUEUE_CAPACITY = 1000;
const FLUSH_INTERVAL_MS = 5000;
const BODY_LIMIT = 16 * 1024;

const consentSchema = z.strictObject({ analytics: z.boolean() });

function consentCookie(): {
  path: string;
  httpOnly: true;
  secure: true;
  sameSite: "strict";
} {
  return { path: "/", httpOnly: true, secure: true, sameSite: "strict" };
}

async function buildAdapter(
  a: AnalyticsConfig,
  log: FastifyBaseLogger,
): Promise<Adapter> {
  if (!a.enabled || a.backend === "none") {
    return noneAdapter;
  }
  if (a.backend === "log") {
    return createLogAdapter(log);
  }
  if (a.backend === "otel") {
    return createOtelAdapter(log);
  }
  return createUmamiAdapter({
    endpoint: a.endpoint as string,
    siteId: a.siteId as string,
    hostname: a.hostname,
    log,
  });
}

/** Whether this request's events may be recorded at all (the drop rules). */
function mayRecord(a: AnalyticsConfig, request: FastifyRequest): boolean {
  if (!a.enabled || a.backend === "none") {
    return false;
  }
  const { "sec-gpc": gpc, dnt } = request.headers;
  if (a.respectGpc && (gpc === "1" || dnt === "1")) {
    return false;
  }
  // An explicit decline ("0") wins in every mode, including `implied`.
  if (request.cookies[CONSENT_COOKIE_NAME] === "0") {
    return false;
  }
  return a.consent !== "opt-in" || request.bffAnalyticsConsent === true;
}

/**
 * `POST /bff/analytics` (SPA events), and `GET`/`POST /bff/consent` (the
 * opt-in state, I6). Analytics never fail a request: a dropped or accepted
 * event answers the same `202`, so the SPA learns nothing about the policy.
 * See ADR 0004 and NFR-0002.
 */
const analytics: FastifyPluginAsync<BffConfig> = async (app, config) => {
  const a = config.analytics;
  const limit = {
    max: config.rateLimit.max,
    timeWindow: config.rateLimit.windowSeconds * 1000,
  };
  const schema = bodySchema(a.propKeys);
  const visitorToken = createVisitorToken();
  const adapter = await buildAdapter(a, app.log);
  // Only the HTTP adapter is queued; log and otel run inline, like Python's.
  const queue =
    a.enabled && a.backend === "umami"
      ? new BoundedQueue<AnalyticsEvent>({
          capacity: QUEUE_CAPACITY,
          intervalMs: FLUSH_INTERVAL_MS,
          deliver: (events) => adapter.send(events),
          log: app.log,
        })
      : undefined;

  app.decorateRequest("bffAnalyticsConsent", false);
  app.addHook("onRequest", async (request) => {
    request.bffAnalyticsConsent = request.cookies[CONSENT_COOKIE_NAME] === "1";
  });
  app.addHook("onClose", async () => {
    await queue?.close();
  });

  app.post(
    "/bff/analytics",
    { bodyLimit: BODY_LIMIT, config: { rateLimit: limit } },
    async (request, reply) => {
      if (!mayRecord(a, request)) {
        return reply.code(202).send();
      }
      const parsed = schema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "invalid_event" });
      }
      const visitor = visitorToken(request.ip, request.headers["user-agent"]);
      const timestamp = Math.floor(Date.now() / 1000);
      const events = parsed.data.map((e) => ({ ...e, timestamp, visitor }));
      if (queue === undefined) {
        // Inline adapters; a throwing one is logged, never surfaced.
        Promise.resolve()
          .then(() => adapter.send(events))
          .catch((error: unknown) => {
            request.log.warn(
              { err: String(error) },
              "analytics adapter failed",
            );
          });
      } else {
        for (const event of events) {
          queue.push(event);
        }
      }
      return reply.code(202).send();
    },
  );

  app.post(
    "/bff/consent",
    { bodyLimit: BODY_LIMIT, config: { rateLimit: limit } },
    async (request, reply) => {
      const parsed = consentSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "invalid_consent" });
      }
      // Both answers are stored: "0" records an explicit decline, which the
      // drop rules honour even under `implied` consent.
      void reply.setCookie(
        CONSENT_COOKIE_NAME,
        parsed.data.analytics ? "1" : "0",
        { ...consentCookie(), maxAge: CONSENT_MAX_AGE_SECONDS },
      );
      return { analytics: parsed.data.analytics };
    },
  );

  app.get(
    "/bff/consent",
    { config: { rateLimit: limit } },
    async (request) => ({ analytics: request.bffAnalyticsConsent === true }),
  );
};

/** Analytics intake and consent state. Register after `auth` (it owns the rate limiter). */
const plugin: FastifyPluginAsync<BffConfig> = fp(analytics, {
  name: "bff-analytics",
  dependencies: ["bff-auth"],
});
export default plugin;
