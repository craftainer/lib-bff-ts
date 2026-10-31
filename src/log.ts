import type { FastifyBaseLogger, FastifyRequest, FastifyServerOptions } from "fastify";

/** Security-relevant events that are always logged as structured JSON. */
export type SecurityEvent =
  | "login_started"
  | "login_success"
  | "login_failed"
  | "logout"
  | "refresh_failed"
  | "csrf_rejected"
  | "origin_rejected"
  | "backchannel_logout"
  | "backchannel_logout_rejected"
  | "rate_limited";

const WARN_EVENTS: ReadonlySet<SecurityEvent> = new Set([
  "login_failed",
  "refresh_failed",
  "csrf_rejected",
  "origin_rejected",
  "backchannel_logout_rejected",
  "rate_limited",
]);

/** Allowed field values: never pass tokens, cookies or session IDs here. */
export type SecurityFields = Record<string, string | number | boolean | null>;

/**
 * Logs a security event as `{ security: true, event, ...fields }`. Callers
 * pass only identifiers that are safe to log (`sub`, `ip`, a reason code),
 * never tokens, cookies, session IDs or authorization codes.
 */
export function securityLog(log: FastifyBaseLogger, event: SecurityEvent, fields: SecurityFields = {}): void {
  const level = WARN_EVENTS.has(event) ? "warn" : "info";
  log[level]({ security: true, event, ...fields }, `security event: ${event}`);
}

/** Headers pino must censor even if a custom serializer ever includes them. */
export const REDACT_PATHS: string[] = [
  "req.headers.authorization",
  "req.headers.cookie",
  'res.headers["set-cookie"]',
  "headers.authorization",
  "headers.cookie",
];

/** The path of a request URL, without its query string. */
export function pathOf(url: string): string {
  return url.split("?", 1)[0] as string;
}

/** A request serializer that drops the query string (it carries the authorization code and state). */
export function serializeRequest(request: FastifyRequest): { method: string; url: string; remoteAddress: string } {
  return { method: request.method, url: pathOf(request.url), remoteAddress: request.ip };
}

/** The `logger` option as Fastify 5 accepts it (a logger instance goes in `loggerInstance`, not here). */
export type LoggerOption = NonNullable<FastifyServerOptions["logger"]>;

/**
 * Applies the library's logging rules to the `logger` option: the request
 * serializer drops query strings and sensitive headers are redacted.
 * `false` disables logging. Caller-supplied `redact` is replaced.
 */
export function hardenLogger(logger: FastifyServerOptions["logger"]): LoggerOption {
  if (logger === false) {
    return false;
  }
  const options = logger === undefined || logger === true ? { level: "info" } : logger;
  return {
    ...options,
    redact: { paths: REDACT_PATHS, censor: "[redacted]" },
    serializers: { ...("serializers" in options ? options.serializers : {}), req: serializeRequest },
  };
}
