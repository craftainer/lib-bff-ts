import replyFrom from "@fastify/reply-from";
import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
} from "fastify";
import fp from "fastify-plugin";
import type { IncomingHttpHeaders } from "node:http";
import { pipeline, Transform } from "node:stream";
import type { BffConfig, UpstreamConfig } from "./config.ts";
import { BffHttpError } from "./session.ts";

declare module "fastify" {
  interface FastifyRequest {
    /**
     * Interface I6. Set by the analytics plugin (before the proxy runs) to
     * whether the visitor consents to analytics. The proxy forwards
     * `Analytics-Consent: 1` upstream only when this is exactly `true`.
     */
    bffAnalyticsConsent?: boolean;
  }
}

/**
 * The only inbound headers forwarded upstream. Everything else is dropped,
 * in particular `Authorization`, `Cookie`, `X-CSRF`, `X-Forwarded-*` and
 * `Analytics-Consent`. `Sec-GPC` and `DNT` pass so that the backends'
 * analytics can honour them.
 */
export const FORWARDED_REQUEST_HEADERS: readonly string[] = [
  "accept",
  "accept-language",
  "content-type",
  "content-length",
  "if-none-match",
  "if-modified-since",
  "if-match",
  "if-unmodified-since",
  "if-range",
  "range",
  "accept-encoding",
  "traceparent",
  "tracestate",
  "x-request-id",
  "sec-gpc",
  "dnt",
];

/** Upstream response headers the BFF never relays to the browser. */
function dropResponseHeader(name: string): boolean {
  return (
    name === "set-cookie" ||
    name === "strict-transport-security" ||
    name.startsWith("access-control-")
  );
}

function upstreamRequestHeaders(
  inbound: IncomingHttpHeaders,
  token: string,
  consent: boolean | undefined,
): IncomingHttpHeaders {
  // `host` is already the upstream's (reply-from sets it before this runs).
  // reply-from adds no X-Forwarded-* headers by design, and neither do we.
  const out: IncomingHttpHeaders = { host: inbound.host };
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = inbound[name];
    if (value !== undefined) {
      out[name] = value;
    }
  }
  out.authorization = `Bearer ${token}`;
  if (consent === true) {
    out["analytics-consent"] = "1";
  }
  return out;
}

/**
 * True when the part of the path after `/api/<name>` cannot climb out of the
 * upstream's base path: no `.`/`..` segment (also percent-encoded, which the
 * WHATWG URL parser would resolve) and no backslash (parsed as `/`). Takes
 * the raw (still encoded) suffix.
 */
function isSafeSuffix(suffix: string): boolean {
  // Looks at the encoded form only, so it cannot throw: `%2e` is a dot,
  // `%2f` a slash and `%5c` a backslash. A double-encoded `%252e` stays
  // literal text, and the raw path goes upstream as is.
  return (
    !/\\|%5c/i.test(suffix) &&
    !suffix
      .replace(/%2e/gi, ".")
      .split(/\/|%2f/i)
      .some((segment) => segment === "." || segment === "..")
  );
}

async function mountUpstream(
  scope: FastifyInstance,
  name: string,
  upstream: UpstreamConfig,
  bodyLimit: number,
): Promise<void> {
  // The body goes upstream byte for byte: no JSON parsing, any content type.
  // It streams (nothing is buffered), but Fastify applies `bodyLimit` only to
  // buffered bodies, so the limit is enforced here: a `Content-Length` above
  // it answers 413 before anything goes upstream, and a counting transform
  // aborts a longer chunked body mid-flight (the upstream request is aborted,
  // never completed) and answers 413.
  const tooLarge = new WeakSet<FastifyRequest>();
  scope.removeAllContentTypeParsers();
  scope.addContentTypeParser("*", (request, payload, done) => {
    if (Number(request.headers["content-length"] ?? 0) > bodyLimit) {
      done(new BffHttpError(413, "payload_too_large"));
      return;
    }
    let seen = 0;
    const counter = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        seen += chunk.length;
        if (seen > bodyLimit) {
          tooLarge.add(request);
          callback(new BffHttpError(413, "payload_too_large"));
          return;
        }
        callback(null, chunk);
      },
    });
    // The pipeline destroys both streams when either fails.
    pipeline(payload, counter, () => undefined);
    done(null, counter);
  });
  await scope.register(replyFrom, {
    base: upstream.url,
    // SSE: no body timeout (reply-from also clears the socket timeout for
    // `text/event-stream` responses).
    ...(upstream.stream ? { undici: { bodyTimeout: 0 } } : {}),
  });

  const prefix = `/api/${name}`;
  const basePath = new URL(upstream.url).pathname.replace(/\/$/, "");
  const methods = new Set(upstream.methods);

  const handler = async (
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<FastifyReply> => {
    if (request.bffSession === null) {
      return reply.code(401).send({ error: "unauthorized" });
    }
    if (!methods.has(request.method)) {
      return reply
        .code(405)
        .header("Allow", upstream.methods.join(", "))
        .send({ error: "method_not_allowed" });
    }
    // The raw (still encoded) path goes upstream untouched, so an encoded
    // `%25`, `%2F` or `%23` means to the upstream what it meant to the
    // client. A prefix that only matches once decoded fails closed.
    const rawPath = request.url.split(/[?#]/, 1)[0] as string;
    const suffix = rawPath.slice(prefix.length);
    if (!rawPath.startsWith(prefix) || !isSafeSuffix(suffix)) {
      return reply.code(400).send({ error: "invalid_path" });
    }
    // Rejects with a BffHttpError (401 session_expired, 502
    // token_exchange_failed, 503) the app's error handler maps. On failure the
    // request never goes upstream, and never with another token.
    const token = await request.bffSession.accessTokenFor(name);
    return reply.from(basePath + (suffix === "" ? "/" : suffix), {
      rewriteRequestHeaders: (req, headers) =>
        upstreamRequestHeaders(headers, token, req.bffAnalyticsConsent),
      rewriteHeaders: (headers) =>
        Object.fromEntries(
          Object.entries(headers).filter(([key]) => !dropResponseHeader(key)),
        ),
      onError: (res, { error }) => {
        if (tooLarge.has(request)) {
          void res.code(413).send({ error: "payload_too_large" });
          return;
        }
        res.log.warn({ err: error }, "upstream request failed");
        void res.code(502).send({ error: "bad_gateway" });
      },
    });
  };

  scope.all(prefix, handler);
  scope.all(`${prefix}/*`, handler);
}

/**
 * The upstream allowlist proxy (RFC 10017 6.1.3.6): each entry of
 * `config.upstreams` is mounted at `/api/<name>/*` with the prefix stripped,
 * and nothing else is reachable. Built on `@fastify/reply-from` 12.8. Register
 * after `session` (and after `analytics`, which sets `bffAnalyticsConsent`).
 */
const proxy: FastifyPluginAsync<BffConfig> = async (app, config) => {
  for (const [name, upstream] of Object.entries(config.upstreams)) {
    await app.register(async (scope) =>
      mountUpstream(scope, name, upstream, config.proxyBodyLimitBytes),
    );
  }
};

/** The authenticated upstream proxy. */
const plugin: FastifyPluginAsync<BffConfig> = fp(proxy, {
  name: "bff-proxy",
  dependencies: ["bff-session"],
});
export default plugin;
