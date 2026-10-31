import type { FastifyBaseLogger } from "fastify";
import type { Adapter, AnalyticsEvent, Log } from "./types.ts";

/** Umami's batch endpoint takes at most this many items per request (I3). */
export const BATCH_SIZE = 50;
/** Per-request timeout of the Umami adapter. */
export const TIMEOUT_MS = 2000;
/**
 * Umami silently drops events whose `User-Agent` looks like a bot (its
 * default `undici` one included), so the adapter sends a browser-shaped one.
 */
export const USER_AGENT = "Mozilla/5.0 (compatible; craftainer-bff)";

/** `none`: discards everything. */
export const noneAdapter: Adapter = {
  send: () => Promise.resolve(),
};

/** `{ analytics_event, analytics_url, analytics_prop_<key>: value }`: flat, as OTel attributes must be primitives. */
export function flatten(
  event: AnalyticsEvent,
): Record<string, string | number | boolean> {
  const fields: Record<string, string | number | boolean> = {
    analytics_event: event.name,
    analytics_url: event.url,
  };
  for (const [key, value] of Object.entries(event.props)) {
    fields[`analytics_prop_${key}`] = value;
  }
  return fields;
}

/** `log`: one structured log line per event. The visitor token is not logged. */
export function createLogAdapter(log: FastifyBaseLogger): Adapter {
  return {
    send(events) {
      for (const event of events) {
        log.info(flatten(event), "analytics_event");
      }
      return Promise.resolve();
    },
  };
}

/** The slice of `@opentelemetry/api-logs` the `otel` adapter uses. */
export interface OtelLogger {
  emit(record: {
    timestamp: number;
    severityNumber: number;
    severityText: string;
    body: string;
    attributes: Record<string, string | number | boolean>;
  }): void;
  enabled(): boolean;
}

/** Loads the OpenTelemetry logs API; rejects when the optional peer is absent. */
export async function loadOtelLogger(): Promise<OtelLogger> {
  const api = await import("@opentelemetry/api-logs");
  return api.logs.getLogger("@craftainer/bff") as unknown as OtelLogger;
}

/** OpenTelemetry `SeverityNumber.INFO`. */
const SEVERITY_INFO = 9;

/**
 * `otel`: one OpenTelemetry log record per event, props as primitive
 * attributes. `@opentelemetry/api-logs` is an optional peer dependency: when
 * it is not installed, or no LoggerProvider is registered (the API is then a
 * no-op), the adapter warns once and discards events, like `none`.
 */
export async function createOtelAdapter(
  log: Log,
  load: () => Promise<OtelLogger> = loadOtelLogger,
): Promise<Adapter> {
  let logger: OtelLogger;
  try {
    logger = await load();
  } catch {
    log.warn(
      "ANALYTICS_BACKEND=otel needs the optional peer @opentelemetry/api-logs; analytics off",
    );
    return noneAdapter;
  }
  let warned = false;
  return {
    send(events) {
      if (!logger.enabled()) {
        if (!warned) {
          warned = true;
          log.warn(
            "ANALYTICS_BACKEND=otel but no OpenTelemetry LoggerProvider is registered; events discarded",
          );
        }
        return Promise.resolve();
      }
      for (const event of events) {
        logger.emit({
          timestamp: event.timestamp * 1000,
          severityNumber: SEVERITY_INFO,
          severityText: "INFO",
          body: "analytics_event",
          attributes: flatten(event),
        });
      }
      return Promise.resolve();
    },
  };
}

/** Options of {@link createUmamiAdapter}. */
export interface UmamiOptions {
  /** Umami base URL; `/api/batch` is appended. */
  endpoint: string;
  siteId: string;
  /** Sent as `payload.hostname`; omitted when null. */
  hostname: string | null;
  log: Log;
  /** Test seams. */
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/** The exact item Umami's `/api/batch` expects (`type: "event"`), per its v3.4.1 schema. */
export function umamiItem(
  event: AnalyticsEvent,
  siteId: string,
  hostname: string | null,
): { type: "event"; payload: Record<string, unknown> } {
  const payload: Record<string, unknown> = {
    website: siteId,
    url: event.url,
    name: event.name,
    ip: event.visitor,
    timestamp: event.timestamp,
  };
  if (hostname !== null) {
    payload["hostname"] = hostname;
  }
  if (Object.keys(event.props).length > 0) {
    payload["data"] = event.props;
  }
  return { type: "event", payload };
}

/**
 * `umami`: `POST {endpoint}/api/batch`, at most 50 items per request, 2 s
 * timeout, no redirects followed (a 3xx is logged and the batch dropped: the
 * endpoint must be the final URL). A non-200 reply, or a 200 whose `errors`
 * is non-zero, is logged. Never rejects.
 */
export function createUmamiAdapter(options: UmamiOptions): Adapter {
  const url = `${options.endpoint.replace(/\/+$/, "")}/api/batch`;
  const doFetch = options.fetch ?? fetch;
  const timeoutMs = options.timeoutMs ?? TIMEOUT_MS;

  async function post(chunk: AnalyticsEvent[]): Promise<void> {
    const response = await doFetch(url, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify(
        chunk.map((e) => umamiItem(e, options.siteId, options.hostname)),
      ),
    });
    const text = await response.text();
    if (response.status >= 300 && response.status < 400) {
      options.log.warn(
        {
          status: response.status,
          location: response.headers.get("location") ?? "",
        },
        "umami batch dropped: redirect; ANALYTICS_ENDPOINT must be the final URL",
      );
    } else if (response.status !== 200) {
      options.log.warn({ status: response.status }, "umami batch rejected");
    } else {
      let errors: unknown;
      try {
        errors = (JSON.parse(text) as { errors?: unknown } | null)?.errors;
      } catch {
        options.log.warn("umami batch reply was not JSON");
        return;
      }
      if (typeof errors === "number" && errors > 0) {
        options.log.warn(
          { errors, events: chunk.length },
          "umami batch reported errors",
        );
      }
    }
  }

  return {
    async send(events) {
      for (let start = 0; start < events.length; start += BATCH_SIZE) {
        try {
          await post(events.slice(start, start + BATCH_SIZE));
        } catch (error) {
          options.log.warn({ err: String(error) }, "umami batch failed");
        }
      }
    },
  };
}
