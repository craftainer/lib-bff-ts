/** A property value: scalars only (I3). */
export type Scalar = string | number | boolean;

/** One validated event, ready for an adapter. */
export interface AnalyticsEvent {
  /** `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`, at most 50 characters. */
  name: string;
  /** Allowlisted scalar properties. */
  props: Record<string, Scalar>;
  /** A path only: no query, no fragment. */
  url: string;
  /** Unix seconds. */
  timestamp: number;
  /** Pseudonymous daily visitor token (see `visitor.ts`); never a raw IP. */
  visitor: string;
}

/** Where validated events go. `send` may reject; the caller catches it. */
export interface Adapter {
  send(events: AnalyticsEvent[]): Promise<void>;
}

/** The slice of the Fastify logger the analytics code needs. */
export interface Log {
  warn(message: string): void;
  warn(fields: object, message: string): void;
}
