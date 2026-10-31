import { randomBytes } from "node:crypto";
import { z } from "zod";
import { MemoryKv, createValkeyKv, type KvClient } from "./kv.ts";

/** What a session holds server-side. Tokens never reach the browser. */
export interface SessionData {
  sub: string;
  /** The IdP session ID (`sid` claim), when the IdP issues one. */
  sid: string | null;
  name: string;
  email: string | null;
  roles: Record<string, string[]>;
  idToken: string;
  accessToken: string;
  refreshToken: string | null;
  /** Epoch seconds. */
  accessExpiresAt: number;
  /** Epoch seconds. */
  createdAt: number;
  /** Epoch seconds; the session never outlives this, however often it is used. */
  absoluteExpiresAt: number;
}

/** The server-side login transaction (state is its key). */
export interface LoginTransaction {
  nonce: string;
  codeVerifier: string;
  returnTo: string;
}

const sessionDataSchema: z.ZodType<SessionData> = z.object({
  sub: z.string(),
  sid: z.string().nullable(),
  name: z.string(),
  email: z.string().nullable(),
  roles: z.record(z.string(), z.array(z.string())),
  idToken: z.string(),
  accessToken: z.string(),
  refreshToken: z.string().nullable(),
  accessExpiresAt: z.number(),
  createdAt: z.number(),
  absoluteExpiresAt: z.number(),
});

const transactionSchema: z.ZodType<LoginTransaction> = z.object({
  nonce: z.string(),
  codeVerifier: z.string(),
  returnTo: z.string(),
});

/** Persistence for sessions, login transactions and one-time claims. */
export interface SessionStore {
  /** Creates or replaces a session; it expires after `ttlSeconds` unless touched. */
  put(id: string, data: SessionData, ttlSeconds: number): Promise<void>;
  /** Returns undefined when the session is missing, expired or unreadable. */
  get(id: string): Promise<SessionData | undefined>;
  /** Slides the idle timeout. Returns false when the session no longer exists. */
  touch(id: string, ttlSeconds: number): Promise<boolean>;
  /** Returns whether a session was destroyed. */
  destroy(id: string): Promise<boolean>;
  /** Back-channel logout: destroys every session of an IdP session id. Returns the count. */
  destroyBySid(sid: string): Promise<number>;
  /** Back-channel logout: destroys every session of a subject. Returns the count. */
  destroyBySub(sub: string): Promise<number>;
  /** Takes the per-session refresh lock; undefined when someone else holds it. */
  acquireLock(id: string, ttlMs: number): Promise<string | undefined>;
  releaseLock(id: string, token: string): Promise<void>;
  putTransaction(
    state: string,
    tx: LoginTransaction,
    ttlSeconds: number,
  ): Promise<void>;
  /** Single use: reads and deletes. */
  takeTransaction(state: string): Promise<LoginTransaction | undefined>;
  /** Returns true the first time a key is claimed within its TTL (replay protection). */
  claimOnce(key: string, ttlSeconds: number): Promise<boolean>;
  /** Rejects when the backing store is unreachable. */
  ping(): Promise<void>;
  close(): Promise<void>;
}

/** A 256-bit random identifier, URL-safe. */
export function randomId(): string {
  return randomBytes(32).toString("base64url");
}

function parse<T>(schema: z.ZodType<T>, raw: string | null): T | undefined {
  if (raw === null) {
    return undefined;
  }
  try {
    const result = schema.safeParse(JSON.parse(raw));
    return result.success ? result.data : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The session store over a {@link KvClient}: `sess:<id>` holds the session,
 * `sid:<sid>` and `sub:<sub>` are index sets for back-channel logout,
 * `lock:<id>` is the refresh lock, `tx:<state>` the login transaction and
 * `once:<key>` a one-time claim.
 */
export class KvSessionStore implements SessionStore {
  readonly #kv: KvClient;
  readonly #indexTtlMs: number;

  /** `indexTtlSeconds` must be at least the longest session lifetime. */
  constructor(kv: KvClient, opts: { indexTtlSeconds: number }) {
    this.#kv = kv;
    this.#indexTtlMs = opts.indexTtlSeconds * 1000;
  }

  async put(id: string, data: SessionData, ttlSeconds: number): Promise<void> {
    await this.#kv.set(`sess:${id}`, JSON.stringify(data), {
      ttlMs: ttlSeconds * 1000,
    });
    const indexes = [
      `sub:${data.sub}`,
      ...(data.sid === null ? [] : [`sid:${data.sid}`]),
    ];
    for (const key of indexes) {
      await this.#kv.sadd(key, id);
      await this.#kv.pexpire(key, this.#indexTtlMs);
    }
  }

  async get(id: string): Promise<SessionData | undefined> {
    return parse(sessionDataSchema, await this.#kv.get(`sess:${id}`));
  }

  touch(id: string, ttlSeconds: number): Promise<boolean> {
    return this.#kv.pexpire(`sess:${id}`, ttlSeconds * 1000);
  }

  async destroy(id: string): Promise<boolean> {
    const data = await this.get(id);
    const existed = (await this.#kv.del(`sess:${id}`)) > 0;
    if (data !== undefined) {
      await this.#kv.srem(`sub:${data.sub}`, id);
      if (data.sid !== null) {
        await this.#kv.srem(`sid:${data.sid}`, id);
      }
    }
    return existed;
  }

  destroyBySid(sid: string): Promise<number> {
    return this.#destroyIndex(`sid:${sid}`);
  }

  destroyBySub(sub: string): Promise<number> {
    return this.#destroyIndex(`sub:${sub}`);
  }

  async #destroyIndex(key: string): Promise<number> {
    let count = 0;
    for (const id of await this.#kv.smembers(key)) {
      if (await this.destroy(id)) {
        count += 1;
      }
    }
    await this.#kv.del(key);
    return count;
  }

  async acquireLock(id: string, ttlMs: number): Promise<string | undefined> {
    const token = randomId();
    return (await this.#kv.set(`lock:${id}`, token, { ttlMs, nx: true }))
      ? token
      : undefined;
  }

  async releaseLock(id: string, token: string): Promise<void> {
    await this.#kv.delIfEquals(`lock:${id}`, token);
  }

  async putTransaction(
    state: string,
    tx: LoginTransaction,
    ttlSeconds: number,
  ): Promise<void> {
    await this.#kv.set(`tx:${state}`, JSON.stringify(tx), {
      ttlMs: ttlSeconds * 1000,
    });
  }

  async takeTransaction(state: string): Promise<LoginTransaction | undefined> {
    return parse(transactionSchema, await this.#kv.getDel(`tx:${state}`));
  }

  claimOnce(key: string, ttlSeconds: number): Promise<boolean> {
    return this.#kv.set(`once:${key}`, "1", {
      ttlMs: ttlSeconds * 1000,
      nx: true,
    });
  }

  ping(): Promise<void> {
    return this.#kv.ping();
  }

  close(): Promise<void> {
    return this.#kv.quit();
  }
}

/** An in-memory store for tests and single-process development. */
export function createMemorySessionStore(
  opts: { indexTtlSeconds?: number; now?: () => number } = {},
): SessionStore {
  return new KvSessionStore(new MemoryKv(opts.now), {
    indexTtlSeconds: opts.indexTtlSeconds ?? 86_400,
  });
}

/** The production store: Valkey via `iovalkey`, connecting lazily on first use. */
export function createValkeySessionStore(
  storeUrl: string,
  indexTtlSeconds: number,
): SessionStore {
  return new KvSessionStore(createValkeyKv(storeUrl), { indexTtlSeconds });
}
