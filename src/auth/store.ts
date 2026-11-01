import { randomBytes } from "node:crypto";
import { z } from "zod";
import { MemoryKv, createValkeyKv, type KvClient, type KvOp } from "./kv.ts";

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
  /**
   * Fencing token: 0 at login, bumped by every {@link SessionStore.replace}.
   * A token refresh only lands when the version it started from is still current.
   */
  version: number;
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
  version: z.number().int().nonnegative(),
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
  /**
   * Compare-and-set for a token refresh: writes `data` (stored with version
   * `expectedVersion + 1`) only when the stored session still has version
   * `expectedVersion`. Returns false, writing nothing, when the version moved
   * (another refresh won) or the session is gone (logout). Atomic.
   */
  replace(
    id: string,
    data: SessionData,
    ttlMs: number,
    expectedVersion: number,
  ): Promise<boolean>;
  /** Returns undefined when the session is missing, expired or unreadable. */
  get(id: string): Promise<SessionData | undefined>;
  /** Slides the idle timeout. Returns false when the session no longer exists. */
  touch(id: string, ttlSeconds: number): Promise<boolean>;
  /** Returns whether a session was destroyed. */
  destroy(id: string): Promise<boolean>;
  /**
   * Destroys a session and returns what was stored at that instant (atomic
   * GETDEL), or undefined when there was none. Logout revokes the refresh
   * token of this record, not of a stale snapshot.
   */
  take(id: string): Promise<SessionData | undefined>;
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
  /** Gives up a {@link claimOnce} claim (the claimed work failed and may be retried). */
  releaseClaim(key: string): Promise<void>;
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

  /** The index entries of a session: `sub:` always, `sid:` when the IdP issued one. */
  #indexKeys(data: SessionData): string[] {
    return [
      `sub:${data.sub}`,
      ...(data.sid === null ? [] : [`sid:${data.sid}`]),
    ];
  }

  async put(id: string, data: SessionData, ttlSeconds: number): Promise<void> {
    // One MULTI: the session and its index entries are written together.
    try {
      await this.#kv.multi([
        {
          op: "set",
          key: `sess:${id}`,
          value: JSON.stringify(data),
          ttlMs: ttlSeconds * 1000,
        },
        ...this.#indexKeys(data).map((key): KvOp => ({
          op: "sadd",
          key,
          member: id,
          ttlMs: this.#indexTtlMs,
        })),
      ]);
    } catch (error) {
      // MULTI does not roll back run-time failures: never leave a session
      // that back-channel logout cannot find.
      await this.#kv.del(`sess:${id}`).catch(() => 0);
      throw error;
    }
  }

  async replace(
    id: string,
    data: SessionData,
    ttlMs: number,
    expectedVersion: number,
  ): Promise<boolean> {
    return this.#kv.compareAndSetVersion(
      `sess:${id}`,
      expectedVersion,
      JSON.stringify({ ...data, version: expectedVersion + 1 }),
      ttlMs,
    );
  }

  async get(id: string): Promise<SessionData | undefined> {
    return parse(sessionDataSchema, await this.#kv.get(`sess:${id}`));
  }

  touch(id: string, ttlSeconds: number): Promise<boolean> {
    return this.#kv.pexpire(`sess:${id}`, ttlSeconds * 1000);
  }

  async destroy(id: string): Promise<boolean> {
    return (await this.take(id)) !== undefined;
  }

  async take(id: string): Promise<SessionData | undefined> {
    // GETDEL is atomic: what it returns is exactly what was removed.
    const data = parse(sessionDataSchema, await this.#kv.getDel(`sess:${id}`));
    if (data !== undefined) {
      await this.#kv.multi(
        this.#indexKeys(data).map((key): KvOp => ({
          op: "srem",
          key,
          member: id,
        })),
      );
    }
    return data;
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
      // Also drops ids whose session already expired (destroy found no data).
      await this.#kv.multi([{ op: "srem", key, member: id }]);
    }
    // No `del(key)` here: destroy() removes each id from the index, and a
    // session added meanwhile must keep its entry. The set expires by its TTL.
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

  async releaseClaim(key: string): Promise<void> {
    await this.#kv.del(`once:${key}`);
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
