import { Valkey } from "iovalkey";

/**
 * The minimal key-value surface the session store needs. Every key has a
 * TTL. The Valkey implementation wraps `iovalkey`; the in-memory one backs
 * tests, so the store logic is exercised without a server.
 */
export interface KvClient {
  get(key: string): Promise<string | null>;
  /** Returns false only when `nx` is set and the key already exists. */
  set(
    key: string,
    value: string,
    opts: { ttlMs: number; nx?: boolean },
  ): Promise<boolean>;
  /** Atomically reads and deletes a key. */
  getDel(key: string): Promise<string | null>;
  /** Returns the number of keys that existed. */
  del(...keys: string[]): Promise<number>;
  /** Returns false when the key does not exist. */
  pexpire(key: string, ttlMs: number): Promise<boolean>;
  sadd(key: string, member: string): Promise<void>;
  srem(key: string, member: string): Promise<void>;
  smembers(key: string): Promise<string[]>;
  /** Deletes the key only when it still holds `value` (lock release). Returns whether it deleted. */
  delIfEquals(key: string, value: string): Promise<boolean>;
  ping(): Promise<void>;
  quit(): Promise<void>;
}

interface Entry {
  value: string | undefined;
  members: Set<string> | undefined;
  expiresAt: number | undefined;
}

/** In-memory {@link KvClient} for tests and single-process use. Not shared between replicas. */
export class MemoryKv implements KvClient {
  readonly #entries = new Map<string, Entry>();
  readonly #now: () => number;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  #live(key: string): Entry | undefined {
    const entry = this.#entries.get(key);
    if (entry?.expiresAt !== undefined && entry.expiresAt <= this.#now()) {
      this.#entries.delete(key);
      return undefined;
    }
    return entry;
  }

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.#live(key)?.value ?? null);
  }

  set(
    key: string,
    value: string,
    opts: { ttlMs: number; nx?: boolean },
  ): Promise<boolean> {
    if (opts.nx === true && this.#live(key) !== undefined) {
      return Promise.resolve(false);
    }
    this.#entries.set(key, {
      value,
      members: undefined,
      expiresAt: this.#now() + opts.ttlMs,
    });
    return Promise.resolve(true);
  }

  async getDel(key: string): Promise<string | null> {
    const value = await this.get(key);
    this.#entries.delete(key);
    return value;
  }

  del(...keys: string[]): Promise<number> {
    let count = 0;
    for (const key of keys) {
      if (this.#live(key) !== undefined) {
        count += 1;
      }
      this.#entries.delete(key);
    }
    return Promise.resolve(count);
  }

  pexpire(key: string, ttlMs: number): Promise<boolean> {
    const entry = this.#live(key);
    if (entry === undefined) {
      return Promise.resolve(false);
    }
    entry.expiresAt = this.#now() + ttlMs;
    return Promise.resolve(true);
  }

  sadd(key: string, member: string): Promise<void> {
    const existing = this.#live(key);
    if (existing?.members === undefined) {
      this.#entries.set(key, {
        value: undefined,
        members: new Set([member]),
        expiresAt: undefined,
      });
    } else {
      existing.members.add(member);
    }
    return Promise.resolve();
  }

  srem(key: string, member: string): Promise<void> {
    this.#live(key)?.members?.delete(member);
    return Promise.resolve();
  }

  smembers(key: string): Promise<string[]> {
    return Promise.resolve([...(this.#live(key)?.members ?? [])]);
  }

  async delIfEquals(key: string, value: string): Promise<boolean> {
    if ((await this.get(key)) !== value) {
      return false;
    }
    this.#entries.delete(key);
    return true;
  }

  ping(): Promise<void> {
    return Promise.resolve();
  }

  quit(): Promise<void> {
    return Promise.resolve();
  }
}

const RELEASE_LOCK_SCRIPT =
  'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end';

/** {@link KvClient} over an `iovalkey` connection. */
export class ValkeyKv implements KvClient {
  readonly #client: Valkey;

  constructor(client: Valkey) {
    this.#client = client;
  }

  get(key: string): Promise<string | null> {
    return this.#client.get(key);
  }

  async set(
    key: string,
    value: string,
    opts: { ttlMs: number; nx?: boolean },
  ): Promise<boolean> {
    const reply =
      opts.nx === true
        ? await this.#client.set(key, value, "PX", opts.ttlMs, "NX")
        : await this.#client.set(key, value, "PX", opts.ttlMs);
    return reply === "OK";
  }

  getDel(key: string): Promise<string | null> {
    return this.#client.getdel(key);
  }

  del(...keys: string[]): Promise<number> {
    return this.#client.del(...keys);
  }

  async pexpire(key: string, ttlMs: number): Promise<boolean> {
    return (await this.#client.pexpire(key, ttlMs)) === 1;
  }

  async sadd(key: string, member: string): Promise<void> {
    await this.#client.sadd(key, member);
  }

  async srem(key: string, member: string): Promise<void> {
    await this.#client.srem(key, member);
  }

  smembers(key: string): Promise<string[]> {
    return this.#client.smembers(key);
  }

  async delIfEquals(key: string, value: string): Promise<boolean> {
    return (await this.#client.eval(RELEASE_LOCK_SCRIPT, 1, key, value)) === 1;
  }

  async ping(): Promise<void> {
    await this.#client.ping();
  }

  async quit(): Promise<void> {
    if (this.#client.status === "ready") {
      await this.#client.quit();
    } else {
      this.#client.disconnect();
    }
  }
}

/**
 * Builds a lazily connecting Valkey client from a `redis(s)://` or
 * `valkey(s)://` URL. Nothing connects until the first command.
 */
export function createValkeyKv(url: string): KvClient {
  return new ValkeyKv(
    new Valkey(url.replace(/^valkey(s?):/, "redis$1:"), {
      lazyConnect: true,
      maxRetriesPerRequest: 2,
      enableReadyCheck: true,
    }),
  );
}
